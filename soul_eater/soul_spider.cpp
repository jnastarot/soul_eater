#include "stdafx.h"
#include "soul_spider.h"


struct relocation_data_item {
    uint64_t data;
    uint32_t offset;
};

bool function_basic_block_processor(
    csh handle,
    fuku_code_holder& code_holder,
    uint64_t image_base,
    uint64_t process_va,
    std::vector<uint8_t>& image_map,
    std::vector<uint64_t>& process_queue,
    std::map<uint64_t, uint32_t>& processed_addresses) {

    cs_insn *insn;
    size_t count = cs_disasm(handle, &image_map[process_va - image_base], 0x1000, process_va, 0, &insn); //TODO: CHUNK SIZE

    if (count) {

        for (size_t insn_idx = 0; insn_idx < count; insn_idx++) {
            fuku_instruction &line = code_holder.add_line();

            auto& current_insn = insn[insn_idx];

            processed_addresses[current_insn.address] = current_insn.size;

            line.set_source_virtual_address(current_insn.address)
                .set_virtual_address(current_insn.address)
                .set_op_code(&image_map[current_insn.address - image_base], (uint8_t)current_insn.size)
                .set_used_eflags(current_insn.detail->x86.eflags)
                .set_id(current_insn.id)
                .set_used_regs(current_insn.detail->x86.encoding.disp_offset << 8 | current_insn.detail->x86.encoding.imm_offset);


            for (uint8_t op_idx = 0; op_idx < current_insn.detail->x86.op_count; op_idx++) {
                auto& operand = current_insn.detail->x86.operands[op_idx];

                if (operand.type == X86_OP_MEM) {

                    if (operand.mem.base == X86_REG_RIP) {

                        line.set_rip_relocation_idx(
                            code_holder.create_rip_relocation(current_insn.detail->x86.encoding.disp_offset, X86_REL_ADDR(current_insn))
                        );

                        break;
                    }
                }
            }

            switch (current_insn.id) {
            case  X86_INS_CALL:
            case  X86_INS_JO: case  X86_INS_JNO:
            case  X86_INS_JB: case  X86_INS_JAE:
            case  X86_INS_JE: case  X86_INS_JNE:
            case  X86_INS_JBE:case  X86_INS_JA:
            case  X86_INS_JS: case  X86_INS_JNS:
            case  X86_INS_JP: case  X86_INS_JNP:
            case  X86_INS_JL: case  X86_INS_JGE:
            case  X86_INS_JLE:case  X86_INS_JG:
            case  X86_INS_JMP:
            case  X86_INS_JECXZ:case X86_INS_JCXZ:
            case  X86_INS_LOOP: case X86_INS_LOOPE: case X86_INS_LOOPNE: {

                if (current_insn.detail->x86.operands[0].type == X86_OP_IMM) {

                    uint64_t target_va = X86_REL_ADDR(current_insn);

                    line.set_rip_relocation_idx(
                        code_holder.create_rip_relocation(current_insn.detail->x86.encoding.imm_offset, target_va)
                    );

                    if (process_va > target_va ||
                        current_insn.address < target_va) {

                        process_queue.push_back(target_va);
                    }

                }

                break;
            }

            default:break;

            }


            if (current_insn.id == X86_INS_JMP &&
                current_insn.detail->x86.operands[0].type != X86_OP_IMM) {

                if (current_insn.detail->x86.operands[0].type == X86_OP_MEM &&
                    (current_insn.detail->x86.operands[0].mem.base == X86_REG_RIP ||
                        current_insn.detail->x86.operands[0].mem.base == X86_REG_INVALID) &&
                    current_insn.detail->x86.operands[1].mem.base == X86_REG_INVALID) {


                    continue;
                }


                printf("has unreachable jmp in va 0x%I64x (basic block) \n", process_va);

                cs_free(insn, count);
                return false;

            }
            else if (current_insn.id == X86_INS_RET ||
                current_insn.id == X86_INS_JMP ||
                current_insn.id == X86_INS_INT3) {

                cs_free(insn, count);
                return true;
            }
        }
    }
    else {

        printf("error to disassamle in va 0x%I64x (basic block) \n", process_va);

        return false;
    }


    cs_free(insn, count);

    return true;
}


void extend_handle_jmps(fuku_code_holder& code_holder) {

    fuku_assambler fuku_asm(code_holder.get_arch());
    fuku_asm.set_holder(&code_holder, ASSAMBLER_HOLD_TYPE_FIRST_OVERWRITE);

    for (auto line_iter = code_holder.get_lines().begin(); line_iter != code_holder.get_lines().end(); ++line_iter) {

        fuku_instruction& line = *line_iter;

        switch (line.get_id()) {

        case X86_INS_JMP: {

            if (line.get_op_code()[line.get_op_pref_size()] == 0xEB) { //near jump

                uint8_t op_code[16];
                memcpy(op_code, line.get_op_code(), line.get_op_length());

                op_code[line.get_op_pref_size()] = 0xE9;

                line.set_op_code(op_code, line.get_op_length() + 3);
            }

            break;
        }

        case  X86_INS_JO: case  X86_INS_JNO:
        case  X86_INS_JB: case  X86_INS_JAE:
        case  X86_INS_JE: case  X86_INS_JNE:
        case  X86_INS_JBE:case  X86_INS_JA:
        case  X86_INS_JS: case  X86_INS_JNS:
        case  X86_INS_JP: case  X86_INS_JNP:
        case  X86_INS_JL: case  X86_INS_JGE:
        case  X86_INS_JLE:case  X86_INS_JG: {

            if ((line.get_op_code()[line.get_op_pref_size()] & 0xF0) == 0x70) { //near jump

                uint8_t op_code[16];
                memcpy(op_code, line.get_op_code(), line.get_op_length());

                op_code[line.get_op_pref_size()] = 0x0F;
                op_code[line.get_op_pref_size() + 1] = 0x80 | (line.get_op_code()[line.get_op_pref_size()] & 0x0F);
                line.set_op_code(op_code, line.get_op_length() + 4);

                code_holder.get_rip_relocations()[line.get_rip_relocation_idx()].offset = 2;
            }

            break;
        }


        case X86_INS_JCXZ:
        case X86_INS_JECXZ: {

            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_register reg;

            if (line.get_id() == X86_INS_JECXZ) { //or ecx,ecx
                reg = reg_(FUKU_REG_ECX);
            }
            else { //or cx,cx
                reg = reg_(FUKU_REG_CX);
            }

            fuku_asm.or_(reg, reg);
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_EQUAL, fuku_immediate(0));
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code_holder.get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }


        case X86_INS_LOOP: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_NOT_EQUAL, imm(0));      //jnz
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code_holder.get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        case X86_INS_LOOPE: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_EQUAL, imm(0));      //jz
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code_holder.get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        case X86_INS_LOOPNE: {
            fuku_asm.set_first_emit(true).set_position(line_iter);

            size_t label_idx_f = line.get_label_idx();
            size_t rip_label_idx = line.get_rip_relocation_idx();

            fuku_asm.dec(reg_(FUKU_REG_ECX));                  //dec ecx
            fuku_asm.get_context().inst->set_label_idx(label_idx_f);

            fuku_asm.jcc(FUKU_CONDITION_NOT_EQUAL, imm(0));      //jne
            fuku_asm.get_context().inst->set_rip_relocation_idx(rip_label_idx);
            code_holder.get_rip_relocations()[line.get_rip_relocation_idx()].offset = fuku_asm.get_context().immediate_offset;

            ++line_iter;
            break;
        }

        default:break;
        }
    }
}


se_soul_spider_initialize_status se_soul_spider_initialize_code(soul_holder& soul) {

    std::vector<uint64_t> process_queue;
    std::map<uint64_t, uint32_t> processed_addresses;

    soul.code_holder.clear();
    soul.relocations.clear();

    pe_image& image = soul.main_image.get_image();


    soul.code_holder.set_arch(image.is_x32_image() ?
        FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

    std::vector<uint8_t> image_map;

    {//create image virtual map

        pe_image_io image_map_io(image);
        image_map_io.seek_to_start();

        uint64_t hi_barier = 0;
        for (auto& section : image.get_sections()) {
            uint64_t barier = section->get_virtual_address() + section->get_virtual_size();

            if (barier > hi_barier) { hi_barier = barier; }
        }

        image_map_io.read(
            image_map,
            ALIGN_UP(hi_barier, image.get_section_align())
        );
    }
    

    {//get functions code

        csh handle;

        if (cs_open(CS_ARCH_X86,
            image.is_x32_image() ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK) {

            return se_soul_spider_initialize_status_fail;
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        for (auto& function : soul.functions) {
            process_queue.push_back(function.entry_va);
        }


        for (size_t process_va_idx = 0; process_va_idx < process_queue.size(); process_va_idx++) {

            if (processed_addresses.find(process_queue[process_va_idx]) == processed_addresses.end()) {

                if (!function_basic_block_processor(
                    handle,
                    soul.code_holder,
                    image.get_image_base(), process_queue[process_va_idx], image_map,
                    process_queue, processed_addresses)) {

                    printf("its must not happened!\n");

                    cs_close(&handle);
                    return se_soul_spider_initialize_status_fail;
                }
            }
        }

        cs_close(&handle);

        extend_handle_jmps(soul.code_holder);
    }


    {//debug print
        struct placement_item {
            uint64_t address;
            uint64_t size;
        };

        std::vector<placement_item> placement_items;

        for (auto& place_item : processed_addresses) {
            placement_items.push_back({ place_item.first, place_item.second });
        }

        for (size_t parent_zone_idx = 0; parent_zone_idx + 1 < placement_items.size(); parent_zone_idx++) { //link zones

            if (placement_items[parent_zone_idx].address <= placement_items[parent_zone_idx + 1].address &&
                (placement_items[parent_zone_idx].address + placement_items[parent_zone_idx].size) >= placement_items[parent_zone_idx + 1].address
                ) {

                if ((placement_items[parent_zone_idx + 1].address +
                    placement_items[parent_zone_idx + 1].size) > (placement_items[parent_zone_idx].address + placement_items[parent_zone_idx].size)) {

                    placement_items[parent_zone_idx].size =
                        ((placement_items[parent_zone_idx + 1].address + placement_items[parent_zone_idx + 1].size) - placement_items[parent_zone_idx].address);
                }

                placement_items.erase(placement_items.begin() + parent_zone_idx + 1);
                parent_zone_idx--;
            }
        }

        for (auto& entry : placement_items) {
            printf("linked code in : 0x%I64x-0x%I64x\n", entry.address, entry.address + entry.size);
        }
    }

    return se_soul_spider_initialize_status_ok;
}

se_soul_spider_initialize_status se_soul_spider_initialize_data(
    soul_holder& soul
) {

    {//get data raw
        pe_image_io data_io(soul.main_image.get_image());

        for (auto& dep_entry : soul.dependencies) {

            data_io.set_image_offset(dep_entry.entry_original_va - image.get_image_base());

            if (data_io.read(dep_entry.raw_data, dep_entry.data_size) != enma_io_success) {

                printf("error to get data entry in : %I64x - %I64x \n",
                    dep_entry.entry_original_va, dep_entry.entry_original_va + dep_entry.data_size);

                return se_soul_spider_initialize_status_fail;
            }
        }
    }



    return se_soul_spider_initialize_status_ok;
}