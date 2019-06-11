#include "stdafx.h"
#include "soul_linker.h"

struct relocation_data_item {
    uint64_t data;
    uint32_t offset;
};

bool link_data_relocations(soul_holder& soul, std::vector<relocation_data_item>& out_relocs, pe_image& new_image) {

    pe_relocations_directory relocations;
    pe_directory_code relcode = get_relocation_directory(soul.main_image.get_image(), relocations);

    {
        pe_image_io relocation_io(soul.main_image.get_image());
        relocations.sort();
        for (auto& rel_entry : relocations.get_entries()) {

            relocation_io.set_image_offset(rel_entry.relative_virtual_address).read(
                &rel_entry.data,
                soul.code_holder.get_arch() == FUKU_ASSAMBLER_ARCH_X86 ? sizeof(uint32_t) : sizeof(uint64_t)
            );
        }
    }

    if (relcode == pe_directory_code_success) {
        relocations.sort();

        for (auto& data : soul.dependencies) {

            for (auto& rel_item : relocations.get_entries()) {

                if (data.entry_original_va - soul.main_image.get_image().get_image_base() <= rel_item.relative_virtual_address &&
                    data.entry_original_va + data.data_size - soul.main_image.get_image().get_image_base() > rel_item.relative_virtual_address) {

                    fuku_instruction * line = soul.code_holder.get_direct_line_by_source_va(rel_item.data);

                    if (line) { //found in code

                        out_relocs.push_back({
                                    line->get_virtual_address(),
                                    (uint32_t)(data.entry_new_va + (rel_item.relative_virtual_address 
                                    - (data.entry_original_va - soul.main_image.get_image().get_image_base())) - new_image.get_image_base())
                            });
                    }
                    else { //try to find in data
                        bool has_found_in_data = false;

                        for (auto& t_data : soul.dependencies) {

                            if (t_data.entry_original_va <= rel_item.data &&
                                t_data.entry_original_va + t_data.data_size > rel_item.data) {

                                out_relocs.push_back({
                                    t_data.entry_new_va + (rel_item.data - t_data.entry_original_va),
                                    (uint32_t)(data.entry_new_va + (rel_item.relative_virtual_address
                                    - (data.entry_original_va - soul.main_image.get_image().get_image_base())) - new_image.get_image_base())
                                    });

                                has_found_in_data = true;

                                break;
                            }
                        }

                        if (!has_found_in_data) {
                            printf("cant link relocation in %I64x \n",
                                rel_item.relative_virtual_address + soul.main_image.get_image().get_image_base());
                            return false;
                        }

                    }

                }

                if (rel_item.relative_virtual_address > data.entry_original_va + data.data_size - soul.main_image.get_image().get_image_base()) { break; }
            }
        }

        return true;
    }

    return false;
}

se_soul_spider_link_status se_soul_link(
    soul_holder& soul, pe_image_full& new_image
) {


    pe_image& image = soul.main_image.get_image();
    uint32_t image_ptr_size = image.is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t);

    {
        bool has_unlinked = false;

        soul.code_holder.update_origin_idxs();
        soul.code_holder.merge_labels();

        for (auto& label : soul.code_holder.get_labels()) {//try to link all dependencies of code

            if (!label.has_linked_instruction) {

                //try to find in data dependences
                for (auto& deps_data : soul.dependencies) {
                    if (deps_data.entry_original_va <= label.dst_address &&
                        deps_data.entry_original_va + deps_data.data_size > label.dst_address) {

                        goto next_label;
                    }
                }

                //try to find it in import
                auto& image_imports = soul.main_image.get_imports();
                for (auto& library : image_imports.get_libraries()) {

                    if ((library.get_rva_iat() + image.get_image_base()) <= label.dst_address &&
                        (library.get_rva_iat() + image.get_image_base() +
                            library.get_entries().size() * image_ptr_size) >= label.dst_address) {

                        //was found in import

                        goto next_label;
                    }
                }


                //try to find in load configs
                auto& load_config = soul.main_image.get_load_config();
                if (image.get_image_base() + load_config.get_guard_cf_dispatch_function_pointer() == label.dst_address) {

                    //is a reference to not direct call

                    goto next_label;
                }

                if (image.get_image_base() + load_config.get_security_cookie() == label.dst_address) {

                    //is a reference to not direct call

                    soul.dependencies.push_back({ label.dst_address, image_ptr_size, 0, std::vector<uint8_t>() });
                    soul.dependencies.back().raw_data.resize(image_ptr_size);

                    goto next_label;
                }




                has_unlinked = true;

                printf("error unlinked label %I64x\n", label.dst_address);
            }

        next_label:;
        }

        if (has_unlinked) {
            return se_soul_spider_link_status_fail;
        }
    }


    new_image.get_image() = pe_image(image.is_x32_image());
    pe_image_io image_io(new_image.get_image(), enma_io_mode_allow_expand);

    pe_section& text_section = new_image.get_image().add_section();

    text_section.set_section_name(".text")
        .set_readable(true).set_executable(true).set_writeable(false);


    soul.code_holder.update_virtual_address(
        new_image.get_image().get_image_base() + 0x1000
    );

    auto&  last_line = soul.code_holder.get_lines().back();

    {
        uint64_t data_region = ALIGN_UP((last_line.get_virtual_address() + last_line.get_op_length()), 0x1000);
        size_t data_region_size = 0;

        for (auto& dep_entry : soul.dependencies) {
            dep_entry.entry_new_va = data_region + data_region_size;
            data_region_size += dep_entry.data_size;
            data_region_size = ALIGN_UP(data_region_size, 0x10);
        }
    }

    //handle all code labels 
    for (auto& label : soul.code_holder.get_labels()) {

        if (!label.has_linked_instruction) {

            for (auto& dep_entry : soul.dependencies) {
                if (dep_entry.entry_original_va <= label.dst_address &&
                    dep_entry.entry_original_va + dep_entry.data_size > label.dst_address) {

                    label.dst_address = dep_entry.entry_new_va + (label.dst_address - dep_entry.entry_original_va);
                    break;
                }
            }
        }
    }

    std::vector<fuku_image_relocation> code_relocations;
    std::vector<fuku_code_association> associations;
    std::vector<uint8_t> raw_code = finalize_code(soul.code_holder, &associations, &code_relocations);


    if (image_io.set_image_offset(0x1000).write(raw_code) != enma_io_success) {

        return se_soul_spider_link_status_fail;
    }

    pe_section& data_section = new_image.get_image().add_section();
    data_section.set_section_name(".data")
        .set_readable(true).set_executable(false).set_writeable(true);

    for (auto& dep_entry : soul.dependencies) {

        if (image_io.set_image_offset(
                dep_entry.entry_new_va - new_image.get_image().get_image_base()
            ).write(dep_entry.raw_data) != enma_io_success) {

            return se_soul_spider_link_status_fail;
        }
    }

    std::vector<relocation_data_item> data_relocations;
    if (!link_data_relocations(soul, data_relocations, new_image.get_image())) {

        return se_soul_spider_link_status_fail;
    }



    for (auto& data_reloc : data_relocations) {
        if (image_io.set_image_offset(data_reloc.offset).write(&data_reloc.data, image_ptr_size) != enma_io_success) {

            return se_soul_spider_link_status_fail;
        }
    }

    //handle all relocations
    {
        auto& relocations = new_image.get_relocations();


        for (auto& code_reloc : code_relocations) {
            relocations.add_entry(code_reloc.virtual_address, 0);
        }

        for (auto& data_reloc : data_relocations) {
            relocations.add_entry(data_reloc.offset, 0);
        }
    }


    if (soul.exports.size()) {

        auto& exports = new_image.get_exports();

        for (auto& sl_export : soul.exports) {
            pe_export_entry entry;

            entry.set_has_name(!sl_export.b_ord);

            if (sl_export.b_ord) {
                entry.set_name_ordinal(sl_export.ordinal);
            }
            else {
                entry.set_func_name(sl_export.export_name);
            }
            
            auto line = soul.code_holder.get_direct_line_by_source_va(sl_export.entry_va);

            if (!line) {
                printf("not found va for export ! \n");
            }

            entry.set_rva(line->get_virtual_address() - new_image.get_image().get_image_base());


            exports.add_entry(entry);
        }
    }

    /*
    for (auto func : functions_table) {
        for (auto& assoc : associations) { //fix it later
            if (func == assoc.original_virtual_address) {
                code.functions_offset.push_back(assoc.virtual_address);
                break;
            }
        }
    }
    */

    return se_soul_spider_link_status_ok;
}