#pragma once

#define SE_RELOC_IMPORT_CALL 0xE0000000
#define SE_RELOC_GUARD_CALL  0xF0000000


struct se_export_entry {
    bool b_ord;

    std::string export_name;
    uint64_t ordinal;

    uint64_t entry_va;
};

struct se_function_entry{
    uint64_t entry_va;
    uint64_t new_va;
};

struct se_data_entry {
    uint64_t entry_original_va;
    uint64_t data_size;
    uint64_t entry_new_va;

    std::vector<uint8_t> raw_data;
};

struct soul_holder {
    pe_image_full main_image;
    fuku_code_holder code_holder;
    std::vector<se_function_entry> functions;
    std::vector<se_data_entry> dependencies;
    std::vector<se_export_entry> exports;

    std::vector<pe_relocation_entry> relocations;
};


#include "soul_spider.h"
#include "soul_linker.h"