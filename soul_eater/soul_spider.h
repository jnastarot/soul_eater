#pragma once

enum se_soul_spider_initialize_status {
    se_soul_spider_initialize_status_ok,
    se_soul_spider_initialize_status_fail,
};

#define SE_CODE_SPIDER_STOP_ON_INT3          1 //ignore int3 instrction like stop to parse this basic code block
#define SE_CODE_SPIDER_ALLOW_UNREACHABLE_JMP 2 //jmp [eax] now allowed
#define SE_CODE_SPIDER_ALLOW_UNRETURNED_CODE 4 //where code was end on some instruction like mov but not on jmp or ret



se_soul_spider_initialize_status se_soul_spider_initialize_code(
    soul_holder& soul, uint32_t flags
);

se_soul_spider_initialize_status se_soul_spider_initialize_data(
    soul_holder& soul
);