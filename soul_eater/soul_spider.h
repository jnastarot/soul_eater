#pragma once

enum se_soul_spider_initialize_status {
    se_soul_spider_initialize_status_ok,
    se_soul_spider_initialize_status_fail,

};

se_soul_spider_initialize_status se_soul_spider_initialize_code(
    soul_holder& soul
);

se_soul_spider_initialize_status se_soul_spider_initialize_data(
    soul_holder& soul
);