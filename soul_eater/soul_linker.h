#pragma once

enum se_soul_spider_link_status {
    se_soul_spider_link_status_ok,
    se_soul_spider_link_status_fail,

};


se_soul_spider_link_status se_soul_link(
    soul_holder& soul, pe_image_full& new_image
);