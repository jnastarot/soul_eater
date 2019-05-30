#include "pch.h"
#include <iostream>

int main() {

    soul_holder sh;
    sh.main_image = pe_image(std::string("..\\..\\app for test\\test.sys"));
    sh.functions.push_back({0x1C000E0F0 , 0});
    sh.dependencies.push_back({ 0x1C009BE74, 4, 0, std::vector<uint8_t>() });
    sh.dependencies.push_back({ 0x1C009BE70, 4, 0, std::vector<uint8_t>() });
    sh.dependencies.push_back({ 0x1C009BEC0, 0x800, 0, std::vector<uint8_t>() });
    sh.dependencies.push_back({ 0x1c0035000, 0x4000, 0, std::vector<uint8_t>() });


    if (!se_soul_spider_initialize_code(sh, 0) &&
        !se_soul_spider_initialize_data(sh)) {

        pe_image new_image;

        se_soul_link(sh, new_image);
    }



    return 0;
}