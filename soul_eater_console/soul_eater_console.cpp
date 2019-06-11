#include "pch.h"
#include <iostream>


int main(int argc, char **argv) {

    /*
    if (argc < 2) {
        printf("please set soul_map file as a argument!\n");
        return 0;
    }
    */


    argv[1] = (char*)"C:\\projects\\soul_eater\\example\\soul_map.txt";

    soul_holder sh;

    if (process_text_map(argv[1], sh)) {

        if (!se_soul_spider_initialize_code(sh, 0) &&
            !se_soul_spider_initialize_data(sh)) {

            pe_image_full new_image;

            se_soul_link(sh, new_image);

            std::vector<uint8_t> out_image;
            build_pe_image_full(new_image, PE_IMAGE_BUILD_ALL_EXTENDED_SECTIONS | PE_IMAGE_BUILD_ALL_DIRECTORIES, out_image);

            FILE* hTargetFile;
            fopen_s(&hTargetFile, "..\\..\\app for test\\sl_test.exe", "wb");

            if (hTargetFile) {
                fwrite(out_image.data(), out_image.size(), 1, hTargetFile);
                fclose(hTargetFile);
            }
        }
    }


    return 0;
}