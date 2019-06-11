#include "pch.h"
#include "text_processor.h"


uint64_t string_to_hex(const char* strhex) {
    
    uint64_t hex_value = 0;

    for (size_t char_idx = 0;
        (strhex[char_idx] >= '0' && strhex[char_idx] <= '9') ||
        (strhex[char_idx] >= 'a' && strhex[char_idx] <= 'f') ||
        (strhex[char_idx] >= 'A' && strhex[char_idx] <= 'F'); char_idx++) {

        if ((strhex[char_idx] >= '0' && strhex[char_idx] <= '9')) {

            hex_value = hex_value * 0x10 + (strhex[char_idx] - '0');
        }
        else if (strhex[char_idx] >= 'a' && strhex[char_idx] <= 'f') {

            hex_value = hex_value * 0x10 + ((strhex[char_idx] - 'a') + 10);
        }
        else if (strhex[char_idx] >= 'A' && strhex[char_idx] <= 'F') {

            hex_value = hex_value * 0x10 + ((strhex[char_idx] - 'A') + 10);
        }
    }

    return hex_value;
}

bool process_text_map(const std::string& text_map, soul_holder& sh) {


    ifstream file(text_map);

    std::string line;
    while (getline(file, line)) {

        if (!line.size()) { continue; }


        if (line.find("IMAGE") != std::string::npos) {
            sh.main_image = pe_image(std::string(&line[6]));

            continue;

        }
        else if (line.find("FUNCTION") != std::string::npos) {
            size_t address_pos = line.find("0x");

            if (address_pos != std::string::npos) {
                sh.functions.push_back({ string_to_hex(&line[address_pos + 2]), 0 });

                continue;
            }

        }
        else if (line.find("DATA") != std::string::npos) {

            size_t address_pos = line.find("0x");

            if (address_pos != std::string::npos) {

                size_t size_pos = line.find("0x", address_pos + 2);

                if (size_pos != std::string::npos) {
                    sh.dependencies.push_back({
                        string_to_hex(&line[address_pos + 2]) ,
                        string_to_hex(&line[size_pos + 2]),
                        0,
                        std::vector<uint8_t>()
                        });

                    continue;
                }
            }

        }
        else if (line.find("EXPORT") != std::string::npos) {

            size_t address_pos = line.find("0x");

            if (address_pos != std::string::npos) {

                size_t name_pos = line.find("NAME:", address_pos);

                if (name_pos != std::string::npos) {
                    sh.exports.push_back({
                        false,
                        &line[name_pos + 5],
                        0,
                        string_to_hex(&line[address_pos + 2]) ,
                        });

                    continue;
                }

                size_t ord_pos = line.find("ORD:" , address_pos);

                if (ord_pos != std::string::npos) {
                    sh.exports.push_back({
                        false,
                        "",
                        string_to_hex(&line[ord_pos + 4]),
                        string_to_hex(&line[address_pos + 2]) ,
                        });

                    continue;
                }

            }
        }

        printf("unknown map format: %s\n", line.c_str());
        return false;
    }

    return true;
}