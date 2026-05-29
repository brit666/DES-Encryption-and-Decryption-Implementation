#include <iostream>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include "des.h"

void generate_subkeys(const unsigned char* key, uint64_t* subkeys);
uint32_t des_feistel(uint32_t R, uint64_t round_key);
uint64_t des_initial_permutation(const DES_Block* input_block);
uint64_t des_final_permutation(uint64_t block_val);

unsigned char* des_decrypt(const uint64_t* ciphertext_array, const unsigned char* key)
{
    size_t block_count = (size_t)ciphertext_array[0];

    uint64_t subkeys[16] = { 0 };
    generate_subkeys(key, subkeys);

    DES_Block* decrypted_blocks = new DES_Block[block_count];

    for (size_t i = 0; i < block_count; i++) {
        uint64_t current_block = ciphertext_array[i + 1];

        DES_Block temp_struct;
        for (int b = 0; b < 8; b++) {
            temp_struct.bytes[b] = (uint8_t)(current_block >> (56 - (b * 8))) & 0xFF;
        }
        uint64_t ip_result = des_initial_permutation(&temp_struct);

        uint32_t L = (uint32_t)(ip_result >> 32);
        uint32_t R = (uint32_t)(ip_result & 0xFFFFFFFF);

        for (int round = 15; round >= 0; round--) {
            uint32_t prev_L = L;
            L = R;
            R = prev_L ^ des_feistel(R, subkeys[round]);
        }

        uint64_t pre_fp_block = ((uint64_t)R << 32) | L;

        uint64_t final_block_val = des_final_permutation(pre_fp_block);

        for (int b = 0; b < 8; b++) {
            decrypted_blocks[i].bytes[b] = (uint8_t)(final_block_val >> (56 - (b * 8))) & 0xFF;
        }
    }

    size_t total_allocated_bytes = block_count * 8;
    uint8_t pad_value = decrypted_blocks[block_count - 1].bytes[7];

    if (pad_value < 1 || pad_value > 8) {
        std::cout << "Error: Decryption failed. Invalid padding or wrong key!" << std::endl;
        delete[] decrypted_blocks;
        return nullptr;
    }

    size_t clean_string_len = total_allocated_bytes - pad_value;

    unsigned char* plaintext = new unsigned char[clean_string_len + 1];

    for (size_t i = 0; i < clean_string_len; i++) {
        size_t source_block = i / 8;
        size_t source_byte = i % 8;
        plaintext[i] = decrypted_blocks[source_block].bytes[source_byte];
    }
    plaintext[clean_string_len] = '\0'; 

    delete[] decrypted_blocks;

    return plaintext;
}
