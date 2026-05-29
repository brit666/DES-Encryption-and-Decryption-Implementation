#include <iostream>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include "des.h"

void generate_subkeys(const unsigned char* key, uint64_t subkeys[16]);
uint32_t des_feistel(uint32_t R, uint64_t round_key);
uint64_t des_initial_permutation(const DES_Block* input_block);
uint64_t des_final_permutation(uint64_t block_val);

uint64_t *des_encrypt(const unsigned char* plaintext, const unsigned char* key)
{
    size_t len = strlen((const char*)plaintext);
    size_t pad = 8 - (len % 8);
    size_t block_count = (len + pad) / 8;

    DES_Block* block = new DES_Block[block_count];

    for (size_t i = 0; i < len; i++) {
        size_t target_block = i / 8;
        size_t target_byte = i % 8;

        block[target_block].bytes[target_byte] = plaintext[i];
    }

    size_t total_padded_bytes = block_count * 8;

    for (size_t j = len; j < total_padded_bytes; j++) {
        size_t target_block = j / 8;
        size_t target_byte = j % 8;

        block[target_block].bytes[target_byte] = (uint8_t)pad;
    }

    uint64_t* permuted_blocks = new uint64_t[block_count];

    for (size_t i = 0; i < block_count; i++) {
        permuted_blocks[i] = des_initial_permutation(&block[i]);
    }

    uint64_t subkeys[16] = { 0 };
    generate_subkeys(key, subkeys);

    uint64_t* encrypted_blocks = new uint64_t[block_count];

    for (size_t i = 0; i < block_count; i++) {
        uint64_t current_block = permuted_blocks[i];

        uint32_t L = (uint32_t)(current_block >> 32);
        uint32_t R = (uint32_t)(current_block & 0xFFFFFFFF);

        for (int round = 0; round < 16; round++) {
            uint32_t prev_L = L;
            L = R;
            R = prev_L ^ des_feistel(R, subkeys[round]);
        }

        uint64_t pre_fp_block = ((uint64_t)R << 32) | L;

        encrypted_blocks[i] = des_final_permutation(pre_fp_block);
    }

    delete[] block;
    delete[] permuted_blocks;

    uint64_t* output = new uint64_t[block_count + 1];
    output[0] = (uint64_t)block_count;
    for (size_t i = 0; i < block_count; i++) {
        output[i + 1] = encrypted_blocks[i];
    }
    delete[] encrypted_blocks;

    return output;
}

uint64_t des_initial_permutation(const DES_Block* input_block) {
    uint64_t permuted_output = 0;

    for (int i = 0; i < 64; i++) {
        int des_bit = IP_TABLE[i];

        int bit_index = des_bit - 1;
        int src_byte = bit_index / 8;
        int src_bit = bit_index % 8;

        uint8_t isolated_bit = (input_block->bytes[src_byte] >> (7 - src_bit)) & 1;

        int dest_shift = 63 - i;
        permuted_output |= ((uint64_t)isolated_bit << dest_shift);
    }

    return permuted_output;
}

uint32_t des_feistel(uint32_t R, uint64_t round_key) {
    uint64_t expanded_R = 0;
    for (int i = 0; i < 48; i++) {
        int src_shift = 32 - E_TABLE[i];
        uint64_t bit = (R >> src_shift) & 1;
        expanded_R |= (bit << (47 - i));
    }

    uint64_t xor_result = expanded_R ^ round_key;

    uint32_t sbox_output = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t chunk = (xor_result >> (42 - (i * 6))) & 0x3F;

        uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        uint8_t col = (chunk & 0x1E) >> 1;

        uint32_t val = S_BOXES[i][row][col];
        sbox_output |= (val << (28 - (i * 4)));
    }

    uint32_t final_p_output = 0;
    for (int i = 0; i < 32; i++) {
        int src_shift = 32 - P_TABLE[i];
        uint32_t bit = (sbox_output >> src_shift) & 1;
        final_p_output |= (bit << (31 - i));
    }

    return final_p_output;
}

void generate_subkeys(const unsigned char* key, uint64_t subkeys[16]) {
    uint64_t packed_key = 0;
    for (int i = 0; i < 8; i++) {
        packed_key |= ((uint64_t)key[i]) << (56 - (i * 8));
    }

    uint64_t permuted_key = 0;
    for (int i = 0; i < 56; i++) {
        int src_shift = 64 - PC1_TABLE[i];
        uint64_t bit = (packed_key >> src_shift) & 1;
        permuted_key |= (bit << (55 - i));
    }

    uint32_t C = (uint32_t)(permuted_key >> 28);
    uint32_t D = (uint32_t)(permuted_key & 0x0FFFFFFF);

    for (int round = 0; round < 16; round++) {
        int shifts = SHIFT_TABLE[round];

        C = ((C << shifts) | (C >> (28 - shifts))) & 0x0FFFFFFF;
        D = ((D << shifts) | (D >> (28 - shifts))) & 0x0FFFFFFF;

        uint64_t combined = ((uint64_t)C << 28) | D;
        uint64_t round_key = 0;

        for (int i = 0; i < 48; i++) {
            int src_shift = 56 - PC2_TABLE[i];
            uint64_t bit = (combined >> src_shift) & 1;
            round_key |= (bit << (47 - i));
        }

        subkeys[round] = round_key;
    }
}

uint64_t des_final_permutation(uint64_t block_val) {
    uint64_t output = 0;
    for (int i = 0; i < 64; i++) {
        int src_shift = 64 - FP_TABLE[i];
        uint64_t bit = (block_val >> src_shift) & 1;
        output |= (bit << (63 - i));
    }
    return output;
}