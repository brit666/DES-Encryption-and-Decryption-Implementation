#include <iostream>
#include <stdio.h>
#include "des.h"

uint64_t* des_encrypt(const unsigned char* plaintext, const unsigned char* key);

int main() {
    const unsigned char* plaintext = (const unsigned char*)"Hello World!";
    const unsigned char* my_key = (const unsigned char*)"SECRET";

    size_t len = strlen((const char*)plaintext);
    size_t pad = 8 - (len % 8);
    size_t block_count = (len + pad) / 8;

    uint64_t* result = des_encrypt(plaintext, my_key);

    std::cout << "Encrypted Data (Hex): ";
    for (size_t i = 0; i < block_count; i++) {
        printf("%016llX ", (unsigned long long)result[i]);
    }
    std::cout << std::endl;

	unsigned char* decrypted_text = des_decrypt(result, my_key);

    std::cout << "Decrypted Clean Text: " << reinterpret_cast<const char*>(decrypted_text) << "\n";

    delete[] result;
    return 0;
}

