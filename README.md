# DES Encryption Algorithm — C/C++ Implementation

## Overview

This project implements symmetric encryption and decryption using the DES block cipher. The goal was to build every component of the algorithm manually — permutation tables, S-box lookups, key schedule generation — to develop a low-level understanding of how classical block ciphers work.

---

## Features

- Full DES encryption and decryption
- 16-round Feistel network
- Key schedule generation with PC-1 and PC-2 permutations
- Initial and final permutations (IP / FP)
- E-box expansion, S-box substitution, and P-box permutation in the Feistel function
- PKCS#7 padding for arbitrary-length plaintext
- Multi-block support (plaintext longer than 8 bytes is split into 64-bit blocks)
- Hex output of ciphertext blocks

---

## Project Structure

```
DES Algorithm/
├── main.cpp              # Entry point — encrypt and decrypt a test string
├── des_encryption.cpp    # Core DES encryption logic (encrypt, Feistel, permutations, key schedule)
├── des_decryption.cpp    # Core DES decryption logic (decrypt, output generation)
├── des.h                 # Header — function declarations, DES_Block struct, all lookup tables
```

---

## How It Works

### Encryption (`des_encrypt`)
1. Input plaintext is split into 8-byte blocks
2. PKCS#7 padding is applied to the final block if needed
3. Each block goes through the Initial Permutation (IP)
4. 16 Feistel rounds are applied using round-specific subkeys
5. Left and right halves are swapped and recombined
6. Final Permutation (FP) is applied
7. Returns an array where `result[0]` is the block count and `result[1..n]` are the ciphertext blocks

### Decryption (`des_decrypt`)
Identical to encryption except the 16 subkeys are applied in reverse order (round 15 → 0). DES is symmetric in structure — only the key schedule direction changes.

### Key Schedule (`generate_subkeys`)
1. 64-bit key is reduced to 56 bits via PC-1 permutation
2. Split into two 28-bit halves C and D
3. Each round, both halves are rotated left by 1 or 2 bits (per SHIFT_TABLE)
4. PC-2 permutation selects 48 bits from the combined 56-bit half to form each round key

### Feistel Function
1. 32-bit half is expanded to 48 bits via E-box
2. XORed with the 48-bit round key
3. Result split into 8 × 6-bit chunks, each passed through a corresponding S-box (8 S-boxes, 4×16 each)
4. 32-bit S-box output is permuted via P-box

---

## Building

Open the solution in **Visual Studio** (x64 platform).

Build configuration:
- Debug: full symbol info, bounds checking enabled
- Release: optimized, no runtime checks

No external dependencies. Standard C++ only.

---

## Usage

```cpp
const unsigned char* plaintext = (const unsigned char*)"Hello World";
const unsigned char* key       = (const unsigned char*)"MYSECRET";  // must be exactly 8 bytes

uint64_t* encrypted = des_encrypt(plaintext, key);

unsigned char* decrypted = des_decrypt(encrypted, key);
// decrypted is null-terminated, padding stripped automatically

delete[] encrypted;
delete[] decrypted;
```

Expected output for the above:
```
Encrypted Data (Hex): 0000000000000002 7C2E609306A8A609 #first block indicates total number of blocks (padding included)
Decrypted Clean Text: Hello World!
```

---

## Notes

- Key must be exactly **8 bytes**. DES uses a 56-bit effective key (every 8th bit is a parity bit and is ignored by PC-1).
- This is **ECB mode** (each block encrypted independently). Not suitable for production use.

---

## Author

Built as part of a cryptography study project — implementing DES from the FIPS specification with no reference implementations.
