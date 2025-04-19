/*
 * Submitted by: Anika Siddiqui Mayesha (D24125187).
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */

// Core AES transformation functions
void sub_bytes(unsigned char *state);
void shift_rows(unsigned char *state);
void mix_columns(unsigned char *state);
void add_round_key(unsigned char *state, const unsigned char *round_key);

// Inverse functions for decryption
void inv_sub_bytes(unsigned char *state);
void inv_shift_rows(unsigned char *state);
void inv_mix_columns(unsigned char *state);

// Key expansion
unsigned char *expand_key(const unsigned char *key);

// Main encryption and decryption functions
unsigned char *aes_encrypt_block(const unsigned char *plaintext, const unsigned char *key);
unsigned char *aes_decrypt_block(const unsigned char *ciphertext, const unsigned char *key);

#endif /* RIJNDAEL_H */