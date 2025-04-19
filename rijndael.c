/*
 * Submitted by: Anika Siddiqui Mayesha (D24125187)
 */

#include <stdlib.h>
#include <string.h>
#include "rijndael.h"

// S-box lookup table for SubBytes transformation
static const unsigned char s_box[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box lookup table for InvSubBytes transformation
static const unsigned char inv_s_box[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants for key expansion
static const unsigned char r_con[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


/*
 * Operations used when encrypting a block
 */
//Helper functions for Galois Field (GF) operations
// Helper function for GF(2^8) multiplication by 2
static unsigned char xtime(unsigned char x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
// Helper function to multiply by higher powers of 2 in GF(2^8)
static unsigned char multiply(unsigned char x, unsigned char y) {
  unsigned char result = 0;
  for (int i = 0; i < 8; i++) {
      if (y & 1) {
          result ^= x;
      }
      x = xtime(x);
      y >>= 1;
  }
  return result;
}

// SubBytes transformation: replaces each byte with its S-box value
void sub_bytes(unsigned char *state) {
  for (int i = 0; i < 16; i++) {
      state[i] = s_box[state[i]];
  }
}

// ShiftRows transformation: cyclically shift rows left
/* 
 * ShiftRows transformation - cyclically shifts rows to the left by different offsets
 * Implementation approach: Uses a temporary array to reorder elements directly
 * by their target indices rather than sequential swapping.
 * Conceptually rearranges a 4x4 matrix where each row is shifted:
 *  - Row 0: No shift
 *  - Row 1: Left shift by 1
 *  - Row 2: Left shift by 2
 *  - Row 3: Left shift by 3
 */
 void shift_rows(unsigned char *state) {
  // Create temporary array to hold transformed state
  unsigned char temp_state[16];
  
  // Apply row shifts by directly placing bytes in their target positions
  // Row 0: No shift (indices 0,4,8,12 remain unchanged)
  temp_state[0] = state[0];
  temp_state[4] = state[4];
  temp_state[8] = state[8];
  temp_state[12] = state[12];
  
  // Row 1: Shift left by 1 (1→5→9→13→1)
  temp_state[1] = state[5];   // 1 gets value from 5
  temp_state[5] = state[9];   // 5 gets value from 9
  temp_state[9] = state[13];  // 9 gets value from 13
  temp_state[13] = state[1];  // 13 gets value from 1
  
  // Row 2: Shift left by 2 (2→10→2, 6→14→6)
  temp_state[2] = state[10];  // 2 gets value from 10
  temp_state[10] = state[2];  // 10 gets value from 2
  temp_state[6] = state[14];  // 6 gets value from 14
  temp_state[14] = state[6];  // 14 gets value from 6
  
  // Row 3: Shift left by 3 (3→7→11→15→3)
  temp_state[3] = state[7];   // 3 gets value from 7
  temp_state[7] = state[11];  // 7 gets value from 11
  temp_state[11] = state[15]; // 11 gets value from 15
  temp_state[15] = state[3];  // 15 gets value from 3
  
  // Copy transformed state back to original array
  memcpy(state, temp_state, 16);
}

// MixColumns transformation
/*
 * Mix a single column in the state matrix using Galois Field multiplication
 * Each output byte is a linear combination of all input bytes in the column
 * This provides diffusion in the cipher by ensuring each byte affects multiple bytes
 */
 void mix_single_column(unsigned char *column) {
  // Store original column values before transformation
  unsigned char a = column[0]; 
  unsigned char b = column[1];
  unsigned char c = column[2];
  unsigned char d = column[3];
  
  // Apply the fixed matrix multiplication in GF(2^8)
  // This matrix multiplication ensures that each output byte depends on all input bytes
  // Using the formula defined in the AES specification:
  //   [ 2 3 1 1 ]   [ a ]
  //   [ 1 2 3 1 ] × [ b ]
  //   [ 1 1 2 3 ]   [ c ]
  //   [ 3 1 1 2 ]   [ d ]
  
  column[0] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;        // 2a + 3b + c + d
  column[1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;        // a + 2b + 3c + d
  column[2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;        // a + b + 2c + 3d
  column[3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);        // 3a + b + c + 2d
}
// MixColumns transformation: applies mix_single_column to each column of the state
void mix_columns(unsigned char *state) {
  // Process each of the 4 columns independently
  for (int col = 0; col < 4; col++) {
    // Create a pointer to the current column (offset by column index * 4)
    unsigned char *current_column = &state[col * 4];
    
    // Apply the mixing operation to this column
    mix_single_column(current_column);
  }
}

/*
 * Operations used when decrypting a block
 */
// Helper functions for inverse mix columns
static unsigned char multiply2(unsigned char x) { return xtime(x); }
static unsigned char multiply3(unsigned char x) { return xtime(x) ^ x; }
static unsigned char multiply9(unsigned char x) { return xtime(xtime(xtime(x))) ^ x; }
static unsigned char multiply11(unsigned char x) { return xtime(xtime(xtime(x)) ^ x) ^ x; }
static unsigned char multiply13(unsigned char x) { return xtime(xtime(xtime(x) ^ x)) ^ x; }
static unsigned char multiply14(unsigned char x) { return xtime(xtime(xtime(x) ^ x) ^ x); }

// Inverse SubBytes transformation for decryption
void inv_sub_bytes(unsigned char *state) {
  for (int i = 0; i < 16; i++) {
      state[i] = inv_s_box[state[i]];
  }
}

// Inverse ShiftRows transformation for decryption
/*
 * InvShiftRows transformation - cyclically shifts rows to the right to undo ShiftRows
 * Implementation approach: Uses a direct mapping method for clarity instead of sequential shifts
 * Conceptually rearranges a 4x4 matrix where each row is shifted right:
 *  - Row 0: No shift
 *  - Row 1: Right shift by 1
 *  - Row 2: Right shift by 2
 *  - Row 3: Right shift by 3
 */
 void inv_shift_rows(unsigned char *state) {
  // Create a temporary buffer to store transformed state
  unsigned char temp_state[16];
  
  // Map each byte to its original position before ShiftRows
  
  // Row 0: No shift (bytes at positions 0,4,8,12 stay in place)
  temp_state[0] = state[0];
  temp_state[4] = state[4];
  temp_state[8] = state[8];
  temp_state[12] = state[12];
  
  // Row 1: Right shift by 1 (13→9→5→1→13)
  temp_state[1] = state[13];  // 1 gets value from 13
  temp_state[5] = state[1];   // 5 gets value from 1
  temp_state[9] = state[5];   // 9 gets value from 5
  temp_state[13] = state[9];  // 13 gets value from 9
  
  // Row 2: Right shift by 2 (2↔10, 6↔14)
  temp_state[2] = state[10];  // 2 gets value from 10
  temp_state[10] = state[2];  // 10 gets value from 2
  temp_state[6] = state[14];  // 6 gets value from 14
  temp_state[14] = state[6];  // 14 gets value from 6
  
  // Row 3: Right shift by 3 (15→11→7→3→15)
  temp_state[3] = state[15];  // 3 gets value from 15
  temp_state[7] = state[3];   // 7 gets value from 3
  temp_state[11] = state[7];  // 11 gets value from 7
  temp_state[15] = state[11]; // 15 gets value from 11
  
  // Copy transformed state back to original buffer
  memcpy(state, temp_state, 16);
}

// Inverse MixColumns transformation for decryption
/*
 * InvertMixColumns transformation - reverses the MixColumns operation
 * Implementation approach: Uses matrix multiplication in GF(2^8) with the inverse matrix
 * The inverse matrix requires multiplications by larger constants (9, 11, 13, 14)
 * which are implemented as separate helper functions
 */
 void inv_mix_columns(unsigned char *state) {
  // Process each column independently
  for (int col = 0; col < 4; col++) {
    // Calculate starting index for this column
    int col_idx = col * 4;
    
    // Store original column values before transformation
    unsigned char s0 = state[col_idx];
    unsigned char s1 = state[col_idx + 1];
    unsigned char s2 = state[col_idx + 2];
    unsigned char s3 = state[col_idx + 3];
    
    // Apply the inverse matrix multiplication in GF(2^8)
    // This undoes the MixColumns transformation using the inverse matrix:
    //   [ 14 11 13  9 ]   [ s0 ]
    //   [  9 14 11 13 ] × [ s1 ]
    //   [ 13  9 14 11 ]   [ s2 ]
    //   [ 11 13  9 14 ]   [ s3 ]
    
    state[col_idx]     = multiply14(s0) ^ multiply11(s1) ^ multiply13(s2) ^ multiply9(s3);
    state[col_idx + 1] = multiply9(s0)  ^ multiply14(s1) ^ multiply11(s2) ^ multiply13(s3);
    state[col_idx + 2] = multiply13(s0) ^ multiply9(s1)  ^ multiply14(s2) ^ multiply11(s3);
    state[col_idx + 3] = multiply11(s0) ^ multiply13(s1) ^ multiply9(s2)  ^ multiply14(s3);
  }
}

/*
 * This operation is shared between encryption and decryption
 */
// AddRoundKey transformation: XOR the state with the round key
void add_round_key(unsigned char *state, const unsigned char *round_key) {
  for (int i = 0; i < 16; i++) {
      state[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
// Key expansion: generate round keys from the cipher key
unsigned char *expand_key(const unsigned char *key) {
  // For AES-128, we need 11 round keys (initial + 10 rounds)
  unsigned char *expanded_key = (unsigned char *)malloc(176); // 11 * 16 bytes
  
  // Copy the original key to the first round key
  memcpy(expanded_key, key, 16);
  
  // Variables for the key expansion process
  unsigned char temp[4];
  int i = 1;
  int bytes_generated = 16;
  
  // Generate the rest of the round keys
  while (bytes_generated < 176) {
      // Copy the last 4 bytes of the previous round key
      for (int j = 0; j < 4; j++) {
          temp[j] = expanded_key[bytes_generated - 4 + j];
      }
      
      // Perform the key schedule core once every 16 bytes
      if (bytes_generated % 16 == 0) {
          // Rotate word
          unsigned char k = temp[0];
          temp[0] = temp[1];
          temp[1] = temp[2];
          temp[2] = temp[3];
          temp[3] = k;
          
          // Apply S-box
          for (int j = 0; j < 4; j++) {
              temp[j] = s_box[temp[j]];
          }
          
          // XOR with round constant
          temp[0] ^= r_con[i++];
      }
      
      // XOR with the 4-byte block 16 bytes before
      for (int j = 0; j < 4; j++) {
          expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ temp[j];
          bytes_generated++;
      }
  }
  
  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
// Main encryption function
unsigned char *aes_encrypt_block(const unsigned char *plaintext, const unsigned char *key) {
  // Allocate memory for the output
  unsigned char *output = (unsigned char *)malloc(16);
  if (!output) return NULL;
  
  // Create a temporary state array and copy the plaintext into it
  unsigned char state[16];
  memcpy(state, plaintext, 16);
  
  // Expand the key
  unsigned char *round_keys = expand_key(key);
  
  // Initial round: AddRoundKey
  add_round_key(state, round_keys);
  
  // Main rounds (1-9)
  for (int round = 1; round < 10; round++) {
      sub_bytes(state);
      shift_rows(state);
      mix_columns(state);
      add_round_key(state, round_keys + (round * 16));
  }
  
  // Final round (no MixColumns)
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, round_keys + 160); // 10 * 16 = 160
  
  // Copy the result to the output buffer
  memcpy(output, state, 16);
  
  // Free the expanded key
  free(round_keys);
  
  return output;
}


// Main decryption function
unsigned char *aes_decrypt_block(const unsigned char *ciphertext, const unsigned char *key) {
  // Allocate memory for the output
  unsigned char *output = (unsigned char *)malloc(16);
  if (!output) return NULL;
  
  // Create a temporary state array and copy the ciphertext into it
  unsigned char state[16];
  memcpy(state, ciphertext, 16);
  
  // Expand the key
  unsigned char *round_keys = expand_key(key);
  
  // Initial round: AddRoundKey (with the last round key)
  add_round_key(state, round_keys + 160);
  
  // Main rounds (9-1)
  for (int round = 9; round > 0; round--) {
      inv_shift_rows(state);
      inv_sub_bytes(state);
      add_round_key(state, round_keys + (round * 16));
      inv_mix_columns(state);
  }
  
  // Final round
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, round_keys);
  
  // Copy the result to the output buffer
  memcpy(output, state, 16);
  
  // Free the expanded key
  free(round_keys);
  
  return output;
}