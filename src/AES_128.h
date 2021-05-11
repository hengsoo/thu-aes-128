#pragma once
#include <iostream>
#include <iomanip>
using namespace std;

/*	State's Bytes order
	=================
	0 4 8  12	Row 0
	1 5 9  13	Row 1
	2 6 10 14	Row 2
	3 7 11 15	Row 3
*/

class AES_128
{
public:
	static const int AES_BLOCK_SIZE = 16;
	static const int AES_ROUNDS = 10;
	static const uint8_t RCON[10];
	static const uint8_t SBOX[256];
	static const uint8_t INV_SBOX[256];

	static void encrypt_(uint8_t* plaintext, int plaintext_len,
		uint8_t* cipher_key, int cipherkey_len, uint8_t* init_vector, uint8_t* ciphertext_);
	static void decrypt_(uint8_t* ciphertext, int ciphertext_len,
		uint8_t* cipher_key, int cipherkey_len, uint8_t* init_vector, uint8_t* plaintext_);


private:
	// Multiplication lookup tables
	static const uint8_t MUL9[256];
	static const uint8_t MUL11[256];
	static const uint8_t MUL13[256];
	static const uint8_t MUL14[256];

	static inline uint8_t xtime(uint8_t val);
	static void sub_bytes(uint8_t *state);
	static void inv_sub_bytes(uint8_t *state);
	static void shift_rows(uint8_t *state);
	static void inv_shift_rows(uint8_t *state);
	static void mix_columns(uint8_t *state);
	static void inv_mix_columns(uint8_t *state);
	static void add_round_keys(uint8_t *state, uint8_t *round_keys);
	static void generate_key_schedule_128(uint8_t *round_keys, uint8_t *cipher_key);

	static void encrypt_block_(uint8_t* plaintext_, uint8_t* round_keys);
	static void decrypt_block_(uint8_t* ciphertext_, uint8_t* round_keys);
};
