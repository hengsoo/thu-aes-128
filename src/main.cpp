#include "AES_128.h"
#include <ctime>
#include <chrono>

using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::microseconds;

// 16k bits = 128 bits * 125 blocks
const int LENGTH = AES_128::AES_BLOCK_SIZE * 125;
// + 1 is for trailing \0
const int STR_LENGTH = LENGTH + 1;

void print(const char* words, uint8_t* data, bool hex_mode = false) {
	cout << words << endl;
	if (hex_mode) {
		for (int i = 0; i < LENGTH; i++) {
			cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
		}
	}
	else {
		for (int i = 0; i < LENGTH; i++) {
			cout << dec << (data[i]);
		}
	}
	cout << endl << endl;
}

void random_str_(const int len, uint8_t* str) {

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	static const int mod_num = (sizeof(alphanum) - 1);

	for (int i = 0; i < len; ++i)
		str[i] = alphanum[rand() % mod_num];
}

int main() {

	cout << endl << "=======================================" << endl;
	cout << "= AES 128-bit - CBC Mode - No Padding =" << endl;
	cout << "=======================================" << endl << endl;;

	//uint8_t plaintext[STR_LENGTH] = "Hello World 1234Hello World 1234";
	uint8_t plaintext[LENGTH] = { 0 };
	uint8_t cipher_key[AES_128::AES_BLOCK_SIZE] = { 0 };
	uint8_t init_vector[AES_128::AES_BLOCK_SIZE] = { 0 };

	uint8_t ciphertext[LENGTH] = { 0 };
	uint8_t decrypt_ciphertext[LENGTH] = { 0 };
	
	srand(time(0));
	random_str_(LENGTH, plaintext);
	random_str_(AES_128::AES_BLOCK_SIZE, cipher_key);
	random_str_(AES_128::AES_BLOCK_SIZE, init_vector);

	print("===== Plaintext ===== ", plaintext);
	//print("===== Plaintext(HEX) ===== ", plaintext, true);

	print("===== Cipher Key ===== ", cipher_key);
	print("===== Initialization Vector ===== ", init_vector);

	auto start_time = high_resolution_clock::now();
	AES_128::encrypt_(plaintext, LENGTH, cipher_key, AES_128::AES_BLOCK_SIZE, init_vector, ciphertext);
	auto end_time = high_resolution_clock::now();

	auto s_int = duration_cast<microseconds>(end_time - start_time);
	std::cout << "Time Elapsed: " << s_int.count() << "ms" << endl;

	//print("===== AES Encrypt(HEX) =====", ciphertext, true);

	AES_128::decrypt_(ciphertext, LENGTH, cipher_key, AES_128::AES_BLOCK_SIZE, init_vector, decrypt_ciphertext);
	print("===== AES Decrypt =====", decrypt_ciphertext);
	//print("===== AES Decrypt(HEX) =====", decrypt_ciphertext, true);

	return 0;
}