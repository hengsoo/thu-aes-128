#include "AES_128.h"
#include <ctime>
#include <chrono>

using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::microseconds;

// 16k bits = 16 * 1024 bits = 2048 char = 128 * 16 bytes
const int LENGTH = AES_128::AES_BLOCK_SIZE * 128;
// + 1 is for trailing \0
const int STR_LENGTH = LENGTH + 1;

void print(const char* words, uint8_t* data, bool hex_mode = false, int size = LENGTH) {
	cout << words << endl;
	if (hex_mode) {
		for (int i = 0; i < LENGTH; i++) {
			cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
		}
	}
	else {
		for (int i = 0; i < size; i++) {
			cout << dec << (data[i]);
		}
	}
	cout << endl << endl;
}

void random_str_(const int len, uint8_t* str) {

	static const uint8_t alphanum[] =
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

	print("===== Plaintext 16Kb ===== ", plaintext);
	//print("===== Plaintext(HEX) ===== ", plaintext, true);

	print("===== Cipher Key 128b ===== ", cipher_key, false, AES_128::AES_BLOCK_SIZE);
	print("===== Initialization Vector 128b ===== ", init_vector, false, AES_128::AES_BLOCK_SIZE);

	// Encrypt
	auto start_time = high_resolution_clock::now();
	AES_128::encrypt_(plaintext, LENGTH, cipher_key, AES_128::AES_BLOCK_SIZE, init_vector, ciphertext);
	auto end_time = high_resolution_clock::now();

	auto s_int = duration_cast<microseconds>(end_time - start_time);
	std::cout << "16Kb Encryption Time Elapsed: " << dec << s_int.count() << "us" << endl;
	std::cout << "Encryption Efficiency: " << dec <<  (16 * 1000) / s_int.count() << "Mbps" << endl;

	print("===== AES Encrypt(HEX) =====", ciphertext, true);

	// Decrypt
	auto d_start_time = high_resolution_clock::now();
	AES_128::decrypt_(ciphertext, LENGTH, cipher_key, AES_128::AES_BLOCK_SIZE, init_vector, decrypt_ciphertext);
	auto d_end_time = high_resolution_clock::now();

	auto d_s_int = duration_cast<microseconds>(d_end_time - d_start_time);
	std::cout << "16Kb Decryption Time Elapsed: " << dec << d_s_int.count() << "us" << endl;
	std::cout << "Decryption Efficiency: " << dec << (16 * 1000) / d_s_int.count() << "Mbps" << endl;

	print("===== AES Decrypt =====", decrypt_ciphertext);
	//print("===== AES Decrypt(HEX) =====", decrypt_ciphertext, true);

	return 0;
}