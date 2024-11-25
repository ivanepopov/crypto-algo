#include "aes.h"
#include <fstream>

int main(int argc, char* argv[]) {

    if (argc != 2) {
        std::cerr << "Usage: ./aes-[128|192|256] [file]\n";
        return 1;
    }

    string PLAINTEXT = argv[1];
    unsigned aesKeyLength; string key;

    if      (strcmp(argv[0], "./aes-128")==0) { aesKeyLength = 128; key = "Thats my Kung Fu"; }
    else if (strcmp(argv[0], "./aes-192")==0) { aesKeyLength = 192; key = "Thats my Kung FuThats my"; }
    else if (strcmp(argv[0], "./aes-256")==0) { aesKeyLength = 256; key = "Thats my Kung FuThats my Kung Fu"; }
    else {
        std::cerr << "Usage: ./aes-[128|192|256] [file]\n";
        return 1;   
    }

    string FILE_ENCRYPT = "encrypted_text.txt";
    string FILE_DECRYPT = "decrypted_text.txt";
    
    std::ifstream FILE_IN_PLAINTEXT(PLAINTEXT, std::ios::binary);
    std::ofstream FILE_OUT_ENCRYPT(FILE_ENCRYPT, std::ios::binary);

    if (!FILE_IN_PLAINTEXT.is_open()) { std::cerr << "Error opening file(s)!\n"; return 1; }

    // Creates AES object with 10 rounds and key "Thats my Kung Fu"
    // Simulates AES-128 only, will add more
    AES aes(aesKeyLength, key);

    char buffer[16];

    // Perform AES encryption on input
    // (1) read 16 bytes
    // (2) encrypt
    // (3) write to encrypted text file
    while (FILE_IN_PLAINTEXT.read(buffer, 16)) {
        FILE_OUT_ENCRYPT << aes.encrypt(buffer);
    }

    // if input text file length modulo 16 != 0
    // (4) final encryption of bytes with padding of spaces at end
    if (FILE_IN_PLAINTEXT.gcount() != 0) {
        for (int i = FILE_IN_PLAINTEXT.gcount(); i < 16; i++) buffer[i] = ' ';
        FILE_OUT_ENCRYPT << aes.encrypt(buffer);
    }

    FILE_IN_PLAINTEXT.close();
    FILE_OUT_ENCRYPT.close();

    std::ifstream FILE_IN_ENCRYPT(FILE_ENCRYPT, std::ios::binary);
    std::ofstream FILE_OUT_DECRYPT(FILE_DECRYPT, std::ios::binary);

    if (!FILE_IN_ENCRYPT.is_open()) { std::cerr << "Error opening file(s)!\n"; return 1; }

    // Perform AES decryption
    // (1) read 16 bytes
    // (2) decrypt
    // (3) write to decrypted text file
    while (FILE_IN_ENCRYPT.read(buffer, 16)) {
        FILE_OUT_DECRYPT << aes.decrypt(buffer);
    }

    // if text file length modulo 16 != 0
    // (4) final decryption of bytes with padding of spaces at end
    if (FILE_IN_ENCRYPT.gcount() != 0) {
        for (int i = FILE_IN_ENCRYPT.gcount(); i < 16; i++) buffer[i] = ' ';
        FILE_OUT_DECRYPT << aes.decrypt(buffer);
    }

    FILE_IN_ENCRYPT.close();
    FILE_OUT_DECRYPT.close();
}