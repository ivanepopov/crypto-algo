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

    // Creates AES object with Nr rounds and key
    // Simulates AES-128, AES-192, and AES-256
    AES aes(aesKeyLength, key);

    char buffer[16], decodebuffer[32];
    vector<byte> bytes(16, 0);

    // Perform AES encryption on input
    // (1) read 16 bytes
    // (2) encrypt
    // (3) write to encrypted text file
    while (FILE_IN_PLAINTEXT.read(buffer, 16)) {
        aes.encrypt(buffer, bytes);
        for (byte i = 0; i < 16; i++) FILE_OUT_ENCRYPT << std::setfill('0') << std::setw(2) << std::hex << +bytes[i];
    }

    // if input text file length modulo 16 != 0
    // (4) final encryption of bytes with padding of spaces at end
    if (FILE_IN_PLAINTEXT.gcount() != 0) {
        for (byte i = FILE_IN_PLAINTEXT.gcount(); i < 16; i++) buffer[i] = ' ';
        aes.encrypt(buffer, bytes);
        for (byte i = 0; i < 16; i++) FILE_OUT_ENCRYPT << std::setfill('0') << std::setw(2) << std::hex << +bytes[i];
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
    while (FILE_IN_ENCRYPT.read(decodebuffer, 32)) {
        aes.textToBytes(decodebuffer, bytes);
        aes.decrypt(bytes);
        FILE_OUT_DECRYPT << reinterpret_cast<char*>(bytes.data());
    }

    // if text file length modulo 16 != 0
    // (4) final decryption of bytes with padding of spaces at end
    if (FILE_IN_ENCRYPT.gcount() != 0) {
        for (byte i = FILE_IN_ENCRYPT.gcount(); i < 32; i++) buffer[i] = ' ';
        aes.textToBytes(decodebuffer, bytes);
        aes.decrypt(bytes);
        FILE_OUT_DECRYPT << reinterpret_cast<char*>(bytes.data());
    }

    FILE_IN_ENCRYPT.close();
    FILE_OUT_DECRYPT.close();
}