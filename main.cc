#include "aes.h"
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {

    std::cout << argv[0] << std::endl;
    if (argc != 2) {
        std::cerr << "Usage: ./aes-[128|192|256] [file]\n";
        return 1;
    }

    std::string infile = argv[1];
    unsigned aesKeyLength;

    if      (strcmp(argv[0], "./aes-128")) aesKeyLength = 128;
    else if (strcmp(argv[0], "./aes-192")) aesKeyLength = 192;
    else if (strcmp(argv[0], "./aes-256")) aesKeyLength = 256;
    else {
        std::cerr << "Usage: ./aes-[128|192|256] [file]\n";
        return 1;   
    }
    
    std::string encryptoutfile = "encrypted_text.txt";
    std::string decryptoutfile = "decrypted_text.txt";

    std::ifstream plaintext(infile);
    std::ofstream outencrypt(encryptoutfile);

    if (!plaintext.is_open()) {
        std::cerr << "Error opening file(s)!\n";
        return 1;
    }

    // Creates AES object with 10 rounds and key "Thats my Kung Fu"
    // Simulates AES-128 only, will add more
    AES aes(aesKeyLength, "Thats my Kung Fu");

    char buffer[16];

    // Perform AES encryption on input
    // (1) read 16 bytes
    // (2) encrypt
    // (3) write to encrypted text file
    while (plaintext.read(buffer, 16))
        outencrypt.write(aes.encrypt(buffer), 16);
    
    // if input text file length modulo 16 != 0
    // (4) final encryption of bytes with padding of spaces at end
    if (plaintext.gcount() != 0) {
        for (int i = plaintext.gcount(); i < 16; i++) buffer[i] = ' ';
        outencrypt.write(aes.encrypt(buffer), 16);
    }

    plaintext.close();
    outencrypt.close();

    std::ifstream inencrypt(encryptoutfile);
    std::ofstream outdecrypt(decryptoutfile);

    // Perform AES decryption
    // (1) read 16 bytes
    // (2) decrypt
    // (3) write to decrypted text file
    while (inencrypt.read(buffer, 16))
        outdecrypt.write(aes.decrypt(buffer), 16);

    // if text file length modulo 16 != 0
    // (4) final decryption of bytes with padding of spaces at end
    if (inencrypt.gcount() != 0) {
        for (int i = plaintext.gcount(); i < 16; i++) buffer[i] = ' ';
        outencrypt.write(aes.encrypt(buffer), 16);
    }

    inencrypt.close();
    outdecrypt.close();
}