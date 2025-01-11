#include "rsa.h"
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: ./rsa [file]\n";
        return 1;
    }

    std::string PLAINTEXT = argv[1];
    RSA rsa;

    std::ifstream F_PLAINTEXT(PLAINTEXT);
    std::ofstream F_OUT_ENCRYPT("encrypted_text.txt");

    // (1) Read each character
    // (2) Encrypt to a numeric value
    // (3) Write to output file
    std::string line;
    while(getline(F_PLAINTEXT, line))
    {
        for (char& ch : line) F_OUT_ENCRYPT << rsa.encrypt(ch) << std::endl;

        // Newline character
        F_OUT_ENCRYPT << rsa.encrypt(10) << std::endl;
    }
    F_PLAINTEXT.close(); F_OUT_ENCRYPT.close();

    std::ifstream F_IN_ENCRYPT("encrypted_text.txt");
    std::ofstream F_OUT_DECRYPT("decrypted_text.txt");

    // (1) Read each encrypted numeric value
    // (2) Decrypt it
    // (3) Write to new file
    while(getline(F_IN_ENCRYPT, line))
    {
        F_OUT_DECRYPT << (char)rsa.decrypt(std::stoi(line));
    }
    F_IN_ENCRYPT.close(); F_OUT_DECRYPT.close();
}
