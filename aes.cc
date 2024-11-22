#include "aes.h"

AES::AES() {

    const char* plaintext = "Two One Nine Two";
    const char* keyinenglish = "Thats my Kung Fu";

    byte* bytes = textToBytes(plaintext);
    byte* key128 = textToBytes(keyinenglish);

    byte** keyList = createRoundKeys(key128);
    
    printBytes(bytes, "Before everything");

    // ROUND 0
    addRoundKey(bytes, keyList[0]);
    printBytes(bytes, "After Round 0");
    
    // ROUNDS 1 - 9
    int i = 1;
    for (; i < 10; i++) {
        substituteBytes(bytes);
        shiftRows(bytes);
        mixColumns(bytes);
        addRoundKey(bytes, keyList[i]);
    }

    // ROUND 10
    substituteBytes(bytes);
    shiftRows(bytes);
    addRoundKey(bytes, keyList[i]);

    printBytes(bytes, "After Round 10");

};

// *** STEP 1: SUB BYTES *** //
byte AES::substituteByte(byte byte) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << +byte;
    return sbox[byteToInt(ss.str()[0])][byteToInt(ss.str()[1])];
}
void AES::substituteBytes(byte* bytes) { 
    for (int i = 0; i < 16; i++)
        bytes[i] = substituteByte(bytes[i]);
}

// *** STEP 2: SHIFT ROWS *** //
void AES::shiftRows(byte* bytes) { 
    // DO NOTHING WITH ROW 0
    // SHIFT LEFT 1 ROW 1
    std::swap(bytes[1], bytes[13]);
    std::swap(bytes[1], bytes[9]);
    std::swap(bytes[1], bytes[5]);

    // SHIFT LEFT 2 ROW 2
    std::swap(bytes[2], bytes[10]);
    std::swap(bytes[6], bytes[14]);

    // SHIFT LEFT 3 ROW 3
    std::swap(bytes[15], bytes[3]);
    std::swap(bytes[15], bytes[7]);
    std::swap(bytes[15], bytes[11]);
}

// *** STEP 3: MIX COLS *** //
byte AES::mixByte(byte b, byte galoisValue) {
    switch (galoisValue) {
        case 0x01: return b;
        case 0x02: return (b << 1) ^ ((b & 0x80) ? 0x1B : 0);
        case 0x03: return (b << 1) ^ ((b & 0x80) ? 0x1B : 0) ^ b;
        default: return b;
    }
}
void AES::mixColumns(byte* bytes) { 

    for (int i = 0; i < 4; i++) {
        byte newBytes[4] = {0};
        for (int j = 0; j < 4; j++)
            newBytes[j] =
                mixByte(bytes[0 + 4*i], galoisField[0 + 4*j]) ^
                mixByte(bytes[1 + 4*i], galoisField[1 + 4*j]) ^
                mixByte(bytes[2 + 4*i], galoisField[2 + 4*j]) ^
                mixByte(bytes[3 + 4*i], galoisField[3 + 4*j]);

        for (int j = 0; j < 4; j++) 
            bytes[j + 4*i] = newBytes[j];
    }
}

// *** STEP 4: ADD ROUND KEY *** //
void AES::addRoundKey(byte* bytes, byte* key) {
    for (int i = 0; i < 16; i++)
        bytes[i] ^= key[i];
}

// *** KEY METHODS *** //
byte* AES::createRoundKey(byte* prevKey, byte rc) {

    byte* key = new byte[16];

    for (int i = 0; i < 4; i++)
        key[i] = prevKey[i+12];

    /*** g Function ***/
    // left shift 1
    std::swap(key[0], key[3]);
    std::swap(key[0], key[2]);
    std::swap(key[0], key[1]);
    // byte sub
    for (int i = 0; i < 4; i++)
        key[i] = substituteByte(key[i]);
    // add round constant
    key[0] ^= rc;
    /*** end g Function ***/

    for (int i = 0; i < 4; i++)
        key[i] ^= prevKey[i];

    for (int i = 4; i < 16; i++)
        key[i] = prevKey[i] ^ key[i - 4];

    return key;
}
byte** AES::createRoundKeys(byte* key) { 
    byte**  roundKeys = new byte*[11];
    roundKeys[0] = key;
    roundKeys[1] = createRoundKey(roundKeys[0], 0x01);

    byte rc = 0x02;
    for (int i = 2; i < 11; i++) {
        roundKeys[i] = createRoundKey(roundKeys[i-1], rc);
        rc <<= 1;
        if (rc == 0) { rc ^= 0x11b; }
    }

    return roundKeys;
}

// *** SUPPORTER METHODS *** //
int AES::byteToInt(byte hex) {
    if ((int)+hex > 60) return hex - 'a' + 10;
    return hex - '0';
}
byte* AES::textToBytes(const char* plaintext) {
    byte* bytes = new byte[16];
    for (int i = 0; i < 16; i++) bytes[i] = (int)plaintext[i];
    return bytes;
}
void AES::printBytes(byte* bytes, const char* info) { 
    std::cout << "\n" << info << "\n";

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << +bytes[i + 4*j] << " ";
        std::cout << "\n";
    }
}
