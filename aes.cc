#include "aes.h"

AES::AES(unsigned newrounds, const char* newkey) {
    
    key = textToBytes(newkey);
    rounds = newrounds;

    keyList = new byte*[11];
    keyList[0] = key;
    keyList = expandKeys(key);
}

char* AES::encrypt(const char* plaintext) {

    byte* bytes = textToBytes(plaintext);

    // ROUND 0
    addRoundKey(bytes, keyList[0]);

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

    return bytesToText(bytes);
};
char* AES::decrypt(const char* ciphertext) {
    
    byte* bytes = textToBytes(ciphertext);

    // ROUND 10
    addRoundKey(bytes, keyList[10]);

    // ROUNDS 9 - 1
    int i = 9;
    for (; i > 0; i--) {
        inverseShiftRows(bytes);
        inverseSubstituteBytes(bytes);
        addRoundKey(bytes, keyList[i]);
        inverseMixColumns(bytes);
    }

    inverseShiftRows(bytes);
    inverseSubstituteBytes(bytes);
    addRoundKey(bytes, keyList[0]);

    return bytesToText(bytes);
}

// *** STEP 1 : SUB BYTES *** //
byte AES::substituteByte(byte byte) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << +byte;
    return Sbox[byteToInt(ss.str()[0])][byteToInt(ss.str()[1])];
}
void AES::substituteBytes(byte* bytes) { 
    for (int i = 0; i < 16; i++)
        bytes[i] = substituteByte(bytes[i]);
}
byte AES::inverseSubstituteByte(byte byte) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << +byte;
    return inverseSbox[byteToInt(ss.str()[0])][byteToInt(ss.str()[1])];
}
void AES::inverseSubstituteBytes(byte* bytes) { 
    for (int i = 0; i < 16; i++)
        bytes[i] = inverseSubstituteByte(bytes[i]);
}

// *** STEP 2 : SHIFT ROWS *** //
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
void AES::inverseShiftRows(byte* bytes) { 
    // DO NOTHING WITH ROW 0
    // SHIFT RIGHT 1 ROW 1
    std::swap(bytes[1], bytes[5]);
    std::swap(bytes[1], bytes[9]);
    std::swap(bytes[1], bytes[13]);

    // SHIFT RIGHT 2 ROW 2
    std::swap(bytes[2], bytes[10]);
    std::swap(bytes[6], bytes[14]);

    // SHIFT RIGHT 3 ROW 3
    std::swap(bytes[3], bytes[15]);
    std::swap(bytes[3], bytes[11]);
    std::swap(bytes[3], bytes[7]);
}

// *** STEP 3 / STEP 4 INVERSE : MIX COLS *** //
byte AES::mixByte(byte b, byte galoisValue) {
    switch (galoisValue) {
        case 0x01: return b;
        case 0x02: return (b << 1) ^ ((b & 0x80) ? 0x1B : 0);
        case 0x03: return (b << 1) ^ ((b & 0x80) ? 0x1B : 0) ^ b;
        case 0x09: return mixByte(mixByte(mixByte(b, 2), 2), 2) ^ b;
        case 0x0B: return mixByte(mixByte(mixByte(b, 2), 2) ^ b, 2) ^ b;
        case 0x0D: return mixByte(mixByte(mixByte(b, 2) ^ b, 2), 2) ^ b;
        case 0x0E: return mixByte(mixByte(mixByte(b, 2) ^ b, 2) ^ b, 2);
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
void AES::inverseMixColumns(byte* bytes) { 
    for (int i = 0; i < 4; i++) {
        byte newBytes[4] = {0};
        for (int j = 0; j < 4; j++)
            newBytes[j] =
                mixByte(bytes[0 + 4*i], inverseGaloisField[0 + 4*j]) ^
                mixByte(bytes[1 + 4*i], inverseGaloisField[1 + 4*j]) ^
                mixByte(bytes[2 + 4*i], inverseGaloisField[2 + 4*j]) ^
                mixByte(bytes[3 + 4*i], inverseGaloisField[3 + 4*j]);

        for (int j = 0; j < 4; j++) 
            bytes[j + 4*i] = newBytes[j];
    }
}

// *** STEP 4 / STEP 3 INVERSE : ADD ROUND KEY *** //
void AES::addRoundKey(byte* bytes, byte* key) {
    for (int i = 0; i < 16; i++)
        bytes[i] ^= key[i];
}

// *** KEY METHODS *** //
byte* AES::expandKey(byte* prevKey, byte rc) {

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
byte** AES::expandKeys(byte* key) { 
    byte**  roundKeys = new byte*[11];
    roundKeys[0] = key;
    roundKeys[1] = expandKey(roundKeys[0], 0x01);

    byte rc = 0x02;
    for (int i = 2; i < 11; i++) {
        roundKeys[i] = expandKey(roundKeys[i-1], rc);
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
char* AES::bytesToText(byte* bytes) {
    char* text = new char[16];
    for (int i = 0; i < 16; i++) text[i] = (char)bytes[i];
    return text;
}
void AES::printBytes(byte* bytes, const char* info) { 
    std::cout << "\n" << info << "\n";

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << +bytes[i + 4*j] << " ";
        std::cout << "\n";
    }
}
