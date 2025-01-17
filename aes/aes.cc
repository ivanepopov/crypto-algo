#include "aes.h"

/**
 * AES Constructor
 * Creates the initial AES object, sets variables to their default values,
 * and calls expandKeys() to generate the series of round keys from the
 * initial keyText
 *
 * @param keyLength length of key in bytes, accepted: 128/192/256
 * @param keyText private key to be used for encryption and decryption
 *
 * @note
 * nk: number of 32-bit words comprising the key
 * nr: number of rounds
 * **************************************************************************/
AES::AES(unsigned keyLength, const string& keyText)
{
    if      (keyLength == 128)   nr = 10;
    else if (keyLength == 192)   nr = 12;
    else  /*(keyLength == 256)*/ nr = 14;

    key = keyText;
    nk = keyLength / 32;
    wordCount = (nr + 1) * 4;

    vector<vector<byte>> words(wordCount, vector<byte>(4, 0));
    wordList = words;
    expandKeys(keyLength, keyText);
}

/**
 * Encrypts 16 bytes of plaintext at a time. The encryption algorithm works as follows:
 * - Round  0      : Add Round Key 0
 * - Rounds 1 -> Nr: SubstituteBytes()
 *                   ShiftRows()
 *                   MixColumns()
 *                   AddRoundKey(n)
 * - Round Nr      : SubstituteBytes()
 *                   ShiftRows()
 *                   AddRoundKey(n)
 *
 * @param plaintext Initial 16 bytes of plaintext
 * @param bytes Output 16 bytes after encryption
 * **************************************************************************/
void AES::encrypt(const string& plaintext, vector<byte>& bytes)
{
    for (byte i = 0; i < 16; i++) bytes[i] = plaintext[i];

    // ROUND 0
    addRoundKey(bytes, 0);

    // ROUNDS 1 - Nr
    byte i = 1;
    for (; i < nr; i++)
    {
        substituteBytes(bytes);
        shiftRows(bytes);
        mixColumns(bytes);
        addRoundKey(bytes, 4*i);
    }

    // FINAL ROUND
    substituteBytes(bytes);
    shiftRows(bytes);
    addRoundKey(bytes, 4*i);
}

/**
 * Decrypts 16 bytes of plaintext at a time. The decryption  algorithm works as follows:
 * - Round  Nr     : Add Round Key Nr
 * - Rounds Nr -> 1: InverseSubstituteBytes()
 *                   InverseShiftRows()
 *                   AddRoundKey(n)
 *                   InverseMixColumns()
 * - Round 0       : InverseSubstituteBytes()
 *                   InverseShiftRows()
 *                   InverseAddRoundKey(0)
 *
 * @param bytes Input & Output 16 bytes
 * **************************************************************************/
void AES::decrypt(vector<byte>& bytes)
{
    // ROUND Nr
    addRoundKey(bytes, 4*nr);

    // ROUNDS Nr - 1
    byte i = nr - 1;
    for (; i > 0; i--)
    {
        inverseSubstituteBytes(bytes);
        inverseShiftRows(bytes);
        addRoundKey(bytes, 4*i);
        inverseMixColumns(bytes);
    }

    // ROUND 0
    inverseSubstituteBytes(bytes);
    inverseShiftRows(bytes);
    addRoundKey(bytes, 0);
}

// *** STEP 1 : SUB BYTES *** //
void AES::substituteByte(byte& byte)
{
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << +byte;
    byte = Sbox[hexToInt(ss.str()[0])][hexToInt(ss.str()[1])];
}

void AES::substituteBytes(vector<byte>& bytes)
{
    for (byte i = 0; i < 16; i++)
        substituteByte(bytes[i]);
}

void AES::inverseSubstituteByte(byte& byte)
{
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << +byte;
    byte = inverseSbox[hexToInt(ss.str()[0])][hexToInt(ss.str()[1])];
}

void AES::inverseSubstituteBytes(vector<byte>& bytes)
{
    for (byte i = 0; i < 16; i++)
        inverseSubstituteByte(bytes[i]);
}

// *** STEP 2 : SHIFT ROWS *** //
void AES::shiftRows(vector<byte>& bytes)
{
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

void AES::inverseShiftRows(vector<byte>& bytes)
{
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
byte AES::mixByte(byte b, byte galoisValue)
{
    switch (galoisValue)
    {
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
void AES::mixColumns(vector<byte>& bytes)
{
    for (byte i = 0; i < 4; i++)
    {
        byte newBytes[4] = {0};
        for (byte j = 0; j < 4; j++)
            newBytes[j] =
                mixByte(bytes[0 + 4*i], galoisField[0 + 4*j]) ^
                mixByte(bytes[1 + 4*i], galoisField[1 + 4*j]) ^
                mixByte(bytes[2 + 4*i], galoisField[2 + 4*j]) ^
                mixByte(bytes[3 + 4*i], galoisField[3 + 4*j]);

        for (byte j = 0; j < 4; j++)
            bytes[j + 4*i] = newBytes[j];
    }
}

void AES::inverseMixColumns(vector<byte>& bytes)
{
    for (byte i = 0; i < 4; i++)
    {
        byte newBytes[4] = {0};
        for (byte j = 0; j < 4; j++)
            newBytes[j] =
                mixByte(bytes[0 + 4*i], inverseGaloisField[0 + 4*j]) ^
                mixByte(bytes[1 + 4*i], inverseGaloisField[1 + 4*j]) ^
                mixByte(bytes[2 + 4*i], inverseGaloisField[2 + 4*j]) ^
                mixByte(bytes[3 + 4*i], inverseGaloisField[3 + 4*j]);

        for (byte j = 0; j < 4; j++)
            bytes[j + 4*i] = newBytes[j];
    }
}

// *** STEP 4 / STEP 3 INVERSE : ADD ROUND KEY *** //
void AES::addRoundKey(vector<byte>& bytes, byte wordIndex)
{
    for (byte i = 0; i < 4; i++)
    {
        byte byteIndex = 4 * i;
        for (byte j = 0; j < 4; j++)
            bytes[byteIndex + j] ^= wordList[wordIndex + i][j];
    }
}

// *** KEY METHODS *** //
void AES::expandKeys(unsigned keyLength, const string& keyText)
{
    for (byte i = 0; i < nk; i++)
    {
        byte offset = 4 * i;
        wordList[i][0] = keyText[0 + offset];
        wordList[i][1] = keyText[1 + offset];
        wordList[i][2] = keyText[2 + offset];
        wordList[i][3] = keyText[3 + offset];
    }

    byte rcon = 0x01;
    for (byte i = nk; i < wordCount; i++)
    {
        wordList[i] = wordList[i-1];

        if (i % nk == 0)
        {
            /*** g Function ***/
            // RotWord()
            std::swap(wordList[i][0], wordList[i][3]);
            std::swap(wordList[i][0], wordList[i][2]);
            std::swap(wordList[i][0], wordList[i][1]);
            // SubWord()
            for (byte j = 0; j < 4; j++)
                substituteByte(wordList[i][j]);
            // xor Rcon
            wordList[i][0] ^= rcon;
            rcon >= 0x7f ? rcon = 0x1b : rcon *= 2;
            /*** end g Function ***/
        }
        else if (i % 4 == 0 && nk == 8)
        {
            for (byte j = 0; j < 4; j++)
                substituteByte(wordList[i][j]);
        }

        for (byte j = 0; j < 4; j++)
            wordList[i][j] ^= wordList[i - nk][j];
    }
}

// *** SUPPORTER METHODS *** //
byte AES::hexToInt(byte hex)
{
    if ((byte)+hex > 60) return hex - 'a' + 10;
    return hex - '0';
}

void AES::textToBytes(const char* text, vector<byte>& bytes)
{
    byte temp;
    for (byte i = 0, j = 0; i < 32; i += 2, j++)
    {
        temp = hexToInt(text[i]) * 16;
        temp += hexToInt(text[i+1]);
        bytes[j] = temp;
    }
}

string AES::bytesToText(vector<byte>& bytes)
{
    string text = "                ";
    for (byte i = 0; i < 16; i++) text[i] = +bytes[i];
    return text;
}

void AES::printBytes(vector<byte>& bytes, const string& info)
{
    std::cout << "\n" << info << "\n";
    for (byte i = 0; i < 16; i++)
        std::cout << std::setfill('0') << std::setw(2) << std::hex << +bytes[i] << " ";
    std::cout << "\n";
}
