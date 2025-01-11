#include "rsa.h"

/**
 * RSA Constructor
 * Creates the initial RSA object, and generates n, e, d
 *
 * @note p and q are large primes
 * **************************************************************************/
RSA::RSA()
{
    // Generate Keys

    // (1) Compute n = pq
    // p and q are large prime numbers
    // n is used as the modulus for both public and private keys
    n = p * q;

    // (2) Compute λ(n), Carmichael's totient function
    int phi = (p - 1) * (q - 1);

    // (3) Choose an integer e where 1 < e < λ(n) and gcd(e, λ(n)) = 1
    for (e = 2; e < phi; e++) if (std::gcd(e, phi) == 1) break;

    // (4) Determine d as d ≡ e^−1 (mod λ(n))
    // Rewrite equation to (e * d) % λ(n) == 1
    for (d = 2; d < phi; d++) if ((e * d) % phi == 1) break;
};

/**
 * Modular Exponentiation using right to left binary method
 * **************************************************************************/
int RSA::exponentiation(long b, int e, long m)
{
    if (m == 1) return 0;

    long res = 1;
    b = b % m;
    while (e > 0)
    {
        if (e & 1) res = (res * b) % m;
        e >>= 1;
        b = (b * b) % m;
    }
    return res;
}

/**
 * Encryption
 * c ≡ m^e (mod n)
 * **************************************************************************/
int RSA::encrypt(int M)
{
    return exponentiation(M, e, n);
}

/**
 * Decryption
 * c ≡ m^d (mod n)
 * **************************************************************************/
int RSA::decrypt(int M)
{
    return exponentiation(M, d, n);
}
