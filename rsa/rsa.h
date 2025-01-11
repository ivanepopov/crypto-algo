#ifndef RSA_H
#define RSA_H

#include <iostream>
#include <numeric>

class RSA {
private:
    int p = 18223, q = 34019;
    long e, d, n;

    int exponentiation(long b, int e, long m);
public:
    RSA();
    int encrypt(int M);
    int decrypt(int M);
};

#endif
