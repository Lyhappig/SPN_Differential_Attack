#ifndef DIFFERENTIAL_ATTACK_SPN_DEMO_CIPHER_HPP_
#define DIFFERENTIAL_ATTACK_SPN_DEMO_CIPHER_HPP_

#define ROUNDS 4
#define CRYPTO_SIZE 16
#define SBOX_SIZE 16
#define PBOX_SIZE 16

typedef bool bit;

struct SPN_KEY {
  int rounds = ROUNDS + 1;
  bit rd_key[ROUNDS + 2][CRYPTO_SIZE];
};

const int S[SBOX_SIZE] = {
    14, 4, 13, 1, 2, 15, 11, 8,
    3, 10, 6, 12, 5, 9, 0, 7
};

const int RS[SBOX_SIZE] = {
    14, 3, 4, 8, 1, 12, 10, 15,
    7, 13, 9, 6, 11, 2, 0, 5,
};

const int P[PBOX_SIZE] = {
    0, 4, 8, 12, 1, 5, 9, 13,
    2, 6, 10, 14, 3, 7, 11, 15
};

const int RP[PBOX_SIZE] = {
    0, 4, 8, 12, 1, 5, 9, 13,
    2, 6, 10, 14, 3, 7, 11, 15
};

void Xor(bit *in, bit *key);

void substitution(bit *in, const int *Sbox);

void permutation(bit *in, const int *Pbox);

void spn_encrypt(bit *in, bit *out, SPN_KEY *key);

void spn_decrypt(bit *in, bit *out, SPN_KEY *key);

#endif //DIFFERENTIAL_ATTACK_SPN_DEMO_CIPHER_HPP_
