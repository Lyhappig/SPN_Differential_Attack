#include "cipher.hpp"
using namespace std;

void Xor(bit *in, bit *key) {
    for(int i = 0; i < CRYPTO_SIZE; i++) {
        in[i] ^= key[i];
    }
}

void substitution(bit *in, const int *Sbox) {
    int temp;
    for(int j = 0; j < 4; j++) {
        temp = 0;
        for(int k = 0; k < 4; k++) {
            temp = (temp << 1) | in[j * 4 + k];
        }
        temp = Sbox[temp];
        for(int k = 0; k < 4; k++) {
            in[j * 4 + k] = (temp >> (3 - k)) & 1;
        }
    }
}

void permutation(bit *in, const int *Pbox) {
    bit temp[16];
    for(int j = 0; j < 16; j++) {
        temp[j] = in[Pbox[j]];
    }
    for(int j = 0; j < 16; j++) in[j] = temp[j];
}

void spn_encrypt(bit *in, bit *out, SPN_KEY *key) {
    for(int j = 0; j < CRYPTO_SIZE; j++) out[j] = in[j];
    for(int i = 1; i <= ROUNDS; i++) {
        Xor(out, key->rd_key[i]);
        substitution(out, S);
        if(i == ROUNDS) continue;
        permutation(out, P);
    }
    Xor(out, key->rd_key[ROUNDS + 1]);
}

void spn_decrypt(bit *in, bit *out, SPN_KEY *key) {
    for(int j = 0; j < 16; j++) out[j] = in[j];
    Xor(out, key->rd_key[5]);
    substitution(out, RS);
    for(int i = ROUNDS; i > 1; i--) {
        Xor(out, key->rd_key[i]);
        permutation(out, RP);
        substitution(out, RS);
    }
    Xor(out, key->rd_key[1]);
}