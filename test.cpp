#include <iostream>
#include "cipher.hpp"
using namespace std;

void print(bit *a) {
    for(int i = 0; i < 16; i++) {
        if(i % 4 == 0) cout << " ";
        cout << a[i];
    }
    cout << endl;
}

void test_crypt() {
    srand(time(0));
    bit in[16], out[16], t[16];
    SPN_KEY sk;
    for(int i = 1; i <= sk.rounds; i++) {
        cout << "K" << i << ": ";
        for(int j = 0; j < 16; j++) {
            sk.rd_key[i][j] = rand() % 2;
        }
        print(sk.rd_key[i]);
    }
    cout << "plain: ";
    for(int i = 0; i < 16; i++) {
        in[i] = rand() % 2;
    }
    print(in);
    spn_encrypt(in, out, &sk);
    cout << "cipher: ";
    print(out);
    spn_decrypt(out, t, &sk);
    cout << "decrypt: ";
    print(t);
}

int main() {
    test_crypt();
    return 0;
}