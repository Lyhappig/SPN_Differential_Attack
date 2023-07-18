#ifndef DIFFERENTIAL_ATTACK__LOCAL_HPP_
#define DIFFERENTIAL_ATTACK__LOCAL_HPP_

#include <string>
#include "cipher.hpp"
using namespace std;
typedef bool bit;
#define SBOX_NUM 4
#define BYTE_SIZE 4
#define CHECK_DIFF
//#define CHECK_PLAIN
//#define CHECK_RAND_KEY
//#define CHECK_FILTER
//#define PRINT_ANS

#define nth_bit(x, n) (((x) >> (n)) & 1)

const int maxn = 5005;

/**
 * 第一轮的输入差分
 * 0000 1011 0000 0000
 */
string SU1 = "0000101100000000";

/**
 * 第一轮的输出差分
 * 0000 0010 0000 0000
 */
string SV1 = "0000001000000000";

/**
 * 第二轮的输入差分
 * 0000 0000 0100 0000
 */
string SU2 = "0000000001000000";

/**
 * 第二轮的输出差分
 * 0000 0000 0110 0000
 */
string SV2 = "0000000001100000";

/**
 * 第三轮的输入差分
 * 0000 0010 0010 0000
 */
string SU3 = "0000001000100000";

/**
 * 第三轮的输出差分
 * 0000 0101 0101 0000
 */
string SV3 = "0000010101010000";

/**
 * 第四轮的输入差分
 * 0000 0110 0000 0110
 */
string SU4 = "0000011000000110";

bit U1[16], V1[16], U2[16], V2[16], U3[16], V3[16], U4[16];

/**
 * 部分密钥比特的计数矩阵
 * 第一维代表[K5 - K8]
 * 第二维代表[K13 - K16]
 */
int key_count[16][16];

void init_differential() {
    // round1
    for(int i = 0; i < 16; i++) U1[i] = SU1[i] - '0';
    for(int i = 0; i < 16; i++) V1[i] = SV1[i] - '0';
    // round2
    for(int i = 0; i < 16; i++) U2[i] = SU2[i] - '0';
    for(int i = 0; i < 16; i++) V2[i] = SV2[i] - '0';
    // round3
    for(int i = 0; i < 16; i++) U3[i] = SU3[i] - '0';
    for(int i = 0; i < 16; i++) V3[i] = SV3[i] - '0';
    // round4
    for(int i = 0; i < 16; i++) U4[i] = SU4[i] - '0';
#ifdef CHECK_DIFF
    string s1 = "";
    for(int i = 0; i < 16; i++) s1 += '0' + U1[i];
    assert(s1 == SU1);
    string s2 = "";
    for(int i = 0; i < 16; i++) s2 += '0' + V1[i];
    assert(s2 == SV1);
    string s3 = "";
    for(int i = 0; i < 16; i++) s3 += '0' + U2[i];
    assert(s3 == SU2);
    string s4 = "";
    for(int i = 0; i < 16; i++) s4 += '0' + V2[i];
    assert(s4 == SV2);
    string s5 = "";
    for(int i = 0; i < 16; i++) s5 += '0' + U3[i];
    assert(s5 == SU3);
    string s6 = "";
    for(int i = 0; i < 16; i++) s6 += '0' + V3[i];
    assert(s6 == SV3);
    string s7 = "";
    for(int i = 0; i < 16; i++) s7 += '0' + U4[i];
    assert(s7 == SU4);
#endif
}

void print_nbits(bit *a, int n) {
    for(int i = 0; i < n; i++) {
        if(i % 4 == 0) printf(" ");
        printf("%d", a[i]);
    }
    puts("");
}

/**
 * 计算一个01比特从左到右的第i个字节
 * @param a 比特流数组
 * @param i 第i个字节, i >= 0
 * @return 这个字节表示的数的大小
 */
int get_nth_byte(bit *a, int i) {
    int ret = 0;
    for(int j = 0; j < 4; j++) {
        ret = (ret << 1) | a[i * 4 + j];
    }
    return ret;
}

bool vec_count(vector<int> &a, int x) {
    for(auto &val: a) {
        if(val == x) {
            return true;
        }
    }
    return false;
}

void round4_partial_decrypt(int in, bit *out, int k) {
    in ^= k;
    in = RS[in];
    for(int i = 0; i < 4; i++) {
        out[i] = nth_bit(in, 3 - i);
    }
}

#endif //DIFFERENTIAL_ATTACK__LOCAL_HPP_
