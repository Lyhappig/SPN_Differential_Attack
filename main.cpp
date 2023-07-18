#include <iostream>
#include <map>
#include <cstring>
#include <time.h>
#include "local.hpp"
using namespace std;

/**
 * 攻击用的轮密钥
 */
SPN_KEY sk;

/**
 * 初始明文差分
 */
int DP[4];

/**
 * 满足明文差分的一对明文，是否是错误对而被过滤
 */
bool filter[maxn];

/**
 * 5000明文对，第i个和第i+5000个是一对
 */
bit plain[maxn * 2][CRYPTO_SIZE];

/**
 * 5000密文对，第i个和第i+5000个是一对
 */
bit cypher[maxn * 2][CRYPTO_SIZE];

/**
 * 活跃S盒的编号，这里是1，3（即第四轮加密的第2，4个S盒）
 */
vector<int> active_sbox = {1, 3};

/**
 * 标记一个明文对是否已经被产生，因为需要若干个不同的明文对
 */
map<vector<int>, bool> vis;

void init() {
    // 初始化每一轮的输入/输出差分
    init_differential();
    vis.clear();
    memset(filter, 0, sizeof(filter));
}

/**
 * 默认生成5000个不同的明文对
 * @param number
 */
void generate_rand_plain(int number = 5000) {
    srand(time(0));
    vector<int> t, xt;
    t.resize(4);
    xt.resize(4);
    int temp = 0;
    // 计算明文差分
    for(int i = 0; i < 16; i++) {
        temp = (temp << 1) | U1[i];
        if((i + 1) % 4 == 0) {
            DP[i / 4] = temp;
            temp = 0;
        }
    }
    for(int k = 0; k < number; k++) {
        for(int i = 0; i < 4; i++) {
            t[i] = rand() % 16;
            xt[i] = DP[i] ^ t[i];
        }
        while(vis.count(t) || vis.count(xt)) {
            for(int i = 0; i < 4; i++) {
                t[i] = rand() % 16;
                xt[i] = DP[i] ^ t[i];
            }
        }
        vis[t] = true;
        vis[xt] = true;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                plain[k][i * 4 + j] = nth_bit(t[i], 3 - j);
                plain[k + number][i * 4 + j] = nth_bit(xt[i], 3 - j);
            }
        }
    }
    // 确保map的大小是10000
#ifdef CHECK_PLAIN
    printf("map's size is %d\n", vis.size());
#endif
}

/**
 * 生成攻击的五轮轮密钥
 */
void generate_rand_key() {
    srand(time(0));
    for(int i = 1; i <= sk.rounds; i++) {
        for(int j = 0; j < 16; j++) {
            sk.rd_key[i][j] = rand() % 2;
        }
    }
#ifdef CHECK_RAND_KEY
    for(int i = 1; i <= sk.rounds; i++) {
        printf("K%d: ", i);
        print_nbits(sk.rd_key[i], 16);
    }
#endif
}

/**
 * 获取每个明文的密文
 * @param number
 */
void get_cipher(int number = 5000) {
    for(int k = 0; k < number; k++) {
        spn_encrypt(plain[k], cypher[k], &sk);
        spn_encrypt(plain[k + number], cypher[k + number], &sk);
    }
}

/**
 * 对于给定的部分子密钥，获得正确对的数量
 * @param rd_k5
 * @param number
 * @return
 */
int get_right_number(int *rd_k5, int number) {
    // 部分子密钥解密后对应r-1轮的两个字节的输入明文以及差分
    bit p1[BYTE_SIZE], p2[BYTE_SIZE], delta[BYTE_SIZE];
    int ans = 0;
    for(int i = 0; i < number; i++) {
        if(filter[i]) continue;
        bool right = true;
        for(int j = 0; j < SBOX_NUM; j++) {
            // 非活跃S盒差分为0
            if(!vec_count(active_sbox, j)) continue;
            round4_partial_decrypt(get_nth_byte(cypher[i], j), p1, rd_k5[j]);
            round4_partial_decrypt(get_nth_byte(cypher[i + number], j), p2, rd_k5[j]);
            for(int k = 0; k < BYTE_SIZE; k++) {
                delta[k] = p1[k] ^ p2[k];
                // 确保与r-1轮的输入差分相等
                if(delta[k] != U4[j * BYTE_SIZE + k]) {
                    right = false;
                }
            }
        }
        ans += right;
    }
    return ans;
}

void failure_print(int *rd_k5) {
    printf("K5: ");
    print_nbits(sk.rd_key[5], 16);
    printf("attacked partial K5: ");
    for(int i = 0; i < SBOX_NUM; i++) {
        if(rd_k5[i] == -1) {
            printf(" ????");
        } else {
            printf(" ");
            for(int j = 0; j < BYTE_SIZE; j++) {
                printf("%d", nth_bit(rd_k5[i], 3 - j));
            }
        }
    }
    puts("");
}

/**
 * 差分攻击的函数
 * @param number
 * @return 是否攻击成功
 */
bool differential_attack(int number = 5000) {
    time_t st = time(NULL);
    // 根据最后一轮的非活跃S盒对应比特，进行错误对的过滤
    int s4_out1, s4_out2, cnt = number;
    for(int i = 0; i < number; i++) {
        for(int j = 0; j < SBOX_NUM; j++) {
            if(vec_count(active_sbox, j)) continue;
            s4_out1 = get_nth_byte(cypher[i], j);
            s4_out2 = get_nth_byte(cypher[i + number], j);
            if((s4_out1 ^ s4_out2) != 0) {
                filter[i] = true;
                cnt--;
                break;
            }
        }
    }
#ifdef CHECK_FILTER
    printf("After filter, group size is %d\n", cnt);
#endif
    // 枚举第五轮的部分轮密钥比特
    int rd_k5[SBOX_NUM];
    rd_k5[0] = rd_k5[2] = -1;  // let inactive key byte -1
    for(rd_k5[1] = 0; rd_k5[1] < 16; rd_k5[1]++) {
        for(rd_k5[3] = 0; rd_k5[3] < 16; rd_k5[3]++) {
            key_count[rd_k5[1]][rd_k5[3]] = get_right_number(rd_k5, number);
        }
    }
    // 得到对应数量最大的就是正确的部分密钥比特
    int max_cnt = 0;
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 16; j++) {
            if(key_count[i][j] > max_cnt) {
                max_cnt = key_count[i][j];
                rd_k5[1] = i;
                rd_k5[3] = j;
            }
        }
    }
    // 检验是否攻击失败
    for(int i = 0; i < SBOX_NUM; i++) {
        if(!vec_count(active_sbox, i)) continue;
        for(int j = 0; j < BYTE_SIZE; j++) {
            if(nth_bit(rd_k5[i], 3 - j) != sk.rd_key[5][i * 4 + j]) {
                failure_print(rd_k5);
                return false;
            }
        }
    }

#ifdef PRINT_ANS
    printf("probability is %.7lf\n", 1.0 * max_cnt / number);
    print_nbits(sk.rd_key[5], 16);
    printf("attacked partial K5: ");
    for(int i = 0; i < SBOX_NUM; i++) {
        if(rd_k5[i] == -1) {
            printf(" ????");
        } else {
            printf(" ");
            for(int j = 0; j < BYTE_SIZE; j++) {
                printf("%d", nth_bit(rd_k5[i], 3 - j));
            }
        }
    }
    puts("");
    time_t ed = time(NULL);
    double cost = ed - st;
    printf("Differential Attack cost %.5lf seconds\n", cost);
#endif
    return true;
}


int main() {
    // 差分攻击 times 次，检验算法
    int times = 1000;
    while(times--) {
        init();
        generate_rand_plain();
        generate_rand_key();
        get_cipher();
        if(!differential_attack()) {
            puts("differential attack failed");
            exit(-1);
        }
    }
    return 0;
}
