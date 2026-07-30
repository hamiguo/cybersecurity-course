/**
 * twine128_basic.c  —  TWINE-128 basic 实现
 *
 * TWINE-128: 64-bit 分组, 128-bit 密钥, 36 轮 Type-2 GFS, 16 个 nibble.
 * 每轮: 偶数 nibble XOR round key → S-box → XOR 到下一个奇数 nibble.
 * 然后 block shuffle π 重新排列, 最后第 36 轮省略 shuffle。
 *
 * 测试向量: (来自 NEC 原始论文示例验证)
 *   Key:        000102030405060708090A0B0C0D0E0F (128 bits)
 *   Plaintext:  0123456789ABCDEF01234567          (64 bits, nibble-first)
 *   实际使用参考实现来验证。
 */
#include "algo_if.h"
#include "config.h"
#include <string.h>
#include <stdlib.h>

/* ==================== S-box (4-bit) ==================== */
static const uint8_t SBOX[16] = {
    0xC, 0x0, 0xF, 0xA, 0x2, 0xB, 0x9, 0x5,
    0x8, 0x3, 0xD, 0x7, 0x1, 0xE, 0x6, 0x4
};

/* ==================== Block shuffle ==================== */
static const uint8_t SHUFFLE[16] = {
     5,  0,  1,  4,  7, 12,  3,  8,
    13,  6,  9,  2, 15, 10, 11, 14
};

static const uint8_t SHUFFLE_INV[16] = {
     1,  2, 11,  6,  3,  0,  9,  4,
     7, 10, 13, 14,  5,  8, 15, 12
};

/* ==================== 轮常数 (CON_i) ==================== */
static const uint8_t RCON[36] = {
    0x01,0x03,0x07,0x0f,0x1f,0x3f,0x3e,0x3d,0x3a,0x35,0x2a,0x15,
    0x2b,0x16,0x2c,0x19,0x33,0x26,0x0d,0x1b,0x37,0x2e,0x1d,0x3b,
    0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x09,0x13,0x27,0x0e,0x1c
};

/* ==================== 上下文 (36 轮 × 8 nibble round keys) ==================== */
typedef struct {
    uint8_t rk[36][8];  /* 每轮 8 个 4-bit round key nibble */
} twine128_basic_ctx;

/* ==================== 密钥扩展 (128-bit) ==================== */
static void twine128_key_schedule(const uint8_t *key, void *ctx) {
    twine128_basic_ctx *c = (twine128_basic_ctx *)ctx;

    /* 128-bit 密钥分成 32 个 nibble 存入 WK[0..31] */
    uint8_t WK[32];
    for (int i = 0; i < 16; i++) {
        WK[2*i]     = (key[i] >> 4) & 0xF;
        WK[2*i + 1] = key[i] & 0xF;
    }

    for (int r = 0; r < 36; r++) {
        /* 提取轮密钥 (from Table 4, TWINE-128) */
        c->rk[r][0] = WK[2];
        c->rk[r][1] = WK[3];
        c->rk[r][2] = WK[12];
        c->rk[r][3] = WK[15];
        c->rk[r][4] = WK[17];
        c->rk[r][5] = WK[18];
        c->rk[r][6] = WK[28];
        c->rk[r][7] = WK[31];

        if (r == 35) break;  /* 最后一轮不需要再更新 */

        /* 密钥状态更新 */
        uint8_t con = RCON[r];
        WK[1]  ^= SBOX[WK[0]];
        WK[4]  ^= SBOX[WK[16]];
        WK[23] ^= SBOX[WK[30]];
        WK[7]  ^= (con >> 3) & 0x7;       /* CON^{H} */
        WK[19] ^= con & 0x7;              /* CON^{L} */

        /* 保存旧值, 然后轮转 */
        uint8_t tmp0 = WK[0], tmp1 = WK[1], tmp2 = WK[2], tmp3 = WK[3];
        /* WK[0..3] 来自 WK[4..7], ... WK[28..31] 来自 tmp0..tmp3 */
        /* 正确的操作: WK 每 4-nibble group 左移 */
        for (int g = 0; g < 7; g++) {
            WK[g*4]   = WK[g*4 + 4];
            WK[g*4+1] = WK[g*4 + 5];
            WK[g*4+2] = WK[g*4 + 6];
            WK[g*4+3] = WK[g*4 + 7];
        }
        WK[28] = tmp0; WK[29] = tmp1; WK[30] = tmp2; WK[31] = tmp3;
    }
}

/* ==================== 加密 ==================== */
static void twine128_encrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    const twine128_basic_ctx *c = (const twine128_basic_ctx *)ctx;

    /* 加载明文 → 16 个 nibble */
    uint8_t X[16];
    for (int i = 0; i < 8; i++) {
        X[2*i]     = (in[i] >> 4) & 0xF;
        X[2*i + 1] = in[i] & 0xF;
    }

    for (int r = 0; r < 35; r++) {
        /* 8 个 F 函数并行 */
        for (int j = 0; j < 8; j++) {
            X[2*j + 1] ^= SBOX[X[2*j] ^ c->rk[r][j]];
        }
        /* Block shuffle */
        uint8_t next[16];
        for (int h = 0; h < 16; h++)
            next[SHUFFLE[h]] = X[h];
        memcpy(X, next, 16);
    }

    /* 最后一轮 (无 shuffle) */
    for (int j = 0; j < 8; j++)
        X[2*j + 1] ^= SBOX[X[2*j] ^ c->rk[35][j]];

    /* 输出密文 */
    for (int i = 0; i < 8; i++)
        out[i] = (X[2*i] << 4) | X[2*i + 1];
}

/* ==================== 解密 ==================== */
static void twine128_decrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    const twine128_basic_ctx *c = (const twine128_basic_ctx *)ctx;

    uint8_t X[16];
    for (int i = 0; i < 8; i++) {
        X[2*i]     = (in[i] >> 4) & 0xF;
        X[2*i + 1] = in[i] & 0xF;
    }

    /* 解密: 逆序进行 */
    /* 先做最后一轮的逆 */
    for (int j = 0; j < 8; j++)
        X[2*j + 1] ^= SBOX[X[2*j] ^ c->rk[35][j]];

    for (int r = 34; r >= 0; r--) {
        /* 逆 shuffle */
        uint8_t prev[16];
        for (int h = 0; h < 16; h++)
            prev[SHUFFLE_INV[h]] = X[h];
        memcpy(X, prev, 16);

        /* F 函数逆 */
        for (int j = 0; j < 8; j++)
            X[2*j + 1] ^= SBOX[X[2*j] ^ c->rk[r][j]];
    }

    for (int i = 0; i < 8; i++)
        out[i] = (X[2*i] << 4) | X[2*i + 1];
}

/* ==================== 块密码接口 ==================== */
const block_cipher_t twine128_basic_impl = {
    .name         = "TWINE128-basic",
    .ctx_size     = sizeof(twine128_basic_ctx),
    .block_size   = 8,
    .key_schedule = twine128_key_schedule,
    .encrypt      = twine128_encrypt,
    .decrypt      = twine128_decrypt
};
