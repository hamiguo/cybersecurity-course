/**
 * modes.h / modes.c  —  工作模式实现: CTR, GCM, XTS
 *
 * 基于统一的 block_cipher_t 接口实现。
 * - CTR:  counter mode (NIST SP 800-38A)
 * - GCM:  Galois/Counter Mode (NIST SP 800-38D)
 * - XTS:  XEX-based tweaked-codebook mode with ciphertext stealing (IEEE 1619)
 *
 * 注意: GCM 需要 GF(2^128) 乘法, 使用预计算表加速。
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "algo_if.h"

#ifndef MODES_H
#define MODES_H

/* ==================== CTR 模式 ==================== */
/**
 * CTR 上下文: nonce(12B) || counter(4B, big-endian)
 * 适合 128-bit 分组的算法 (AES, SM4, GIFT-128)
 */
typedef struct {
    uint8_t   nonce[12];
    uint32_t  counter;
    uint8_t   keystream[16];   /* 缓存的 keystream 块 */
    size_t    ks_pos;          /* 当前 keystream 位置 */
    const block_cipher_t *cipher;
    uint8_t   cipher_ctx[];    /* 柔性数组 */
} ctr_ctx_t;

/* CTR 初始化: nonce 12 字节, 初始 counter 通常为 0 或 1 */
ctr_ctx_t *ctr_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *nonce, uint32_t start_ctr);

/* CTR 加密/解密 (相同操作) */
void ctr_crypt(ctr_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len);

/* 释放 */
void ctr_free(ctr_ctx_t *ctx);

/* ==================== GCM 模式 ==================== */
/**
 * GCM 上下文
 */
typedef struct {
    uint8_t   H[16];           /* E_K(0^128) — GHASH key */
    uint8_t   Y0[16];          /* 初始 counter */
    uint8_t   counter[16];     /* 当前 counter 块 */
    uint8_t   keystream[16];
    size_t    ks_pos;

    /* GHASH 状态 */
    uint8_t   ghash_state[16];
    uint64_t  aad_len;
    uint64_t  msg_len;
    int       finalized;

    const block_cipher_t *cipher;
    uint8_t   cipher_ctx[];
} gcm_ctx_t;

/* GCM 初始化: nonce 12 字节 (推荐), tag_len 通常 16 */
gcm_ctx_t *gcm_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *nonce, size_t nonce_len);

/* GCM 处理 AAD */
void gcm_update_aad(gcm_ctx_t *ctx, const uint8_t *aad, size_t len);

/* GCM 加密 */
void gcm_encrypt(gcm_ctx_t *ctx, const uint8_t *pt, uint8_t *ct, size_t len);

/* GCM 解密 */
void gcm_decrypt(gcm_ctx_t *ctx, const uint8_t *ct, uint8_t *pt, size_t len);

/* GCM 生成/验证 tag (tag_len 通常 16) */
void gcm_finalize(gcm_ctx_t *ctx, uint8_t *tag, size_t tag_len);

/* 释放 */
void gcm_free(gcm_ctx_t *ctx);

/* ==================== XTS 模式 ==================== */
/**
 * XTS 上下文: 需要两个独立的密钥 K1, K2
 * block 大小 = 16 字节 (128-bit)
 */
typedef struct {
    uint8_t   tweak[16];       /* 当前 tweak */
    const block_cipher_t *cipher;
    uint8_t   cipher_ctx1[];   /* K1 的上下文 */
    /* cipher_ctx2 紧跟其后 */
} xts_ctx_t;

/* XTS 初始化: key 为 K1||K2 (32 字节), 对 128-bit 分组算法 */
xts_ctx_t *xts_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *tweak);

/* XTS 加密: len >= 16, 处理 n 个完整块 + 可能的 CTS */
void xts_encrypt(xts_ctx_t *ctx, const uint8_t *pt, uint8_t *ct, size_t len);

/* XTS 解密 */
void xts_decrypt(xts_ctx_t *ctx, const uint8_t *ct, uint8_t *pt, size_t len);

/* 释放 */
void xts_free(xts_ctx_t *ctx);

#endif /* MODES_H */
