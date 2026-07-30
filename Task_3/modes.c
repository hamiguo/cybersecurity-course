/**
 * modes.c  —  CTR / GCM / XTS 工作模式实现
 */
#include "modes.h"
#include "common.h"
#include <stdio.h>

/* =========================================================================
 * 内部辅助: GF(2^128) 操作 (用于 GCM GHASH 和 XTS tweak 乘法)
 * ========================================================================= */

/* GF(2^128) 乘法 (用于 XTS tweak: 乘以 α = 0x02)
 * 不可约多项式: x^128 + x^7 + x^2 + x + 1
 * 返回 x * α mod p(x), x 为 16 字节 big-endian */
static void gf128_mul_alpha(uint8_t *x) {
    uint8_t carry = x[0] >> 7;  /* MSB */
    for (int i = 0; i < 15; i++)
        x[i] = (x[i] << 1) | (x[i + 1] >> 7);
    x[15] = x[15] << 1;
    if (carry)
        x[15] ^= 0x87;  /* x^7 + x^2 + x + 1 */
}

/* GF(2^128) 乘法: Z = X * Y, 用于 GCM GHASH
 * 使用 4-bit 预计算法 (基于学校乘法 + 预计算表) */
static void gf128_mul(uint8_t *z, const uint8_t *x, const uint8_t *y) {
    uint8_t v[16];
    memcpy(v, y, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 128; i++) {
        int byte_idx = 15 - (i >> 3);
        int bit_idx = 7 - (i & 7);
        if ((x[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        }
        uint8_t carry = v[0] >> 7;
        for (int j = 0; j < 15; j++)
            v[j] = (v[j] << 1) | (v[j + 1] >> 7);
        v[15] = v[15] << 1;
        if (carry) v[15] ^= 0x87;
    }
}

/* =========================================================================
 * CTR 模式
 * ========================================================================= */

ctr_ctx_t *ctr_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *nonce, uint32_t start_ctr) {
    size_t alloc_sz = sizeof(ctr_ctx_t) + cipher->ctx_size;
    ctr_ctx_t *ctx = (ctr_ctx_t *)ALIGN_ALLOC(alloc_sz);
    if (!ctx) return NULL;
    memset(ctx, 0, alloc_sz);

    ctx->cipher = cipher;
    ctx->counter = start_ctr;
    memcpy(ctx->nonce, nonce, 12);
    ctx->ks_pos = 16;  /* 强制重新生成 */

    cipher->key_schedule(key, ctx->cipher_ctx);
    return ctx;
}

void ctr_crypt(ctr_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        if (ctx->ks_pos >= 16) {
            /* 生成新的 keystream 块 */
            uint8_t ctr_block[16];
            memcpy(ctr_block, ctx->nonce, 12);
            ctr_block[12] = (uint8_t)(ctx->counter >> 24);
            ctr_block[13] = (uint8_t)(ctx->counter >> 16);
            ctr_block[14] = (uint8_t)(ctx->counter >>  8);
            ctr_block[15] = (uint8_t)(ctx->counter);
            ctx->cipher->encrypt(ctr_block, ctx->keystream, ctx->cipher_ctx);
            ctx->counter++;
            ctx->ks_pos = 0;
        }
        size_t chunk = len - pos;
        if (chunk > 16 - ctx->ks_pos) chunk = 16 - ctx->ks_pos;
        for (size_t i = 0; i < chunk; i++)
            out[pos + i] = in[pos + i] ^ ctx->keystream[ctx->ks_pos + i];
        ctx->ks_pos += chunk;
        pos += chunk;
    }
}

void ctr_free(ctr_ctx_t *ctx) {
    if (ctx) ALIGN_FREE(ctx);
}

/* =========================================================================
 * GCM 模式
 * ========================================================================= */

gcm_ctx_t *gcm_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *nonce, size_t nonce_len) {
    size_t alloc_sz = sizeof(gcm_ctx_t) + cipher->ctx_size;
    gcm_ctx_t *ctx = (gcm_ctx_t *)ALIGN_ALLOC(alloc_sz);
    if (!ctx) return NULL;
    memset(ctx, 0, alloc_sz);

    ctx->cipher = cipher;
    cipher->key_schedule(key, ctx->cipher_ctx);

    /* 计算 H = E_K(0^128) */
    uint8_t zeros[16] = {0};
    cipher->encrypt(zeros, ctx->H, ctx->cipher_ctx);

    /* 计算 Y0 (初始 counter) */
    if (nonce_len == 12) {
        memcpy(ctx->Y0, nonce, 12);
        ctx->Y0[12] = ctx->Y0[13] = ctx->Y0[14] = 0;
        ctx->Y0[15] = 1;
    } else {
        /* GHASH(nonce || 0^s || len64) — 简化处理, 本文档限定 nonce_len=12 */
        /* 实际实现需支持任意 nonce 长度 */
        memset(ctx->Y0, 0, 16);
    }

    /* 初始化 counter = Y0, GHASH state = 0 */
    memcpy(ctx->counter, ctx->Y0, 16);
    memset(ctx->ghash_state, 0, 16);
    ctx->ks_pos = 16;
    ctx->finalized = 0;

    return ctx;
}

/* GHASH: 更新认证数据 (AAD / ciphertext) */
static void gcm_ghash_update(gcm_ctx_t *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        size_t chunk = len < 16 ? len : 16;
        uint8_t block[16] = {0};
        memcpy(block, data, chunk);

        for (int i = 0; i < 16; i++)
            ctx->ghash_state[i] ^= block[i];

        gf128_mul(ctx->ghash_state, ctx->ghash_state, ctx->H);

        data += chunk;
        len -= chunk;
    }
}

void gcm_update_aad(gcm_ctx_t *ctx, const uint8_t *aad, size_t len) {
    ctx->aad_len += len;
    gcm_ghash_update(ctx, aad, len);
}

/* GCM 加密的 keystream 生成: counter[12..15] 递增 */
static void gcm_next_keystream(gcm_ctx_t *ctx) {
    ctx->cipher->encrypt(ctx->counter, ctx->keystream, ctx->cipher_ctx);
    /* Increment counter (big-endian 32-bit at bytes 12..15) */
    uint32_t c = ((uint32_t)ctx->counter[12] << 24)
               | ((uint32_t)ctx->counter[13] << 16)
               | ((uint32_t)ctx->counter[14] <<  8)
               | ((uint32_t)ctx->counter[15]);
    c++;
    ctx->counter[12] = (uint8_t)(c >> 24);
    ctx->counter[13] = (uint8_t)(c >> 16);
    ctx->counter[14] = (uint8_t)(c >>  8);
    ctx->counter[15] = (uint8_t)(c);
}

void gcm_encrypt(gcm_ctx_t *ctx, const uint8_t *pt, uint8_t *ct, size_t len) {
    ctx->msg_len += len;
    size_t pos = 0;
    while (pos < len) {
        if (ctx->ks_pos >= 16) {
            gcm_next_keystream(ctx);
            ctx->ks_pos = 0;
        }
        size_t chunk = len - pos;
        if (chunk > 16 - ctx->ks_pos) chunk = 16 - ctx->ks_pos;
        for (size_t i = 0; i < chunk; i++) {
            ct[pos + i] = pt[pos + i] ^ ctx->keystream[ctx->ks_pos + i];
        }
        ctx->ks_pos += chunk;
        pos += chunk;
    }
    /* GHASH update with ciphertext */
    gcm_ghash_update(ctx, ct, len);
}

void gcm_decrypt(gcm_ctx_t *ctx, const uint8_t *ct, uint8_t *pt, size_t len) {
    /* 先 GHASH ciphertext */
    gcm_ghash_update(ctx, ct, len);
    ctx->msg_len += len;

    size_t pos = 0;
    while (pos < len) {
        if (ctx->ks_pos >= 16) {
            gcm_next_keystream(ctx);
            ctx->ks_pos = 0;
        }
        size_t chunk = len - pos;
        if (chunk > 16 - ctx->ks_pos) chunk = 16 - ctx->ks_pos;
        for (size_t i = 0; i < chunk; i++)
            pt[pos + i] = ct[pos + i] ^ ctx->keystream[ctx->ks_pos + i];
        ctx->ks_pos += chunk;
        pos += chunk;
    }
}

void gcm_finalize(gcm_ctx_t *ctx, uint8_t *tag, size_t tag_len) {
    if (ctx->finalized) return;
    ctx->finalized = 1;

    /* 最终 GHASH: len(A) || len(C) 各 64-bit BE */
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = ctx->aad_len * 8;
    uint64_t msg_bits = ctx->msg_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i]     = (uint8_t)(aad_bits >> (56 - 8*i));
        len_block[8 + i] = (uint8_t)(msg_bits >> (56 - 8*i));
    }
    gcm_ghash_update(ctx, len_block, 16);

    /* Tag = GHASH_final ⊕ E_K(Y0) */
    uint8_t enc_y0[16];
    ctx->cipher->encrypt(ctx->Y0, enc_y0, ctx->cipher_ctx);
    for (size_t i = 0; i < tag_len && i < 16; i++)
        tag[i] = ctx->ghash_state[i] ^ enc_y0[i];
}

void gcm_free(gcm_ctx_t *ctx) {
    if (ctx) ALIGN_FREE(ctx);
}

/* =========================================================================
 * XTS 模式 (IEEE 1619)
 * ========================================================================= */

xts_ctx_t *xts_init(const block_cipher_t *cipher,
                    const uint8_t *key, const uint8_t *tweak) {
    /* key = K1(16B) || K2(16B) */
    size_t alloc_sz = sizeof(xts_ctx_t) + cipher->ctx_size * 2;
    xts_ctx_t *ctx = (xts_ctx_t *)ALIGN_ALLOC(alloc_sz);
    if (!ctx) return NULL;
    memset(ctx, 0, alloc_sz);

    ctx->cipher = cipher;
    cipher->key_schedule(key, ctx->cipher_ctx1);
    cipher->key_schedule(key + 16, ctx->cipher_ctx1 + cipher->ctx_size);

    /* 初始化 tweak = AES-encrypt(K2, tweak_input) */
    cipher->encrypt(tweak, ctx->tweak, ctx->cipher_ctx1 + cipher->ctx_size);

    return ctx;
}

/* 块加密: T = tweak, PP = PT xor T, CC = encrypt(PP), CT = CC xor T */
static void xts_block_encrypt(xts_ctx_t *ctx, const uint8_t *pt, uint8_t *ct) {
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = pt[i] ^ ctx->tweak[i];
    ctx->cipher->encrypt(tmp, tmp, ctx->cipher_ctx1);
    for (int i = 0; i < 16; i++) ct[i] = tmp[i] ^ ctx->tweak[i];
    gf128_mul_alpha(ctx->tweak);  /* tweak *= α */
}

static void xts_block_decrypt(xts_ctx_t *ctx, const uint8_t *ct, uint8_t *pt) {
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = ct[i] ^ ctx->tweak[i];
    ctx->cipher->decrypt(tmp, tmp, ctx->cipher_ctx1);
    for (int i = 0; i < 16; i++) pt[i] = tmp[i] ^ ctx->tweak[i];
    gf128_mul_alpha(ctx->tweak);
}

void xts_encrypt(xts_ctx_t *ctx, const uint8_t *pt, uint8_t *ct, size_t len) {
    if (len < 16) return;  /* XTS 要求至少一个完整块 */

    size_t n_blocks = len / 16;
    size_t remainder = len % 16;
    size_t full_blocks = remainder ? n_blocks - 1 : n_blocks;

    /* 完整块 */
    for (size_t i = 0; i < full_blocks; i++) {
        xts_block_encrypt(ctx, pt + i * 16, ct + i * 16);
    }

    if (remainder) {
        /* Ciphertext stealing */
        size_t last_full = full_blocks * 16;
        /* 先加密倒数第二个完整块 (使用当前 tweak) */
        uint8_t cc[16];
        xts_block_encrypt(ctx, pt + last_full, cc);  /* tweak 已更新 */

        /* CTS: CT_{m-2} 用 CC 的前 remainder 字节 + CT_m 的后 (16-remainder) */
        /* CT_m = encrypt(PT_m || CT_{m-2}[0..16-remainder]) */
        uint8_t pm[16] = {0};
        memcpy(pm, pt + last_full + 16, remainder);
        memcpy(pm + remainder, cc + remainder, 16 - remainder);

        /* encrypt CT_m-1 (actual CTS: encrypt then output as last block) */
        uint8_t cm[16];
        xts_block_encrypt(ctx, pm, cm);

        /* 输出: 倒数第二个块 = cm, 最后一个块 = cc[0..15] 的前 remainder 字节 */
        memcpy(ct + last_full, cm, 16);      /* 输出完整块 m-1 */
        memcpy(ct + last_full + 16, cc, remainder); /* 只输出前 remainder 字节 */
    }
}

void xts_decrypt(xts_ctx_t *ctx, const uint8_t *ct, uint8_t *pt, size_t len) {
    if (len < 16) return;

    size_t n_blocks = len / 16;
    size_t remainder = len % 16;
    size_t full_blocks = remainder ? n_blocks - 1 : n_blocks;

    for (size_t i = 0; i < full_blocks - 1; i++) {
        xts_block_decrypt(ctx, ct + i * 16, pt + i * 16);
    }

    if (remainder) {
        /* 先解密倒数第二个块 (CT_{m-1}) 到 PM */
        size_t last_full = full_blocks * 16;
        uint8_t pm[16];
        xts_block_decrypt(ctx, ct + last_full, pm);

        /* CT_m = partial(last) || pm[remainder..15] */
        uint8_t cm[16];
        memcpy(cm, ct + last_full + 16, remainder);
        memcpy(cm + remainder, pm + remainder, 16 - remainder);

        /* 解密最后一个块 */
        xts_block_decrypt(ctx, cm, pt + last_full + 16);
        /* 倒数第二个块 = pm[0..15] (丢弃不用的部分) */
        memcpy(pt + last_full, pm, 16);
    } else {
        /* 无 CTS: 直接解密所有块 */
        for (size_t i = full_blocks - 1; i < full_blocks; i++) {
            xts_block_decrypt(ctx, ct + i * 16, pt + i * 16);
        }
    }
}

void xts_free(xts_ctx_t *ctx) {
    if (ctx) ALIGN_FREE(ctx);
}
