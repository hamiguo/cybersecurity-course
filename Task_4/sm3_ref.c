/**
 * sm3_ref.c - SM3 reference implementation (pure C, portable)
 */

#include "sm3.h"
#include <string.h>

static inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}
static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}
static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

static void sm3_message_expand(const uint8_t block[64],
                               uint32_t W[68], uint32_t Wprime[64])
{
    int j;
    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4]     << 24) |
               ((uint32_t)block[j * 4 + 1] << 16) |
               ((uint32_t)block[j * 4 + 2] << 8)  |
               ((uint32_t)block[j * 4 + 3]);
    }
    for (j = 16; j < 68; j++) {
        uint32_t t = W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15);
        W[j] = P1(t) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }
    for (j = 0; j < 64; j++) {
        Wprime[j] = W[j] ^ W[j + 4];
    }
}

void sm3_compress_ref(uint32_t V[8], const uint8_t block[64])
{
    uint32_t W[68], Wprime[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    sm3_message_expand(block, W, Wprime);

    A = V[0]; B = V[1]; C = V[2]; D = V[3];
    E = V[4]; F = V[5]; G = V[6]; H = V[7];

    for (j = 0; j < 64; j++) {
        /* FIXED: compute TJ = ROTL32(T0 or T1, j) at runtime */
        uint32_t tj = (j < 16) ? 0x79CC4519 : 0x7A879D8A;
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(tj, j), 7);
        SS2 = SS1 ^ ROTL32(A, 12);

        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + Wprime[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + Wprime[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void sm3_ref_init(sm3_ctx_t *ctx)
{
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->total_bits = 0;
    ctx->buf_len    = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

void sm3_ref_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t consumed = 0;
    if (ctx->buf_len > 0) {
        size_t fill = SM3_BLOCK_SIZE - ctx->buf_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buf_len, data, len);
            ctx->buf_len += len;
            ctx->total_bits += (uint64_t)len * 8;
            return;
        }
        memcpy(ctx->buffer + ctx->buf_len, data, fill);
        sm3_compress_ref(ctx->state, ctx->buffer);
        ctx->total_bits += (uint64_t)fill * 8;
        consumed = fill;
        ctx->buf_len = 0;
    }
    while (consumed + SM3_BLOCK_SIZE <= len) {
        sm3_compress_ref(ctx->state, data + consumed);
        ctx->total_bits += SM3_BLOCK_SIZE * 8;
        consumed += SM3_BLOCK_SIZE;
    }
    if (consumed < len) {
        size_t remain = len - consumed;
        memcpy(ctx->buffer, data + consumed, remain);
        ctx->buf_len = remain;
        ctx->total_bits += (uint64_t)remain * 8;
    }
}

void sm3_ref_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE])
{
    size_t pad_len;
    uint8_t padding[SM3_BLOCK_SIZE * 2];
    uint64_t total_bits = ctx->total_bits;
    int i;

    memset(padding, 0, sizeof(padding));
    memcpy(padding, ctx->buffer, ctx->buf_len);
    padding[ctx->buf_len] = 0x80;

    if (ctx->buf_len < 56) {
        pad_len = SM3_BLOCK_SIZE;
    } else {
        pad_len = SM3_BLOCK_SIZE * 2;
    }

    for (i = 0; i < 8; i++) {
        padding[pad_len - 8 + i] = (uint8_t)(total_bits >> ((7 - i) * 8));
    }

    for (i = 0; i < (int)(pad_len / SM3_BLOCK_SIZE); i++) {
        sm3_compress_ref(ctx->state, padding + i * SM3_BLOCK_SIZE);
    }

    for (i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sm3_ref_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx_t ctx;
    sm3_ref_init(&ctx);
    sm3_ref_update(&ctx, data, len);
    sm3_ref_final(&ctx, digest);
}
