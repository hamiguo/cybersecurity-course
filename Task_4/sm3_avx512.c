/**
 * sm3_avx512.c — SM3 x86 AVX-512 优化实现 (16路并行)
 *
 * 优化策略：
 *   利用Intel AVX-512 512-bit SIMD寄存器 (__m512i)，
 *   同时处理16个独立的SM3消息块。每个ZMM向量包含16个
 *   32-bit lane，分别对应16条消息的同一变量。
 *
 * 三大硬件加速亮点:
 *   1. _mm512_rol_epi32 — 单指令循环左移 (1周期)
 *   2. _mm512_ternarylogic_epi32 — 单指令实现FF0/FF1/GG0/GG1/P0/P1
 *   3. 32个ZMM寄存器 — 完全消除寄存器溢出
 *
 * 适用平台: x86_64 with AVX-512F+VL (Skylake-X+, 2017+)
 * 编译选项: -mavx512f -mavx512vl
 */

#include "sm3.h"
#include <string.h>
#include <stdlib.h>

#ifdef __x86_64__
#include <immintrin.h>

/* FIX: runtime ROTL32 for TJ computation */
static inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* ================================================================
 * AVX-512 辅助内联函数
 * ================================================================ */

/* 32-bit 循环左移 — AVX-512 原生支持! (_mm512_rol_epi32) */
static inline __m512i avx512_rotl32(__m512i x, int n) {
    return _mm512_rol_epi32(x, n);
}

/* P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17) — 用 ternarylogic */
static inline __m512i avx512_P0(__m512i x) {
    /* ternarylogic: idx = 0x96 = (a^b^c) → 0b10010110 */
    __m512i t1 = avx512_rotl32(x, 9);
    __m512i t2 = avx512_rotl32(x, 17);
    return _mm512_ternarylogic_epi32(x, t1, t2, 0x96);
}

/* P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23) */
static inline __m512i avx512_P1(__m512i x) {
    __m512i t1 = avx512_rotl32(x, 15);
    __m512i t2 = avx512_rotl32(x, 23);
    return _mm512_ternarylogic_epi32(x, t1, t2, 0x96);
}

/* FF0(X,Y,Z) = X ⊕ Y ⊕ Z — ternarylogic 0x96 */
static inline __m512i avx512_FF0(__m512i x, __m512i y, __m512i z) {
    return _mm512_ternarylogic_epi32(x, y, z, 0x96);
}

/* FF1(X,Y,Z) = (X∧Y) ∨ (X∧Z) ∨ (Y∧Z) — ternarylogic 0xE8 */
static inline __m512i avx512_FF1(__m512i x, __m512i y, __m512i z) {
    return _mm512_ternarylogic_epi32(x, y, z, 0xE8);
}

/* GG0(X,Y,Z) = X ⊕ Y ⊕ Z */
static inline __m512i avx512_GG0(__m512i x, __m512i y, __m512i z) {
    return _mm512_ternarylogic_epi32(x, y, z, 0x96);
}

/* GG1(X,Y,Z) = (X∧Y) ∨ (¬X∧Z) — ternarylogic 0xCA */
static inline __m512i avx512_GG1(__m512i x, __m512i y, __m512i z) {
    return _mm512_ternarylogic_epi32(x, y, z, 0xCA);
}


/* ================================================================
 * 常量
 * ================================================================ */
static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};


/* ================================================================
 * 16路加载: 从16个独立block中取第word_idx个字
 * ================================================================ */
static inline __m512i avx512_load_16way(const uint8_t *blocks[16], int word_idx)
{
    uint32_t vals[16] __attribute__((aligned(64)));
    for (int i = 0; i < 16; i++) {
        int off = word_idx * 4;
        vals[i] = ((uint32_t)blocks[i][off]   << 24) |
                  ((uint32_t)blocks[i][off+1] << 16) |
                  ((uint32_t)blocks[i][off+2] << 8)  |
                  ((uint32_t)blocks[i][off+3]);
    }
    return _mm512_load_si512((__m512i*)vals);
}


/* ================================================================
 * 16路并行消息扩展
 * ================================================================ */
static void
avx512_message_expand_16way(const uint8_t *blocks[16],
                            __m512i W[68], __m512i Wprime[64])
{
    int j;

    for (j = 0; j < 16; j++)
        W[j] = avx512_load_16way(blocks, j);

    for (j = 16; j < 68; j++) {
        __m512i t = _mm512_xor_si512(
            _mm512_xor_si512(W[j - 16], W[j - 9]),
            avx512_rotl32(W[j - 3], 15));

        W[j] = _mm512_xor_si512(
            _mm512_xor_si512(avx512_P1(t), avx512_rotl32(W[j - 13], 7)),
            W[j - 6]);
    }

    for (j = 0; j < 64; j++)
        Wprime[j] = _mm512_xor_si512(W[j], W[j + 4]);
}


/* ================================================================
 * 16路并行压缩函数
 * ================================================================ */
static void
avx512_compress_16way(__m512i state[8],
                      const __m512i W[68],
                      const __m512i Wprime[64])
{
    __m512i A, B, C, D, E, F, G, H;
    __m512i SS1, SS2, TT1, TT2;
    __m512i tj_broadcast;
    int j;

    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (j = 0; j < 64; j++) {
        /* FIXED: compute TJ = ROTL32(T0 or T1, j) at runtime */
        tj_broadcast = _mm512_set1_epi32(
            (j < 16) ? ROTL32(0x79CC4519, j) : ROTL32(0x7A879D8A, j));

        SS1 = avx512_rotl32(
            _mm512_add_epi32(
                _mm512_add_epi32(avx512_rotl32(A, 12), E),
                tj_broadcast),
            7);

        SS2 = _mm512_xor_si512(SS1, avx512_rotl32(A, 12));

        if (j < 16) {
            TT1 = _mm512_add_epi32(
                _mm512_add_epi32(
                    _mm512_add_epi32(avx512_FF0(A, B, C), D), SS2), Wprime[j]);

            TT2 = _mm512_add_epi32(
                _mm512_add_epi32(
                    _mm512_add_epi32(avx512_GG0(E, F, G), H), SS1), W[j]);
        } else {
            TT1 = _mm512_add_epi32(
                _mm512_add_epi32(
                    _mm512_add_epi32(avx512_FF1(A, B, C), D), SS2), Wprime[j]);

            TT2 = _mm512_add_epi32(
                _mm512_add_epi32(
                    _mm512_add_epi32(avx512_GG1(E, F, G), H), SS1), W[j]);
        }

        D = C;
        C = avx512_rotl32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = avx512_rotl32(F, 19);
        F = E;
        E = avx512_P0(TT2);
    }

    state[0] = _mm512_xor_si512(state[0], A);
    state[1] = _mm512_xor_si512(state[1], B);
    state[2] = _mm512_xor_si512(state[2], C);
    state[3] = _mm512_xor_si512(state[3], D);
    state[4] = _mm512_xor_si512(state[4], E);
    state[5] = _mm512_xor_si512(state[5], F);
    state[6] = _mm512_xor_si512(state[6], G);
    state[7] = _mm512_xor_si512(state[7], H);
}


/* ================================================================
 * 填充辅助函数
 * ================================================================ */
static int sm3_pad_message_avx512(const uint8_t *msg, size_t len,
                                   uint8_t *padded, size_t *padded_len,
                                   uint64_t total_bits)
{
    size_t pad_bytes;
    int i;
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    pad_bytes = (len % 64 < 56) ? (64 - len % 64) : (128 - len % 64);
    *padded_len = len + pad_bytes;
    for (i = (int)len + 1; i < (int)(*padded_len) - 8; i++)
        padded[i] = 0;
    for (i = 0; i < 8; i++)
        padded[*padded_len - 8 + i] =
            (uint8_t)(total_bits >> ((7 - i) * 8));
    return (int)(*padded_len / 64);
}


/* ================================================================
 * 批量哈希 API: 16路并行 (FIXED batch loop)
 * ================================================================ */
void sm3_avx512_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE])
{
    int i, round, max_blocks = 0;
    int num_blocks_arr[256];
    uint8_t *padded_msgs[256];
    uint8_t *padded_buf = NULL;
    size_t total_padded = 0;
    __m512i state[8];
    __m512i W[68], Wprime[64];

    if (n <= 0) return;

    /* 阶段1: 填充所有消息 */
    for (i = 0; i < n; i++)
        total_padded += ((lens[i] + 72 + 63) / 64) * 64;

    padded_buf = (uint8_t *)malloc(total_padded);
    if (!padded_buf) return;

    {
        uint8_t *ptr = padded_buf;
        for (i = 0; i < n; i++) {
            size_t plen;
            padded_msgs[i] = ptr;
            num_blocks_arr[i] = sm3_pad_message_avx512(
                msgs[i], lens[i], ptr, &plen, (uint64_t)lens[i] * 8);
            ptr += plen;
            if (num_blocks_arr[i] > max_blocks)
                max_blocks = num_blocks_arr[i];
        }
    }

    /* 阶段2: 初始化状态 */
    uint32_t (*state_all)[8] = (uint32_t(*)[8])malloc(n * 8 * sizeof(uint32_t));
    for (i = 0; i < n; i++)
        memcpy(state_all[i], SM3_IV, sizeof(SM3_IV));

    /* 阶段3: 按块组并行处理 (FIXED: processes ALL messages, not just first 16) */
    for (round = 0; round < max_blocks; round++) {
        int batch_i = 0;
        while (batch_i < n) {
            int active_count = 0;
            int active_idx[16];
            const uint8_t *blocks[16];

            while (batch_i < n && active_count < 16) {
                if (round < num_blocks_arr[batch_i]) {
                    active_idx[active_count] = batch_i;
                    blocks[active_count] = padded_msgs[batch_i] + round * 64;
                    active_count++;
                }
                batch_i++;
            }
            if (active_count == 0) break;

            if (active_count == 16) {
                uint32_t aligned_vals[16] __attribute__((aligned(64)));
                for (int w = 0; w < 8; w++) {
                    for (int k = 0; k < 16; k++)
                        aligned_vals[k] = state_all[active_idx[k]][w];
                    state[w] = _mm512_load_si512((__m512i*)aligned_vals);
                }
                avx512_message_expand_16way(blocks, W, Wprime);
                avx512_compress_16way(state, W, Wprime);
                for (int w = 0; w < 8; w++) {
                    _mm512_store_si512((__m512i*)aligned_vals, state[w]);
                    for (int k = 0; k < 16; k++)
                        state_all[active_idx[k]][w] = aligned_vals[k];
                }
            } else if (active_count >= 8) {
                for (int k = 0; k < active_count; k++)
                    sm3_compress_ref(state_all[active_idx[k]], blocks[k]);
            } else {
                for (int k = 0; k < active_count; k++)
                    sm3_compress_ref(state_all[active_idx[k]], blocks[k]);
            }
        }
    }

    /* 阶段4: 提取摘要 */
    for (i = 0; i < n; i++) {
        for (int w = 0; w < 8; w++) {
            digests[i][w * 4]     = (uint8_t)(state_all[i][w] >> 24);
            digests[i][w * 4 + 1] = (uint8_t)(state_all[i][w] >> 16);
            digests[i][w * 4 + 2] = (uint8_t)(state_all[i][w] >> 8);
            digests[i][w * 4 + 3] = (uint8_t)(state_all[i][w]);
        }
    }

    free(state_all);
    free(padded_buf);
}

#endif /* __x86_64__ */
