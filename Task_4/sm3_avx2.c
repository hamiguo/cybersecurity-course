/**
 * sm3_avx2.c — SM3 x86 AVX2 优化实现 (8路并行)
 *
 * 优化策略：
 *   利用Intel AVX2 256-bit SIMD寄存器 (__m256i)，
 *   同时处理8个独立的SM3消息块。每个YMM向量包含8个
 *   32-bit lane，分别对应8条消息的同一变量。
 *
 *   SIMD指令用于：
 *     - 消息扩展中的全部运算 (P1置换, XOR, ROTL)
 *     - 压缩函数中的全部轮运算 (FF, GG, ADD, XOR, ROTL)
 *   通用寄存器用于：
 *     - 轮计数器 j
 *     - 函数选择 (j<16 vs j>=16)
 *     - 内存寻址和循环控制
 *
 *   8路并行 vs 单路: 理论吞吐量提升 ~8x
 *   (实际取决于内存带宽和缓存)
 *
 * 适用平台: x86_64 with AVX2 support (Haswell+, 2013+)
 * 编译选项: -mavx2
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
 * AVX2 辅助内联函数
 * ================================================================ */

/* 32-bit 循环左移 — AVX2没有直接rotate指令，用shift+OR组合 */
static inline __m256i avx2_rotl32(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n));
}

/* P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17) — 8路并行 */
static inline __m256i avx2_P0(__m256i x) {
    __m256i t1 = _mm256_xor_si256(x, avx2_rotl32(x, 9));
    return _mm256_xor_si256(t1, avx2_rotl32(x, 17));
}

/* P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23) — 8路并行 */
static inline __m256i avx2_P1(__m256i x) {
    __m256i t1 = _mm256_xor_si256(x, avx2_rotl32(x, 15));
    return _mm256_xor_si256(t1, avx2_rotl32(x, 23));
}

/* FF0(X,Y,Z) = X ⊕ Y ⊕ Z */
static inline __m256i avx2_FF0(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

/* FF1(X,Y,Z) = (X∧Y) ∨ (X∧Z) ∨ (Y∧Z) */
static inline __m256i avx2_FF1(__m256i x, __m256i y, __m256i z) {
    __m256i xy = _mm256_and_si256(x, y);
    __m256i xz = _mm256_and_si256(x, z);
    __m256i yz = _mm256_and_si256(y, z);
    return _mm256_or_si256(_mm256_or_si256(xy, xz), yz);
}

/* GG0(X,Y,Z) = X ⊕ Y ⊕ Z */
static inline __m256i avx2_GG0(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

/*
 * GG1(X,Y,Z) = (X∧Y) ∨ (¬X∧Z)
 *
 * AVX2技巧: 使用 blendv 按位选择
 * _mm256_blendv_epi8(c, b, a): 当a的最高位为1时选b，否则选c
 * 我们需要 X 的每个bit控制选择: X=1选Y, X=0选Z
 * 将 Y 的高位置为对应的位扩展... 其实直接用 AND/ANDNOT/OR 更直观
 */
static inline __m256i avx2_GG1(__m256i x, __m256i y, __m256i z) {
    /* (X & Y) | (~X & Z) = (X & Y) ^ (~X & Z)
     * 注意 ~X = X ^ 0xFFFFFFFF */
    __m256i not_x = _mm256_xor_si256(x, _mm256_set1_epi32(0xFFFFFFFF));
    return _mm256_or_si256(
        _mm256_and_si256(x, y),
        _mm256_and_si256(not_x, z));
}


/* ================================================================
 * 预计算常量
 * ================================================================ */

static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};


/* ================================================================
 * 8路加载: 从8个独立block中取第word_idx个字
 * 返回 __m256i 按 lane 0..7 依次存放
 * ================================================================ */
static inline __m256i avx2_load_8way(const uint8_t *blocks[8], int word_idx)
{
    /*
     * 策略: 先用标量代码收集8个值到数组，再一次加载。
     *
     * 优化: 如果8个block在内存中连续排列，可以直接用
     *   _mm256_i32gather_epi32 做 gather 加载。
     *   这里保持通用性，用标量收集。
     */
    uint32_t vals[8] __attribute__((aligned(32)));
    for (int i = 0; i < 8; i++) {
        int off = word_idx * 4;
        vals[i] = ((uint32_t)blocks[i][off]   << 24) |
                  ((uint32_t)blocks[i][off+1] << 16) |
                  ((uint32_t)blocks[i][off+2] << 8)  |
                  ((uint32_t)blocks[i][off+3]);
    }
    return _mm256_load_si256((__m256i*)vals);
}


/* ================================================================
 * 8路并行消息扩展
 *
 * 每组W[j]是一个__m256i，8条消息的第j个字并行存放。
 * W[0..15]: 从消息块直接加载
 * W[16..67]: 用递推公式计算
 *
 * 原理图:
 *   ┌─────────────────────────────────────────┐
 *   │ Lane 0: Msg0的 W[0]~W[67]              │
 *   │ Lane 1: Msg1的 W[0]~W[67]              │
 *   │ ...                                      │
 *   │ Lane 7: Msg7的 W[0]~W[67]              │
 *   └─────────────────────────────────────────┘
 *   SIMD操作同时应用到所有8条消息
 * ================================================================ */
static void
avx2_message_expand_8way(const uint8_t *blocks[8],
                         __m256i W[68], __m256i Wprime[64])
{
    int j;

    /* W[0..15] */
    for (j = 0; j < 16; j++) {
        W[j] = avx2_load_8way(blocks, j);
    }

    /* W[16..67] — 所有操作lane-wise并行 */
    for (j = 16; j < 68; j++) {
        __m256i t = _mm256_xor_si256(
            _mm256_xor_si256(W[j - 16], W[j - 9]),
            avx2_rotl32(W[j - 3], 15));

        W[j] = _mm256_xor_si256(
            _mm256_xor_si256(avx2_P1(t), avx2_rotl32(W[j - 13], 7)),
            W[j - 6]);
    }

    /* W'[j] = W[j] ⊕ W[j+4] */
    for (j = 0; j < 64; j++) {
        Wprime[j] = _mm256_xor_si256(W[j], W[j + 4]);
    }
}


/* ================================================================
 * 8路并行压缩函数
 *
 * 核心优化点:
 *   1. 8个状态变量 (A~H) 各为 __m256i (8×32-bit)
 *   2. 64轮每轮的所有算术都是在256-bit向量上完成
 *   3. ROTL(T_j, j) 作为标量广播到8个lane
 *   4. 状态移位 (D=C, C=ROTL(B,9)...) 直接在向量间移动
 * ================================================================ */
static void
avx2_compress_8way(__m256i state[8],
                   const __m256i W[68],
                   const __m256i Wprime[64])
{
    __m256i A, B, C, D, E, F, G, H;
    __m256i SS1, SS2, TT1, TT2;
    __m256i tj_broadcast;
    int j;

    /* 加载状态 */
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    /*
     * 64轮压缩 — 全部在256-bit YMM寄存器中完成
     *
     * 通用寄存器角色:
     *   j (轮计数) → 控制FF0/FF1和GG0/GG1的选择
     *   SM3_TJ_ROTL 索引 → 加载标量常数
     */
    for (j = 0; j < 64; j++) {
        /* 广播 T_j <<< j 到所有8个lane */
        tj_broadcast = _mm256_set1_epi32((j < 16) ? ROTL32(0x79CC4519, j) : ROTL32(0x7A879D8A, j));

        /* SS1 = ((A <<< 12) + E + (T_j <<< j)) <<< 7 */
        SS1 = avx2_rotl32(
            _mm256_add_epi32(
                _mm256_add_epi32(avx2_rotl32(A, 12), E),
                tj_broadcast),
            7);

        /* SS2 = SS1 ⊕ (A <<< 12) */
        SS2 = _mm256_xor_si256(SS1, avx2_rotl32(A, 12));

        if (j < 16) {
            /* 轮 0..15: FF0/GG0 (XOR) */
            TT1 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(avx2_FF0(A, B, C), D),
                    SS2),
                Wprime[j]);

            TT2 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(avx2_GG0(E, F, G), H),
                    SS1),
                W[j]);
        } else {
            /* 轮 16..63: FF1 (majority) / GG1 (choose) */
            TT1 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(avx2_FF1(A, B, C), D),
                    SS2),
                Wprime[j]);

            TT2 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(avx2_GG1(E, F, G), H),
                    SS1),
                W[j]);
        }

        /* 状态移位 (lane-wise) */
        D = C;
        C = avx2_rotl32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = avx2_rotl32(F, 19);
        F = E;
        E = avx2_P0(TT2);
    }

    /* V' = V ⊕ (A,B,C,D,E,F,G,H) */
    state[0] = _mm256_xor_si256(state[0], A);
    state[1] = _mm256_xor_si256(state[1], B);
    state[2] = _mm256_xor_si256(state[2], C);
    state[3] = _mm256_xor_si256(state[3], D);
    state[4] = _mm256_xor_si256(state[4], E);
    state[5] = _mm256_xor_si256(state[5], F);
    state[6] = _mm256_xor_si256(state[6], G);
    state[7] = _mm256_xor_si256(state[7], H);
}


/* ================================================================
 * 填充辅助函数
 * ================================================================ */
static int sm3_pad_message_avx2(const uint8_t *msg, size_t len,
                                 uint8_t *padded, size_t *padded_len,
                                 uint64_t total_bits)
{
    size_t pad_bytes;
    int i;

    memcpy(padded, msg, len);
    padded[len] = 0x80;

    if (len % 64 < 56)
        pad_bytes = 64 - (len % 64);
    else
        pad_bytes = 128 - (len % 64);

    *padded_len = len + pad_bytes;

    for (i = (int)len + 1; i < (int)(*padded_len) - 8; i++)
        padded[i] = 0;

    for (i = 0; i < 8; i++)
        padded[*padded_len - 8 + i] =
            (uint8_t)(total_bits >> ((7 - i) * 8));

    return (int)(*padded_len / 64);
}


/* ================================================================
 * 批量哈希 API: 8路并行
 * ================================================================ */
void sm3_avx2_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE])
{
    int i, round, max_blocks = 0;
    int num_blocks_arr[256];
    uint8_t *padded_msgs[256];
    uint8_t *padded_buf = NULL;
    size_t total_padded = 0;
    __m256i state[8];
    __m256i W[68], Wprime[64];

    if (n <= 0) return;

    /* 阶段1: 填充所有消息 */
    for (i = 0; i < n; i++) {
        size_t max_pad = ((lens[i] + 72 + 63) / 64) * 64;
        total_padded += max_pad;
    }

    padded_buf = (uint8_t *)malloc(total_padded);
    if (!padded_buf) return;

    {
        uint8_t *ptr = padded_buf;
        for (i = 0; i < n; i++) {
            size_t plen;
            padded_msgs[i] = ptr;
            num_blocks_arr[i] = sm3_pad_message_avx2(
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

    /* 阶段3: 按块组并行处理, 每组最多8条 */
    for (round = 0; round < max_blocks; round++) {
        int batch_i = 0;
        while (batch_i < n) {
            int active_count = 0;
            int active_idx[8];
            const uint8_t *blocks[8];

            while (batch_i < n && active_count < 8) {
                if (round < num_blocks_arr[batch_i]) {
                    active_idx[active_count] = batch_i;
                    blocks[active_count] = padded_msgs[batch_i] + round * 64;
                    active_count++;
                }
                batch_i++;
            }

            if (active_count == 0) break;

        if (active_count == 8) {
            /* ---- 8路满并行 (AVX2) ---- */
            uint32_t aligned_vals[8] __attribute__((aligned(32)));

            for (int w = 0; w < 8; w++) {
                for (int k = 0; k < 8; k++)
                    aligned_vals[k] = state_all[active_idx[k]][w];
                state[w] = _mm256_load_si256((__m256i*)aligned_vals);
            }

            avx2_message_expand_8way(blocks, W, Wprime);
            avx2_compress_8way(state, W, Wprime);

            for (int w = 0; w < 8; w++) {
                _mm256_store_si256((__m256i*)aligned_vals, state[w]);
                for (int k = 0; k < 8; k++)
                    state_all[active_idx[k]][w] = aligned_vals[k];
            }
        } else {
            /* 不足8条: 回退参考实现 */
            for (int k = 0; k < active_count; k++)
                sm3_compress_ref(state_all[active_idx[k]], blocks[k]);
        }
    }

        } /* end while(batch_i < n) */

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
