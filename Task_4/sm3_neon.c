/**
 * sm3_neon.c — SM3 ARM64 NEON 优化实现 (4路并行)
 *
 * 优化策略：
 *   利用ARM NEON 128-bit SIMD寄存器 (uint32x4_t)，
 *   同时处理4个独立的SM3消息块。每个NEON向量包含4个
 *   32-bit lane，分别对应4条消息的同一变量。
 *
 *   混合使用：
 *     - SIMD寄存器: 存放跨消息块的 A~H 状态和 W 数组
 *     - 通用寄存器: 循环计数器、轮函数选择、地址计算
 *
 * 适用平台: ARM64 (AArch64) with NEON/ASIMD
 * 编译选项: -march=armv8-a+simd 或 -march=native
 */

#include "sm3.h"
#include <string.h>
#include <stdlib.h>

#ifdef __aarch64__
#include <arm_neon.h>

/* ================================================================
 * NEON 辅助内联函数
 * ================================================================ */

/* 32-bit 循环左移 (每个lane独立) */
static inline uint32x4_t neon_rotl32(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_n_u32(x, n), vshrq_n_u32(x, 32 - n));
}

/* P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17) — 4路并行 */
static inline uint32x4_t neon_P0(uint32x4_t x) {
    return veorq_u32(veorq_u32(x, neon_rotl32(x, 9)), neon_rotl32(x, 17));
}

/* P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23) — 4路并行 */
static inline uint32x4_t neon_P1(uint32x4_t x) {
    return veorq_u32(veorq_u32(x, neon_rotl32(x, 15)), neon_rotl32(x, 23));
}

/* FF0(X,Y,Z) = X ⊕ Y ⊕ Z */
static inline uint32x4_t neon_FF0(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return veorq_u32(veorq_u32(x, y), z);
}

/* FF1(X,Y,Z) = (X∧Y) ∨ (X∧Z) ∨ (Y∧Z) */
static inline uint32x4_t neon_FF1(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    /* (X∧Y)⊕(X∧Z)⊕(Y∧Z) = majority */
    return veorq_u32(veorq_u32(vandq_u32(x, y),
                               vandq_u32(x, z)),
                               vandq_u32(y, z));
}

/* GG0(X,Y,Z) = X ⊕ Y ⊕ Z */
static inline uint32x4_t neon_GG0(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return veorq_u32(veorq_u32(x, y), z);
}

/* GG1(X,Y,Z) = (X∧Y) ∨ (¬X∧Z)
 * NEON vbslq:  dst = (mask & a) | (~mask & b)
 * 令 mask=X, a=Y, b=Z 即得 GG1
 */
static inline uint32x4_t neon_GG1(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return vbslq_u32(x, y, z);  /* (X&Y) | (~X&Z) */
}


/* ================================================================
 * 预计算常量 (与参考实现相同)
 * ================================================================ */
static const uint32_t SM3_TJ_ROTL[64] = {
    0x79CC4519, 0xF3988A32, 0xE7311464, 0xCE6228C8,
    0x9CC45199, 0x3988A332, 0x7311464C, 0xE6228C99,
    0xCC451993, 0x988A3326, 0x311464CE, 0x6228C99C,
    0xC4519938, 0x88A33271, 0x11464CE6, 0x228C99CC,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E6, 0xC53D43CC,
    0x8A7A8799, 0x14F50F33, 0x29EA1E67, 0x53D43CCE,
    0xA7A8799D, 0x4F50F33B, 0x9EA1E676, 0x3D43CCEC,
    0x7A8799D8, 0xF50F33B1, 0xEA1E6762, 0xD43CCEC5,
    0xA8799D8A, 0x50F33B15, 0xA1E6762A, 0x43CCEC55,
    0x8799D8AA, 0x0F33B155, 0x1E6762AB, 0x3CCEC556,
    0x799D8AAC, 0xF33B1559, 0xE6762AB3, 0xCCEC5566,
    0x99D8AACC, 0x33B15599, 0x6762AB33, 0xCEC55667,
    0x9D8AACCE, 0x3B15599D, 0x762AB33A, 0xEC556674,
    0xD8AACCEC, 0xB15599D9, 0x62AB33B2, 0xC5566764,
    0x8AACCEC8, 0x15599D91, 0x2AB33B22, 0x55667645
};

static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};


/* ================================================================
 * 4路加载：从4个独立的消息块中取出第word_idx个字
 * blocks[0..3] 分别指向4个64-byte消息块
 * 返回 uint32x4_t = { blocks[0][word_idx], blocks[1][word_idx],
 *                      blocks[2][word_idx], blocks[3][word_idx] }
 * ================================================================ */
static inline uint32x4_t neon_load_4way(const uint8_t *blocks[4], int word_idx)
{
    uint32x4_t result;
    /* 手动收集：每个lane从一个独立block读取 */
    result = vsetq_lane_u32(
        ((uint32_t)blocks[0][word_idx*4]   << 24) |
        ((uint32_t)blocks[0][word_idx*4+1] << 16) |
        ((uint32_t)blocks[0][word_idx*4+2] << 8)  |
        ((uint32_t)blocks[0][word_idx*4+3]), result, 0);

    result = vsetq_lane_u32(
        ((uint32_t)blocks[1][word_idx*4]   << 24) |
        ((uint32_t)blocks[1][word_idx*4+1] << 16) |
        ((uint32_t)blocks[1][word_idx*4+2] << 8)  |
        ((uint32_t)blocks[1][word_idx*4+3]), result, 1);

    result = vsetq_lane_u32(
        ((uint32_t)blocks[2][word_idx*4]   << 24) |
        ((uint32_t)blocks[2][word_idx*4+1] << 16) |
        ((uint32_t)blocks[2][word_idx*4+2] << 8)  |
        ((uint32_t)blocks[2][word_idx*4+3]), result, 2);

    result = vsetq_lane_u32(
        ((uint32_t)blocks[3][word_idx*4]   << 24) |
        ((uint32_t)blocks[3][word_idx*4+1] << 16) |
        ((uint32_t)blocks[3][word_idx*4+2] << 8)  |
        ((uint32_t)blocks[3][word_idx*4+3]), result, 3);

    return result;
}

/* 4路存储：将4个32-bit值写回各自block的第word_idx个字 */
static inline void neon_store_4way(uint32x4_t val,
                                   uint8_t *blocks[4], int word_idx)
{
    uint32_t vals[4];
    vst1q_u32(vals, val);
    for (int i = 0; i < 4; i++) {
        blocks[i][word_idx*4]   = (uint8_t)(vals[i] >> 24);
        blocks[i][word_idx*4+1] = (uint8_t)(vals[i] >> 16);
        blocks[i][word_idx*4+2] = (uint8_t)(vals[i] >> 8);
        blocks[i][word_idx*4+3] = (uint8_t)(vals[i]);
    }
}


/* ================================================================
 * 核心: 4路并行消息扩展
 *
 * 输入: 4个64-byte消息块 (blocks[0..3])
 * 输出: W[0..67] 和 Wprime[0..63]，每项为 uint32x4_t
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  W_simd[0] = { B0_W0, B1_W0, B2_W0, B3_W0 }      ║
 * ║  W_simd[1] = { B0_W1, B1_W1, B2_W1, B3_W1 }      ║
 * ║  ...                                                ║
 * ║  W_simd[67]= { B0_W67, B1_W67, B2_W67, B3_W67 }  ║
 * ╚══════════════════════════════════════════════════════╝
 * ================================================================ */
static void
neon_message_expand_4way(const uint8_t *blocks[4],
                         uint32x4_t W[68], uint32x4_t Wprime[64])
{
    int j;

    /* W[0..15] = 直接来自消息块 */
    for (j = 0; j < 16; j++) {
        W[j] = neon_load_4way(blocks, j);
    }

    /* W[16..67] 递推 — 所有运算都是lane-wise 4路并行 */
    for (j = 16; j < 68; j++) {
        /*
         * t = W[j-16] ⊕ W[j-9] ⊕ (W[j-3] <<< 15)
         * W[j] = P1(t) ⊕ (W[j-13] <<< 7) ⊕ W[j-6]
         */
        uint32x4_t t = veorq_u32(
            veorq_u32(W[j - 16], W[j - 9]),
            neon_rotl32(W[j - 3], 15));

        W[j] = veorq_u32(
            veorq_u32(neon_P1(t), neon_rotl32(W[j - 13], 7)),
            W[j - 6]);
    }

    /* W'[j] = W[j] ⊕ W[j+4] */
    for (j = 0; j < 64; j++) {
        Wprime[j] = veorq_u32(W[j], W[j + 4]);
    }
}


/* ================================================================
 * 核心: 4路并行压缩函数
 *
 * 8组状态向量，每组4个lane (对应4条消息):
 *   A_simd = {A0, A1, A2, A3}
 *   B_simd = {B0, B1, B2, B3}
 *   ...
 *
 * 64轮迭代中，所有算术/逻辑操作均在SIMD寄存器中并行完成，
 * 通用寄存器负责轮计数j、函数选择(FF0/FF1, GG0/GG1)。
 * ================================================================ */
static void
neon_compress_4way(uint32x4_t state[8],
                   const uint32x4_t W[68],
                   const uint32x4_t Wprime[64])
{
    uint32x4_t A, B, C, D, E, F, G, H;
    uint32x4_t SS1, SS2, TT1, TT2;
    uint32x4_t tj_rotl;
    int j;

    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (j = 0; j < 64; j++) {
        /* 广播标量常量到4个lane */
        tj_rotl = vdupq_n_u32(SM3_TJ_ROTL[j]);

        /*
         * SS1 = ((A <<< 12) + E + (T_j <<< j)) <<< 7
         *
         * 关键优化: ROTL(T_j, j) 是标量值，在每条lane中相同，
         *          因此用 vdupq_n_u32 广播，然后用 vaddq_u32 并行加。
         */
        SS1 = neon_rotl32(
            vaddq_u32(vaddq_u32(neon_rotl32(A, 12), E), tj_rotl), 7);

        /* SS2 = SS1 ⊕ (A <<< 12) */
        SS2 = veorq_u32(SS1, neon_rotl32(A, 12));

        /* 选择布尔函数 */
        if (j < 16) {
            TT1 = vaddq_u32(
                vaddq_u32(
                    vaddq_u32(neon_FF0(A, B, C), D), SS2), Wprime[j]);
            TT2 = vaddq_u32(
                vaddq_u32(
                    vaddq_u32(neon_GG0(E, F, G), H), SS1), W[j]);
        } else {
            TT1 = vaddq_u32(
                vaddq_u32(
                    vaddq_u32(neon_FF1(A, B, C), D), SS2), Wprime[j]);
            TT2 = vaddq_u32(
                vaddq_u32(
                    vaddq_u32(neon_GG1(E, F, G), H), SS1), W[j]);
        }

        /* 状态更新 (lane-wise 寄存器移动) */
        D = C;
        C = neon_rotl32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = neon_rotl32(F, 19);
        F = E;
        E = neon_P0(TT2);
    }

    /* V' = V ⊕ (A,B,C,D,E,F,G,H) */
    state[0] = veorq_u32(state[0], A);
    state[1] = veorq_u32(state[1], B);
    state[2] = veorq_u32(state[2], C);
    state[3] = veorq_u32(state[3], D);
    state[4] = veorq_u32(state[4], E);
    state[5] = veorq_u32(state[5], F);
    state[6] = veorq_u32(state[6], G);
    state[7] = veorq_u32(state[7], H);
}


/* ================================================================
 * 高层批量API: 一次计算4条消息的SM3摘要
 *
 * 步骤:
 *   1. 分别填充每条消息到512-bit块边界
 *   2. 将4条消息按块对齐分组
 *   3. 每轮取4个对齐的块，用NEON 4路并行处理
 *   4. 提取各条消息的最终摘要
 * ================================================================ */

/* 填充单条消息，返回填充后的总块数 */
static int sm3_pad_message(const uint8_t *msg, size_t len,
                           uint8_t *padded, size_t *padded_len,
                           uint64_t total_bits)
{
    size_t pad_bytes;
    int i;

    /* 复制消息 */
    memcpy(padded, msg, len);

    /* 添加 bit '1' */
    padded[len] = 0x80;

    /* 计算填充长度: 使得 (len*8 + padding*8) ≡ 448 (mod 512) */
    /* 即 (len + pad_len) ≡ 56 (mod 64) */
    if (len % 64 < 56) {
        pad_bytes = 64 - (len % 64);
    } else {
        pad_bytes = 128 - (len % 64);
    }

    *padded_len = len + pad_bytes;

    /* 清零填充区 (含长度区之前的部分) */
    for (i = (int)len + 1; i < (int)(*padded_len) - 8; i++) {
        padded[i] = 0;
    }

    /* 写入64-bit长度 (大端) */
    for (i = 0; i < 8; i++) {
        padded[*padded_len - 8 + i] =
            (uint8_t)(total_bits >> ((7 - i) * 8));
    }

    return (int)(*padded_len / 64);  /* 返回块数 */
}

void sm3_neon_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE])
{
    /*
     * 策略:
     *   - 先将每条消息填充好
     *   - 找到最大块数
     *   - 逐组(4条)并行处理
     *   - 对不足4条的情况用参考实现补齐
     */

    int i, g, round, max_blocks = 0;
    int num_blocks_arr[256];  /* 每条消息的填充块数 */
    uint8_t *padded_msgs[256];
    uint8_t *padded_buf = NULL;
    size_t total_padded = 0;
    uint32x4_t state[8];

    if (n <= 0) return;

    /* --- 阶段1: 填充所有消息 --- */
    for (i = 0; i < n; i++) {
        /* 计算填充后大小: 最多 len + 1 + 8 + 63 = len + 72 */
        size_t max_pad = lens[i] + 72;
        /* 对齐到64 */
        max_pad = ((max_pad + 63) / 64) * 64;
        total_padded += max_pad;
    }

    padded_buf = (uint8_t *)malloc(total_padded);
    if (!padded_buf) return;

    {
        uint8_t *ptr = padded_buf;
        for (i = 0; i < n; i++) {
            size_t plen;
            padded_msgs[i] = ptr;
            num_blocks_arr[i] = sm3_pad_message(
                msgs[i], lens[i], ptr, &plen, (uint64_t)lens[i] * 8);
            ptr += plen;
            if (num_blocks_arr[i] > max_blocks)
                max_blocks = num_blocks_arr[i];
        }
    }

    /* --- 阶段2: 初始化所有摘要状态为 IV --- */
    /* 使用二维数组存储每条消息的状态 */
    /* state_all[msg_idx][word_idx] */
    uint32_t (*state_all)[8] = (uint32_t(*)[8])malloc(n * 8 * sizeof(uint32_t));
    for (i = 0; i < n; i++) {
        memcpy(state_all[i], SM3_IV, sizeof(SM3_IV));
    }

    /* --- 阶段3: 按块组并行处理 --- */
    for (round = 0; round < max_blocks; round++) {
        /*
         * 每轮最多处理4条消息的同一序号块。
         * 如果某条消息在该轮次没有块了，跳过它。
         */
        int active_count = 0;
        int active_idx[4];       /* 活跃消息在 msgs 中的下标 */
        const uint8_t *blocks[4]; /* 指向各活跃消息当前块的指针 */

        for (i = 0; i < n && active_count < 4; i++) {
            if (round < num_blocks_arr[i]) {
                active_idx[active_count] = i;
                blocks[active_count] = padded_msgs[i] + round * 64;
                active_count++;
            }
        }

        if (active_count == 0) continue;

        if (active_count == 4) {
            /* ---- 4路满并行处理 ---- */
            uint32x4_t W[68], Wprime[64];

            /* 加载4条消息的状态 */
            for (int w = 0; w < 8; w++) {
                state[w] = vld1q_u32((uint32_t[]){
                    state_all[active_idx[0]][w],
                    state_all[active_idx[1]][w],
                    state_all[active_idx[2]][w],
                    state_all[active_idx[3]][w]
                });
            }

            /* 消息扩展 + 压缩 */
            neon_message_expand_4way(blocks, W, Wprime);
            neon_compress_4way(state, W, Wprime);

            /* 存回4条消息的状态 */
            uint32_t tmp[4];
            for (int w = 0; w < 8; w++) {
                vst1q_u32(tmp, state[w]);
                for (int k = 0; k < 4; k++) {
                    state_all[active_idx[k]][w] = tmp[k];
                }
            }
        } else {
            /* 不足4条: 回退到参考实现 (单条处理) */
            for (int k = 0; k < active_count; k++) {
                sm3_compress_ref(state_all[active_idx[k]], blocks[k]);
            }
        }
    }

    /* --- 阶段4: 提取摘要 --- */
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

#endif /* __aarch64__ */
