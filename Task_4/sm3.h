/**
 * SM3 密码杂凑算法 — 优化实现
 * 
 * 支持架构：
 *   - 纯C参考实现 (可移植，无SIMD)
 *   - ARM64 NEON (4路并行)
 *   - x86 AVX2   (8路并行)
 *   - x86 AVX-512 (16路并行)
 *
 * 优化策略：混合使用SIMD寄存器和通用寄存器，
 *   利用SIMD实现多消息块并行处理，大幅提升吞吐量。
 */

#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 常量定义
 * ================================================================ */
#define SM3_BLOCK_SIZE      64    /* 消息块：512 bits = 64 bytes */
#define SM3_DIGEST_SIZE     32    /* 摘要：  256 bits = 32 bytes */
#define SM3_DIGEST_WORDS    8     /* 摘要字数 (32-bit words)   */

/* ================================================================
 * 通用 SM3 上下文（参考实现 & 单块处理）
 * ================================================================ */
typedef struct {
    uint32_t state[8];               /* 8个32-bit状态字 A~H     */
    uint64_t total_bits;             /* 已处理消息总比特数       */
    uint8_t  buffer[SM3_BLOCK_SIZE]; /* 未处理的输入缓冲         */
    size_t   buf_len;                /* buffer 中已缓存的字节数  */
} sm3_ctx_t;

/* ---- 参考实现 API ---- */
void sm3_ref_init(sm3_ctx_t *ctx);
void sm3_ref_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_ref_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

/* 便捷函数：一次性计算摘要 */
void sm3_ref_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);


/* ================================================================
 * 4路并行 NEON 上下文 (ARM64)
 * ================================================================ */
#ifdef __aarch64__
typedef struct {
    uint32_t state[4][8];            /* 4组状态，每组8字        */
    uint64_t total_bits[4];          /* 4条消息各自的比特数     */
    uint8_t  buffer[4][SM3_BLOCK_SIZE];
    size_t   buf_len[4];
    int      active;                 /* 活跃消息数 (0~4)       */
} sm3_neon_ctx_t;

void sm3_neon_init(sm3_neon_ctx_t *ctx);
void sm3_neon_update(sm3_neon_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_neon_final(sm3_neon_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

/* 批量计算：一次处理 n 条消息，n 应为4的倍数（不足会内部补齐） */
void sm3_neon_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE]);
#endif /* __aarch64__ */


/* ================================================================
 * 8路并行 AVX2 上下文 (x86_64)
 * ================================================================ */
#ifdef __x86_64__
typedef struct {
    uint32_t state[8][8];            /* 8组状态，每组8字        */
    uint64_t total_bits[8];
    uint8_t  buffer[8][SM3_BLOCK_SIZE];
    size_t   buf_len[8];
    int      active;
} sm3_avx2_ctx_t;

void sm3_avx2_init(sm3_avx2_ctx_t *ctx);
void sm3_avx2_update(sm3_avx2_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_avx2_final(sm3_avx2_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

void sm3_avx2_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE]);


/* ================================================================
 * 16路并行 AVX-512 上下文 (x86_64)
 * ================================================================ */
typedef struct {
    uint32_t state[16][8];
    uint64_t total_bits[16];
    uint8_t  buffer[16][SM3_BLOCK_SIZE];
    size_t   buf_len[16];
    int      active;
} sm3_avx512_ctx_t;

void sm3_avx512_init(sm3_avx512_ctx_t *ctx);
void sm3_avx512_update(sm3_avx512_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_avx512_final(sm3_avx512_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

void sm3_avx512_hash_batch(
    const uint8_t *msgs[], const size_t lens[],
    int n, uint8_t digests[][SM3_DIGEST_SIZE]);
#endif /* __x86_64__ */


/* ================================================================
 * 内部核心函数（跨文件可见）
 * ================================================================ */
void sm3_compress_ref(uint32_t state[8], const uint8_t block[64]);

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */
