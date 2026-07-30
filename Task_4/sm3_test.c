/**
 * sm3_test.c — SM3 正确性测试和性能基准
 *
 * 测试内容：
 *   1. 标准测试向量验证 (RFC/GB标准)
 *   2. 参考实现 vs SIMD优化实现交叉验证
 *   3. 性能基准测试
 */

#define _POSIX_C_SOURCE 199309L

#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * 标准测试向量 (GM/T 0004-2012 附录A)
 * ================================================================ */

/* 测试向量 1: 空消息 "" */
static const uint8_t tv1_msg[1] = {0};
static const char tv1_expected[] =
    "1ab21d8355cfa17f8e61194831e81a8f"
    "22bec8c728fefb747ed035eb5082aa2b";

/* 测试向量 2: "abc" */
static const uint8_t tv2_msg[] = "abc";
static const char tv2_expected[] =
    "66c7f0f462eeedd9d1f2d46bdc10e4e2"
    "4167c4875cf2f7a2297da02b8f4ba8e0";

/* 测试向量 3: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" (64 bytes) */
static const uint8_t tv3_msg[] =
    "abcdabcdabcdabcdabcdabcdabcdabcd"
    "abcdabcdabcdabcdabcdabcdabcdabcd";
static const char tv3_expected[] =
    "debe9ff92275b8a138604889c18e5a4d"
    "6fdb70e5387e5765293dcba39c0c5732";

/* 测试向量 4: 64-byte 全零 */
static const uint8_t tv4_msg[64] = {0};
static const char tv4_expected[] =
    "46b58571be41685c253194d20ec7f82b"
    "659cc8c6b753f26d4e9ec85bc91c231e";

/* 测试向量 5: "Hello, SM3!" (11 bytes) */
static const uint8_t tv5_msg[] = "Hello, SM3!";
static const char tv5_expected[] =
    "21b937fed61e685b8ac08c67fe9a3300"
    "437f2ca44547dea06e0cfe30219fdc4c";

/* ---- 向量表 ---- */
typedef struct {
    const char *name;
    const uint8_t *msg;
    size_t len;
    const char *expected;
} test_vector_t;

static const test_vector_t vectors[] = {
    {"空消息 \"\"",              tv1_msg, 0,     tv1_expected},
    {"\"abc\"",                  tv2_msg, 3,     tv2_expected},
    {"\"abcd...\" (64B)",        tv3_msg, 64,    tv3_expected},
    {"64-byte 全零",              tv4_msg, 64,    tv4_expected},
    {"\"Hello, SM3!\"",          tv5_msg, 11,    tv5_expected},
};
#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))

/* ================================================================
 * 辅助函数
 * ================================================================ */

/* 十六进制字符串 → 字节数组 */
static int hex2bin(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    if (len != 64) return -1;
    for (size_t i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* 比对两个摘要 */
static int digest_equal(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 32) == 0;
}

/* 打印摘要 */
static void print_digest(const char *label, const uint8_t *dgst) {
    printf("    %s: ", label);
    for (int i = 0; i < 32; i++) printf("%02x", dgst[i]);
    printf("\n");
}

/* 高精度计时 (微秒) */
static double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* ================================================================
 * 测试: 标准向量 (单条消息)
 * ================================================================ */
static int test_vectors(void) {
    printf("=== 标准测试向量 (GM/T 0004-2012) ===\n");
    int pass = 1;

    for (size_t i = 0; i < NUM_VECTORS; i++) {
        uint8_t expected[32], result[32];
        hex2bin(vectors[i].expected, expected);

        sm3_ref_hash(vectors[i].msg, vectors[i].len, result);

        int ok = digest_equal(result, expected);
        printf("  [%s] %s: %s\n",
               ok ? "PASS" : "FAIL",
               vectors[i].name,
               ok ? "OK" : "MISMATCH");

        if (!ok) {
            print_digest("Expected", expected);
            print_digest("Got     ", result);
            pass = 0;
        }
    }
    printf("  结果: %d/%zu 通过\n\n", pass ? (int)NUM_VECTORS : 0, NUM_VECTORS);
    return pass;
}

/* ================================================================
 * 测试: 批量交叉验证 (参考实现 vs SIMD)
 * ================================================================ */
static int test_batch_crosscheck(void) {
    printf("=== 批量交叉验证 (ref vs SIMD) ===\n");
    int pass = 1;

    /* 构造 32 条不同长度的消息 */
    #define NUM_MSGS 32
    uint8_t *msg_bufs[NUM_MSGS];
    size_t lens[NUM_MSGS];

    for (int i = 0; i < NUM_MSGS; i++) {
        lens[i] = (size_t)(i * 3 + 1);  /* 1, 4, 7, ..., 94 字节 */
        msg_bufs[i] = (uint8_t *)malloc(lens[i]);
        for (size_t j = 0; j < lens[i]; j++)
            msg_bufs[i][j] = (uint8_t)(i + j);
    }

    /* 参考实现: 逐条计算 */
    uint8_t ref_digests[NUM_MSGS][32];
    for (int i = 0; i < NUM_MSGS; i++)
        sm3_ref_hash(msg_bufs[i], lens[i], ref_digests[i]);

    /* ---- ARM NEON 4路并行测试 ---- */
#ifdef __aarch64__
    {
        printf("  [NEON 4-way batch] ...\n");
        uint8_t neon_digests[NUM_MSGS][32];
        sm3_neon_hash_batch((const uint8_t **)msg_bufs, lens, NUM_MSGS, neon_digests);

        for (int i = 0; i < NUM_MSGS; i++) {
            if (!digest_equal(ref_digests[i], neon_digests[i])) {
                printf("    FAIL: message %d (len=%zu)\n", i, lens[i]);
                print_digest("      Expected", ref_digests[i]);
                print_digest("      NEON    ", neon_digests[i]);
                pass = 0;
            }
        }
        if (pass) printf("    PASS: all %d messages match\n", NUM_MSGS);
    }
#endif

    /* ---- x86 AVX2 8路并行测试 ---- */
#ifdef __x86_64__
    {
        printf("  [AVX2 8-way batch] ...\n");
        uint8_t avx2_digests[NUM_MSGS][32];
        sm3_avx2_hash_batch((const uint8_t **)msg_bufs, lens, NUM_MSGS, avx2_digests);

        int ok = 1;
        for (int i = 0; i < NUM_MSGS; i++) {
            if (!digest_equal(ref_digests[i], avx2_digests[i])) {
                printf("    FAIL: message %d (len=%zu)\n", i, lens[i]);
                print_digest("      Expected", ref_digests[i]);
                print_digest("      AVX2    ", avx2_digests[i]);
                ok = 0;
            }
        }
        if (ok) printf("    PASS: all %d messages match\n", NUM_MSGS);
        else pass = 0;

        /* ---- AVX-512 16路并行测试 ---- */
#ifdef __AVX512F__
        printf("  [AVX-512 16-way batch] ...\n");
        uint8_t avx512_digests[NUM_MSGS][32];
        sm3_avx512_hash_batch((const uint8_t **)msg_bufs, lens, NUM_MSGS, avx512_digests);

        ok = 1;
        for (int i = 0; i < NUM_MSGS; i++) {
            if (!digest_equal(ref_digests[i], avx512_digests[i])) {
                printf("    FAIL: message %d (len=%zu)\n", i, lens[i]);
                ok = 0;
            }
        }
        if (ok) printf("    PASS: all %d messages match\n", NUM_MSGS);
        else pass = 0;
#else
        printf("  [AVX-512 16-way batch] ... SKIP (no AVX-512 support)\n");
#endif
    }
#endif

    /* 清理 */
    for (int i = 0; i < NUM_MSGS; i++) free(msg_bufs[i]);

    printf("  结果: %s\n\n", pass ? "PASS" : "FAIL");
    return pass;
}

/* ================================================================
 * 测试: 性能基准
 * ================================================================ */
static void test_benchmark(void) {
    printf("=== 性能基准测试 ===\n");

    #define BENCH_MSGS 16
    #define BENCH_LEN  1024
    #define ITERATIONS 50000

    uint8_t *msg_bufs[BENCH_MSGS];
    size_t lens[BENCH_MSGS];

    for (int i = 0; i < BENCH_MSGS; i++) {
        msg_bufs[i] = (uint8_t *)malloc(BENCH_LEN);
        memset(msg_bufs[i], (uint8_t)i, BENCH_LEN);
        lens[i] = BENCH_LEN;
    }

    const uint8_t **msgs = (const uint8_t **)msg_bufs;

    /* 参考实现 */
    {
        uint8_t digests[BENCH_MSGS][32];
        double start = get_time_us();
        for (int iter = 0; iter < ITERATIONS; iter++) {
            for (int i = 0; i < BENCH_MSGS; i++)
                sm3_ref_hash(msgs[i], lens[i], digests[i]);
        }
        double elapsed = get_time_us() - start;
        double total_mb = (double)BENCH_MSGS * BENCH_LEN * ITERATIONS / (1024.0 * 1024.0);
        double mbps = total_mb / (elapsed / 1e6);

        printf("  Reference (1-way):  %8.2f ms,  %8.2f MB/s\n",
               elapsed / 1000.0, mbps);
    }

    /* ARM NEON */
#ifdef __aarch64__
    {
        uint8_t digests[BENCH_MSGS][32];
        double start = get_time_us();
        for (int iter = 0; iter < ITERATIONS; iter++) {
            sm3_neon_hash_batch(msgs, lens, BENCH_MSGS, digests);
        }
        double elapsed = get_time_us() - start;
        double total_mb = (double)BENCH_MSGS * BENCH_LEN * ITERATIONS / (1024.0 * 1024.0);
        double mbps = total_mb / (elapsed / 1e6);

        printf("  NEON   (4-way):    %8.2f ms,  %8.2f MB/s\n",
               elapsed / 1000.0, mbps);
    }
#endif

    /* AVX2 */
#ifdef __x86_64__
    {
        uint8_t digests[BENCH_MSGS][32];
        double start = get_time_us();
        for (int iter = 0; iter < ITERATIONS; iter++) {
            sm3_avx2_hash_batch(msgs, lens, BENCH_MSGS, digests);
        }
        double elapsed = get_time_us() - start;
        double total_mb = (double)BENCH_MSGS * BENCH_LEN * ITERATIONS / (1024.0 * 1024.0);
        double mbps = total_mb / (elapsed / 1e6);

        printf("  AVX2   (8-way):    %8.2f ms,  %8.2f MB/s\n",
               elapsed / 1000.0, mbps);
    }

    /* AVX-512 */
#ifdef __AVX512F__
    {
        uint8_t digests[BENCH_MSGS][32];
        double start = get_time_us();
        for (int iter = 0; iter < ITERATIONS; iter++) {
            sm3_avx512_hash_batch(msgs, lens, BENCH_MSGS, digests);
        }
        double elapsed = get_time_us() - start;
        double total_mb = (double)BENCH_MSGS * BENCH_LEN * ITERATIONS / (1024.0 * 1024.0);
        double mbps = total_mb / (elapsed / 1e6);

        printf("  AVX512 (16-way):   %8.2f ms,  %8.2f MB/s\n",
               elapsed / 1000.0, mbps);
    }
#else
    printf("  AVX512 (16-way):   SKIP (no AVX-512 support)\n");
#endif
#endif

    /* 清理 */
    for (int i = 0; i < BENCH_MSGS; i++) free(msg_bufs[i]);

    printf("\n");
}

/* ================================================================
 * 主函数
 * ================================================================ */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("============================================\n");
    printf("  SM3 密码杂凑算法 — 正确性 & 性能测试\n");
    printf("============================================\n\n");

    int all_pass = 1;

    /* 1. 标准测试向量 */
    all_pass &= test_vectors();

    /* 2. 批量交叉验证 */
    all_pass &= test_batch_crosscheck();

    /* 3. 性能基准 */
    test_benchmark();

    /* 总结 */
    printf("============================================\n");
    printf("  %s\n", all_pass ? "全部测试通过! ✓" : "存在失败测试! ✗");
    printf("============================================\n");

    return all_pass ? 0 : 1;
}
