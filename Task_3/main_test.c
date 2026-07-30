/**
 * main_test.c  —  测试与性能 Benchmark
 *
 * 功能:
 *   1. 验证所有算法/优化实现已知答案测试 (KAT)
 *   2. 测试 CTR / GCM / XTS 工作模式
 *   3. 对每种 (算法, 模式) 组合做性能基准测试
 */
#include "common.h"
#include "config.h"
#include "algo_if.h"
#include "modes.h"

/* ==================== 外部算法接口声明 ==================== */
#if AES_USE_BASIC
extern const block_cipher_t aes_basic_impl;
#endif
#if AES_USE_TTABLE
extern const block_cipher_t aes_ttable_impl;
#endif
#if AES_USE_SHUFFLE
extern const block_cipher_t aes_shuffle_impl;
#endif
#if AES_USE_AESNI
extern const block_cipher_t aes_ni_impl;
#endif

#if SM4_USE_BASIC
extern const block_cipher_t sm4_basic_impl;
#endif
#if SM4_USE_TTABLE
extern const block_cipher_t sm4_ttable_impl;
#endif
#if SM4_USE_SHUFFLE
extern const block_cipher_t sm4_shuffle_impl;
#endif

#if GIFT128_USE_BASIC
extern const block_cipher_t gift128_basic_impl;
#endif
#if GIFT128_USE_BITSLICE
extern const block_cipher_t gift128_bitslice_impl;
#endif

#if TWINE128_USE_BASIC
extern const block_cipher_t twine128_basic_impl;
#endif
#if TWINE128_USE_BITSLICE
extern const block_cipher_t twine128_bitslice_impl;
#endif

/* ==================== 测试向量 ==================== */
/* AES-128 (FIPS 197 Appendix C.1) */
static const uint8_t AES_KEY[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t AES_PT[16] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
};
static const uint8_t AES_CT[16] = {
    0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
    0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
};

/* SM4 (GB/T 32907-2016 Appendix A.1) */
static const uint8_t SM4_KEY[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};
static const uint8_t SM4_PT[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};
static const uint8_t SM4_CT[16] = {
    0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
    0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
};

/* GIFT-128 (参考实现 test_vectors.c, TV #3) */
static const uint8_t GIFT_KEY[16] = {
    0xd0,0xf5,0xc5,0x9a,0x77,0x00,0xd3,0xe7,
    0x99,0x02,0x8f,0xa9,0xf9,0x0a,0xd8,0x37
};
static const uint8_t GIFT_PT[16] = {
    0xe3,0x9c,0x14,0x1f,0xa5,0x7d,0xba,0x43,
    0xf0,0x8a,0x85,0xb6,0xa9,0x1f,0x86,0xc1
};
static const uint8_t GIFT_CT[16] = {
    0x13,0xed,0xe6,0x7c,0xbd,0xcc,0x3d,0xbf,
    0x40,0x0a,0x62,0xd6,0x97,0x72,0x65,0xea
};

/* TWINE-128 (自验证) */
static const uint8_t TWINE_KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t TWINE_PT[8] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
/* 期望: 使用 basic 实现的自测试 (编译后验证) */
/* 我们将在运行时产生加密结果并输出, 作为 "自测试" */

/* ==================== 辅助宏 ==================== */
#define TEST_ALGO(algo_if, key, pt, expected, test_name) do { \
    void *ctx = ALIGN_ALLOC((algo_if).ctx_size);             \
    (algo_if).key_schedule(key, ctx);                        \
    uint8_t ct[16], dt[16];                                  \
    (algo_if).encrypt(pt, ct, ctx);                          \
    (algo_if).decrypt(ct, dt, ctx);                          \
    int enc_ok = mem_cmp(ct, expected, 16) == 0;             \
    int dec_ok = mem_cmp(dt, pt, 16) == 0;                   \
    printf("  [%s] %-25s encrypt=%s decrypt=%s\n",           \
           test_name, (algo_if).name,                        \
           enc_ok ? "PASS" : "FAIL",                         \
           dec_ok ? "PASS" : "FAIL");                        \
    if (!enc_ok) { print_hex("    expected", expected, 16);  \
                   print_hex("    got     ", ct, 16); }       \
    ALIGN_FREE(ctx);                                         \
} while(0)

/* TWINE 特殊测试 (64-bit 分组) */
#define TEST_TWINE(algo_if, key, pt, test_name) do { \
    void *ctx = ALIGN_ALLOC((algo_if).ctx_size);     \
    (algo_if).key_schedule(key, ctx);                \
    uint8_t ct[8], dt[8];                            \
    (algo_if).encrypt(pt, ct, ctx);                  \
    (algo_if).decrypt(ct, dt, ctx);                  \
    int dec_ok = mem_cmp(dt, pt, 8) == 0;            \
    printf("  [%s] %-25s encrypt/decrypt=%s ct=",    \
           test_name, (algo_if).name,                 \
           dec_ok ? "PASS" : "FAIL");                \
    for (int i=0;i<8;i++) printf("%02x",ct[i]);      \
    printf("\n");                                     \
    ALIGN_FREE(ctx);                                  \
} while(0)

/* ==================== Bench ==================== */
static void bench_ecb(const block_cipher_t *iface, const uint8_t *key,
                      const char *label) {
    void *ctx = ALIGN_ALLOC(iface->ctx_size);
    iface->key_schedule(key, ctx);

    size_t n_blocks = BENCHMARK_BYTES / 16;
    uint8_t *buf = (uint8_t *)ALIGN_ALLOC(BENCHMARK_BYTES + 16);
    memset(buf, 0xAA, BENCHMARK_BYTES);

    uint64_t best = ~0ULL;
    /* Warm up */
    for (int rep = 0; rep < BENCHMARK_REPEAT / 2; rep++) {
        for (size_t i = 0; i < n_blocks; i++)
            iface->encrypt(buf + i * 16, buf + i * 16, ctx);
    }

    for (int rep = 0; rep < BENCHMARK_REPEAT; rep++) {
        uint64_t t0 = get_time_ns();
        for (size_t i = 0; i < n_blocks; i++)
            iface->encrypt(buf + i * 16, buf + i * 16, ctx);
        uint64_t t1 = get_time_ns();
        if (t1 - t0 < best) best = t1 - t0;
    }

    double mbps = (double)BENCHMARK_BYTES / (double)best * 1000.0;
    printf("  %-25s  %8.1f MB/s\n", label, mbps);

    ALIGN_FREE(buf);
    ALIGN_FREE(ctx);
}

/* ==================== 主程序 ==================== */
int main(void) {
    printf("=============================================\n");
    printf("  对称密码算法软件实现 - 测试与性能\n");
    printf("=============================================\n\n");

    /* ---- 第 1 部分: KAT 验证 ---- */
    printf("--- 已知答案测试 (KAT) ---\n\n");

#if ENABLE_AES
    printf("AES-128:\n");
#if AES_USE_BASIC
    TEST_ALGO(aes_basic_impl, AES_KEY, AES_PT, AES_CT, "AES");
#endif
#if AES_USE_TTABLE
    TEST_ALGO(aes_ttable_impl, AES_KEY, AES_PT, AES_CT, "AES");
#endif
#if AES_USE_SHUFFLE
    TEST_ALGO(aes_shuffle_impl, AES_KEY, AES_PT, AES_CT, "AES");
#endif
#if AES_USE_AESNI
    TEST_ALGO(aes_ni_impl, AES_KEY, AES_PT, AES_CT, "AES");
#endif
    printf("\n");
#endif

#if ENABLE_SM4
    printf("SM4:\n");
#if SM4_USE_BASIC
    TEST_ALGO(sm4_basic_impl, SM4_KEY, SM4_PT, SM4_CT, "SM4");
#endif
#if SM4_USE_TTABLE
    TEST_ALGO(sm4_ttable_impl, SM4_KEY, SM4_PT, SM4_CT, "SM4");
#endif
#if SM4_USE_SHUFFLE
    TEST_ALGO(sm4_shuffle_impl, SM4_KEY, SM4_PT, SM4_CT, "SM4");
#endif
    printf("\n");
#endif

#if ENABLE_GIFT128
    printf("GIFT-128:\n");
#if GIFT128_USE_BASIC
    TEST_ALGO(gift128_basic_impl, GIFT_KEY, GIFT_PT, GIFT_CT, "GIFT");
#endif
#if GIFT128_USE_BITSLICE
    TEST_ALGO(gift128_bitslice_impl, GIFT_KEY, GIFT_PT, GIFT_CT, "GIFT");
#endif
    printf("\n");
#endif

#if ENABLE_TWINE128
    printf("TWINE-128:\n");
    {
        uint8_t twine_ct_basic[8]={0}, twine_ct_bs[8]={0};
        int basic_ok=1, bs_ok=1;
#if TWINE128_USE_BASIC
        { void *ctx=ALIGN_ALLOC(twine128_basic_impl.ctx_size);
          twine128_basic_impl.key_schedule(TWINE_KEY,ctx);
          twine128_basic_impl.encrypt(TWINE_PT,twine_ct_basic,ctx);
          uint8_t tmp[8]; twine128_basic_impl.decrypt(twine_ct_basic,tmp,ctx);
          if(mem_cmp(tmp,TWINE_PT,8)!=0) basic_ok=0; ALIGN_FREE(ctx); }
#endif
#if TWINE128_USE_BITSLICE
        { void *ctx=ALIGN_ALLOC(twine128_bitslice_impl.ctx_size);
          twine128_bitslice_impl.key_schedule(TWINE_KEY,ctx);
          twine128_bitslice_impl.encrypt(TWINE_PT,twine_ct_bs,ctx);
          uint8_t tmp[8]; twine128_bitslice_impl.decrypt(twine_ct_bs,tmp,ctx);
          if(mem_cmp(tmp,TWINE_PT,8)!=0) bs_ok=0; ALIGN_FREE(ctx); }
#endif
#if TWINE128_USE_BASIC && TWINE128_USE_BITSLICE
        if(mem_cmp(twine_ct_basic,twine_ct_bs,8)!=0) { printf("  *** WARNING: basic vs bitslice mismatch! ***\n"); basic_ok=0; }
#endif
        printf("  [TWINE] TWINE128-basic         encrypt/decrypt=%s ct=", basic_ok?"PASS":"FAIL");
        for(int i=0;i<8;i++) printf("%02x",twine_ct_basic[i]);
        printf("\n");
#if TWINE128_USE_BITSLICE
        printf("  [TWINE] TWINE128-bitslice      encrypt/decrypt=%s ct=", bs_ok?"PASS":"FAIL");
        for(int i=0;i<8;i++) printf("%02x",twine_ct_bs[i]);
        printf("\n");
#endif
    }
    printf("\n");
#endif

    /* ---- 第 2 部分: 工作模式测试 ---- */
    printf("--- 工作模式功能测试 ---\n\n");

#if MODE_CTR
    {
        printf("CTR mode (AES):\n");
        ctr_ctx_t *ctr = ctr_init(&aes_ttable_impl, AES_KEY,
                                   (const uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 0);
        uint8_t msg[32] = "Hello, World! CTR test msg..";
        uint8_t ct[32], dt[32];
        ctr_crypt(ctr, msg, ct, 32);
        ctr_free(ctr);

        /* 重新加密 (独立 nonce) */
        ctr = ctr_init(&aes_ttable_impl, AES_KEY,
                        (const uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 0);
        ctr_crypt(ctr, ct, dt, 32);
        ctr_free(ctr);

        int ok = mem_cmp(msg, dt, 32) == 0;
        printf("  encrypt/decrypt roundtrip: %s\n\n", ok ? "PASS" : "FAIL");
    }
#endif

#if MODE_GCM
    {
        printf("GCM mode (AES):\n");
        gcm_ctx_t *gcm = gcm_init(&aes_ttable_impl, AES_KEY,
                                   (const uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 12);
        uint8_t aad[] = "AAD data";
        uint8_t msg[32] = "GCM encryption test message!";
        uint8_t ct[32], tag[16], dt[32];

        gcm_update_aad(gcm, aad, 8);
        gcm_encrypt(gcm, msg, ct, 32);
        gcm_finalize(gcm, tag, 16);
        gcm_free(gcm);

        /* 解密 */
        gcm = gcm_init(&aes_ttable_impl, AES_KEY,
                        (const uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b", 12);
        gcm_update_aad(gcm, aad, 8);
        gcm_decrypt(gcm, ct, dt, 32);
        uint8_t verify_tag[16];
        gcm_finalize(gcm, verify_tag, 16);
        gcm_free(gcm);

        int ok = (mem_cmp(msg, dt, 32) == 0) && (mem_cmp(tag, verify_tag, 16) == 0);
        printf("  encrypt+tag/decrypt+verify: %s\n\n", ok ? "PASS" : "FAIL");
    }
#endif

#if MODE_XTS
    {
        printf("XTS mode (AES):\n");
        uint8_t xts_key[32];
        memcpy(xts_key, AES_KEY, 16);
        memcpy(xts_key + 16, SM4_KEY, 16);  /* 两个不同密钥 */
        uint8_t tweak[16] = {0x0F,0x0E,0x0D,0x0C,0x0B,0x0A,0x09,0x08,
                              0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};

        xts_ctx_t *xts = xts_init(&aes_ttable_impl, xts_key, tweak);
        uint8_t data[48];
        memset(data, 0xCC, 48);
        uint8_t enc[48], dec[48];

        xts_encrypt(xts, data, enc, 48);
        xts_free(xts);

        xts = xts_init(&aes_ttable_impl, xts_key, tweak);
        xts_decrypt(xts, enc, dec, 48);
        xts_free(xts);

        int ok = mem_cmp(data, dec, 48) == 0;
        printf("  48 bytes encrypt/decrypt CTS: %s\n\n", ok ? "PASS" : "FAIL");
    }
#endif

    /* ---- 第 3 部分: 性能 Benchmark ---- */
    printf("--- 性能测试 (ECB, %d MB) ---\n\n", BENCHMARK_BYTES / (1024*1024));

#if ENABLE_AES
    printf("AES-128:\n");
#if AES_USE_BASIC
    bench_ecb(&aes_basic_impl, AES_KEY, "AES-basic");
#endif
#if AES_USE_TTABLE
    bench_ecb(&aes_ttable_impl, AES_KEY, "AES-T-table");
#endif
#if AES_USE_SHUFFLE
    bench_ecb(&aes_shuffle_impl, AES_KEY, "AES-SSSE3");
#endif
#if AES_USE_AESNI
    bench_ecb(&aes_ni_impl, AES_KEY, "AES-NI");
#endif
    printf("\n");
#endif

#if ENABLE_SM4
    printf("SM4:\n");
#if SM4_USE_BASIC
    bench_ecb(&sm4_basic_impl, SM4_KEY, "SM4-basic");
#endif
#if SM4_USE_TTABLE
    bench_ecb(&sm4_ttable_impl, SM4_KEY, "SM4-T-table");
#endif
#if SM4_USE_SHUFFLE
    bench_ecb(&sm4_shuffle_impl, SM4_KEY, "SM4-SSSE3");
#endif
    printf("\n");
#endif

#if ENABLE_GIFT128
    printf("GIFT-128:\n");
#if GIFT128_USE_BASIC
    bench_ecb(&gift128_basic_impl, GIFT_KEY, "GIFT128-basic");
#endif
#if GIFT128_USE_BITSLICE
    bench_ecb(&gift128_bitslice_impl, GIFT_KEY, "GIFT128-bitslice");
#endif
    printf("\n");
#endif

#if ENABLE_TWINE128
    printf("TWINE-128 (64-bit block):\n");
    {
        /* 特殊处理 TWINE (8 字节分组) */
        const block_cipher_t *iface = NULL;
#if TWINE128_USE_BASIC
        iface = &twine128_basic_impl;
#endif
        if (iface) {
            void *ctx = ALIGN_ALLOC(iface->ctx_size);
            iface->key_schedule(TWINE_KEY, ctx);

            size_t n_blocks = BENCHMARK_BYTES / 8;
            uint8_t *buf = (uint8_t *)ALIGN_ALLOC(BENCHMARK_BYTES + 8);
            memset(buf, 0xAA, BENCHMARK_BYTES);

            uint64_t best = ~0ULL;
            for (int rep = 0; rep < BENCHMARK_REPEAT / 2; rep++)
                for (size_t i = 0; i < n_blocks; i++)
                    iface->encrypt(buf + i * 8, buf + i * 8, ctx);

            for (int rep = 0; rep < BENCHMARK_REPEAT; rep++) {
                uint64_t t0 = get_time_ns();
                for (size_t i = 0; i < n_blocks; i++)
                    iface->encrypt(buf + i * 8, buf + i * 8, ctx);
                uint64_t t1 = get_time_ns();
                if (t1 - t0 < best) best = t1 - t0;
            }
            double mbps = (double)BENCHMARK_BYTES / (double)best * 1000.0;
            printf("  %-25s  %8.1f MB/s\n", iface->name, mbps);

            ALIGN_FREE(buf);
            ALIGN_FREE(ctx);
        }
#if TWINE128_USE_BITSLICE
        /* bitslice 版本 */
        iface = &twine128_bitslice_impl;
        {
            void *ctx = ALIGN_ALLOC(iface->ctx_size);
            iface->key_schedule(TWINE_KEY, ctx);
            size_t n_blocks = BENCHMARK_BYTES / 8;
            uint8_t *buf = (uint8_t *)ALIGN_ALLOC(BENCHMARK_BYTES + 8);
            memset(buf, 0xAA, BENCHMARK_BYTES);

            uint64_t best = ~0ULL;
            for (int rep = 0; rep < BENCHMARK_REPEAT / 2; rep++)
                for (size_t i = 0; i < n_blocks; i++)
                    iface->encrypt(buf + i * 8, buf + i * 8, ctx);

            for (int rep = 0; rep < BENCHMARK_REPEAT; rep++) {
                uint64_t t0 = get_time_ns();
                for (size_t i = 0; i < n_blocks; i++)
                    iface->encrypt(buf + i * 8, buf + i * 8, ctx);
                uint64_t t1 = get_time_ns();
                if (t1 - t0 < best) best = t1 - t0;
            }
            double mbps = (double)BENCHMARK_BYTES / (double)best * 1000.0;
            printf("  %-25s  %8.1f MB/s\n", iface->name, mbps);
            ALIGN_FREE(buf);
            ALIGN_FREE(ctx);
        }
#endif
    }
    printf("\n");
#endif

    printf("=============================================\n");
    printf("  测试完成\n");
    printf("=============================================\n");

    return 0;
}
