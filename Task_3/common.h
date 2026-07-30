#ifndef COMMON_H
#define COMMON_H

/* POSIX 函数需要此宏 (clock_gettime) */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
  #define _POSIX_C_SOURCE 199309L
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// --------------- 字节读取宏 ---------------
#define GETU32(p) ( ((uint32_t)(p)[0] << 24) | \
                    ((uint32_t)(p)[1] << 16) | \
                    ((uint32_t)(p)[2] <<  8) | \
                    ((uint32_t)(p)[3]) )

#define PUTU32(p, v) do { (p)[0] = (uint8_t)((v) >> 24); \
                          (p)[1] = (uint8_t)((v) >> 16); \
                          (p)[2] = (uint8_t)((v) >>  8); \
                          (p)[3] = (uint8_t)(v);        } while(0)

// 循环左移32位
#define ROL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// --------------- 计时器 ---------------
// 返回自开机以来的纳秒数（单调时钟）
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// --------------- 测试辅助函数 ---------------
// 打印十六进制（无换行）
static inline void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

// 比较两个缓冲区，返回 0 表示相等
static inline int mem_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 1;
    }
    return 0;
}

// --------------- 对齐分配辅助（SIMD 需要16字节对齐） ---------------
#ifdef _MSC_VER
  #define ALIGN_ALLOC(size) _aligned_malloc(size, 16)
  #define ALIGN_FREE(p)     _aligned_free(p)
#else
  #define ALIGN_ALLOC(size) aligned_alloc(16, ((size) + 15) & ~15)
  #define ALIGN_FREE(p)     free(p)
#endif

#endif // COMMON_H
