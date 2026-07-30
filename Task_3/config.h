#ifndef CONFIG_H
#define CONFIG_H

// --------------- 算法启用开关 ---------------
#define ENABLE_AES          1
#define ENABLE_SM4          1
#define ENABLE_GIFT128      1
#define ENABLE_TWINE128     1

// 每种算法可选的优化方法（按需打开，可以同时打开多种用于测试）
#define AES_USE_BASIC       1
#define AES_USE_TTABLE      1
#define AES_USE_SHUFFLE     1
#define AES_USE_AESNI       1

#define SM4_USE_BASIC       1
#define SM4_USE_TTABLE      1
#define SM4_USE_SHUFFLE     1

#define GIFT128_USE_BASIC   1
#define GIFT128_USE_BITSLICE 1

#define TWINE128_USE_BASIC  1
#define TWINE128_USE_BITSLICE 1

// --------------- 工作模式开关 ---------------
#define MODE_CTR            1
#define MODE_GCM            1
#define MODE_XTS            1

// --------------- 调试与测试配置 ---------------
#define BENCHMARK_BYTES     (1024 * 1024 * 16)   // 16 MB
#define BENCHMARK_REPEAT    20                   // 重复次数取平均

#endif // CONFIG_H
