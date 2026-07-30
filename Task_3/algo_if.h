#ifndef ALGO_IF_H
#define ALGO_IF_H

#include <stdint.h>
#include <stddef.h>

/**
 * 对称算法抽象接口
 * 每个算法实现需提供:
 *   - context 大小
 *   - 密钥扩展函数 (void key_schedule(const uint8_t *key, void *ctx))
 *   - 加密函数 (void encrypt(const uint8_t *in, uint8_t *out, const void *ctx))
 *   - 解密函数 (void decrypt(const uint8_t *in, uint8_t *out, const void *ctx))
 *
 * ctx 结构的前几个字节必须包含轮密钥或子密钥，且 ctx 需 16 字节对齐（若使用 SIMD）。
 */
typedef struct {
    const char *name;                     // 算法实现名称，如 "AES-NI"
    size_t ctx_size;                      // 上下文结构体大小
    size_t block_size;                    // 固定为 16
    void (*key_schedule)(const uint8_t *key, void *ctx);
    void (*encrypt)(const uint8_t *in, uint8_t *out, const void *ctx);
    void (*decrypt)(const uint8_t *in, uint8_t *out, const void *ctx);
} block_cipher_t;

/**
 * 工作模式上下文，可用于 CTR / GCM / XTS
 * 由上层模式实现持有，此处仅为接口示例。
 */
// 示例：CTR 所需的状态
typedef struct {
    uint8_t nonce[12];
    uint32_t counter;
    const block_cipher_t *cipher;
    uint8_t cipher_ctx[];                 // 柔性数组，实际大小在初始化时分配
} ctr_context_t;

#endif // ALGO_IF_H
