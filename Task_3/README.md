# 对称密码算法的软件实现

本项目实现了四种对称密码算法的多种优化方法，以及三种工作模式。

## 算法与实现

| 算法 | 分组大小 | 实现方法 | 指令集 |
|------|---------|---------|--------|
| AES-128 | 128-bit | basic, T-table, SSSE3 shuffle, AES-NI | SSE2, SSSE3, AES-NI |
| SM4 | 128-bit | basic, T-table, SSSE3 shuffle | SSE2, SSSE3 |
| GIFT-128 | 128-bit | basic, bitslice | SSE2 |
| TWINE-128 | 64-bit | basic, bitslice (PSHUFB) | SSSE3 |

## 工作模式
- **CTR** — Counter mode (NIST SP 800-38A)
- **GCM** — Galois/Counter Mode (NIST SP 800-38D)
- **XTS** — XEX-based tweaked-codebook with ciphertext stealing (IEEE 1619)

## 编译与运行

```bash
# 需要 x86_64 CPU (支持 SSSE3 和 AES-NI)
make          # 编译
make run      # 编译并运行
./crypto_test # 直接运行
```

## 文件结构

- `algo_if.h` — 统一的 block_cipher_t 接口定义
- `common.h/c` — 辅助工具（字节操作、计时器）
- `config.h` — 编译开关
- `modes.h/c` — CTR / GCM / XTS 工作模式实现
- `main_test.c` — 测试向量验证 + 性能基准测试
- `aes_*.c` — AES-128 四种实现
- `sm4_*.c` — SM4 三种实现
- `gift128_*.c` — GIFT-128 两种实现
- `twine128_*.c` — TWINE-128 两种实现

## 测试向量

所有算法均使用标准测试向量验证：
- AES: FIPS 197 Appendix C.1
- SM4: GB/T 32907-2016 Appendix A.1
- GIFT-128: GIFT-COFB NIST LWC test vectors
- TWINE-128: NEC 论文规范自测试
