# SM3 密码杂凑算法 — SIMD优化实现

## 作业概述

本工程实现了国密SM3密码杂凑算法的SIMD寄存器与通用寄存器混合优化，
覆盖 **ARM64 NEON** 和 **x86 (AVX2/AVX512)** 两种架构指令集。

## 文件结构

```
├── sm3.h              # 公共头文件 (API声明、数据结构)
├── sm3_ref.c          # 纯C参考实现 (可移植，无SIMD)
├── sm3_neon.c         # ARM64 NEON优化 (4路并行, uint32x4_t)
├── sm3_avx2.c         # x86 AVX2优化 (8路并行, __m256i)
├── sm3_avx512.c       # x86 AVX-512优化 (16路并行, __m512i)
├── sm3_test.c         # 测试程序 (正确性验证 + 性能基准)
└── Makefile           # 构建系统
```

## 优化策略

### 核心思想：多消息块并行处理

传统的SM3实现逐块处理单条消息的每个512-bit块。
SIMD优化的关键思想是 **同时处理N条独立消息**，
每条消息占用SIMD向量的一个lane：

```
ARM NEON   (128-bit): 4条消息 同时处理  → 理论加速 ~4x
x86 AVX2   (256-bit): 8条消息 同时处理  → 理论加速 ~8x
x86 AVX-512(512-bit): 16条消息同时处理  → 理论加速 ~16x
```

### SIMD寄存器 vs 通用寄存器分工

| 用途 | 寄存器类型 | 说明 |
|------|-----------|------|
| A~H 状态变量 | SIMD (V/Q/YMM/ZMM) | 每条消息一个lane，8个向量并行计算 |
| W[0..67] 消息扩展 | SIMD | 递推公式全部在向量上完成 |
| W'[0..63] | SIMD | W[j] ⊕ W[j+4] 逐lane异或 |
| FF/GG 布尔函数 | SIMD | 三元逻辑/位选择指令 |
| SS1/SS2/TT1/TT2 | SIMD | 加法、异或、循环移位 |
| 轮计数器 j | 通用寄存器 (GPR) | 控制FF0↔FF1、GG0↔GG1切换 |
| 内存地址 | GPR | 数组索引、块指针 |
| 循环控制 | GPR | for循环、条件分支 |

### 各架构优化亮点

#### ARM64 NEON (`sm3_neon.c`)

```c
// GG1(X,Y,Z) = (X∧Y) ∨ (¬X∧Z)
// 利用NEON的 vbslq_u32 位选择指令，一条指令完成！
static inline uint32x4_t neon_GG1(uint32x4_t x, uint32x4_t y, uint32x4_t z) {
    return vbslq_u32(x, y, z);  // (mask & a) | (~mask & b)
}
```

- `vbslq_u32` 硬件指令直接实现 GG1，无额外AND/OR
- `vshlq_n_u32` + `vshrq_n_u32` + `vorrq_u32` 组合实现循环左移
- 4条消息并行：状态变量占8个Q寄存器，W数组在内存中

#### x86 AVX2 (`sm3_avx2.c`)

```c
// 循环左移: shift-left + shift-right + OR (无原生rotate)
static inline __m256i avx2_rotl32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
                           _mm256_srli_epi32(x, 32 - n));
}
```

- 8条消息并行，256-bit YMM寄存器
- `_mm256_add_epi32`, `_mm256_xor_si256` 等基础运算
- 适合Haswell及以上 (2013+)

#### x86 AVX-512 (`sm3_avx512.c`)

```c
// 原生循环左移 — 单指令！
#define avx512_rotl32(x, n)  _mm512_rol_epi32((x), (n))

// 三元逻辑: 一条指令实现任意3输入布尔函数
// FF1 majority: 
//   真值表 11101000b = 0xE8
static inline __m512i avx512_FF1(__m512i x, __m512i y, __m512i z) {
    return _mm512_ternarylogic_epi32(x, y, z, 0xE8);
}
```

AVX-512的三大优势：
1. **`_mm512_rol_epi32`** — 硬件循环左移，1周期延迟
2. **`_mm512_ternarylogic_epi32`** — 单指令完成任意3输入布尔函数
   - FF0/GG0: XOR3 = `0x96`
   - FF1(majority): `0xE8`
   - GG1(choose): `0xCA`
   - P0/P1: XOR3 = `0x96`
3. **32个ZMM寄存器** — 减少内存溢出

## 算法核心：SM3压缩函数

### 消息扩展 (Message Expansion)

```
W[0..15]  = 消息块的16个32-bit字 (大端)
W[16..67] = P1(W[j-16] ⊕ W[j-9] ⊕ ROTL(W[j-3],15))
          ⊕ ROTL(W[j-13],7) ⊕ W[j-6]
W'[0..63] = W[j] ⊕ W[j+4]
```

SIMD中，每个W[j]是N-lane向量，所有运算逐lane并行执行。

### 压缩函数 (Compression)

```
初始: A..H = V[0..7]  (256-bit状态)

for j = 0 to 63:
    SS1 = ROTL(ROTL(A,12) + E + ROTL(T_j, j), 7)
    SS2 = SS1 ⊕ ROTL(A,12)
    TT1 = FF(A,B,C) + D + SS2 + W'[j]
    TT2 = GG(E,F,G) + H + SS1 + W[j]
    // 状态更新
    D = C;  C = ROTL(B,9);  B = A;  A = TT1
    H = G;  G = ROTL(F,19); F = E;  E = P0(TT2)

V' = V ⊕ (A,B,C,D,E,F,G,H)
```

**关键优化**: ROTL(T_j, j) 是标量值，在所有lane中相同，
用 `vdupq_n_u32` / `_mm256_set1_epi32` / `_mm512_set1_epi32` 广播。

## 编译与运行

### ARM64 (Apple M1/M2/M3, 树莓派5, 鲲鹏等)

```bash
make neon
./sm3_test_neon
```

### x86_64 (Intel/AMD)

```bash
# AVX2 (Haswell 2013+)
make avx2
./sm3_test_avx2

# AVX-512 (Skylake-X 2017+, Ice Lake 2019+)
make avx512
./sm3_test_avx512

# 自动检测架构
make
./sm3_test_x86
```

### 手动编译

```bash
# ARM64 NEON
gcc -O3 -march=armv8-a+simd -D__aarch64__ -o test sm3_ref.c sm3_neon.c sm3_test.c -lm

# x86 AVX2
gcc -O3 -mavx2 -D__x86_64__ -o test sm3_ref.c sm3_avx2.c sm3_test.c -lm

# x86 AVX-512
gcc -O3 -mavx512f -mavx512vl -D__x86_64__ -o test sm3_ref.c sm3_avx512.c sm3_test.c -lm
```

## 测试向量

| 消息 | 预期摘要 (前16字节) |
|------|-------------------|
| "" (空) | `1ab21d8355cfa17f8e61194831e81a8f...` |
| "abc" | `66c7f0f462eeedd9d1f2d46bdc10e4e2...` |
| "abcd..." x16 | `debe9ff92275b8a138604889c18e5a4d...` |

## 性能预期

以1KB消息、批量处理64条为例：

| 实现 | 并行度 | 预期相对吞吐量 |
|------|--------|---------------|
| 参考C | 1x | 1.0x |
| ARM NEON | 4x | ~2.5-3.5x |
| AVX2 | 8x | ~4-6x |
| AVX-512 | 16x | ~6-10x |

实际加速比受内存带宽、缓存命中率、指令调度等因素影响。

## 技术要点总结

1. **混合寄存器策略**: SIMD处理数据并行部分(A~H状态、W数组、FF/GG)，
   通用寄存器处理控制流(轮计数、分支、地址)

2. **多路消息并行**: 不是加速单条消息，而是同时处理多条独立消息

3. **架构特定优化**:
   - ARM NEON: `vbslq_u32` 实现 GG1
   - AVX-512: `_mm512_ternarylogic_epi32` 实现所有3输入布尔函数
   - AVX-512: `_mm512_rol_epi32` 原生循环左移

4. **保持正确性**: 所有SIMD实现与参考实现交叉验证通过
