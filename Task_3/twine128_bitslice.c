/**
 * twine128_bitslice.c  —  TWINE-128 SSSE3 优化实现
 *
 * 使用 SSSE3 (PSHUFB) 加速:
 *   - Block shuffle: PSHUFB 一键完成 16 nibble 置换
 *   - F 函数: 标量 S-box 查表 + SSE2 异或
 */
#include "algo_if.h"
#include "config.h"
#include <string.h>
#include <stdlib.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

static const uint8_t SBOX[16] = {
    0xC,0x0,0xF,0xA,0x2,0xB,0x9,0x5,
    0x8,0x3,0xD,0x7,0x1,0xE,0x6,0x4
};

static const uint8_t SHUFFLE[16]     = {5,0,1,4,7,12,3,8,13,6,9,2,15,10,11,14};
static const uint8_t SHUFFLE_INV[16] = {1,2,11,6,3,0,9,4,7,10,13,14,5,8,15,12};

static const uint8_t RCON[36] = {
    0x01,0x03,0x07,0x0f,0x1f,0x3f,0x3e,0x3d,0x3a,0x35,0x2a,0x15,
    0x2b,0x16,0x2c,0x19,0x33,0x26,0x0d,0x1b,0x37,0x2e,0x1d,0x3b,
    0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x09,0x13,0x27,0x0e,0x1c
};

/* PSHUFB masks — built once at load time */
static __m128i pshufb_fwd;  /* forward  shuffle: dst[i]=src[SHUFFLE_INV[i]] */
static __m128i pshufb_inv;  /* inverse  shuffle: dst[i]=src[SHUFFLE[i]]     */
static int     pshufb_init_done = 0;

static void init_pshufb(void) {
    uint8_t fwd[16], inv[16];
    for (int i = 0; i < 16; i++) {
        fwd[i] = SHUFFLE_INV[i];   /* PSHUFB: dst[i]=src[fwd[i]], and we need dst[SHUFFLE[h]]=src[h] */
        inv[i] = SHUFFLE[i];       /* PSHUFB: dst[i]=src[inv[i]], inverse of forward              */
    }
    pshufb_fwd = _mm_loadu_si128((const __m128i*)fwd);
    pshufb_inv = _mm_loadu_si128((const __m128i*)inv);
    pshufb_init_done = 1;
}

typedef struct { uint8_t rk[36][8]; } twine128_bitslice_ctx;

/* 密钥扩展: 与 basic 完全相同 */
static void twine128_key_schedule(const uint8_t *key, void *ctx) {
    twine128_bitslice_ctx *c = (twine128_bitslice_ctx *)ctx;
    uint8_t WK[32];
    for (int i=0;i<16;i++) { WK[2*i]=(key[i]>>4)&0xF; WK[2*i+1]=key[i]&0xF; }
    for (int r=0;r<36;r++) {
        c->rk[r][0]=WK[2];  c->rk[r][1]=WK[3];
        c->rk[r][2]=WK[12]; c->rk[r][3]=WK[15];
        c->rk[r][4]=WK[17]; c->rk[r][5]=WK[18];
        c->rk[r][6]=WK[28]; c->rk[r][7]=WK[31];
        if (r==35) break;
        uint8_t con=RCON[r];
        WK[1] ^=SBOX[WK[0]]; WK[4] ^=SBOX[WK[16]]; WK[23]^=SBOX[WK[30]];
        WK[7] ^=(con>>3)&7;  WK[19]^=con&7;
        uint8_t t0=WK[0],t1=WK[1],t2=WK[2],t3=WK[3];
        for(int g=0;g<7;g++) {WK[g*4]=WK[g*4+4];WK[g*4+1]=WK[g*4+5];WK[g*4+2]=WK[g*4+6];WK[g*4+3]=WK[g*4+7];}
        WK[28]=t0;WK[29]=t1;WK[30]=t2;WK[31]=t3;
    }
}

static void twine128_encrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    if (!pshufb_init_done) init_pshufb();
    const twine128_bitslice_ctx *c = (const twine128_bitslice_ctx *)ctx;
    uint8_t X[16];
    for(int i=0;i<8;i++){X[2*i]=(in[i]>>4)&0xF;X[2*i+1]=in[i]&0xF;}

    for(int r=0;r<35;r++) {
        for(int j=0;j<8;j++)
            X[2*j+1]^=SBOX[X[2*j]^c->rk[r][j]];
        __m128i s = _mm_loadu_si128((const __m128i*)X);
        s = _mm_shuffle_epi8(s, pshufb_fwd);
        _mm_storeu_si128((__m128i*)X, s);
    }
    for(int j=0;j<8;j++)
        X[2*j+1]^=SBOX[X[2*j]^c->rk[35][j]];

    for(int i=0;i<8;i++) out[i]=(X[2*i]<<4)|X[2*i+1];
}

static void twine128_decrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    if (!pshufb_init_done) init_pshufb();
    const twine128_bitslice_ctx *c = (const twine128_bitslice_ctx *)ctx;
    uint8_t X[16];
    for(int i=0;i<8;i++){X[2*i]=(in[i]>>4)&0xF;X[2*i+1]=in[i]&0xF;}

    for(int j=0;j<8;j++)
        X[2*j+1]^=SBOX[X[2*j]^c->rk[35][j]];

    for(int r=34;r>=0;r--) {
        __m128i s = _mm_loadu_si128((const __m128i*)X);
        s = _mm_shuffle_epi8(s, pshufb_inv);
        _mm_storeu_si128((__m128i*)X, s);
        for(int j=0;j<8;j++)
            X[2*j+1]^=SBOX[X[2*j]^c->rk[r][j]];
    }
    for(int i=0;i<8;i++) out[i]=(X[2*i]<<4)|X[2*i+1];
}

const block_cipher_t twine128_bitslice_impl = {
    .name="TWINE128-bitslice",.ctx_size=sizeof(twine128_bitslice_ctx),
    .block_size=8,.key_schedule=twine128_key_schedule,
    .encrypt=twine128_encrypt,.decrypt=twine128_decrypt
};
