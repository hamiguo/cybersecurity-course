#include "algo_if.h"
#include "common.h"
#include <string.h>

/* ========== SM4 S-box ========== */
static const uint8_t sm4_sbox[256] = {
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
    0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
    0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
    0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
    0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
    0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
    0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
    0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48
};

/* ========== Family Key FK & Constants CK ========== */
static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};
static const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

/* ========== T-table (encryption) ========== */
/*
 * SM4 T(x) = L(tau(x)), where tau applies S-box to each byte independently.
 * Since L is linear, T can be decomposed as:
 *   T(A) = TT[0][a0] ^ TT[1][a1] ^ TT[2][a2] ^ TT[3][a3]
 * where A = (a0<<24)|(a1<<16)|(a2<<8)|a3, and
 *   TT[0][b] = L(S(b), 0, 0, 0)
 *   TT[1][b] = L(0, S(b), 0, 0)
 *   TT[2][b] = L(0, 0, S(b), 0)
 *   TT[3][b] = L(0, 0, 0, S(b))
 */
static uint32_t TT[4][256];
static int tt_ready = 0;

/* L(B) = B xor (B<<<2) xor (B<<<10) xor (B<<<18) xor (B<<<24) */
static uint32_t sm4_L(uint32_t b) {
    return b ^ ROL32(b, 2) ^ ROL32(b, 10) ^ ROL32(b, 18) ^ ROL32(b, 24);
}

static void prepare_tables(void) {
    if (tt_ready) return;
    for (int i = 0; i < 256; i++) {
        uint32_t s = sm4_sbox[i];
        TT[0][i] = sm4_L(s << 24);
        TT[1][i] = sm4_L(s << 16);
        TT[2][i] = sm4_L(s <<  8);
        TT[3][i] = sm4_L(s);
    }
    tt_ready = 1;
}

/* Fast T computation using precomputed tables */
static uint32_t sm4_T_fast(uint32_t a) {
    return TT[0][(a >> 24) & 0xFF] ^
           TT[1][(a >> 16) & 0xFF] ^
           TT[2][(a >>  8) & 0xFF] ^
           TT[3][ a        & 0xFF];
}

/* ========== Key schedule (uses T' which also uses S-box + L') ========== */
/* L'(B) = B xor (B<<<13) xor (B<<<23) */
/* For key schedule we build a combined table too */
static uint32_t TTp[4][256];
static int ttp_ready = 0;

static uint32_t sm4_Lprime(uint32_t b) {
    return b ^ ROL32(b, 13) ^ ROL32(b, 23);
}

static void prepare_key_tables(void) {
    if (ttp_ready) return;
    for (int i = 0; i < 256; i++) {
        uint32_t s = sm4_sbox[i];
        TTp[0][i] = sm4_Lprime(s << 24);
        TTp[1][i] = sm4_Lprime(s << 16);
        TTp[2][i] = sm4_Lprime(s <<  8);
        TTp[3][i] = sm4_Lprime(s);
    }
    ttp_ready = 1;
}

/* Context */
typedef struct {
    uint32_t rk[32];
} sm4_ttable_ctx;

static void sm4_ttable_key_schedule(const uint8_t *key, void *ctx) {
    prepare_tables();
    prepare_key_tables();
    sm4_ttable_ctx *c = (sm4_ttable_ctx*)ctx;
    uint32_t K[36];

    for (int i = 0; i < 4; i++)
        K[i] = GETU32(key + 4 * i) ^ FK[i];

    for (int i = 0; i < 32; i++) {
        /* T'(x) using precomputed tables */
        uint32_t x = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        uint32_t tp = TTp[0][(x >> 24) & 0xFF] ^
                      TTp[1][(x >> 16) & 0xFF] ^
                      TTp[2][(x >>  8) & 0xFF] ^
                      TTp[3][ x        & 0xFF];
        K[i + 4] = K[i] ^ tp;
        c->rk[i] = K[i + 4];
    }
}

/* ========== SM4 encrypt using T-table ========== */
static void sm4_ttable_encrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    const sm4_ttable_ctx *c = (const sm4_ttable_ctx*)ctx;
    const uint32_t *rk = c->rk;

    uint32_t X0 = GETU32(in);
    uint32_t X1 = GETU32(in + 4);
    uint32_t X2 = GETU32(in + 8);
    uint32_t X3 = GETU32(in + 12);

    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ rk[i];
        uint32_t X4 = X0 ^ sm4_T_fast(t);
        X0 = X1; X1 = X2; X2 = X3; X3 = X4;
    }

    /* Reverse order */
    PUTU32(out,      X3);
    PUTU32(out + 4,  X2);
    PUTU32(out + 8,  X1);
    PUTU32(out + 12, X0);
}

static void sm4_ttable_decrypt(const uint8_t *in, uint8_t *out, const void *ctx) {
    const sm4_ttable_ctx *c = (const sm4_ttable_ctx*)ctx;
    const uint32_t *rk = c->rk;

    uint32_t X0 = GETU32(in);
    uint32_t X1 = GETU32(in + 4);
    uint32_t X2 = GETU32(in + 8);
    uint32_t X3 = GETU32(in + 12);

    /* Decryption uses reversed round key order */
    for (int i = 31; i >= 0; i--) {
        uint32_t t = X1 ^ X2 ^ X3 ^ rk[i];
        uint32_t X4 = X0 ^ sm4_T_fast(t);
        X0 = X1; X1 = X2; X2 = X3; X3 = X4;
    }

    PUTU32(out,      X3);
    PUTU32(out + 4,  X2);
    PUTU32(out + 8,  X1);
    PUTU32(out + 12, X0);
}

const block_cipher_t sm4_ttable_impl = {
    .name = "SM4-Ttable",
    .ctx_size = sizeof(sm4_ttable_ctx),
    .block_size = 16,
    .key_schedule = sm4_ttable_key_schedule,
    .encrypt = sm4_ttable_encrypt,
    .decrypt = sm4_ttable_decrypt
};
