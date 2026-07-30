#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static inline uint32_t ROTL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}
static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}
static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static const uint32_t SM3_TJ_ROTL[64] = {
    0x79CC4519, 0xF3988A32, 0xE7311464, 0xCE6228C8,
    0x9CC45199, 0x3988A332, 0x7311464C, 0xE6228C99,
    0xCC451993, 0x988A3326, 0x311464CE, 0x6228C99C,
    0xC4519938, 0x88A33271, 0x11464CE6, 0x228C99CC,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E6, 0xC53D43CC,
    0x8A7A8799, 0x14F50F33, 0x29EA1E67, 0x53D43CCE,
    0xA7A8799D, 0x4F50F33B, 0x9EA1E676, 0x3D43CCEC,
    0x7A8799D8, 0xF50F33B1, 0xEA1E6762, 0xD43CCEC5,
    0xA8799D8A, 0x50F33B15, 0xA1E6762A, 0x43CCEC55,
    0x8799D8AA, 0x0F33B155, 0x1E6762AB, 0x3CCEC556,
    0x799D8AAC, 0xF33B1559, 0xE6762AB3, 0xCCEC5566,
    0x99D8AACC, 0x33B15599, 0x6762AB33, 0xCEC55667,
    0x9D8AACCE, 0x3B15599D, 0x762AB33A, 0xEC556674,
    0xD8AACCEC, 0xB15599D9, 0x62AB33B2, 0xC5566764,
    0x8AACCEC8, 0x15599D91, 0x2AB33B22, 0x55667645
};

int main() {
    uint32_t V[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    // Build padding block for empty message: [0x80, 0x00*55, 0x00*8]
    uint8_t block[64] = {0};
    block[0] = 0x80;

    // Message expansion
    uint32_t W[68], Wprime[64];
    for (int j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j*4]<<24) | ((uint32_t)block[j*4+1]<<16) |
               ((uint32_t)block[j*4+2]<<8) | block[j*4+3];
    }
    printf("W[0] = 0x%08X (expected 0x80000000)\n", W[0]);
    for (int j = 1; j < 16; j++)
        printf("W[%d] = 0x%08X\n", j, W[j]);

    for (int j = 16; j < 68; j++) {
        uint32_t t = W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15);
        W[j] = P1(t) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; j++)
        Wprime[j] = W[j] ^ W[j+4];

    // Print W[16..19] and Wprime[0..3]
    printf("\nW[16]=0x%08X W[17]=0x%08X W[18]=0x%08X W[19]=0x%08X\n",
           W[16], W[17], W[18], W[19]);
    printf("W'[0]=0x%08X W'[1]=0x%08X\n", Wprime[0], Wprime[1]);

    // Compress
    uint32_t A=V[0], B=V[1], C=V[2], D=V[3], E=V[4], F=V[5], G=V[6], H=V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + SM3_TJ_ROTL[j], 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1, TT2;

        if (j < 16) {
            TT1 = FF0(A,B,C) + D + SS2 + Wprime[j];
            TT2 = GG0(E,F,G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A,B,C) + D + SS2 + Wprime[j];
            TT2 = GG1(E,F,G) + H + SS1 + W[j];
        }

        if (j == 0) {
            printf("\n=== Round 0 ===\n");
            printf("SS1 = 0x%08X\n", SS1);
            printf("SS2 = 0x%08X\n", SS2);
            printf("TT1 = 0x%08X\n", TT1);
            printf("TT2 = 0x%08X\n", TT2);
        }

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    printf("\nAfter round 63:\n");
    printf("A=0x%08X B=0x%08X C=0x%08X D=0x%08X\n", A, B, C, D);
    printf("E=0x%08X F=0x%08X G=0x%08X H=0x%08X\n", E, F, G, H);

    // Expected after round 63 (from JS):
    printf("\nExpected after round 63:\n");
    printf("A=0x69320BEC B=0x1CDB13C6 C=0x99455B9F D=0xEB621C8F\n");
    printf("E=0x8BD1F87B F=0x3ECFC3DE G=0x9D5DDBA6 H=0xE079A465\n");

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;

    printf("\nFinal state:\n");
    for (int i = 0; i < 8; i++)
        printf("V[%d] = 0x%08X\n", i, V[i]);

    printf("\nDigest: ");
    for (int i = 0; i < 8; i++)
        printf("%02x%02x%02x%02x",
               (V[i]>>24)&0xFF, (V[i]>>16)&0xFF, (V[i]>>8)&0xFF, V[i]&0xFF);
    printf("\nExpected: 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b\n");

    return 0;
}
