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
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}
static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static const uint32_t TJ[64] = {
    0x79CC4519,0xF3988A32,0xE7311464,0xCE6228C8,
    0x9CC45199,0x3988A332,0x7311464C,0xE6228C99,
    0xCC451993,0x988A3326,0x311464CE,0x6228C99C,
    0xC4519938,0x88A33271,0x11464CE6,0x228C99CC,
    0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C,
    0xD8A7A879,0xB14F50F3,0x629EA1E6,0xC53D43CC,
    0x8A7A8799,0x14F50F33,0x29EA1E67,0x53D43CCE,
    0xA7A8799D,0x4F50F33B,0x9EA1E676,0x3D43CCEC,
    0x7A8799D8,0xF50F33B1,0xEA1E6762,0xD43CCEC5,
    0xA8799D8A,0x50F33B15,0xA1E6762A,0x43CCEC55,
    0x8799D8AA,0x0F33B155,0x1E6762AB,0x3CCEC556,
    0x799D8AAC,0xF33B1559,0xE6762AB3,0xCCEC5566,
    0x99D8AACC,0x33B15599,0x6762AB33,0xCEC55667,
    0x9D8AACCE,0x3B15599D,0x762AB33A,0xEC556674,
    0xD8AACCEC,0xB15599D9,0x62AB33B2,0xC5566764,
    0x8AACCEC8,0x15599D91,0x2AB33B22,0x55667645
};

int main() {
    uint32_t V[8] = {
        0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
        0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
    };
    uint8_t block[64] = {0};
    block[0] = 0x80;

    uint32_t W[68], Wprime[64];
    for (int j = 0; j < 16; j++)
        W[j] = ((uint32_t)block[j*4]<<24)|((uint32_t)block[j*4+1]<<16)|((uint32_t)block[j*4+2]<<8)|block[j*4+3];
    for (int j = 16; j < 68; j++) {
        uint32_t t = W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15);
        W[j] = P1(t) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; j++)
        Wprime[j] = W[j] ^ W[j+4];

    uint32_t A=V[0], B=V[1], C=V[2], D=V[3], E=V[4], F=V[5], G=V[6], H=V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL32(ROTL32(A,12) + E + TJ[j], 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1, TT2;
        if (j < 16) {
            TT1 = FF0(A,B,C) + D + SS2 + Wprime[j];
            TT2 = GG0(E,F,G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A,B,C) + D + SS2 + Wprime[j];
            TT2 = GG1(E,F,G) + H + SS1 + W[j];
        }
        D=C; C=ROTL32(B,9); B=A; A=TT1;
        H=G; G=ROTL32(F,19); F=E; E=P0(TT2);

        /* 打印关键轮: 0,1,15,16,17,18,63 */
        if (j==0||j==1||j==15||j==16||j==17||j==18||j==63) {
            printf("Round %2d: A=%08X B=%08X C=%08X D=%08X E=%08X F=%08X G=%08X H=%08X\n",
                   j, A, B, C, D, E, F, G, H);
            if (j==16)
                printf("          (FF1/GG1 starting)\n");
        }
    }

    V[0]^=A; V[1]^=B; V[2]^=C; V[3]^=D;
    V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;

    printf("\nDigest: ");
    for (int i=0;i<8;i++) printf("%02x%02x%02x%02x",(V[i]>>24)&0xFF,(V[i]>>16)&0xFF,(V[i]>>8)&0xFF,V[i]&0xFF);
    printf("\n");
    return 0;
}
