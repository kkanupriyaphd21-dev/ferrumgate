#include "../include/crypto.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* BLAKE3 — simplified portable implementation (single-chunk, non-streaming).
 * For full streaming use the official blake3 C library. */

#define BLAKE3_OUT_LEN   32
#define BLAKE3_KEY_LEN   32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t MSG_PERMUTATION[16] = {
    2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8
};

#define ROTR32(v,n) (((v)>>(n))|((v)<<(32-(n))))

static void g(uint32_t* s, int a, int b, int c, int d, uint32_t x, uint32_t y) {
    s[a] = s[a]+s[b]+x; s[d] = ROTR32(s[d]^s[a],16);
    s[c] = s[c]+s[d];   s[b] = ROTR32(s[b]^s[c],12);
    s[a] = s[a]+s[b]+y; s[d] = ROTR32(s[d]^s[a], 8);
    s[c] = s[c]+s[d];   s[b] = ROTR32(s[b]^s[c], 7);
}

static void round(uint32_t* s, const uint32_t* m) {
    g(s,0,4, 8,12,m[0],m[1]); g(s,1,5, 9,13,m[2],m[3]);
    g(s,2,6,10,14,m[4],m[5]); g(s,3,7,11,15,m[6],m[7]);
    g(s,0,5,10,15,m[8],m[9]); g(s,1,6,11,12,m[10],m[11]);
    g(s,2,7, 8,13,m[12],m[13]);g(s,3,4,9,14,m[14],m[15]);
}

static void compress(const uint32_t* chaining, const uint32_t* block,
                      uint64_t counter, uint32_t blen, uint32_t flags,
                      uint32_t* out) {
    uint32_t s[16] = {
        chaining[0],chaining[1],chaining[2],chaining[3],
        chaining[4],chaining[5],chaining[6],chaining[7],
        IV[0],IV[1],IV[2],IV[3],
        (uint32_t)counter,(uint32_t)(counter>>32),blen,flags
    };
    uint32_t m[16]; memcpy(m, block, 64);

    for (int r = 0; r < 7; r++) {
        round(s, m);
        uint32_t tmp[16];
        for (int i=0;i<16;i++) tmp[MSG_PERMUTATION[i]]=m[i];
        memcpy(m, tmp, 64);
    }

    for (int i=0;i<8;i++) out[i] = s[i]^s[i+8];
    for (int i=0;i<8;i++) out[i+8] = chaining[i]^s[i+8];
}

int fg_blake3(const uint8_t* data, size_t len, uint8_t out[32]) {
    if (!data || !out) return FG_ERR_INVAL;

    uint32_t cv[8]; memcpy(cv, IV, 32);

    uint8_t block[64] = {0};
    size_t block_len = len < 64 ? len : 64;
    memcpy(block, data, block_len);

    uint32_t m[16];
    for (int i=0;i<16;i++) {
        m[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
               ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    }

    uint32_t result[16];
    compress(cv, m, 0, (uint32_t)block_len,
             0x01 | 0x02 | 0x04, /* CHUNK_START|CHUNK_END|ROOT */
             result);

    for (int i=0;i<8;i++) {
        out[i*4+0]=(uint8_t)result[i];       out[i*4+1]=(uint8_t)(result[i]>>8);
        out[i*4+2]=(uint8_t)(result[i]>>16); out[i*4+3]=(uint8_t)(result[i]>>24);
    }
    return FG_OK;
}
