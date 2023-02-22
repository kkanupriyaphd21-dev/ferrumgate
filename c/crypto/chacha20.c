#include "../include/crypto.h"
#include <stdint.h>
#include <string.h>

/* ChaCha20 stream cipher - IETF variant (RFC 8439) */

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))

#define QR(a,b,c,d) \
    a+=b; d^=a; d=ROTL32(d,16); \
    c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d, 8); \
    c+=d; b^=c; b=ROTL32(b, 7)

static void chacha20_block(const uint32_t* in, uint32_t* out) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        QR(x[ 0],x[ 4],x[ 8],x[12]);
        QR(x[ 1],x[ 5],x[ 9],x[13]);
        QR(x[ 2],x[ 6],x[10],x[14]);
        QR(x[ 3],x[ 7],x[11],x[15]);
        QR(x[ 0],x[ 5],x[10],x[15]);
        QR(x[ 1],x[ 6],x[11],x[12]);
        QR(x[ 2],x[ 7],x[ 8],x[13]);
        QR(x[ 3],x[ 4],x[ 9],x[14]);
    }

    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void load_le32(uint32_t* out, const uint8_t* in, int words) {
    for (int i = 0; i < words; i++) {
        out[i] = (uint32_t)in[i*4]       |
                 ((uint32_t)in[i*4+1]<<8) |
                 ((uint32_t)in[i*4+2]<<16)|
                 ((uint32_t)in[i*4+3]<<24);
    }
}

void fg_chacha20_xor(uint8_t* out, const uint8_t* in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter) {
    uint32_t state[16];
    /* constant: "expand 32-byte k" */
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    load_le32(state + 4,  key,       8);
    state[12] = counter;
    load_le32(state + 13, nonce,     3);

    uint8_t keystream[64];
    size_t  pos = 0;

    while (pos < len) {
        uint32_t block[16];
        chacha20_block(state, block);

        /* serialize block to bytes (LE) */
        for (int i = 0; i < 16; i++) {
            keystream[i*4+0] = (uint8_t)(block[i]      );
            keystream[i*4+1] = (uint8_t)(block[i] >>  8);
            keystream[i*4+2] = (uint8_t)(block[i] >> 16);
            keystream[i*4+3] = (uint8_t)(block[i] >> 24);
        }

        size_t n = len - pos;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; i++) out[pos+i] = in[pos+i] ^ keystream[i];

        pos += n;
        state[12]++;
    }
}

/* Poly1305 MAC */
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final_flag;
} Poly1305Ctx;

static void poly1305_init(Poly1305Ctx* ctx, const uint8_t key[32]) {
    /* r = key[0..15] with clamping */
    ctx->r[0] = (((uint32_t)key[ 0]     )|((uint32_t)key[ 1]<< 8)|((uint32_t)key[ 2]<<16)|((uint32_t)key[ 3]<<24)) & 0x3ffffff;
    ctx->r[1] = (((uint32_t)key[ 3]>> 2)|((uint32_t)key[ 4]<< 6)|((uint32_t)key[ 5]<<14)|((uint32_t)key[ 6]<<22)) & 0x3ffff03;
    ctx->r[2] = (((uint32_t)key[ 6]>> 4)|((uint32_t)key[ 7]<< 4)|((uint32_t)key[ 8]<<12)|((uint32_t)key[ 9]<<20)) & 0x3ffc0ff;
    ctx->r[3] = (((uint32_t)key[ 9]>> 6)|((uint32_t)key[10]<< 2)|((uint32_t)key[11]<<10)|((uint32_t)key[12]<<18)) & 0x3f03fff;
    ctx->r[4] = (((uint32_t)key[12]>> 8)|((uint32_t)key[13]    )|((uint32_t)key[14]<< 8)|((uint32_t)key[15]<<16)) & 0x00fffff;
    memset(ctx->h, 0, 20);
    /* pad = key[16..31] */
    for (int i = 0; i < 4; i++)
        ctx->pad[i] = ((uint32_t)key[16+i*4])|((uint32_t)key[16+i*4+1]<<8)|
                      ((uint32_t)key[16+i*4+2]<<16)|((uint32_t)key[16+i*4+3]<<24);
    ctx->leftover   = 0;
    ctx->final_flag = 0;
}

static void poly1305_blocks(Poly1305Ctx* ctx, const uint8_t* m, size_t bytes, uint32_t hibit) {
    uint32_t r0=ctx->r[0],r1=ctx->r[1],r2=ctx->r[2],r3=ctx->r[3],r4=ctx->r[4];
    uint32_t h0=ctx->h[0],h1=ctx->h[1],h2=ctx->h[2],h3=ctx->h[3],h4=ctx->h[4];
    uint32_t s1=r1*5,s2=r2*5,s3=r3*5,s4=r4*5;

    while (bytes >= 16) {
        uint32_t t0=((uint32_t)m[0])|((uint32_t)m[1]<<8)|((uint32_t)m[2]<<16)|((uint32_t)m[3]<<24);
        uint32_t t1=((uint32_t)m[4])|((uint32_t)m[5]<<8)|((uint32_t)m[6]<<16)|((uint32_t)m[7]<<24);
        uint32_t t2=((uint32_t)m[8])|((uint32_t)m[9]<<8)|((uint32_t)m[10]<<16)|((uint32_t)m[11]<<24);
        uint32_t t3=((uint32_t)m[12])|((uint32_t)m[13]<<8)|((uint32_t)m[14]<<16)|((uint32_t)m[15]<<24);

        h0+=(t0)&0x3ffffff; h1+=(((t0>>26)|(t1<<6)))&0x3ffffff;
        h2+=(((t1>>20)|(t2<<12)))&0x3ffffff; h3+=(((t2>>14)|(t3<<18)))&0x3ffffff;
        h4+=((t3>>8))&0x3ffffff; h4+=hibit;

        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;

        uint32_t c=(uint32_t)(d0>>26); h0=(uint32_t)d0&0x3ffffff;
        d1+=c; c=(uint32_t)(d1>>26); h1=(uint32_t)d1&0x3ffffff;
        d2+=c; c=(uint32_t)(d2>>26); h2=(uint32_t)d2&0x3ffffff;
        d3+=c; c=(uint32_t)(d3>>26); h3=(uint32_t)d3&0x3ffffff;
        d4+=c; c=(uint32_t)(d4>>26); h4=(uint32_t)d4&0x3ffffff;
        h0+=c*5; c=h0>>26; h0&=0x3ffffff; h1+=c;

        m+=16; bytes-=16;
    }
    ctx->h[0]=h0;ctx->h[1]=h1;ctx->h[2]=h2;ctx->h[3]=h3;ctx->h[4]=h4;
}

static void poly1305_finish(Poly1305Ctx* ctx, uint8_t mac[16]) {
    if (ctx->leftover) {
        ctx->buffer[ctx->leftover++] = 1;
        memset(ctx->buffer + ctx->leftover, 0, 16 - ctx->leftover);
        poly1305_blocks(ctx, ctx->buffer, 16, 0);
    }

    uint32_t h0=ctx->h[0],h1=ctx->h[1],h2=ctx->h[2],h3=ctx->h[3],h4=ctx->h[4];
    uint32_t c=h1>>26; h1&=0x3ffffff;
    h2+=c; c=h2>>26; h2&=0x3ffffff;
    h3+=c; c=h3>>26; h3&=0x3ffffff;
    h4+=c; c=h4>>26; h4&=0x3ffffff;
    h0+=c*5; c=h0>>26; h0&=0x3ffffff; h1+=c;

    uint32_t g0=h0+5,g1=h1+(g0>>26);g0&=0x3ffffff;
    uint32_t g2=h2+(g1>>26);g1&=0x3ffffff;
    uint32_t g3=h3+(g2>>26);g2&=0x3ffffff;
    uint32_t g4=h4+(g3>>26);g3&=0x3ffffff;
    uint32_t mask=(g4>>31)-1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask=~mask;
    h0=(h0&mask)|(g0); h1=(h1&mask)|(g1);
    h2=(h2&mask)|(g2); h3=(h3&mask)|(g3);

    uint64_t f0=(uint64_t)((h0     )|((uint64_t)h1<<26))+ctx->pad[0];
    uint64_t f1=(uint64_t)((h1>>6 )|((uint64_t)h2<<20))+(ctx->pad[1])+(f0>>32);
    uint64_t f2=(uint64_t)((h2>>12)|((uint64_t)h3<<14))+(ctx->pad[2])+(f1>>32);
    uint64_t f3=(uint64_t)((h3>>18)|((uint64_t)h4<<8)) +(ctx->pad[3])+(f2>>32);

    mac[0]=(uint8_t)f0;mac[1]=(uint8_t)(f0>>8);mac[2]=(uint8_t)(f0>>16);mac[3]=(uint8_t)(f0>>24);
    mac[4]=(uint8_t)f1;mac[5]=(uint8_t)(f1>>8);mac[6]=(uint8_t)(f1>>16);mac[7]=(uint8_t)(f1>>24);
    mac[8]=(uint8_t)f2;mac[9]=(uint8_t)(f2>>8);mac[10]=(uint8_t)(f2>>16);mac[11]=(uint8_t)(f2>>24);
    mac[12]=(uint8_t)f3;mac[13]=(uint8_t)(f3>>8);mac[14]=(uint8_t)(f3>>16);mac[15]=(uint8_t)(f3>>24);
}

int fg_chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t* plain, size_t plain_len,
                                  uint8_t* out, size_t* out_len,
                                  const uint8_t* aad, size_t aad_len) {
    if (*out_len < plain_len + 16) return FG_ERR_INVAL;

    /* generate Poly1305 key from first keystream block (counter=0) */
    uint8_t poly_key[64] = {0};
    fg_chacha20_xor(poly_key, poly_key, 64, key, nonce, 0);

    /* encrypt with counter=1 */
    fg_chacha20_xor(out, plain, plain_len, key, nonce, 1);

    /* compute MAC over AAD || ciphertext */
    Poly1305Ctx ctx;
    poly1305_init(&ctx, poly_key);

    uint8_t pad[16] = {0};
    if (aad && aad_len) {
        poly1305_blocks(&ctx, aad, aad_len & ~15UL, 1);
        if (aad_len & 15) {
            memcpy(pad, aad + (aad_len & ~15UL), aad_len & 15);
            poly1305_blocks(&ctx, pad, 16, 1);
        }
    }
    memset(pad, 0, 16);
    poly1305_blocks(&ctx, out, plain_len & ~15UL, 1);
    if (plain_len & 15) {
        memcpy(pad, out + (plain_len & ~15UL), plain_len & 15);
        poly1305_blocks(&ctx, pad, 16, 1);
    }

    /* lengths */
    uint8_t lens[16];
    uint64_t al = aad_len, ml = plain_len;
    for (int i=0;i<8;i++) { lens[i]=(uint8_t)(al>>(i*8)); lens[8+i]=(uint8_t)(ml>>(i*8)); }
    poly1305_blocks(&ctx, lens, 16, 1);

    poly1305_finish(&ctx, out + plain_len);
    *out_len = plain_len + 16;
    return FG_OK;
}
