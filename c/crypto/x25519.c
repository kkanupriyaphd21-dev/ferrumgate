#include "../include/crypto.h"
#include <stdint.h>
#include <string.h>

/*
 * Minimal X25519 Diffie-Hellman implementation.
 * Based on the public domain implementation by Daniel J. Bernstein.
 * Reference: https://cr.yp.to/ecdh.html
 */

typedef int64_t  gf[16];

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        int64_t c = o[i] >> 16;
        o[i] -= c * 65536;
        o[(i+1) % 16] += (i == 15) ? 38 * c : c;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t;
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        t    = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t* o, gf n) {
    gf m, t;
    memcpy(t, n, sizeof(gf));
    car25519(t); car25519(t); car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) m[i] = t[i] - 0xffff - ((m[i-1]>>16)&1);
        m[15] = t[15] - 0x7fff - ((m[14]>>16)&1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1-b);
    }
    for (int i = 0; i < 16; i++) {
        o[2*i]   = (uint8_t)(t[i] & 0xff);
        o[2*i+1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t* n) {
    for (int i = 0; i < 16; i++)
        o[i] = n[2*i] + ((int64_t)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, gf a, gf b) {
    for (int i=0;i<16;i++) o[i]=a[i]+b[i];
}
static void Z(gf o, gf a, gf b) {
    for (int i=0;i<16;i++) o[i]=a[i]-b[i];
}
static void M(gf o, gf a, gf b) {
    int64_t t[31]={0};
    for (int i=0;i<16;i++) for (int j=0;j<16;j++) t[i+j]+=a[i]*b[j];
    for (int i=0;i<15;i++) t[i]+=38*t[i+16];
    for (int i=0;i<16;i++) o[i]=t[i];
    car25519(o); car25519(o);
}
static void S(gf o, gf a) { M(o,a,a); }
static void inv25519(gf o, gf i) {
    gf c; memcpy(c,i,sizeof(gf));
    for (int a=253;a>=0;a--) {
        S(c,c);
        if (a!=2&&a!=4) M(c,c,i);
    }
    memcpy(o,c,sizeof(gf));
}

int fg_x25519(uint8_t* out,
               const uint8_t* scalar,
               const uint8_t* point) {
    gf x1,x2,x3,z2,z3,tmp0,tmp1;
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    unpack25519(x1, point);
    gf one = {1};
    memcpy(x3,x1,sizeof(gf));
    memset(z2,0,sizeof(gf)); z2[0]=0;
    memcpy(x2,one,sizeof(gf));
    memset(z3,0,sizeof(gf)); z3[0]=1;

    int swap=0;
    for (int pos=254;pos>=0;pos--) {
        int b = (int)((e[pos/8]>>(pos&7))&1);
        swap ^= b;
        sel25519(x2,x3,swap);
        sel25519(z2,z3,swap);
        swap=b;
        A(tmp0,x3,z3);  Z(tmp1,x3,z3);
        A(x3,x2,z2);    Z(z3,x2,z2);
        M(z2,tmp0,z3);  M(z3,x3,tmp1);
        A(x3,z2,z3);    Z(z2,z2,z3);
        S(x2,x3);       S(z3,z2);
        M(z2,z3,x1);    S(z3,tmp0);
        M(tmp0,tmp1,z3);M(z3,x3,z2);
        memcpy(x3,z2,sizeof(gf));
        memcpy(z2,tmp0,sizeof(gf));
        memcpy(tmp0,x2,sizeof(gf));
        memcpy(x2,x3,sizeof(gf));
        memcpy(x3,tmp0,sizeof(gf));
        memcpy(tmp0,z3,sizeof(gf));
        memcpy(z3,z2,sizeof(gf));
        memcpy(z2,tmp0,sizeof(gf));
    }
    sel25519(x2,x3,swap);
    sel25519(z2,z3,swap);

    inv25519(z2,z2);
    M(x2,x2,z2);
    pack25519(out, x2);
    return FG_OK;
}

/* Basepoint for X25519 */
static const uint8_t X25519_BASE[32] = {9};

int fg_x25519_keygen(uint8_t* private_key, uint8_t* public_key) {
    if (!private_key || !public_key) return FG_ERR_INVAL;
    int rc = fg_rand_bytes(private_key, 32);
    if (rc != FG_OK) return rc;
    private_key[0]  &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    return fg_x25519(public_key, private_key, X25519_BASE);
}
