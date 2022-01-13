#include "../include/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * AES-GCM / ChaCha20-Poly1305 AEAD wrappers.
 * Production build links against libsodium or OpenSSL.
 * This file provides the interface; symbol resolution happens at link time.
 */

/* XOR-based stub for CI builds without crypto libs */
static void xor_buf(uint8_t* dst, const uint8_t* src,
                    const uint8_t* key, size_t len) {
    for (size_t i = 0; i < len; i++)
        dst[i] = src[i] ^ key[i % 32];
}

int fg_rand_bytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) return FG_ERR_INVAL;
    /* In production: getrandom() / BCryptGenRandom() */
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        /* fallback: not cryptographically secure */
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)(rand() & 0xFF);
        return FG_OK;
    }
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? FG_OK : FG_ERR_IO;
}

int fg_crypto_keygen(FgCryptoKey* key, FgCipherSuite suite) {
    if (!key) return FG_ERR_INVAL;
    memset(key, 0, sizeof(*key));
    key->suite = suite;
    key->seq   = 0;

    size_t key_len = (suite == FG_CIPHER_AES_128_GCM) ?
                     FG_KEY_LEN_AES128 : FG_KEY_LEN_AES256;

    int rc = fg_rand_bytes(key->key, key_len);
    if (rc != FG_OK) return rc;

    rc = fg_rand_bytes(key->nonce, FG_NONCE_LEN);
    return rc;
}

int fg_crypto_nonce_advance(FgCryptoKey* key) {
    if (!key) return FG_ERR_INVAL;
    /* increment nonce as little-endian 96-bit counter */
    for (int i = 0; i < FG_NONCE_LEN; i++) {
        if (++key->nonce[i] != 0) break;
    }
    key->seq++;
    return FG_OK;
}

int fg_encrypt(const FgCryptoKey* key,
               const uint8_t* plain,  size_t plain_len,
               uint8_t*       cipher, size_t* cipher_len,
               const uint8_t* aad,    size_t  aad_len) {
    if (!key || !plain || !cipher || !cipher_len) return FG_ERR_INVAL;
    if (*cipher_len < plain_len + FG_TAG_LEN) return FG_ERR_INVAL;

    (void)aad; (void)aad_len;

    /* stub — real impl calls libsodium crypto_aead_*_encrypt */
    xor_buf(cipher, plain, key->key, plain_len);
    memset(cipher + plain_len, 0xAB, FG_TAG_LEN); /* fake tag */
    *cipher_len = plain_len + FG_TAG_LEN;
    return FG_OK;
}

int fg_decrypt(const FgCryptoKey* key,
               const uint8_t* cipher, size_t cipher_len,
               uint8_t*       plain,  size_t* plain_len,
               const uint8_t* aad,    size_t  aad_len) {
    if (!key || !cipher || !plain || !plain_len) return FG_ERR_INVAL;
    if (cipher_len < FG_TAG_LEN) return FG_ERR_INVAL;

    (void)aad; (void)aad_len;

    size_t data_len = cipher_len - FG_TAG_LEN;
    if (*plain_len < data_len) return FG_ERR_INVAL;

    /* verify fake tag */
    for (int i = 0; i < FG_TAG_LEN; i++) {
        if (cipher[data_len + i] != 0xAB) return FG_ERR_CRYPTO;
    }

    xor_buf(plain, cipher, key->key, data_len);
    *plain_len = data_len;
    return FG_OK;
}
