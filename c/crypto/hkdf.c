#include "../include/crypto.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* HKDF (RFC 5869) using HMAC-SHA256 */

#define SHA256_DIGEST_LEN 32

/* forward-declare the HMAC function from hmac.c */
extern int fg_hmac_sha256(const uint8_t* key, size_t key_len,
                           const uint8_t* msg, size_t msg_len,
                           uint8_t out[32]);

int fg_hkdf_extract(const uint8_t* salt, size_t salt_len,
                     const uint8_t* ikm,  size_t ikm_len,
                     uint8_t prk[32]) {
    if (!prk) return FG_ERR_INVAL;

    static const uint8_t zero_salt[32] = {0};
    if (!salt || salt_len == 0) {
        salt     = zero_salt;
        salt_len = SHA256_DIGEST_LEN;
    }
    return fg_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int fg_hkdf_expand(const uint8_t prk[32],
                    const uint8_t* info, size_t info_len,
                    uint8_t* okm,        size_t okm_len) {
    if (!prk || !okm || okm_len == 0) return FG_ERR_INVAL;
    if (okm_len > 255 * SHA256_DIGEST_LEN) return FG_ERR_INVAL;

    uint8_t  t[32] = {0};
    uint8_t  counter = 0;
    size_t   written = 0;

    while (written < okm_len) {
        counter++;
        /* input = T(n-1) || info || counter */
        size_t tlen = (counter == 1) ? 0 : SHA256_DIGEST_LEN;
        size_t mlen = tlen + info_len + 1;
        uint8_t* msg = malloc(mlen);
        if (!msg) return FG_ERR_NOMEM;

        memcpy(msg,              t,    tlen);
        if (info && info_len) memcpy(msg + tlen, info, info_len);
        msg[tlen + info_len] = counter;

        fg_hmac_sha256(prk, SHA256_DIGEST_LEN, msg, mlen, t);
        free(msg);

        size_t n = okm_len - written;
        if (n > SHA256_DIGEST_LEN) n = SHA256_DIGEST_LEN;
        memcpy(okm + written, t, n);
        written += n;
    }
    return FG_OK;
}

/* Convenience: extract-then-expand in one shot */
int fg_hkdf(const uint8_t* salt, size_t salt_len,
             const uint8_t* ikm,  size_t ikm_len,
             const uint8_t* info, size_t info_len,
             uint8_t* okm,        size_t okm_len) {
    uint8_t prk[32];
    int rc = fg_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (rc != FG_OK) return rc;
    return fg_hkdf_expand(prk, info, info_len, okm, okm_len);
}
