#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FG_KEY_LEN_AES128  16
#define FG_KEY_LEN_AES256  32
#define FG_KEY_LEN_CHACHA  32
#define FG_NONCE_LEN       12
#define FG_TAG_LEN         16
#define FG_HMAC_SHA256_LEN 32

typedef enum {
    FG_CIPHER_AES_128_GCM    = 0,
    FG_CIPHER_AES_256_GCM    = 1,
    FG_CIPHER_CHACHA20_POLY  = 2,
} FgCipherSuite;

typedef struct {
    FgCipherSuite suite;
    uint8_t       key[32];
    uint8_t       nonce[FG_NONCE_LEN];
    uint64_t      seq;
} FgCryptoKey;

int fg_crypto_keygen(FgCryptoKey* key, FgCipherSuite suite);
int fg_crypto_nonce_advance(FgCryptoKey* key);

int fg_encrypt(const FgCryptoKey* key,
               const uint8_t* plain,  size_t plain_len,
               uint8_t*       cipher, size_t* cipher_len,
               const uint8_t* aad,    size_t  aad_len);

int fg_decrypt(const FgCryptoKey* key,
               const uint8_t* cipher, size_t cipher_len,
               uint8_t*       plain,  size_t* plain_len,
               const uint8_t* aad,    size_t  aad_len);

int fg_hmac_sha256(const uint8_t* key,  size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t out[FG_HMAC_SHA256_LEN]);

int fg_hkdf_expand(const uint8_t* prk,   size_t prk_len,
                   const uint8_t* info,  size_t info_len,
                   uint8_t*       okm,   size_t okm_len);

int fg_rand_bytes(uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif
