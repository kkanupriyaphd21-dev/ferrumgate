#include "../include/tunnel.h"
#include "../include/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

/* Noise_XX handshake pattern (simplified) */

#define HANDSHAKE_VERSION 2
#define HANDSHAKE_MAGIC   0x46475348u  /* "FGSH" */

typedef enum {
    HS_INIT_SEND    = 0,
    HS_RESP_RECV    = 1,
    HS_FINAL_SEND   = 2,
    HS_COMPLETE     = 3,
    HS_FAILED       = 4,
} HandshakeState;

typedef struct {
    HandshakeState  state;
    uint8_t  local_priv[32];
    uint8_t  local_pub[32];
    uint8_t  remote_pub[32];
    uint8_t  ephemeral_priv[32];
    uint8_t  ephemeral_pub[32];
    uint8_t  chaining_key[32];
    uint8_t  hash[32];
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint64_t nonce;
    uint32_t session_id;
    time_t   created_at;
} FgHandshake;

FgHandshake* fg_handshake_new(const uint8_t local_priv[32],
                               const uint8_t local_pub[32]) {
    FgHandshake* hs = calloc(1, sizeof(FgHandshake));
    if (!hs) return NULL;
    memcpy(hs->local_priv, local_priv, 32);
    memcpy(hs->local_pub,  local_pub,  32);
    hs->state      = HS_INIT_SEND;
    hs->created_at = time(NULL);
    /* initialize chaining key from protocol name hash */
    const uint8_t proto_name[] = "Noise_XX_25519_ChaChaPoly_SHA256";
    fg_hmac_sha256(NULL, 0, proto_name, sizeof(proto_name)-1, hs->chaining_key);
    memcpy(hs->hash, hs->chaining_key, 32);
    return hs;
}

int fg_handshake_initiate(FgHandshake* hs, uint8_t* out, size_t* out_len) {
    if (!hs || hs->state != HS_INIT_SEND) return FG_ERR_INVAL;
    if (*out_len < 64) return FG_ERR_INVAL;

    /* generate ephemeral keypair */
    fg_x25519_keygen(hs->ephemeral_priv, hs->ephemeral_pub);

    /* message: version(1) | magic(4) | session_id(4) | ephemeral_pub(32) | static_pub(32) */
    uint8_t* p = out;
    *p++ = HANDSHAKE_VERSION;
    uint32_t magic = HANDSHAKE_MAGIC;
    memcpy(p, &magic, 4); p += 4;
    fg_rand_bytes(p, 4); /* random session_id */
    memcpy(&hs->session_id, p, 4); p += 4;
    memcpy(p, hs->ephemeral_pub, 32); p += 32;
    memcpy(p, hs->local_pub, 32);     p += 32;

    *out_len = (size_t)(p - out);
    hs->state = HS_RESP_RECV;
    return FG_OK;
}

int fg_handshake_respond(FgHandshake* hs,
                          const uint8_t* msg, size_t msg_len,
                          uint8_t* out, size_t* out_len) {
    if (!hs || msg_len < 73) return FG_ERR_INVAL;

    const uint8_t* p = msg;
    if (*p++ != HANDSHAKE_VERSION) return FG_ERR_PROTO;
    p += 4; /* skip magic */
    p += 4; /* skip session_id */
    const uint8_t* remote_eph = p; p += 32;
    memcpy(hs->remote_pub, p, 32);

    /* DH: local_eph * remote_eph */
    uint8_t dh1[32], dh2[32];
    fg_x25519(dh1, hs->ephemeral_priv, remote_eph);
    fg_x25519(dh2, hs->local_priv, hs->remote_pub);

    /* derive send/recv keys */
    uint8_t combined[64];
    memcpy(combined,    dh1, 32);
    memcpy(combined+32, dh2, 32);
    fg_hkdf_expand(hs->chaining_key, combined, 64, hs->send_key, 32);
    fg_hkdf_expand(hs->send_key,     combined, 64, hs->recv_key, 32);

    /* send ACK: version | magic | session_id */
    if (*out_len < 9) return FG_ERR_INVAL;
    uint8_t* op = out;
    *op++ = HANDSHAKE_VERSION;
    uint32_t magic = HANDSHAKE_MAGIC;
    memcpy(op, &magic, 4); op += 4;
    memcpy(op, &hs->session_id, 4); op += 4;
    *out_len = (size_t)(op - out);

    hs->state = HS_COMPLETE;
    return FG_OK;
}

void fg_handshake_get_keys(const FgHandshake* hs,
                            uint8_t send_key[32], uint8_t recv_key[32]) {
    if (send_key) memcpy(send_key, hs->send_key, 32);
    if (recv_key) memcpy(recv_key, hs->recv_key, 32);
}

int fg_handshake_is_complete(const FgHandshake* hs) {
    return hs && hs->state == HS_COMPLETE;
}

void fg_handshake_free(FgHandshake* hs) {
    if (!hs) return;
    /* zero out key material */
    memset(hs->local_priv,    0, 32);
    memset(hs->ephemeral_priv,0, 32);
    memset(hs->send_key,      0, 32);
    memset(hs->recv_key,      0, 32);
    free(hs);
}
