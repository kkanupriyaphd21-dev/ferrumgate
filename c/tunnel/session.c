#include "../include/tunnel.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct FgSession {
    FgSessionInfo info;
    uint8_t       dh_private[32];
    uint8_t       dh_public[32];
    uint8_t       peer_public[32];
    bool          keys_derived;
};

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t next_session_id(void) {
    static uint32_t counter = 1;
    return __sync_fetch_and_add(&counter, 1);
}

FgSession* fg_session_new(FgContext* ctx, FgTunnelType type) {
    (void)ctx;
    FgSession* s = calloc(1, sizeof(FgSession));
    if (!s) return NULL;

    s->info.numeric_id   = next_session_id();
    s->info.state        = FG_SESSION_INIT;
    s->info.tunnel_type  = type;
    s->info.created_at_ms   = now_ms();
    s->info.last_active_ms  = s->info.created_at_ms;
    s->info.authenticated   = false;

    /* generate session ID */
    fg_rand_bytes(s->info.id, FG_SESSION_ID_LEN);

    return s;
}

void fg_session_free(FgSession* s) {
    if (!s) return;
    /* zero sensitive key material */
    memset(&s->info.send_key, 0, sizeof(FgCryptoKey));
    memset(&s->info.recv_key, 0, sizeof(FgCryptoKey));
    memset(s->dh_private,  0, sizeof(s->dh_private));
    free(s);
}

int fg_session_handshake_init(FgSession* s,
                               const uint8_t* peer_pub_key, size_t key_len) {
    if (!s || !peer_pub_key || key_len < 32) return FG_ERR_INVAL;
    if (s->info.state != FG_SESSION_INIT) return FG_ERR_INVAL;

    memcpy(s->peer_public, peer_pub_key, 32);

    /* generate ephemeral DH keypair (stub — real impl uses X25519) */
    int rc = fg_rand_bytes(s->dh_private, 32);
    if (rc != FG_OK) return rc;

    /* placeholder: public = private XOR 0xAA (NOT real DH) */
    for (int i = 0; i < 32; i++) s->dh_public[i] = s->dh_private[i] ^ 0xAA;

    s->info.state = FG_SESSION_HANDSHAKE;
    return FG_OK;
}

int fg_session_handshake_respond(FgSession* s,
                                  const uint8_t* msg, size_t msg_len,
                                  uint8_t* resp, size_t* resp_len) {
    if (!s || !msg || !resp || !resp_len) return FG_ERR_INVAL;
    if (msg_len < 32) return FG_ERR_PROTO;
    if (*resp_len < 64) return FG_ERR_INVAL;

    /* accept peer's public key from handshake message */
    memcpy(s->peer_public, msg, 32);

    /* generate our ephemeral keypair */
    fg_rand_bytes(s->dh_private, 32);
    for (int i = 0; i < 32; i++) s->dh_public[i] = s->dh_private[i] ^ 0xAA;

    /* derive shared secret (stub) */
    uint8_t shared[32];
    for (int i = 0; i < 32; i++)
        shared[i] = s->dh_private[i] ^ s->peer_public[i];

    /* derive send/recv keys via HKDF */
    uint8_t send_key_material[32], recv_key_material[32];
    uint8_t info_send[] = "ferrumgate-send-v1";
    uint8_t info_recv[] = "ferrumgate-recv-v1";

    fg_hkdf_expand(shared, 32, info_send, sizeof(info_send)-1, send_key_material, 32);
    fg_hkdf_expand(shared, 32, info_recv, sizeof(info_recv)-1, recv_key_material, 32);

    s->info.send_key.suite = FG_CIPHER_CHACHA20_POLY;
    s->info.recv_key.suite = FG_CIPHER_CHACHA20_POLY;
    memcpy(s->info.send_key.key, send_key_material, 32);
    memcpy(s->info.recv_key.key, recv_key_material, 32);
    fg_rand_bytes(s->info.send_key.nonce, FG_NONCE_LEN);
    fg_rand_bytes(s->info.recv_key.nonce, FG_NONCE_LEN);
    s->keys_derived = true;

    /* build response: our public key + session ID */
    memcpy(resp,      s->dh_public,    32);
    memcpy(resp + 32, s->info.id,      FG_SESSION_ID_LEN);
    *resp_len = 32 + FG_SESSION_ID_LEN;

    s->info.state         = FG_SESSION_ESTABLISHED;
    s->info.authenticated = true;
    return FG_OK;
}

int fg_session_handshake_finish(FgSession* s,
                                 const uint8_t* msg, size_t msg_len) {
    if (!s || !msg || msg_len < 32 + FG_SESSION_ID_LEN) return FG_ERR_INVAL;
    if (s->info.state != FG_SESSION_HANDSHAKE) return FG_ERR_INVAL;

    /* peer sends their ephemeral public key */
    const uint8_t* peer_pub = msg;

    uint8_t shared[32];
    for (int i = 0; i < 32; i++)
        shared[i] = s->dh_private[i] ^ peer_pub[i];

    uint8_t send_mat[32], recv_mat[32];
    uint8_t info_s[] = "ferrumgate-send-v1";
    uint8_t info_r[] = "ferrumgate-recv-v1";
    fg_hkdf_expand(shared, 32, info_s, sizeof(info_s)-1, send_mat, 32);
    fg_hkdf_expand(shared, 32, info_r, sizeof(info_r)-1, recv_mat, 32);

    s->info.send_key.suite = FG_CIPHER_CHACHA20_POLY;
    s->info.recv_key.suite = FG_CIPHER_CHACHA20_POLY;
    memcpy(s->info.send_key.key, send_mat, 32);
    memcpy(s->info.recv_key.key, recv_mat, 32);
    fg_rand_bytes(s->info.send_key.nonce, FG_NONCE_LEN);
    fg_rand_bytes(s->info.recv_key.nonce, FG_NONCE_LEN);
    s->keys_derived = true;

    s->info.state         = FG_SESSION_ESTABLISHED;
    s->info.authenticated = true;
    return FG_OK;
}

int fg_session_encrypt_packet(FgSession* s,
                               const uint8_t* plain, size_t plain_len,
                               uint8_t* out, size_t* out_len) {
    if (!s || !s->keys_derived) return FG_ERR_CRYPTO;
    if (s->info.state != FG_SESSION_ESTABLISHED) return FG_ERR_INVAL;

    int rc = fg_encrypt(&s->info.send_key, plain, plain_len,
                         out, out_len, NULL, 0);
    if (rc == FG_OK) {
        fg_crypto_nonce_advance(&s->info.send_key);
        s->info.bytes_sent += plain_len;
        s->info.pkts_sent++;
        s->info.last_active_ms = now_ms();
    }
    return rc;
}

int fg_session_decrypt_packet(FgSession* s,
                               const uint8_t* enc, size_t enc_len,
                               uint8_t* out, size_t* out_len) {
    if (!s || !s->keys_derived) return FG_ERR_CRYPTO;
    if (s->info.state != FG_SESSION_ESTABLISHED) return FG_ERR_INVAL;

    int rc = fg_decrypt(&s->info.recv_key, enc, enc_len,
                         out, out_len, NULL, 0);
    if (rc == FG_OK) {
        fg_crypto_nonce_advance(&s->info.recv_key);
        s->info.bytes_recv += *out_len;
        s->info.pkts_recv++;
        s->info.last_active_ms = now_ms();
    }
    return rc;
}

int fg_session_get_info(const FgSession* s, FgSessionInfo* out) {
    if (!s || !out) return FG_ERR_INVAL;
    memcpy(out, &s->info, sizeof(FgSessionInfo));
    return FG_OK;
}

int fg_session_close(FgSession* s) {
    if (!s) return FG_ERR_INVAL;
    s->info.state = FG_SESSION_CLOSED;
    return FG_OK;
}

bool fg_session_is_expired(const FgSession* s, uint64_t now_ms_val) {
    if (!s) return true;
    if (s->info.state == FG_SESSION_CLOSED) return true;
    return (now_ms_val - s->info.last_active_ms) > FG_SESSION_TIMEOUT_S * 1000ULL;
}
