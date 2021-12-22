#pragma once
#include "ferrumgate.h"
#include "crypto.h"
#include "packet.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FG_SESSION_ID_LEN    16
#define FG_MAX_SESSIONS      65536
#define FG_SESSION_TIMEOUT_S 300

typedef enum {
    FG_SESSION_INIT        = 0,
    FG_SESSION_HANDSHAKE   = 1,
    FG_SESSION_ESTABLISHED = 2,
    FG_SESSION_CLOSING     = 3,
    FG_SESSION_CLOSED      = 4,
} FgSessionState;

typedef struct {
    uint8_t        id[FG_SESSION_ID_LEN];
    uint32_t       numeric_id;
    FgSessionState state;
    FgCryptoKey    send_key;
    FgCryptoKey    recv_key;
    FgTunnelType   tunnel_type;
    uint64_t       bytes_sent;
    uint64_t       bytes_recv;
    uint64_t       pkts_sent;
    uint64_t       pkts_recv;
    uint64_t       created_at_ms;
    uint64_t       last_active_ms;
    uint32_t       peer_ip4;
    uint16_t       peer_port;
    bool           authenticated;
} FgSessionInfo;

FgSession* fg_session_new(FgContext* ctx, FgTunnelType type);
void       fg_session_free(FgSession* s);

int fg_session_handshake_init(FgSession* s,
                               const uint8_t* peer_pub_key, size_t key_len);
int fg_session_handshake_respond(FgSession* s,
                                  const uint8_t* msg, size_t msg_len,
                                  uint8_t* resp, size_t* resp_len);
int fg_session_handshake_finish(FgSession* s,
                                 const uint8_t* msg, size_t msg_len);

int fg_session_encrypt_packet(FgSession* s,
                               const uint8_t* plain, size_t plain_len,
                               uint8_t* out, size_t* out_len);
int fg_session_decrypt_packet(FgSession* s,
                               const uint8_t* enc, size_t enc_len,
                               uint8_t* out, size_t* out_len);

int fg_session_get_info(const FgSession* s, FgSessionInfo* out);
int fg_session_close(FgSession* s);
bool fg_session_is_expired(const FgSession* s, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
