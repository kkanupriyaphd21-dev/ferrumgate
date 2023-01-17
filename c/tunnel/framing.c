#include "../include/tunnel.h"
#include "../include/packet.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
 * Tunnel wire framing:
 *
 *  0               1               2               3
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Type  |Flags|       Payload Length            |   Reserved   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Session ID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Sequence Number (64-bit)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Encrypted Payload ...                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define FG_FRAME_TYPE_DATA    0x01
#define FG_FRAME_TYPE_CONTROL 0x02
#define FG_FRAME_TYPE_KEEPALIVE 0x03
#define FG_FRAME_TYPE_CLOSE   0x04

#define FG_FRAME_FLAG_FRAG    0x01
#define FG_FRAME_FLAG_LAST    0x02

int fg_frame_encode(uint8_t* out, size_t* out_len,
                     uint32_t session_id, uint64_t seq,
                     uint8_t type, uint8_t flags,
                     const uint8_t* payload, size_t payload_len) {
    if (!out || !out_len || !payload) return FG_ERR_INVAL;

    size_t total = FG_TUNNEL_HDR_LEN + payload_len;
    if (*out_len < total) return FG_ERR_INVAL;

    uint8_t* p = out;
    *p++ = type;
    *p++ = flags;

    uint16_t plen = htons((uint16_t)payload_len);
    memcpy(p, &plen, 2); p += 2;

    memset(p, 0, 4); p += 4; /* reserved */

    uint32_t sid = htonl(session_id);
    memcpy(p, &sid, 4); p += 4;

    /* seq as big-endian 64-bit */
    for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(seq >> (i*8));

    memcpy(p, payload, payload_len);
    *out_len = total;
    return FG_OK;
}

int fg_frame_decode(const uint8_t* in, size_t in_len,
                     uint32_t* session_id, uint64_t* seq,
                     uint8_t* type, uint8_t* flags,
                     const uint8_t** payload, size_t* payload_len) {
    if (!in || in_len < FG_TUNNEL_HDR_LEN) return FG_ERR_INVAL;

    const uint8_t* p = in;
    if (type)  *type  = *p++;
    if (flags) *flags = *p++;

    uint16_t plen; memcpy(&plen, p, 2); p += 2;
    plen = ntohs(plen);

    p += 4; /* skip reserved */

    uint32_t sid; memcpy(&sid, p, 4); p += 4;
    if (session_id) *session_id = ntohl(sid);

    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s = (s << 8) | *p++;
    if (seq) *seq = s;

    if (in_len < FG_TUNNEL_HDR_LEN + plen) return FG_ERR_PROTO;

    if (payload)     *payload     = p;
    if (payload_len) *payload_len = plen;
    return FG_OK;
}

int fg_frame_keepalive(uint8_t* out, size_t* out_len,
                        uint32_t session_id, uint64_t seq) {
    uint8_t empty = 0;
    return fg_frame_encode(out, out_len, session_id, seq,
                            FG_FRAME_TYPE_KEEPALIVE, 0, &empty, 0);
}

int fg_frame_close(uint8_t* out, size_t* out_len,
                    uint32_t session_id, uint64_t seq, uint8_t reason) {
    return fg_frame_encode(out, out_len, session_id, seq,
                            FG_FRAME_TYPE_CLOSE, 0, &reason, 1);
}
