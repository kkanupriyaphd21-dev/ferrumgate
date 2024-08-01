#include "../include/net.h"
#include "../include/ferrumgate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* Minimal QUIC-like shim layer over UDP.
 * Handles stream multiplexing and connection IDs. */

#define QUIC_MAX_STREAMS   64
#define QUIC_HDR_LEN       16
#define QUIC_FLAG_STREAM   0x01
#define QUIC_FLAG_FIN      0x02
#define QUIC_FLAG_RESET    0x04
#define QUIC_FLAG_ACK      0x08

typedef struct {
    uint32_t stream_id;
    uint64_t offset;
    uint8_t  flags;
    bool     fin_received;
    bool     reset;
    uint64_t bytes_rx;
    uint64_t bytes_tx;
} QuicStream;

typedef struct {
    uint64_t  conn_id;
    int       udp_fd;
    uint32_t  peer_ip;
    uint16_t  peer_port;
    QuicStream streams[QUIC_MAX_STREAMS];
    int        stream_count;
    uint64_t   packet_number;
    bool       established;
    uint64_t   total_bytes_rx;
    uint64_t   total_bytes_tx;
} QuicConn;

static uint64_t quic_gen_conn_id(void) {
    uint64_t id;
    fg_rand_bytes((uint8_t*)&id, 8);
    return id;
}

QuicConn* fg_quic_conn_new(int udp_fd, uint32_t peer_ip, uint16_t peer_port) {
    QuicConn* c = calloc(1, sizeof(QuicConn));
    if (!c) return NULL;
    c->conn_id   = quic_gen_conn_id();
    c->udp_fd    = udp_fd;
    c->peer_ip   = peer_ip;
    c->peer_port = peer_port;
    return c;
}

int fg_quic_open_stream(QuicConn* c, uint32_t* stream_id_out) {
    if (!c || c->stream_count >= QUIC_MAX_STREAMS) return FG_ERR_NOMEM;
    QuicStream* s = &c->streams[c->stream_count];
    s->stream_id = c->stream_count;
    s->offset    = 0;
    s->flags     = 0;
    if (stream_id_out) *stream_id_out = s->stream_id;
    c->stream_count++;
    return FG_OK;
}

/* Wire format: conn_id(8) | pkt_num(4) | stream_id(2) | flags(1) | reserved(1) | payload */
int fg_quic_send(QuicConn* c, uint32_t stream_id, const uint8_t* data, size_t len,
                  bool fin) {
    if (!c || !data) return FG_ERR_INVAL;

    size_t total = QUIC_HDR_LEN + len;
    uint8_t* pkt = malloc(total);
    if (!pkt) return FG_ERR_NOMEM;

    uint8_t* p = pkt;
    memcpy(p, &c->conn_id, 8); p += 8;
    uint32_t pn = (uint32_t)c->packet_number++;
    memcpy(p, &pn, 4); p += 4;
    uint16_t sid = (uint16_t)stream_id;
    memcpy(p, &sid, 2); p += 2;
    *p++ = QUIC_FLAG_STREAM | (fin ? QUIC_FLAG_FIN : 0);
    *p++ = 0; /* reserved */
    memcpy(p, data, len);

    ssize_t n = fg_udp_send(c->udp_fd, pkt, total, c->peer_ip, c->peer_port);
    free(pkt);

    if (n > 0) c->total_bytes_tx += len;
    return (n > 0) ? FG_OK : FG_ERR_IO;
}

int fg_quic_recv(QuicConn* c, uint8_t* buf, size_t buf_len,
                  uint32_t* stream_id_out, size_t* data_len_out) {
    uint8_t raw[65536];
    uint32_t src_ip; uint16_t src_port;
    ssize_t n = fg_udp_recv(c->udp_fd, raw, sizeof(raw), &src_ip, &src_port);
    if (n <= 0) return FG_ERR_IO;
    if ((size_t)n < QUIC_HDR_LEN) return FG_ERR_PROTO;

    uint64_t cid; memcpy(&cid, raw, 8);
    if (cid != c->conn_id) return FG_ERR_PROTO;

    uint16_t sid; memcpy(&sid, raw + 12, 2);
    if (stream_id_out) *stream_id_out = sid;

    size_t dlen = n - QUIC_HDR_LEN;
    if (dlen > buf_len) dlen = buf_len;
    memcpy(buf, raw + QUIC_HDR_LEN, dlen);
    if (data_len_out) *data_len_out = dlen;

    c->total_bytes_rx += dlen;
    return FG_OK;
}

void fg_quic_conn_free(QuicConn* c) { free(c); }
