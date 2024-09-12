#include "../include/tunnel.h"
#include "../include/ferrumgate.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define FRAG_MAX_PENDING  128
#define FRAG_TTL_MS       5000
#define FRAG_MAX_CHUNKS   16
#define FRAG_MTU          1400

typedef struct {
    uint32_t frag_id;
    uint32_t session_id;
    uint8_t  total_chunks;
    uint8_t  received_mask;
    uint8_t* chunks[FRAG_MAX_CHUNKS];
    uint16_t chunk_lens[FRAG_MAX_CHUNKS];
    uint64_t created_ms;
    bool     complete;
} FragEntry;

static FragEntry g_frags[FRAG_MAX_PENDING];

static uint64_t ms_now(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static FragEntry* frag_alloc(uint32_t frag_id, uint32_t session_id,
                               uint8_t total) {
    uint64_t now = ms_now();
    for (int i = 0; i < FRAG_MAX_PENDING; i++) {
        FragEntry* e = &g_frags[i];
        if (!e->frag_id || now - e->created_ms > FRAG_TTL_MS) {
            /* reuse/clear */
            for (int j = 0; j < FRAG_MAX_CHUNKS; j++) {
                free(e->chunks[j]); e->chunks[j] = NULL;
            }
            memset(e, 0, sizeof(*e));
            e->frag_id   = frag_id;
            e->session_id = session_id;
            e->total_chunks = total;
            e->created_ms = now;
            return e;
        }
        if (e->frag_id == frag_id && e->session_id == session_id)
            return e;
    }
    return NULL;
}

int fg_frag_send(int fd, uint32_t session_id, uint64_t seq,
                  const uint8_t* payload, size_t len,
                  uint32_t dst_ip, uint16_t dst_port) {
    if (len <= FRAG_MTU)
        return fg_udp_send(fd, payload, len, dst_ip, dst_port) > 0 ? FG_OK : FG_ERR_IO;

    uint8_t total = (uint8_t)((len + FRAG_MTU - 1) / FRAG_MTU);
    if (total > FRAG_MAX_CHUNKS) return FG_ERR_INVAL;

    uint32_t frag_id = (uint32_t)seq ^ session_id;
    uint8_t buf[FRAG_MTU + 8];

    for (uint8_t i = 0; i < total; i++) {
        size_t off   = (size_t)i * FRAG_MTU;
        size_t chunk = (off + FRAG_MTU <= len) ? FRAG_MTU : len - off;

        /* header: frag_id(4) | chunk_idx(1) | total(1) | session_id(2 lo) */
        uint8_t* p = buf;
        memcpy(p, &frag_id, 4); p += 4;
        *p++ = i; *p++ = total;
        uint16_t sid = (uint16_t)session_id;
        memcpy(p, &sid, 2); p += 2;
        memcpy(p, payload + off, chunk);

        if (fg_udp_send(fd, buf, chunk + 8, dst_ip, dst_port) < 0)
            return FG_ERR_IO;
    }
    return FG_OK;
}

int fg_frag_recv(const uint8_t* pkt, size_t pkt_len,
                  uint8_t* out, size_t* out_len) {
    if (pkt_len < 8) return FG_ERR_INVAL;

    uint32_t frag_id; memcpy(&frag_id, pkt, 4);
    uint8_t idx   = pkt[4];
    uint8_t total = pkt[5];
    uint16_t sid; memcpy(&sid, pkt + 6, 2);

    FragEntry* e = frag_alloc(frag_id, sid, total);
    if (!e) return FG_ERR_NOMEM;

    size_t dlen = pkt_len - 8;
    e->chunks[idx] = malloc(dlen);
    if (!e->chunks[idx]) return FG_ERR_NOMEM;
    memcpy(e->chunks[idx], pkt + 8, dlen);
    e->chunk_lens[idx] = (uint16_t)dlen;
    e->received_mask |= (1u << idx);

    uint8_t full = (1u << total) - 1;
    if ((e->received_mask & full) != full) return FG_ERR_AGAIN;

    /* reassemble */
    size_t total_len = 0;
    for (int i = 0; i < total; i++) total_len += e->chunk_lens[i];
    if (total_len > *out_len) return FG_ERR_INVAL;

    size_t off = 0;
    for (int i = 0; i < total; i++) {
        memcpy(out + off, e->chunks[i], e->chunk_lens[i]);
        off += e->chunk_lens[i];
    }
    *out_len = total_len;
    e->frag_id = 0; /* mark free */
    return FG_OK;
}
