#include "../include/ferrumgate.h"
#include "../include/net.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

/* Simple multipath manager: round-robin over N uplinks with
 * health-check-based removal and re-admission. */

#define MAX_UPLINKS 8

typedef struct {
    int      fd;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t failures;
    bool     healthy;
} Uplink;

typedef struct {
    Uplink          links[MAX_UPLINKS];
    int             count;
    int             rr_idx;
    pthread_mutex_t lock;
    uint64_t        total_sent;
} FgMultipath;

FgMultipath* fg_mp_create(void) {
    FgMultipath* mp = calloc(1, sizeof(FgMultipath));
    if (!mp) return NULL;
    pthread_mutex_init(&mp->lock, NULL);
    return mp;
}

int fg_mp_add_uplink(FgMultipath* mp, int fd, uint32_t dst_ip, uint16_t dst_port) {
    if (!mp || mp->count >= MAX_UPLINKS) return FG_ERR_NOMEM;
    pthread_mutex_lock(&mp->lock);
    Uplink* u = &mp->links[mp->count++];
    u->fd       = fd;
    u->dst_ip   = dst_ip;
    u->dst_port = dst_port;
    u->healthy  = true;
    pthread_mutex_unlock(&mp->lock);
    return FG_OK;
}

static Uplink* next_healthy(FgMultipath* mp) {
    for (int i = 0; i < mp->count; i++) {
        int idx = (mp->rr_idx + i) % mp->count;
        if (mp->links[idx].healthy) {
            mp->rr_idx = (idx + 1) % mp->count;
            return &mp->links[idx];
        }
    }
    return NULL;
}

ssize_t fg_mp_send(FgMultipath* mp, const uint8_t* buf, size_t len) {
    if (!mp || !buf) return FG_ERR_INVAL;

    pthread_mutex_lock(&mp->lock);
    Uplink* u = next_healthy(mp);
    if (!u) { pthread_mutex_unlock(&mp->lock); return FG_ERR_IO; }

    ssize_t n = fg_udp_send(u->fd, buf, len, u->dst_ip, u->dst_port);
    if (n > 0) {
        u->bytes_sent += n;
        mp->total_sent += n;
    } else {
        u->failures++;
        if (u->failures >= 5) u->healthy = false;
    }
    pthread_mutex_unlock(&mp->lock);
    return n;
}

void fg_mp_mark_healthy(FgMultipath* mp, int fd, bool healthy) {
    if (!mp) return;
    pthread_mutex_lock(&mp->lock);
    for (int i = 0; i < mp->count; i++) {
        if (mp->links[i].fd == fd) {
            mp->links[i].healthy  = healthy;
            if (healthy) mp->links[i].failures = 0;
            break;
        }
    }
    pthread_mutex_unlock(&mp->lock);
}

void fg_mp_free(FgMultipath* mp) {
    if (!mp) return;
    pthread_mutex_destroy(&mp->lock);
    free(mp);
}
