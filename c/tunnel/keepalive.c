#include "../include/tunnel.h"
#include "../include/ferrumgate.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#define KA_INTERVAL_MS  10000  /* send keepalive every 10s */
#define KA_TIMEOUT_MS   30000  /* declare dead after 30s no response */
#define KA_MAX_SESSIONS 1024

typedef struct {
    uint32_t session_id;
    int      fd;
    uint32_t peer_ip;
    uint16_t peer_port;
    uint64_t last_send_ms;
    uint64_t last_recv_ms;
    bool     active;
    uint32_t missed;
    uint64_t seq;
} KaEntry;

typedef struct {
    KaEntry         entries[KA_MAX_SESSIONS];
    int             count;
    pthread_t       thread;
    bool            running;
    pthread_mutex_t lock;
    void (*on_dead)(uint32_t session_id, void* udata);
    void* udata;
} FgKeepalive;

static uint64_t ka_now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void* ka_thread(void* arg) {
    FgKeepalive* ka = arg;
    while (ka->running) {
        uint64_t now = ka_now_ms();

        pthread_mutex_lock(&ka->lock);
        for (int i = 0; i < ka->count; i++) {
            KaEntry* e = &ka->entries[i];
            if (!e->active) continue;

            /* send keepalive if interval elapsed */
            if (now - e->last_send_ms >= KA_INTERVAL_MS) {
                uint8_t pkt[32]; size_t plen = sizeof(pkt);
                fg_frame_keepalive(pkt, &plen, e->session_id, e->seq++);
                fg_udp_send(e->fd, pkt, plen, e->peer_ip, e->peer_port);
                e->last_send_ms = now;
                e->missed++;
            }

            /* declare dead if no response in timeout */
            if (e->missed >= 3 &&
                now - e->last_recv_ms > KA_TIMEOUT_MS) {
                e->active = false;
                if (ka->on_dead) ka->on_dead(e->session_id, ka->udata);
            }
        }
        pthread_mutex_unlock(&ka->lock);

        usleep(1000 * 1000); /* 1s granularity */
    }
    return NULL;
}

FgKeepalive* fg_ka_create(void (*on_dead)(uint32_t, void*), void* udata) {
    FgKeepalive* ka = calloc(1, sizeof(FgKeepalive));
    if (!ka) return NULL;
    pthread_mutex_init(&ka->lock, NULL);
    ka->on_dead = on_dead;
    ka->udata   = udata;
    return ka;
}

int fg_ka_start(FgKeepalive* ka) {
    ka->running = true;
    return pthread_create(&ka->thread, NULL, ka_thread, ka) == 0 ?
           FG_OK : FG_ERR_IO;
}

void fg_ka_stop(FgKeepalive* ka) {
    if (!ka) return;
    ka->running = false;
    pthread_join(ka->thread, NULL);
}

int fg_ka_add(FgKeepalive* ka, uint32_t sid, int fd,
               uint32_t peer_ip, uint16_t peer_port) {
    if (!ka || ka->count >= KA_MAX_SESSIONS) return FG_ERR_NOMEM;
    pthread_mutex_lock(&ka->lock);
    KaEntry* e = &ka->entries[ka->count++];
    e->session_id = sid; e->fd = fd;
    e->peer_ip = peer_ip; e->peer_port = peer_port;
    e->last_recv_ms = e->last_send_ms = ka_now_ms();
    e->active = true; e->seq = 0; e->missed = 0;
    pthread_mutex_unlock(&ka->lock);
    return FG_OK;
}

void fg_ka_pong(FgKeepalive* ka, uint32_t sid) {
    if (!ka) return;
    pthread_mutex_lock(&ka->lock);
    for (int i = 0; i < ka->count; i++) {
        if (ka->entries[i].session_id == sid) {
            ka->entries[i].last_recv_ms = ka_now_ms();
            ka->entries[i].missed = 0;
            break;
        }
    }
    pthread_mutex_unlock(&ka->lock);
}

void fg_ka_free(FgKeepalive* ka) {
    if (!ka) return;
    fg_ka_stop(ka);
    pthread_mutex_destroy(&ka->lock);
    free(ka);
}
