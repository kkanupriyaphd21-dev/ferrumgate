#include "../include/ferrumgate.h"
#include "../include/net.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/* Health checker for load-balanced backends */

#define HC_MAX_BACKENDS  32
#define HC_INTERVAL_S    5
#define HC_TIMEOUT_S     2
#define HC_FAIL_THRESH   3
#define HC_PASS_THRESH   2

typedef enum {
    HC_STATE_HEALTHY   = 0,
    HC_STATE_DEGRADED  = 1,
    HC_STATE_UNHEALTHY = 2,
} HcState;

typedef struct {
    uint32_t ip;
    uint16_t port;
    HcState  state;
    int      consecutive_fails;
    int      consecutive_pass;
    uint64_t checks;
    uint64_t failures;
    uint32_t latency_ms;
    bool     active;
} Backend;

typedef struct {
    Backend         backends[HC_MAX_BACKENDS];
    int             count;
    pthread_t       thread;
    bool            running;
    pthread_mutex_t lock;
    void (*on_state_change)(uint32_t ip, uint16_t port, HcState old, HcState new);
} FgHealthChecker;

static bool check_tcp(uint32_t ip, uint16_t port, uint32_t* latency_ms) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int fd = -1;
    bool ok = (fg_tcp_connect(ip, port, &fd) == FG_OK);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (ok) close(fd);

    uint64_t elapsed = ((uint64_t)(t1.tv_sec - t0.tv_sec) * 1000)
                     + ((uint64_t)(t1.tv_nsec - t0.tv_nsec) / 1000000);
    *latency_ms = (uint32_t)elapsed;

    return ok && elapsed < HC_TIMEOUT_S * 1000;
}

static void* hc_thread(void* arg) {
    FgHealthChecker* hc = arg;
    while (hc->running) {
        sleep(HC_INTERVAL_S);
        uint32_t lat;

        pthread_mutex_lock(&hc->lock);
        for (int i = 0; i < hc->count; i++) {
            Backend* b = &hc->backends[i];
            if (!b->active) continue;

            bool ok = check_tcp(b->ip, b->port, &lat);
            b->checks++;
            b->latency_ms = lat;

            HcState old = b->state;
            if (ok) {
                b->consecutive_fails = 0;
                b->consecutive_pass++;
                if (b->consecutive_pass >= HC_PASS_THRESH)
                    b->state = HC_STATE_HEALTHY;
            } else {
                b->failures++;
                b->consecutive_pass = 0;
                b->consecutive_fails++;
                if (b->consecutive_fails >= HC_FAIL_THRESH)
                    b->state = HC_STATE_UNHEALTHY;
                else if (b->consecutive_fails > 0)
                    b->state = HC_STATE_DEGRADED;
            }

            if (old != b->state && hc->on_state_change)
                hc->on_state_change(b->ip, b->port, old, b->state);
        }
        pthread_mutex_unlock(&hc->lock);
    }
    return NULL;
}

FgHealthChecker* fg_hc_create(void (*cb)(uint32_t, uint16_t, HcState, HcState)) {
    FgHealthChecker* hc = calloc(1, sizeof(FgHealthChecker));
    if (!hc) return NULL;
    pthread_mutex_init(&hc->lock, NULL);
    hc->on_state_change = cb;
    return hc;
}

int fg_hc_add(FgHealthChecker* hc, uint32_t ip, uint16_t port) {
    if (!hc || hc->count >= HC_MAX_BACKENDS) return FG_ERR_NOMEM;
    pthread_mutex_lock(&hc->lock);
    Backend* b = &hc->backends[hc->count++];
    b->ip = ip; b->port = port; b->active = true; b->state = HC_STATE_HEALTHY;
    pthread_mutex_unlock(&hc->lock);
    return FG_OK;
}

int fg_hc_start(FgHealthChecker* hc) {
    hc->running = true;
    return pthread_create(&hc->thread, NULL, hc_thread, hc) == 0 ?
           FG_OK : FG_ERR_IO;
}

void fg_hc_stop(FgHealthChecker* hc) {
    if (!hc) return;
    hc->running = false;
    pthread_join(hc->thread, NULL);
}

bool fg_hc_is_healthy(FgHealthChecker* hc, uint32_t ip, uint16_t port) {
    if (!hc) return false;
    pthread_mutex_lock(&hc->lock);
    for (int i = 0; i < hc->count; i++) {
        if (hc->backends[i].ip == ip && hc->backends[i].port == port) {
            bool h = hc->backends[i].state == HC_STATE_HEALTHY;
            pthread_mutex_unlock(&hc->lock);
            return h;
        }
    }
    pthread_mutex_unlock(&hc->lock);
    return false;
}

void fg_hc_free(FgHealthChecker* hc) {
    if (!hc) return;
    fg_hc_stop(hc);
    pthread_mutex_destroy(&hc->lock);
    free(hc);
}
