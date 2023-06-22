#include "../include/ferrumgate.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

/* Token-bucket rate limiter, per source IP */

#define RL_TABLE_SIZE 2048
#define RL_TABLE_MASK (RL_TABLE_SIZE - 1)
#define NSEC_PER_SEC  1000000000ULL

typedef struct {
    uint32_t src_ip;
    uint64_t tokens;      /* in units of 1/1000 token */
    uint64_t last_fill_ns;
    uint64_t total_allowed;
    uint64_t total_dropped;
    uint8_t  valid;
} RlEntry;

typedef struct {
    RlEntry         table[RL_TABLE_SIZE];
    pthread_mutex_t lock;
    uint64_t        rate_per_sec;   /* tokens per second */
    uint64_t        burst;          /* max burst (in tokens) */
    uint64_t        global_allowed;
    uint64_t        global_dropped;
} FgRateLimiter;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

FgRateLimiter* fg_rl_create(uint64_t rate_per_sec, uint64_t burst) {
    FgRateLimiter* rl = calloc(1, sizeof(FgRateLimiter));
    if (!rl) return NULL;
    rl->rate_per_sec = rate_per_sec;
    rl->burst        = burst;
    pthread_mutex_init(&rl->lock, NULL);
    return rl;
}

void fg_rl_free(FgRateLimiter* rl) {
    if (!rl) return;
    pthread_mutex_destroy(&rl->lock);
    free(rl);
}

bool fg_rl_allow(FgRateLimiter* rl, uint32_t src_ip) {
    if (!rl) return true;

    uint32_t h = src_ip ^ (src_ip >> 16);
    h = (h ^ (h >> 4)) & RL_TABLE_MASK;

    pthread_mutex_lock(&rl->lock);
    RlEntry* e = &rl->table[h];

    uint64_t now = now_ns();
    if (!e->valid || e->src_ip != src_ip) {
        e->src_ip      = src_ip;
        e->tokens      = rl->burst * 1000;
        e->last_fill_ns = now;
        e->total_allowed = 0;
        e->total_dropped = 0;
        e->valid       = 1;
    } else {
        uint64_t elapsed = now - e->last_fill_ns;
        uint64_t new_tokens = (elapsed * rl->rate_per_sec) / NSEC_PER_SEC * 1000;
        e->tokens += new_tokens;
        if (e->tokens > rl->burst * 1000) e->tokens = rl->burst * 1000;
        e->last_fill_ns = now;
    }

    bool allowed = e->tokens >= 1000;
    if (allowed) {
        e->tokens -= 1000;
        e->total_allowed++;
        rl->global_allowed++;
    } else {
        e->total_dropped++;
        rl->global_dropped++;
    }

    pthread_mutex_unlock(&rl->lock);
    return allowed;
}

void fg_rl_stats(const FgRateLimiter* rl,
                 uint64_t* allowed, uint64_t* dropped) {
    if (!rl) return;
    if (allowed) *allowed = rl->global_allowed;
    if (dropped) *dropped = rl->global_dropped;
}
