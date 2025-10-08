#include "../include/ferrumgate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>

/* Per-session and global metrics for observability */

#define MAX_METRIC_SESSIONS 4096
#define HISTOGRAM_BUCKETS   16

typedef struct {
    uint64_t sum;
    uint64_t count;
    uint64_t buckets[HISTOGRAM_BUCKETS];
    /* bucket upper bounds in ms: 1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,inf */
} Histogram;

typedef struct {
    uint32_t session_id;
    bool     active;

    uint64_t packets_rx;
    uint64_t packets_tx;
    uint64_t bytes_rx;
    uint64_t bytes_tx;
    uint64_t errors;
    uint64_t retransmits;
    uint64_t replay_blocks;

    Histogram rtt_hist;
    uint64_t  rtt_min_ms;
    uint64_t  rtt_max_ms;
    uint64_t  rtt_ewma_us;   /* microseconds, EWMA */

    time_t   created_at;
    time_t   last_active;
} SessionMetrics;

static SessionMetrics g_metrics[MAX_METRIC_SESSIONS];
static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;

static SessionMetrics* metrics_find(uint32_t sid) {
    uint32_t h = (sid ^ (sid >> 16)) % MAX_METRIC_SESSIONS;
    for (int i = 0; i < MAX_METRIC_SESSIONS; i++) {
        uint32_t idx = (h + i) % MAX_METRIC_SESSIONS;
        if (g_metrics[idx].active && g_metrics[idx].session_id == sid)
            return &g_metrics[idx];
    }
    return NULL;
}

int fg_metrics_session_init(uint32_t sid) {
    pthread_rwlock_wrlock(&g_lock);
    uint32_t h = (sid ^ (sid >> 16)) % MAX_METRIC_SESSIONS;
    for (int i = 0; i < MAX_METRIC_SESSIONS; i++) {
        uint32_t idx = (h + i) % MAX_METRIC_SESSIONS;
        if (!g_metrics[idx].active) {
            memset(&g_metrics[idx], 0, sizeof(g_metrics[idx]));
            g_metrics[idx].session_id = sid;
            g_metrics[idx].active     = true;
            g_metrics[idx].rtt_min_ms = UINT64_MAX;
            g_metrics[idx].created_at = time(NULL);
            pthread_rwlock_unlock(&g_lock);
            return FG_OK;
        }
    }
    pthread_rwlock_unlock(&g_lock);
    return FG_ERR_NOMEM;
}

static void hist_record(Histogram* h, uint64_t val_ms) {
    static const uint64_t bounds[HISTOGRAM_BUCKETS] = {
        1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,UINT64_MAX
    };
    h->sum += val_ms; h->count++;
    for (int i = 0; i < HISTOGRAM_BUCKETS; i++) {
        if (val_ms <= bounds[i]) { h->buckets[i]++; break; }
    }
}

void fg_metrics_record_rtt(uint32_t sid, uint64_t rtt_ms) {
    pthread_rwlock_wrlock(&g_lock);
    SessionMetrics* m = metrics_find(sid);
    if (m) {
        hist_record(&m->rtt_hist, rtt_ms);
        if (rtt_ms < m->rtt_min_ms) m->rtt_min_ms = rtt_ms;
        if (rtt_ms > m->rtt_max_ms) m->rtt_max_ms = rtt_ms;
        m->rtt_ewma_us = (m->rtt_ewma_us * 7 + rtt_ms * 1000) / 8;
    }
    pthread_rwlock_unlock(&g_lock);
}

void fg_metrics_record_packet(uint32_t sid, bool rx, size_t bytes) {
    pthread_rwlock_wrlock(&g_lock);
    SessionMetrics* m = metrics_find(sid);
    if (m) {
        if (rx) { m->packets_rx++; m->bytes_rx += bytes; }
        else    { m->packets_tx++; m->bytes_tx += bytes; }
        m->last_active = time(NULL);
    }
    pthread_rwlock_unlock(&g_lock);
}

int fg_metrics_snapshot(uint32_t sid, uint64_t* pkts_rx, uint64_t* pkts_tx,
                          uint64_t* bytes_rx, uint64_t* bytes_tx,
                          uint64_t* rtt_ewma_us) {
    pthread_rwlock_rdlock(&g_lock);
    SessionMetrics* m = metrics_find(sid);
    if (!m) { pthread_rwlock_unlock(&g_lock); return FG_ERR_INVAL; }

    if (pkts_rx)    *pkts_rx    = m->packets_rx;
    if (pkts_tx)    *pkts_tx    = m->packets_tx;
    if (bytes_rx)   *bytes_rx   = m->bytes_rx;
    if (bytes_tx)   *bytes_tx   = m->bytes_tx;
    if (rtt_ewma_us)*rtt_ewma_us= m->rtt_ewma_us;

    pthread_rwlock_unlock(&g_lock);
    return FG_OK;
}

void fg_metrics_session_destroy(uint32_t sid) {
    pthread_rwlock_wrlock(&g_lock);
    SessionMetrics* m = metrics_find(sid);
    if (m) m->active = false;
    pthread_rwlock_unlock(&g_lock);
}
