#include "../include/tunnel.h"
#include "../include/ferrumgate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* CUBIC congestion control for tunnel streams */

#define CUBIC_C         0.4
#define CUBIC_BETA      0.7
#define MSEC_PER_SEC    1000
#define MIN_CWND        4
#define MAX_CWND        65535
#define INITIAL_CWND    10

typedef struct {
    uint32_t cwnd;          /* congestion window (packets) */
    uint32_t ssthresh;
    uint32_t w_max;         /* window size at last congestion */
    uint64_t t_epoch_ms;    /* time of last congestion event */
    uint64_t rtt_ms;        /* smoothed RTT */
    uint64_t rtt_var_ms;    /* RTT variance */
    uint64_t bytes_in_flight;
    uint64_t acked_bytes;
    uint32_t loss_count;
    bool     in_slow_start;
} FgCubic;

FgCubic* fg_cubic_new(void) {
    FgCubic* c = calloc(1, sizeof(FgCubic));
    if (!c) return NULL;
    c->cwnd         = INITIAL_CWND;
    c->ssthresh     = MAX_CWND;
    c->rtt_ms       = 100;
    c->rtt_var_ms   = 10;
    c->in_slow_start = true;
    return c;
}

static uint32_t cubic_window(const FgCubic* c, uint64_t now_ms) {
    if (!c->t_epoch_ms) return c->cwnd;

    double t = (double)(now_ms - c->t_epoch_ms) / MSEC_PER_SEC;
    double k = /* cbrt */ __builtin_cbrt((double)c->w_max * (1.0 - CUBIC_BETA) / CUBIC_C);
    double w_cubic = CUBIC_C * (t - k) * (t - k) * (t - k) + c->w_max;

    uint32_t wc = (w_cubic < MIN_CWND) ? MIN_CWND :
                  (w_cubic > MAX_CWND) ? MAX_CWND : (uint32_t)w_cubic;
    return wc;
}

void fg_cubic_on_ack(FgCubic* c, uint32_t bytes_acked, uint64_t rtt_ms,
                      uint64_t now_ms) {
    if (!c) return;

    /* update RTT estimate */
    c->rtt_ms    = (c->rtt_ms * 7 + rtt_ms) / 8;
    c->rtt_var_ms = (c->rtt_var_ms * 3 + (uint64_t)abs((int64_t)(rtt_ms - c->rtt_ms))) / 4;

    c->acked_bytes += bytes_acked;

    if (c->in_slow_start) {
        c->cwnd += (bytes_acked > 1460) ? bytes_acked / 1460 : 1;
        if (c->cwnd >= c->ssthresh) c->in_slow_start = false;
        return;
    }

    uint32_t w_cubic = cubic_window(c, now_ms);
    if (w_cubic > c->cwnd) {
        c->cwnd = w_cubic;
        if (c->cwnd > MAX_CWND) c->cwnd = MAX_CWND;
    } else {
        /* TCP-friendly region */
        c->cwnd++;
    }
}

void fg_cubic_on_loss(FgCubic* c, uint64_t now_ms) {
    if (!c) return;
    c->w_max     = c->cwnd;
    c->cwnd      = (uint32_t)(c->cwnd * CUBIC_BETA);
    c->ssthresh  = c->cwnd;
    if (c->cwnd < MIN_CWND) c->cwnd = MIN_CWND;
    c->t_epoch_ms = now_ms;
    c->loss_count++;
    c->in_slow_start = false;
}

uint32_t fg_cubic_cwnd(const FgCubic* c) {
    return c ? c->cwnd : INITIAL_CWND;
}

void fg_cubic_free(FgCubic* c) { free(c); }
