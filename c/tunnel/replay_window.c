#include "../include/ferrumgate.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* Sliding-window anti-replay protection (RFC 6479 style).
 * Window size = 1024 bits. */

#define REPLAY_WIN_BITS   1024
#define REPLAY_WIN_WORDS  (REPLAY_WIN_BITS / 64)

typedef struct {
    uint64_t  top_seq;
    uint64_t  window[REPLAY_WIN_WORDS];
    uint64_t  replays_blocked;
    uint64_t  accepted;
} ReplayWindow;

static ReplayWindow g_rw[65536]; /* one per session (indexed by session_id & 0xffff) */

static bool rw_check_and_set(ReplayWindow* rw, uint64_t seq) {
    if (seq == 0) return false; /* seq 0 always rejected */

    if (seq > rw->top_seq) {
        /* advance window */
        uint64_t diff = seq - rw->top_seq;
        if (diff >= REPLAY_WIN_BITS) {
            memset(rw->window, 0, sizeof(rw->window));
        } else {
            /* shift window by diff */
            uint64_t word_shift = diff / 64;
            uint64_t bit_shift  = diff % 64;
            for (int i = REPLAY_WIN_WORDS - 1; i >= 0; i--) {
                uint64_t src_lo = ((int)(i - word_shift) >= 0) ?
                                   rw->window[i - word_shift] : 0;
                uint64_t src_hi = ((int)(i - word_shift - 1) >= 0) ?
                                   rw->window[i - word_shift - 1] : 0;
                rw->window[i] = bit_shift ?
                    (src_lo << bit_shift) | (src_hi >> (64 - bit_shift)) :
                    src_lo;
            }
        }
        rw->top_seq = seq;
        /* mark current seq */
        rw->window[REPLAY_WIN_WORDS - 1] |= 1ULL;
        rw->accepted++;
        return true;
    }

    uint64_t diff = rw->top_seq - seq;
    if (diff >= REPLAY_WIN_BITS) {
        rw->replays_blocked++;
        return false;
    }

    uint64_t word_idx = (REPLAY_WIN_WORDS - 1) - (diff / 64);
    uint64_t bit_idx  = diff % 64;

    if (rw->window[word_idx] & (1ULL << bit_idx)) {
        rw->replays_blocked++;
        return false;
    }

    rw->window[word_idx] |= (1ULL << bit_idx);
    rw->accepted++;
    return true;
}

int fg_replay_check(uint32_t session_id, uint64_t seq) {
    ReplayWindow* rw = &g_rw[session_id & 0xffff];
    return rw_check_and_set(rw, seq) ? FG_OK : FG_ERR_REPLAY;
}

void fg_replay_reset(uint32_t session_id) {
    ReplayWindow* rw = &g_rw[session_id & 0xffff];
    memset(rw, 0, sizeof(*rw));
}

void fg_replay_stats(uint32_t session_id,
                     uint64_t* accepted, uint64_t* blocked) {
    ReplayWindow* rw = &g_rw[session_id & 0xffff];
    if (accepted) *accepted = rw->accepted;
    if (blocked)  *blocked  = rw->replays_blocked;
}
