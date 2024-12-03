#include "../include/ferrumgate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

/* Connection flow table — 5-tuple tracking for stateful firewalling */

#define FLOW_TABLE_BITS 14
#define FLOW_TABLE_SIZE (1 << FLOW_TABLE_BITS)
#define FLOW_TABLE_MASK (FLOW_TABLE_SIZE - 1)
#define FLOW_TTL_S      120

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} FlowKey;

typedef enum {
    FLOW_STATE_NEW = 0,
    FLOW_STATE_ESTABLISHED,
    FLOW_STATE_CLOSING,
    FLOW_STATE_CLOSED,
} FlowState;

typedef struct FlowEntry {
    FlowKey          key;
    FlowState        state;
    time_t           last_seen;
    uint64_t         bytes_fwd;
    uint64_t         bytes_rev;
    uint64_t         pkts_fwd;
    struct FlowEntry* next;
} FlowEntry;

typedef struct {
    FlowEntry*      buckets[FLOW_TABLE_SIZE];
    pthread_rwlock_t lock;
    uint32_t        count;
    uint64_t        hits;
    uint64_t        misses;
    uint64_t        evictions;
} FlowTable;

static FlowTable g_ft;
static bool      g_ft_init = false;

void fg_flow_init(void) {
    memset(&g_ft, 0, sizeof(g_ft));
    pthread_rwlock_init(&g_ft.lock, NULL);
    g_ft_init = true;
}

static uint32_t flow_hash(const FlowKey* k) {
    uint32_t h = k->src_ip ^ k->dst_ip;
    h ^= ((uint32_t)k->src_port << 16) | k->dst_port;
    h ^= k->proto;
    h ^= h >> 16; h *= 0x45d9f3b; h ^= h >> 16;
    return h & FLOW_TABLE_MASK;
}

static bool key_eq(const FlowKey* a, const FlowKey* b) {
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

FlowEntry* fg_flow_lookup(uint32_t sip, uint32_t dip,
                           uint16_t sp, uint16_t dp, uint8_t proto) {
    if (!g_ft_init) return NULL;
    FlowKey k = {sip, dip, sp, dp, proto};
    uint32_t h = flow_hash(&k);

    pthread_rwlock_rdlock(&g_ft.lock);
    FlowEntry* e = g_ft.buckets[h];
    while (e) {
        if (key_eq(&e->key, &k)) { g_ft.hits++; pthread_rwlock_unlock(&g_ft.lock); return e; }
        e = e->next;
    }
    g_ft.misses++;
    pthread_rwlock_unlock(&g_ft.lock);
    return NULL;
}

int fg_flow_insert(uint32_t sip, uint32_t dip,
                    uint16_t sp, uint16_t dp, uint8_t proto) {
    FlowKey k = {sip, dip, sp, dp, proto};
    uint32_t h = flow_hash(&k);

    pthread_rwlock_wrlock(&g_ft.lock);
    FlowEntry* e = malloc(sizeof(FlowEntry));
    if (!e) { pthread_rwlock_unlock(&g_ft.lock); return FG_ERR_NOMEM; }
    e->key       = k;
    e->state     = FLOW_STATE_NEW;
    e->last_seen = time(NULL);
    e->bytes_fwd = e->bytes_rev = e->pkts_fwd = 0;
    e->next      = g_ft.buckets[h];
    g_ft.buckets[h] = e;
    g_ft.count++;
    pthread_rwlock_unlock(&g_ft.lock);
    return FG_OK;
}

void fg_flow_evict_stale(void) {
    time_t cutoff = time(NULL) - FLOW_TTL_S;
    pthread_rwlock_wrlock(&g_ft.lock);
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        FlowEntry** pp = &g_ft.buckets[i];
        while (*pp) {
            if ((*pp)->last_seen < cutoff) {
                FlowEntry* del = *pp; *pp = del->next;
                free(del); g_ft.count--; g_ft.evictions++;
            } else pp = &(*pp)->next;
        }
    }
    pthread_rwlock_unlock(&g_ft.lock);
}

uint32_t fg_flow_count(void) { return g_ft.count; }
