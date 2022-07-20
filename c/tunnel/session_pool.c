#include "../include/tunnel.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#define POOL_HASH_SIZE 4096
#define POOL_HASH_MASK (POOL_HASH_SIZE - 1)

typedef struct PoolEntry {
    uint32_t        session_id;
    FgSession*      session;
    struct PoolEntry* next;
} PoolEntry;

typedef struct {
    PoolEntry*      buckets[POOL_HASH_SIZE];
    pthread_rwlock_t lock;
    uint32_t        count;
    uint32_t        max_count;
    uint64_t        hits;
    uint64_t        misses;
    uint64_t        evictions;
} SessionPool;

static SessionPool* g_pool = NULL;

static uint32_t hash_id(uint32_t id) {
    /* Murmur3 finalizer */
    id ^= id >> 16;
    id *= 0x85ebca6b;
    id ^= id >> 13;
    id *= 0xc2b2ae35;
    id ^= id >> 16;
    return id & POOL_HASH_MASK;
}

int fg_pool_init(uint32_t max_sessions) {
    if (g_pool) return FG_ERR_INVAL;

    g_pool = calloc(1, sizeof(SessionPool));
    if (!g_pool) return FG_ERR_NOMEM;

    g_pool->max_count = max_sessions > 0 ? max_sessions : FG_MAX_SESSIONS;
    pthread_rwlock_init(&g_pool->lock, NULL);
    return FG_OK;
}

void fg_pool_destroy(void) {
    if (!g_pool) return;
    pthread_rwlock_wrlock(&g_pool->lock);

    for (int i = 0; i < POOL_HASH_SIZE; i++) {
        PoolEntry* e = g_pool->buckets[i];
        while (e) {
            PoolEntry* next = e->next;
            fg_session_free(e->session);
            free(e);
            e = next;
        }
    }

    pthread_rwlock_unlock(&g_pool->lock);
    pthread_rwlock_destroy(&g_pool->lock);
    free(g_pool);
    g_pool = NULL;
}

int fg_pool_insert(FgSession* s) {
    if (!g_pool || !s) return FG_ERR_INVAL;

    FgSessionInfo info;
    if (fg_session_get_info(s, &info) != FG_OK) return FG_ERR_INVAL;

    pthread_rwlock_wrlock(&g_pool->lock);

    if (g_pool->count >= g_pool->max_count) {
        pthread_rwlock_unlock(&g_pool->lock);
        return FG_ERR_NOMEM;
    }

    uint32_t h = hash_id(info.numeric_id);
    PoolEntry* entry = malloc(sizeof(PoolEntry));
    if (!entry) {
        pthread_rwlock_unlock(&g_pool->lock);
        return FG_ERR_NOMEM;
    }

    entry->session_id = info.numeric_id;
    entry->session    = s;
    entry->next       = g_pool->buckets[h];
    g_pool->buckets[h] = entry;
    g_pool->count++;

    pthread_rwlock_unlock(&g_pool->lock);
    return FG_OK;
}

FgSession* fg_pool_lookup(uint32_t session_id) {
    if (!g_pool) return NULL;

    uint32_t h = hash_id(session_id);
    pthread_rwlock_rdlock(&g_pool->lock);

    PoolEntry* e = g_pool->buckets[h];
    while (e) {
        if (e->session_id == session_id) {
            FgSession* s = e->session;
            g_pool->hits++;
            pthread_rwlock_unlock(&g_pool->lock);
            return s;
        }
        e = e->next;
    }

    g_pool->misses++;
    pthread_rwlock_unlock(&g_pool->lock);
    return NULL;
}

int fg_pool_remove(uint32_t session_id) {
    if (!g_pool) return FG_ERR_INVAL;

    uint32_t h = hash_id(session_id);
    pthread_rwlock_wrlock(&g_pool->lock);

    PoolEntry** pp = &g_pool->buckets[h];
    while (*pp) {
        if ((*pp)->session_id == session_id) {
            PoolEntry* del = *pp;
            *pp = del->next;
            fg_session_free(del->session);
            free(del);
            g_pool->count--;
            pthread_rwlock_unlock(&g_pool->lock);
            return FG_OK;
        }
        pp = &(*pp)->next;
    }

    pthread_rwlock_unlock(&g_pool->lock);
    return FG_ERR_INVAL;
}

void fg_pool_evict_expired(uint64_t now_ms) {
    if (!g_pool) return;
    pthread_rwlock_wrlock(&g_pool->lock);

    for (int i = 0; i < POOL_HASH_SIZE; i++) {
        PoolEntry** pp = &g_pool->buckets[i];
        while (*pp) {
            if (fg_session_is_expired((*pp)->session, now_ms)) {
                PoolEntry* del = *pp;
                *pp = del->next;
                fg_session_free(del->session);
                free(del);
                g_pool->count--;
                g_pool->evictions++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    pthread_rwlock_unlock(&g_pool->lock);
}

uint32_t fg_pool_count(void) {
    return g_pool ? g_pool->count : 0;
}
