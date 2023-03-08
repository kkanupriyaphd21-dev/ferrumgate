#include "../include/net.h"
#include "../include/ferrumgate.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>

#define DNS_CACHE_SIZE   512
#define DNS_CACHE_TTL_S  300

typedef struct {
    char     hostname[256];
    uint32_t ipv4;
    uint8_t  ipv6[16];
    int      family;
    time_t   expires;
    uint8_t  valid;
} DnsCacheEntry;

static DnsCacheEntry g_cache[DNS_CACHE_SIZE];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t dns_hash(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h % DNS_CACHE_SIZE;
}

static DnsCacheEntry* cache_lookup(const char* host) {
    uint32_t h = dns_hash(host);
    DnsCacheEntry* e = &g_cache[h];
    if (e->valid && strcmp(e->hostname, host) == 0 && time(NULL) < e->expires)
        return e;
    return NULL;
}

static void cache_insert(const char* host, int family, uint32_t ipv4, const uint8_t* ipv6) {
    uint32_t h = dns_hash(host);
    DnsCacheEntry* e = &g_cache[h];
    strncpy(e->hostname, host, 255);
    e->family  = family;
    e->ipv4    = ipv4;
    if (ipv6) memcpy(e->ipv6, ipv6, 16);
    e->expires = time(NULL) + DNS_CACHE_TTL_S;
    e->valid   = 1;
}

int fg_dns_resolve(const char* hostname, int prefer_family,
                   char* out_ip, size_t out_len) {
    if (!hostname || !out_ip) return FG_ERR_INVAL;

    pthread_mutex_lock(&g_cache_lock);
    DnsCacheEntry* cached = cache_lookup(hostname);
    if (cached) {
        if (cached->family == AF_INET)
            inet_ntop(AF_INET, &cached->ipv4, out_ip, (socklen_t)out_len);
        else
            inet_ntop(AF_INET6, cached->ipv6, out_ip, (socklen_t)out_len);
        pthread_mutex_unlock(&g_cache_lock);
        return FG_OK;
    }
    pthread_mutex_unlock(&g_cache_lock);

    struct addrinfo hints = {0};
    hints.ai_family   = prefer_family ? prefer_family : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0) return FG_ERR_IO;

    struct addrinfo* ai;
    for (ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) break;
    }
    if (!ai) { freeaddrinfo(res); return FG_ERR_IO; }

    uint32_t ipv4 = 0; uint8_t ipv6[16] = {0};
    if (ai->ai_family == AF_INET) {
        struct sockaddr_in* s = (struct sockaddr_in*)ai->ai_addr;
        ipv4 = s->sin_addr.s_addr;
        inet_ntop(AF_INET, &ipv4, out_ip, (socklen_t)out_len);
    } else {
        struct sockaddr_in6* s = (struct sockaddr_in6*)ai->ai_addr;
        memcpy(ipv6, s->sin6_addr.s6_addr, 16);
        inet_ntop(AF_INET6, ipv6, out_ip, (socklen_t)out_len);
    }

    pthread_mutex_lock(&g_cache_lock);
    cache_insert(hostname, ai->ai_family, ipv4, ai->ai_family == AF_INET6 ? ipv6 : NULL);
    pthread_mutex_unlock(&g_cache_lock);

    freeaddrinfo(res);
    return FG_OK;
}

void fg_dns_cache_flush(void) {
    pthread_mutex_lock(&g_cache_lock);
    memset(g_cache, 0, sizeof(g_cache));
    pthread_mutex_unlock(&g_cache_lock);
}

int fg_dns_cache_count(void) {
    int n = 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < DNS_CACHE_SIZE; i++)
        if (g_cache[i].valid && now < g_cache[i].expires) n++;
    pthread_mutex_unlock(&g_cache_lock);
    return n;
}
