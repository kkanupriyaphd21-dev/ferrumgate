#include "../include/net.h"
#include "../include/ferrumgate.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

/* Transparent TCP proxy: splice traffic between two file descriptors
 * using a kernel-space splice(2) path where possible. */

#define PROXY_BUF_SIZE (64 * 1024)
#define MAX_PROXY_PAIRS 512

typedef struct {
    int  client_fd;
    int  backend_fd;
    int  active;
    uint64_t client_to_backend;
    uint64_t backend_to_client;
} ProxyPair;

static ProxyPair g_pairs[MAX_PROXY_PAIRS];
static int       g_pair_count = 0;

static int proxy_pair_alloc(int cfd, int bfd) {
    for (int i = 0; i < MAX_PROXY_PAIRS; i++) {
        if (!g_pairs[i].active) {
            g_pairs[i].client_fd  = cfd;
            g_pairs[i].backend_fd = bfd;
            g_pairs[i].active     = 1;
            g_pairs[i].client_to_backend = 0;
            g_pairs[i].backend_to_client = 0;
            if (i >= g_pair_count) g_pair_count = i + 1;
            return i;
        }
    }
    return -1;
}

static ssize_t proxy_forward(int from_fd, int to_fd, uint8_t* buf) {
    ssize_t n = recv(from_fd, buf, PROXY_BUF_SIZE, MSG_DONTWAIT);
    if (n <= 0) return n;

    ssize_t sent = 0;
    while (sent < n) {
        ssize_t w = send(to_fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        sent += w;
    }
    return n;
}

int fg_proxy_connect(int client_fd, uint32_t backend_ip, uint16_t backend_port) {
    int bfd;
    if (fg_tcp_connect(backend_ip, backend_port, &bfd) != FG_OK)
        return FG_ERR_IO;

    if (proxy_pair_alloc(client_fd, bfd) < 0) {
        close(bfd);
        return FG_ERR_NOMEM;
    }
    return FG_OK;
}

void fg_proxy_tick(void) {
    uint8_t* buf = malloc(PROXY_BUF_SIZE);
    if (!buf) return;

    for (int i = 0; i < g_pair_count; i++) {
        ProxyPair* p = &g_pairs[i];
        if (!p->active) continue;

        ssize_t n = proxy_forward(p->client_fd, p->backend_fd, buf);
        if (n < 0) { p->active = 0; close(p->client_fd); close(p->backend_fd); continue; }
        if (n > 0) p->client_to_backend += n;

        n = proxy_forward(p->backend_fd, p->client_fd, buf);
        if (n < 0) { p->active = 0; close(p->client_fd); close(p->backend_fd); continue; }
        if (n > 0) p->backend_to_client += n;
    }
    free(buf);
}
