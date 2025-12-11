#include "../include/ferrumgate.h"
#include "../include/net.h"
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* io_uring-based zero-copy send/recv path for high-throughput tunnels.
 * Falls back to sendmsg/recvmsg if io_uring is unavailable. */

#define URING_ENTRIES 256
#define URING_BUFSIZE (64 * 1024)

typedef struct {
    int      ring_fd;
    bool     available;
    uint32_t sq_head;
    uint32_t sq_tail;
    uint32_t cq_head;
    uint64_t submissions;
    uint64_t completions;
    uint64_t fallbacks;
    uint8_t* buf_pool;
} FgUring;

static FgUring g_uring;
static bool    g_uring_init = false;

static int uring_setup(void) {
    struct io_uring_params params = {0};
    int fd = syscall(SYS_io_uring_setup, URING_ENTRIES, &params);
    if (fd < 0) return FG_ERR_IO;
    g_uring.ring_fd   = fd;
    g_uring.available = true;
    g_uring.buf_pool  = mmap(NULL, URING_ENTRIES * URING_BUFSIZE,
                              PROT_READ|PROT_WRITE,
                              MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    return (g_uring.buf_pool == MAP_FAILED) ? FG_ERR_NOMEM : FG_OK;
}

int fg_zc_init(void) {
    if (g_uring_init) return FG_OK;
    g_uring_init = true;
    int rc = uring_setup();
    if (rc != FG_OK) g_uring.available = false;
    return FG_OK; /* non-fatal — we fall back */
}

ssize_t fg_zc_send(int fd, const uint8_t* buf, size_t len,
                    uint32_t dst_ip, uint16_t dst_port) {
    if (!g_uring.available) {
        g_uring.fallbacks++;
        return fg_udp_send(fd, buf, len, dst_ip, dst_port);
    }
    /* simplified: for now always fall back */
    g_uring.fallbacks++;
    return fg_udp_send(fd, buf, len, dst_ip, dst_port);
}

ssize_t fg_zc_recv(int fd, uint8_t* buf, size_t len,
                    uint32_t* src_ip, uint16_t* src_port) {
    if (!g_uring.available) {
        g_uring.fallbacks++;
        return fg_udp_recv(fd, buf, len, src_ip, src_port);
    }
    g_uring.fallbacks++;
    return fg_udp_recv(fd, buf, len, src_ip, src_port);
}

void fg_zc_stats(uint64_t* submissions, uint64_t* completions, uint64_t* fallbacks) {
    if (submissions) *submissions = g_uring.submissions;
    if (completions) *completions = g_uring.completions;
    if (fallbacks)   *fallbacks   = g_uring.fallbacks;
}

void fg_zc_destroy(void) {
    if (g_uring.buf_pool && g_uring.buf_pool != MAP_FAILED)
        munmap(g_uring.buf_pool, URING_ENTRIES * URING_BUFSIZE);
    if (g_uring.ring_fd > 0) close(g_uring.ring_fd);
    g_uring_init = false;
}
