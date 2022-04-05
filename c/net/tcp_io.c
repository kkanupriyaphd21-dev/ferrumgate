#include "../include/net.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int fg_tcp_listen(int port, int backlog) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    bool ipv6 = true;
    if (fd < 0) { fd = socket(AF_INET, SOCK_STREAM, 0); ipv6 = false; }
    if (fd < 0) return FG_ERR_IO;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (ipv6) {
        /* allow IPv4-mapped addresses */
        int no = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));

        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons((uint16_t)port);
        addr.sin6_addr   = in6addr_any;
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd); return FG_ERR_IO;
        }
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((uint16_t)port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd); return FG_ERR_IO;
        }
    }

    if (listen(fd, backlog) < 0) { close(fd); return FG_ERR_IO; }
    return fd;
}

int fg_tcp_accept(int listen_fd, uint32_t* peer_ip4, uint16_t* peer_port) {
    struct sockaddr_in6 peer = {0};
    socklen_t plen = sizeof(peer);
    int client = accept(listen_fd, (struct sockaddr*)&peer, &plen);
    if (client < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }

    if (peer_ip4) {
        if (peer.sin6_family == AF_INET6) {
            /* extract IPv4-mapped */
            const uint8_t* a = (const uint8_t*)&peer.sin6_addr;
            if (a[10]==0xFF && a[11]==0xFF)
                *peer_ip4 = ((uint32_t)a[12]<<24)|((uint32_t)a[13]<<16)|
                            ((uint32_t)a[14]<<8)|a[15];
            else
                *peer_ip4 = 0;
        }
    }
    if (peer_port) *peer_port = ntohs(peer.sin6_port);
    return client;
}

ssize_t fg_tcp_read(int fd, uint8_t* buf, size_t len) {
    ssize_t n;
    do { n = read(fd, buf, len); } while (n < 0 && errno == EINTR);
    if (n == 0) return FG_ERR_CLOSED;
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }
    return n;
}

ssize_t fg_tcp_write(int fd, const uint8_t* buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return FG_ERR_IO;
        }
        if (n == 0) return FG_ERR_CLOSED;
        written += n;
    }
    return (ssize_t)written;
}

void fg_tcp_close(int fd) {
    if (fd >= 0) close(fd);
}

int fg_set_tcp_nodelay(int fd) {
    int yes = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == 0 ?
           FG_OK : FG_ERR_IO;
}

int fg_set_keepalive(int fd, int idle_s, int intvl_s, int cnt) {
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) != 0)
        return FG_ERR_IO;
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle_s, sizeof(idle_s));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl_s,sizeof(intvl_s));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,    sizeof(cnt));
#endif
    return FG_OK;
}
