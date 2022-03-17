#include "../include/ferrumgate.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return FG_ERR_IO;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? FG_OK : FG_ERR_IO;
}

static int set_reuseaddr(int fd) {
    int yes = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == 0 ?
           FG_OK : FG_ERR_IO;
}

static int set_rcvbuf(int fd, int size) {
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0 ?
           FG_OK : FG_ERR_IO;
}

int fg_udp_socket_create(int port, bool nonblocking) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        /* fallback to IPv4 */
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return FG_ERR_IO;
    }

    set_reuseaddr(fd);
    set_rcvbuf(fd, 4 * 1024 * 1024); /* 4MB recv buffer */

    if (nonblocking) {
        if (set_nonblocking(fd) != FG_OK) {
            close(fd);
            return FG_ERR_IO;
        }
    }

    if (port > 0) {
        struct sockaddr_in6 addr6 = {0};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port   = htons((uint16_t)port);
        addr6.sin6_addr   = in6addr_any;

        if (bind(fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            /* fallback to IPv4 */
            close(fd);
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            set_reuseaddr(fd);
            if (nonblocking) set_nonblocking(fd);

            struct sockaddr_in addr4 = {0};
            addr4.sin_family      = AF_INET;
            addr4.sin_port        = htons((uint16_t)port);
            addr4.sin_addr.s_addr = INADDR_ANY;

            if (bind(fd, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
                close(fd);
                return FG_ERR_IO;
            }
        }
    }

    return fd;
}

ssize_t fg_udp_recv(int fd, uint8_t* buf, size_t buf_len,
                    uint32_t* src_ip4, uint16_t* src_port) {
    struct sockaddr_in src_addr = {0};
    socklen_t addr_len = sizeof(src_addr);

    ssize_t n = recvfrom(fd, buf, buf_len, 0,
                          (struct sockaddr*)&src_addr, &addr_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }

    if (src_ip4)   *src_ip4   = ntohl(src_addr.sin_addr.s_addr);
    if (src_port)  *src_port  = ntohs(src_addr.sin_port);
    return n;
}

ssize_t fg_udp_send(int fd, const uint8_t* buf, size_t len,
                    uint32_t dst_ip4, uint16_t dst_port) {
    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(dst_port);
    dst.sin_addr.s_addr = htonl(dst_ip4);

    ssize_t n = sendto(fd, buf, len, 0,
                        (struct sockaddr*)&dst, sizeof(dst));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return FG_ERR_IO;
    }
    return n;
}

void fg_udp_close(int fd) {
    if (fd >= 0) close(fd);
}
