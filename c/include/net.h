#pragma once
#include "ferrumgate.h"
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int     fg_udp_socket_create(int port, bool nonblocking);
ssize_t fg_udp_recv(int fd, uint8_t* buf, size_t buf_len,
                    uint32_t* src_ip4, uint16_t* src_port);
ssize_t fg_udp_send(int fd, const uint8_t* buf, size_t len,
                    uint32_t dst_ip4, uint16_t dst_port);
void    fg_udp_close(int fd);

int     fg_tcp_listen(int port, int backlog);
int     fg_tcp_accept(int listen_fd, uint32_t* peer_ip4, uint16_t* peer_port);
ssize_t fg_tcp_read(int fd, uint8_t* buf, size_t len);
ssize_t fg_tcp_write(int fd, const uint8_t* buf, size_t len);
void    fg_tcp_close(int fd);

int fg_set_tcp_nodelay(int fd);
int fg_set_keepalive(int fd, int idle_s, int intvl_s, int cnt);

#ifdef __cplusplus
}
#endif
