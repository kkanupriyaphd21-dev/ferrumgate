#pragma once
#include "ferrumgate.h"
#include <linux/if.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int     fg_tun_open(const char* name, int* fd_out, char* actual_name);
ssize_t fg_tun_read(int fd, uint8_t* buf, size_t len);
ssize_t fg_tun_write(int fd, const uint8_t* buf, size_t len);
int     fg_tun_set_mtu(const char* name, int mtu);
int     fg_tun_set_up(const char* name);
void    fg_tun_close(int fd);

/* Routing */
int fg_route_add(const char* iface, uint32_t dst, uint8_t prefix_len, uint32_t gw);
int fg_route_del(const char* iface, uint32_t dst, uint8_t prefix_len);

/* Firewall / nftables bridge */
int fg_nft_add_rule(const char* table, const char* chain, const char* rule);
int fg_nft_del_rule(const char* table, const char* chain, uint64_t handle);
int fg_nft_flush_chain(const char* table, const char* chain);

#ifdef __cplusplus
}
#endif
