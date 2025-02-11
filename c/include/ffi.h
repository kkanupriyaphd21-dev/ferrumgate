#pragma once
/* C FFI interface for Rust → C interop via ferrumgate-sys crate */
#include "ferrumgate.h"
#include "crypto.h"
#include "packet.h"
#include "tunnel.h"
#include "net.h"
#include "sys.h"
#include "buffer.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version query */
const char* fg_ffi_version(void);

/* Crypto FFI */
int  fg_ffi_chacha20poly1305_encrypt(const uint8_t* key, const uint8_t* nonce,
                                      const uint8_t* plain, size_t plain_len,
                                      uint8_t* out, size_t* out_len,
                                      const uint8_t* aad, size_t aad_len);
int  fg_ffi_chacha20poly1305_decrypt(const uint8_t* key, const uint8_t* nonce,
                                      const uint8_t* cipher, size_t cipher_len,
                                      uint8_t* out, size_t* out_len,
                                      const uint8_t* aad, size_t aad_len);
int  fg_ffi_x25519_keygen(uint8_t priv_out[32], uint8_t pub_out[32]);
int  fg_ffi_x25519_dh(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);

/* Tunnel FFI */
int      fg_ffi_session_new(uint32_t* id_out);
int      fg_ffi_session_encrypt(uint32_t id, const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t* out_len);
int      fg_ffi_session_decrypt(uint32_t id, const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t* out_len);
void     fg_ffi_session_close(uint32_t id);

/* Network FFI */
int      fg_ffi_udp_open(uint16_t port);
ssize_t  fg_ffi_udp_recv(int fd, uint8_t* buf, size_t len,
                          uint32_t* src_ip, uint16_t* src_port);
ssize_t  fg_ffi_udp_send(int fd, const uint8_t* buf, size_t len,
                          uint32_t dst_ip, uint16_t dst_port);
void     fg_ffi_udp_close(int fd);

/* System FFI */
int      fg_ffi_tun_open(const char* name, char* actual_out);
ssize_t  fg_ffi_tun_read(int fd, uint8_t* buf, size_t len);
ssize_t  fg_ffi_tun_write(int fd, const uint8_t* buf, size_t len);

/* Packet filter FFI */
int      fg_ffi_filter_add_allow(uint32_t src_ip, uint32_t mask,
                                  uint16_t port_lo, uint16_t port_hi, uint8_t proto);
int      fg_ffi_filter_packet(const uint8_t* pkt, size_t len);

#ifdef __cplusplus
}
#endif
