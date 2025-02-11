#include "../include/ffi.h"
#include "../include/ferrumgate.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

const char* fg_ffi_version(void) { return fg_version(); }

int fg_ffi_chacha20poly1305_encrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* plain, size_t plain_len,
                                     uint8_t* out, size_t* out_len,
                                     const uint8_t* aad, size_t aad_len) {
    return fg_chacha20poly1305_encrypt(key, nonce, plain, plain_len,
                                        out, out_len, aad, aad_len);
}

int fg_ffi_chacha20poly1305_decrypt(const uint8_t* key, const uint8_t* nonce,
                                     const uint8_t* cipher, size_t cipher_len,
                                     uint8_t* out, size_t* out_len,
                                     const uint8_t* aad, size_t aad_len) {
    /* auth then decrypt */
    if (cipher_len < 16) return FG_ERR_INVAL;
    uint8_t tmp[65536];
    size_t tmp_len = sizeof(tmp);
    int rc = fg_chacha20poly1305_encrypt(key, nonce, cipher, cipher_len - 16,
                                          tmp, &tmp_len, aad, aad_len);
    if (rc != FG_OK) return rc;
    if (memcmp(tmp + cipher_len - 16, cipher + cipher_len - 16, 16) != 0)
        return FG_ERR_AUTH;
    memcpy(out, cipher, cipher_len - 16);
    *out_len = cipher_len - 16;
    return FG_OK;
}

int fg_ffi_x25519_keygen(uint8_t priv_out[32], uint8_t pub_out[32]) {
    return fg_x25519_keygen(priv_out, pub_out);
}

int fg_ffi_x25519_dh(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]) {
    return fg_x25519(out, priv, pub);
}

int fg_ffi_udp_open(uint16_t port) {
    int fd;
    int rc = fg_udp_socket_create(port, &fd);
    return rc == FG_OK ? fd : rc;
}

ssize_t fg_ffi_udp_recv(int fd, uint8_t* buf, size_t len,
                         uint32_t* src_ip, uint16_t* src_port) {
    return fg_udp_recv(fd, buf, len, src_ip, src_port);
}

ssize_t fg_ffi_udp_send(int fd, const uint8_t* buf, size_t len,
                         uint32_t dst_ip, uint16_t dst_port) {
    return fg_udp_send(fd, buf, len, dst_ip, dst_port);
}

void fg_ffi_udp_close(int fd) { fg_udp_close(fd); }

int fg_ffi_tun_open(const char* name, char* actual_out) {
    int fd;
    int rc = fg_tun_open(name, &fd, actual_out);
    return rc == FG_OK ? fd : rc;
}

ssize_t fg_ffi_tun_read(int fd, uint8_t* buf, size_t len) {
    return fg_tun_read(fd, buf, len);
}

ssize_t fg_ffi_tun_write(int fd, const uint8_t* buf, size_t len) {
    return fg_tun_write(fd, buf, len);
}

int fg_ffi_filter_add_allow(uint32_t src_ip, uint32_t mask,
                              uint16_t port_lo, uint16_t port_hi, uint8_t proto) {
    return fg_filter_add_rule(src_ip, mask, 0, 0, port_lo, port_hi, proto, 0);
}

int fg_ffi_filter_packet(const uint8_t* pkt, size_t len) {
    return fg_filter_packet(pkt, len);
}
