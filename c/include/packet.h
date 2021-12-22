#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FG_MAX_PACKET_SIZE   65536
#define FG_TUNNEL_HDR_LEN    24
#define FG_IP4_HDR_MIN_LEN   20
#define FG_IP6_HDR_LEN       40
#define FG_UDP_HDR_LEN        8
#define FG_TCP_HDR_MIN_LEN   20

typedef struct {
    uint8_t  version;       /* 4 or 6 */
    uint8_t  protocol;      /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t src_ip4;
    uint32_t dst_ip4;
    uint8_t  src_ip6[16];
    uint8_t  dst_ip6[16];
    uint32_t seq;           /* TCP sequence (if TCP) */
    uint32_t ack;
    uint8_t  flags;         /* TCP flags */
    uint16_t window;
    uint16_t payload_off;
    uint16_t payload_len;
    uint8_t  ttl;
    uint8_t  dscp;
} FgPacketInfo;

typedef struct {
    uint8_t  type;          /* tunnel packet type */
    uint8_t  flags;
    uint16_t len;
    uint32_t session_id;
    uint64_t seq;
    uint8_t  reserved[8];
} FgTunnelHeader;

int  fg_parse_ip4(const uint8_t* buf, size_t len, FgPacketInfo* out);
int  fg_parse_ip6(const uint8_t* buf, size_t len, FgPacketInfo* out);
int  fg_parse_packet(const uint8_t* buf, size_t len, FgPacketInfo* out);

int  fg_build_tunnel_hdr(FgTunnelHeader* hdr, uint32_t session_id,
                          uint64_t seq, uint8_t type, uint16_t payload_len);
int  fg_parse_tunnel_hdr(const uint8_t* buf, size_t len, FgTunnelHeader* out);

bool fg_is_fragment(const FgPacketInfo* pkt);
bool fg_is_valid_ip4(const uint8_t* buf, size_t len);
bool fg_is_valid_ip6(const uint8_t* buf, size_t len);

uint16_t fg_checksum(const uint8_t* buf, size_t len);
uint16_t fg_tcp_checksum(const FgPacketInfo* pkt, const uint8_t* payload, size_t len);

#ifdef __cplusplus
}
#endif
