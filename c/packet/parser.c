#include "../include/packet.h"
#include <string.h>
#include <arpa/inet.h>

#define IP4_VERSION(b)  (((b)[0] >> 4) & 0xF)
#define IP4_IHL(b)      ((b)[0] & 0xF)
#define IP6_VERSION(b)  (((b)[0] >> 4) & 0xF)

bool fg_is_valid_ip4(const uint8_t* buf, size_t len) {
    if (!buf || len < FG_IP4_HDR_MIN_LEN) return false;
    if (IP4_VERSION(buf) != 4) return false;
    int ihl = IP4_IHL(buf) * 4;
    if (ihl < FG_IP4_HDR_MIN_LEN || (size_t)ihl > len) return false;
    return true;
}

bool fg_is_valid_ip6(const uint8_t* buf, size_t len) {
    if (!buf || len < FG_IP6_HDR_LEN) return false;
    return IP6_VERSION(buf) == 6;
}

bool fg_is_fragment(const FgPacketInfo* pkt) {
    if (!pkt || pkt->version != 4) return false;
    /* fragmentation offset / MF flag would be checked here */
    return false;
}

uint16_t fg_checksum(const uint8_t* buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t* p = (const uint16_t*)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

int fg_parse_ip4(const uint8_t* buf, size_t len, FgPacketInfo* out) {
    if (!fg_is_valid_ip4(buf, len)) return FG_ERR_INVAL;
    if (!out) return FG_ERR_INVAL;

    memset(out, 0, sizeof(*out));
    out->version  = 4;
    out->ttl      = buf[8];
    out->protocol = buf[9];
    out->dscp     = (buf[1] >> 2) & 0x3F;

    memcpy(&out->src_ip4, buf + 12, 4);
    memcpy(&out->dst_ip4, buf + 16, 4);
    out->src_ip4 = ntohl(out->src_ip4);
    out->dst_ip4 = ntohl(out->dst_ip4);

    int ihl = IP4_IHL(buf) * 4;
    const uint8_t* transport = buf + ihl;
    size_t tlen = len - ihl;

    if (out->protocol == 6 && tlen >= FG_TCP_HDR_MIN_LEN) {
        out->src_port = (transport[0] << 8) | transport[1];
        out->dst_port = (transport[2] << 8) | transport[3];
        out->seq      = ((uint32_t)transport[4]<<24)|((uint32_t)transport[5]<<16)|
                        ((uint32_t)transport[6]<<8)|transport[7];
        out->ack      = ((uint32_t)transport[8]<<24)|((uint32_t)transport[9]<<16)|
                        ((uint32_t)transport[10]<<8)|transport[11];
        out->flags    = transport[13];
        out->window   = (transport[14]<<8)|transport[15];
        int doff = (transport[12] >> 4) * 4;
        out->payload_off = (uint16_t)(ihl + doff);
        out->payload_len = (uint16_t)(len - out->payload_off);
    } else if (out->protocol == 17 && tlen >= FG_UDP_HDR_LEN) {
        out->src_port    = (transport[0] << 8) | transport[1];
        out->dst_port    = (transport[2] << 8) | transport[3];
        out->payload_off = (uint16_t)(ihl + FG_UDP_HDR_LEN);
        out->payload_len = (uint16_t)((transport[4]<<8)|transport[5]) - FG_UDP_HDR_LEN;
    }

    return FG_OK;
}

int fg_parse_ip6(const uint8_t* buf, size_t len, FgPacketInfo* out) {
    if (!fg_is_valid_ip6(buf, len)) return FG_ERR_INVAL;
    if (!out) return FG_ERR_INVAL;

    memset(out, 0, sizeof(*out));
    out->version  = 6;
    out->protocol = buf[6];
    out->ttl      = buf[7]; /* hop limit */
    out->dscp     = ((buf[0] & 0x0F) << 2) | (buf[1] >> 6);

    memcpy(out->src_ip6, buf + 8,  16);
    memcpy(out->dst_ip6, buf + 24, 16);

    const uint8_t* transport = buf + FG_IP6_HDR_LEN;
    size_t tlen = len - FG_IP6_HDR_LEN;

    if (out->protocol == 17 && tlen >= FG_UDP_HDR_LEN) {
        out->src_port    = (transport[0] << 8) | transport[1];
        out->dst_port    = (transport[2] << 8) | transport[3];
        out->payload_off = (uint16_t)(FG_IP6_HDR_LEN + FG_UDP_HDR_LEN);
        out->payload_len = (uint16_t)((transport[4]<<8)|transport[5]) - FG_UDP_HDR_LEN;
    } else if (out->protocol == 6 && tlen >= FG_TCP_HDR_MIN_LEN) {
        out->src_port = (transport[0] << 8) | transport[1];
        out->dst_port = (transport[2] << 8) | transport[3];
        int doff = (transport[12] >> 4) * 4;
        out->payload_off = (uint16_t)(FG_IP6_HDR_LEN + doff);
        out->payload_len = (uint16_t)(len - out->payload_off);
    }

    return FG_OK;
}

int fg_parse_packet(const uint8_t* buf, size_t len, FgPacketInfo* out) {
    if (!buf || len < 1 || !out) return FG_ERR_INVAL;
    int ver = (buf[0] >> 4) & 0xF;
    if (ver == 4) return fg_parse_ip4(buf, len, out);
    if (ver == 6) return fg_parse_ip6(buf, len, out);
    return FG_ERR_PROTO;
}

int fg_build_tunnel_hdr(FgTunnelHeader* hdr, uint32_t session_id,
                         uint64_t seq, uint8_t type, uint16_t payload_len) {
    if (!hdr) return FG_ERR_INVAL;
    memset(hdr, 0, sizeof(*hdr));
    hdr->type       = type;
    hdr->len        = payload_len;
    hdr->session_id = session_id;
    hdr->seq        = seq;
    return FG_OK;
}

int fg_parse_tunnel_hdr(const uint8_t* buf, size_t len, FgTunnelHeader* out) {
    if (!buf || len < sizeof(FgTunnelHeader) || !out) return FG_ERR_INVAL;
    memcpy(out, buf, sizeof(FgTunnelHeader));
    return FG_OK;
}
