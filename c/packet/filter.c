#include "../include/packet.h"
#include "../include/ferrumgate.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RULES 1024

typedef enum {
    FG_RULE_ALLOW = 0,
    FG_RULE_DENY  = 1,
} FgRuleAction;

typedef struct {
    uint32_t    src_ip;
    uint32_t    src_mask;
    uint32_t    dst_ip;
    uint32_t    dst_mask;
    uint16_t    src_port_lo;
    uint16_t    src_port_hi;
    uint16_t    dst_port_lo;
    uint16_t    dst_port_hi;
    uint8_t     protocol;   /* 0 = any */
    FgRuleAction action;
    uint64_t    hit_count;
    bool        enabled;
} FgFilterRule;

typedef struct {
    FgFilterRule rules[MAX_RULES];
    int          count;
    FgRuleAction default_action;
    uint64_t     total_packets;
    uint64_t     allowed;
    uint64_t     denied;
} FgPacketFilter;

static FgPacketFilter g_filter = {
    .count          = 0,
    .default_action = FG_RULE_ALLOW,
};

int fg_filter_add_rule(uint32_t src_ip, uint32_t src_mask,
                        uint32_t dst_ip, uint32_t dst_mask,
                        uint16_t dst_port_lo, uint16_t dst_port_hi,
                        uint8_t proto, FgRuleAction action) {
    if (g_filter.count >= MAX_RULES) return FG_ERR_NOMEM;

    FgFilterRule* r = &g_filter.rules[g_filter.count++];
    r->src_ip      = src_ip;
    r->src_mask    = src_mask;
    r->dst_ip      = dst_ip;
    r->dst_mask    = dst_mask;
    r->dst_port_lo = dst_port_lo;
    r->dst_port_hi = dst_port_hi;
    r->src_port_lo = 0;
    r->src_port_hi = 65535;
    r->protocol    = proto;
    r->action      = action;
    r->hit_count   = 0;
    r->enabled     = true;
    return FG_OK;
}

static bool rule_matches(const FgFilterRule* r, const FgPacketInfo* pkt) {
    if (!r->enabled) return false;
    if (pkt->version != 4) return false; /* IPv4 only for now */

    if (r->src_ip && (pkt->src_ip4 & r->src_mask) != (r->src_ip & r->src_mask))
        return false;
    if (r->dst_ip && (pkt->dst_ip4 & r->dst_mask) != (r->dst_ip & r->dst_mask))
        return false;
    if (r->protocol && pkt->protocol != r->protocol)
        return false;
    if (pkt->dst_port < r->dst_port_lo || pkt->dst_port > r->dst_port_hi)
        return false;
    if (pkt->src_port < r->src_port_lo || pkt->src_port > r->src_port_hi)
        return false;

    return true;
}

/* Returns FG_RULE_ALLOW (0) or FG_RULE_DENY (1) */
int fg_filter_packet(const uint8_t* buf, size_t len) {
    FgPacketInfo pkt;
    g_filter.total_packets++;

    if (fg_parse_packet(buf, len, &pkt) != FG_OK) {
        g_filter.denied++;
        return FG_RULE_DENY;
    }

    for (int i = 0; i < g_filter.count; i++) {
        if (rule_matches(&g_filter.rules[i], &pkt)) {
            g_filter.rules[i].hit_count++;
            if (g_filter.rules[i].action == FG_RULE_ALLOW) {
                g_filter.allowed++;
                return FG_RULE_ALLOW;
            } else {
                g_filter.denied++;
                return FG_RULE_DENY;
            }
        }
    }

    /* default policy */
    if (g_filter.default_action == FG_RULE_ALLOW)
        g_filter.allowed++;
    else
        g_filter.denied++;

    return g_filter.default_action;
}

void fg_filter_set_default(FgRuleAction action) {
    g_filter.default_action = action;
}

void fg_filter_clear(void) {
    g_filter.count = 0;
    g_filter.total_packets = 0;
    g_filter.allowed = 0;
    g_filter.denied  = 0;
}

void fg_filter_stats(uint64_t* total, uint64_t* allowed, uint64_t* denied) {
    if (total)   *total   = g_filter.total_packets;
    if (allowed) *allowed = g_filter.allowed;
    if (denied)  *denied  = g_filter.denied;
}
