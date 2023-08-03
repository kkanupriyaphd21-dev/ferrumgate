#include "../include/sys.h"
#include "../include/ferrumgate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Thin wrapper around nft CLI for firewall rule management.
 * Keeps ferrumgate's packet filter in sync with kernel nftables. */

#define NFT_BIN        "/usr/sbin/nft"
#define NFT_CMD_MAX    512

static int run_nft(const char* cmd) {
    char buf[NFT_CMD_MAX + 64];
    snprintf(buf, sizeof(buf), "%s '%s' 2>/dev/null", NFT_BIN, cmd);
    int rc = system(buf);
    return (rc == 0) ? FG_OK : FG_ERR_IO;
}

int fg_nft_add_rule(const char* table, const char* chain, const char* rule) {
    if (!table || !chain || !rule) return FG_ERR_INVAL;

    char cmd[NFT_CMD_MAX];
    int n = snprintf(cmd, sizeof(cmd),
                     "add rule %s %s %s", table, chain, rule);
    if (n >= (int)sizeof(cmd)) return FG_ERR_INVAL;
    return run_nft(cmd);
}

int fg_nft_del_rule(const char* table, const char* chain, uint64_t handle) {
    if (!table || !chain) return FG_ERR_INVAL;

    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "delete rule %s %s handle %llu",
             table, chain, (unsigned long long)handle);
    return run_nft(cmd);
}

int fg_nft_flush_chain(const char* table, const char* chain) {
    if (!table || !chain) return FG_ERR_INVAL;

    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd), "flush chain %s %s", table, chain);
    return run_nft(cmd);
}

int fg_nft_create_table(const char* table, int family) {
    const char* fam = (family == 6) ? "ip6" : "ip";
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd), "add table %s %s", fam, table);
    return run_nft(cmd);
}

int fg_nft_create_chain(const char* table, const char* chain,
                         const char* type, const char* hook, int priority) {
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "add chain ip %s %s { type %s hook %s priority %d; }",
             table, chain, type, hook, priority);
    return run_nft(cmd);
}

int fg_nft_delete_table(const char* table) {
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd), "delete table ip %s", table);
    return run_nft(cmd);
}

/* Set up the default ferrumgate filter table */
int fg_nft_setup_default(const char* iface) {
    const char* T = "ferrumgate";
    if (fg_nft_create_table(T, 4) != FG_OK) return FG_ERR_IO;

    fg_nft_create_chain(T, "input",   "filter", "input",   0);
    fg_nft_create_chain(T, "forward", "filter", "forward", 0);
    fg_nft_create_chain(T, "output",  "filter", "output",  0);

    /* allow established/related */
    fg_nft_add_rule(T, "input", "ct state established,related accept");
    fg_nft_add_rule(T, "input", "ct state invalid drop");

    if (iface) {
        char rule[256];
        snprintf(rule, sizeof(rule), "iifname \"%s\" accept", iface);
        fg_nft_add_rule(T, "input", rule);
        snprintf(rule, sizeof(rule), "oifname \"%s\" accept", iface);
        fg_nft_add_rule(T, "output", rule);
    }
    return FG_OK;
}
