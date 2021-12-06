#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FERRUMGATE_VERSION_MAJOR 2
#define FERRUMGATE_VERSION_MINOR 0
#define FERRUMGATE_VERSION_PATCH 0

/* Error codes */
#define FG_OK            0
#define FG_ERR_INVAL    -1
#define FG_ERR_NOMEM    -2
#define FG_ERR_IO       -3
#define FG_ERR_TIMEOUT  -4
#define FG_ERR_CRYPTO   -5
#define FG_ERR_PROTO    -6
#define FG_ERR_CLOSED   -7

/* Tunnel types */
typedef enum {
    FG_TUNNEL_UDP   = 0,
    FG_TUNNEL_TCP   = 1,
    FG_TUNNEL_QUIC  = 2,
} FgTunnelType;

/* Packet direction */
typedef enum {
    FG_DIR_INBOUND  = 0,
    FG_DIR_OUTBOUND = 1,
} FgDirection;

/* Opaque handles */
typedef struct FgContext  FgContext;
typedef struct FgSession  FgSession;
typedef struct FgTunnel   FgTunnel;
typedef struct FgPacket   FgPacket;

/* Initialise / teardown */
FgContext* fg_context_new(void);
void       fg_context_free(FgContext* ctx);

int fg_init(FgContext* ctx, const char* config_path);
void fg_shutdown(FgContext* ctx);

const char* fg_version(void);
const char* fg_strerror(int code);

#ifdef __cplusplus
}
#endif
