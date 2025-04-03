cmake_minimum_required(VERSION 3.16)
project(ferrumgate-c VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2 -fPIC)

include_directories(c/include)

set(FG_SOURCES
    c/crypto/aead.c
    c/crypto/hmac.c
    c/crypto/hkdf.c
    c/crypto/x25519.c
    c/crypto/chacha20.c
    c/crypto/aes_gcm.c
    c/crypto/cert_verify.c
    c/packet/parser.c
    c/packet/filter.c
    c/net/udp_io.c
    c/net/tcp_io.c
    c/net/epoll_loop.c
    c/net/ring_buffer.c
    c/net/dns_resolver.c
    c/net/rate_limiter.c
    c/net/multipath.c
    c/net/quic_shim.c
    c/net/tcp_proxy.c
    c/net/flow_table.c
    c/tunnel/session.c
    c/tunnel/session_pool.c
    c/tunnel/framing.c
    c/tunnel/handshake.c
    c/tunnel/congestion.c
    c/tunnel/replay_window.c
    c/tunnel/keepalive.c
    c/tunnel/fragmentation.c
    c/sys/tun_device.c
    c/sys/routing.c
    c/sys/nftables.c
    c/sys/cgroup_limiter.c
    c/ffi/ffi_impl.c
)

add_library(ferrumgate_c STATIC ${FG_SOURCES})
target_link_libraries(ferrumgate_c pthread)

add_library(ferrumgate_c_shared SHARED ${FG_SOURCES})
target_link_libraries(ferrumgate_c_shared pthread)
set_target_properties(ferrumgate_c_shared PROPERTIES OUTPUT_NAME ferrumgate_c)
