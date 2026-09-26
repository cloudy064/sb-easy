/* Panel HTTP server. Port of cpp/include/sbeasy/http_server.hpp. */
#ifndef SB_HTTP_SERVER_H
#define SB_HTTP_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_store sb_store;

/* All strings owned; sb_http_server_options_init sets the C++ defaults. */
typedef struct {
    char *address;                 /* "127.0.0.1" */
    uint16_t port;                 /* 51821 */
    size_t threads;                /* 1 */
    char *public_server;           /* "" */
    char *config_hash_seed;        /* "" */
    char *legacy_agent_token;      /* "" */
    char *jwt_secret;              /* "" */
    char *admin_password;          /* "admin" */
    char *clash_api_url;           /* "http://127.0.0.1:9090" */
    char *clash_api_secret;        /* "" */
    bool singbox_managed;          /* false */
    char *singbox_binary;          /* "sing-box" */
    char *self_singbox_config_path;/* "" */
    uint64_t self_singbox_interval_seconds; /* 10 */
    bool singbox_validate_config;  /* true */
    bool wireguard_enabled;        /* false */
    char *wireguard_interface;     /* "wg0" */
    uint16_t wireguard_port;       /* 51820 */
    char *wireguard_address;       /* "10.59.32.1/24" */
    char *wireguard_dns;           /* "10.59.32.1" */
    uint32_t wireguard_mtu;        /* 1420 */
    char *wireguard_egress;        /* "eth0" */
    char *external_hostname;       /* "127.0.0.1" */
    char *wireguard_config_directory; /* "/etc/wireguard" */
    char *static_directory;        /* "frontend/dist" */
    char *cors_origins;            /* "" */
    char *log_level;               /* "info" */
} sb_http_server_options;

void sb_http_server_options_init(sb_http_server_options *o);
void sb_http_server_options_free(sb_http_server_options *o);
void sb_http_server_options_copy(sb_http_server_options *dst, const sb_http_server_options *src);

typedef struct sb_http_server sb_http_server;

/* register_http_routes(): validates options (LOG_LEVEL etc.), ensures the
 * default admin, builds shared state and all routes. Does not listen. */
sb_http_server *sb_http_server_new(sb_store *store, const sb_http_server_options *options,
                                   sb_err *err);
/* Starts listening (civetweb). Returns the bound port (useful with port 0). */
int sb_http_server_start(sb_http_server *srv, sb_err *err);
uint16_t sb_http_server_port(const sb_http_server *srv);
/* run_http_server(): WireGuard startup, routes, managed sing-box thread,
 * listen, block until SIGINT/SIGTERM, then orderly shutdown. */
int sb_http_server_run(sb_store *store, const sb_http_server_options *options, sb_err *err);
void sb_http_server_stop(sb_http_server *srv);
void sb_http_server_free(sb_http_server *srv);

#ifdef __cplusplus
}
#endif

#endif
