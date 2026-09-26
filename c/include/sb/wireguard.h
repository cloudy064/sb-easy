/* WireGuard hub management: key generation, peer / managed-host provisioning,
 * client and hub config generation, kernel sync via `wg`/`ip`, live stats,
 * quota/expiry enforcement and QR SVGs. Port of cpp/include/sbeasy/wireguard.hpp
 * + cpp/src/wireguard.cpp. */
#ifndef SB_WIREGUARD_H
#define SB_WIREGUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/json.h"
#include "sb/store.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* All strings owned. sb_wireguard_options_init sets the C++ defaults. */
typedef struct {
    bool enabled;              /* false */
    char *interface;           /* "wg0" */
    uint16_t port;             /* 51820 */
    char *address;             /* "10.59.32.1/24" */
    char *dns;                 /* "10.59.32.1" */
    uint32_t mtu;              /* 1420 */
    char *external_hostname;   /* "127.0.0.1" */
    char *egress_interface;    /* "eth0" */
    char *config_directory;    /* "/etc/wireguard" */
} sb_wireguard_options;

void sb_wireguard_options_init(sb_wireguard_options *o);
void sb_wireguard_options_free(sb_wireguard_options *o);
void sb_wireguard_options_copy(sb_wireguard_options *dst, const sb_wireguard_options *src);

typedef struct {
    char *private_key;
    char *public_key;
} sb_wireguard_keypair;
void sb_wireguard_keypair_free(sb_wireguard_keypair *k);

typedef struct {
    char *public_key;
    char *endpoint;            /* nullable */
    bool has_latest_handshake;
    int64_t latest_handshake;
    int64_t transfer_rx;
    int64_t transfer_tx;
} sb_wireguard_peer_stats;
void sb_wireguard_peer_stats_free(sb_wireguard_peer_stats *s);
sbj *sb_wireguard_peer_stats_to_json(const sb_wireguard_peer_stats *s);

typedef struct {
    sb_wireguard_peer_stats *items;
    size_t len, cap;
} sb_wireguard_peer_stats_vec;
void sb_wireguard_peer_stats_vec_free(sb_wireguard_peer_stats_vec *v);
/* JSON array of the stats objects. */
sbj *sb_wireguard_peer_stats_vec_to_json(const sb_wireguard_peer_stats_vec *v);

/* Builds a self-contained QR code SVG for enrollment and WireGuard exports.
 * malloc'd; NULL (err set) when the text does not fit a QR code. */
char *sb_qr_svg_for_text(const char *text, sb_err *err);

typedef struct sb_wireguard sb_wireguard;

/* The service borrows `store` (must outlive it) and copies `options`. */
sb_wireguard *sb_wireguard_new(sb_store *store, const sb_wireguard_options *options);
void sb_wireguard_free(sb_wireguard *wg);

/* Static helpers (WireGuardService::generate_keypair etc.). */
int sb_wireguard_generate_keypair(sb_wireguard_keypair *out, sb_err *err);
char *sb_wireguard_generate_preshared_key(sb_err *err);
char *sb_wireguard_public_key_from_private(const char *private_key, sb_err *err);
bool sb_wireguard_peer_expired(const sb_wireguard_peer *peer);
/* parse_stats(`wg show <if> dump` output). */
int sb_wireguard_parse_stats(const char *dump, sb_wireguard_peer_stats_vec *out, sb_err *err);

/* runtime_options(): the configured options merged with persisted settings
 * (as in C++). Caller frees with sb_wireguard_options_free. */
int sb_wireguard_runtime_options(sb_wireguard *wg, sb_wireguard_options *out, sb_err *err);
char *sb_wireguard_server_public_key(sb_wireguard *wg, sb_err *err);
int sb_wireguard_stats(sb_wireguard *wg, sb_wireguard_peer_stats_vec *out, sb_err *err);
char *sb_wireguard_client_config(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err);
/* client_endpoint(): 1 with *out set, 0 when the host has no endpoint
 * (std::nullopt), -1 error. */
int sb_wireguard_client_endpoint(sb_wireguard *wg, const sb_host *host, sbj **out, sb_err *err);
char *sb_wireguard_qr_svg(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err);
char *sb_wireguard_server_config(sb_wireguard *wg, sb_err *err);
/* provision_host(Host host, bool set_default_clash): *out receives the
 * provisioned host (initialised by caller). */
int sb_wireguard_provision_host(sb_wireguard *wg, const sb_host *host, bool set_default_clash,
                                sb_host *out, sb_err *err);
int sb_wireguard_deprovision_host(sb_wireguard *wg, const char *host_id, sb_err *err);
char *sb_wireguard_host_config(sb_wireguard *wg, const sb_host *host, sb_err *err);
int sb_wireguard_startup(sb_wireguard *wg, sb_err *err);
int sb_wireguard_sync(sb_wireguard *wg, sb_err *err);
void sb_wireguard_shutdown(sb_wireguard *wg);
void sb_wireguard_remove_peer(sb_wireguard *wg, const char *public_key);

#ifdef __cplusplus
}
#endif

#endif
