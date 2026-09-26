/* SKELETON — placeholder so the server links while the WireGuard port is in
 * progress. Every entry point either behaves trivially (options helpers,
 * disabled-mode startup/sync) or fails with "WireGuard is not implemented".
 * The real port of cpp/src/wireguard.cpp replaces this whole file. */
#include "sb/wireguard.h"

#include <stdlib.h>
#include <string.h>

struct sb_wireguard {
    sb_store *store;
    sb_wireguard_options options;
};

#define NOT_IMPLEMENTED(err) sb_fail((err), SB_ERR_GENERIC, "WireGuard is not implemented")

void sb_wireguard_options_init(sb_wireguard_options *o) {
    memset(o, 0, sizeof *o);
    o->interface = sb_strdup("wg0");
    o->port = 51820;
    o->address = sb_strdup("10.59.32.1/24");
    o->dns = sb_strdup("10.59.32.1");
    o->mtu = 1420;
    o->external_hostname = sb_strdup("127.0.0.1");
    o->egress_interface = sb_strdup("eth0");
    o->config_directory = sb_strdup("/etc/wireguard");
}

void sb_wireguard_options_free(sb_wireguard_options *o) {
    free(o->interface);
    free(o->address);
    free(o->dns);
    free(o->external_hostname);
    free(o->egress_interface);
    free(o->config_directory);
    memset(o, 0, sizeof *o);
}

void sb_wireguard_options_copy(sb_wireguard_options *dst, const sb_wireguard_options *src) {
    *dst = *src;
    dst->interface = sb_strdup(src->interface);
    dst->address = sb_strdup(src->address);
    dst->dns = sb_strdup(src->dns);
    dst->external_hostname = sb_strdup(src->external_hostname);
    dst->egress_interface = sb_strdup(src->egress_interface);
    dst->config_directory = sb_strdup(src->config_directory);
}

void sb_wireguard_keypair_free(sb_wireguard_keypair *k) {
    free(k->private_key);
    free(k->public_key);
    memset(k, 0, sizeof *k);
}

void sb_wireguard_peer_stats_free(sb_wireguard_peer_stats *s) {
    free(s->public_key);
    free(s->endpoint);
    memset(s, 0, sizeof *s);
}

sbj *sb_wireguard_peer_stats_to_json(const sb_wireguard_peer_stats *s) { return sbj_object(); }

void sb_wireguard_peer_stats_vec_free(sb_wireguard_peer_stats_vec *v) {
    for (size_t i = 0; i < v->len; ++i) sb_wireguard_peer_stats_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof *v);
}

sbj *sb_wireguard_peer_stats_vec_to_json(const sb_wireguard_peer_stats_vec *v) { return sbj_array(); }

char *sb_qr_svg_for_text(const char *text, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}

sb_wireguard *sb_wireguard_new(sb_store *store, const sb_wireguard_options *options) {
    sb_wireguard *wg = sb_xcalloc(1, sizeof *wg);
    wg->store = store;
    sb_wireguard_options_copy(&wg->options, options);
    return wg;
}

void sb_wireguard_free(sb_wireguard *wg) {
    if (!wg) return;
    sb_wireguard_options_free(&wg->options);
    free(wg);
}

int sb_wireguard_generate_keypair(sb_wireguard_keypair *out, sb_err *err) { return NOT_IMPLEMENTED(err); }
char *sb_wireguard_generate_preshared_key(sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
char *sb_wireguard_public_key_from_private(const char *private_key, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
bool sb_wireguard_peer_expired(const sb_wireguard_peer *peer) { return false; }
int sb_wireguard_parse_stats(const char *dump, sb_wireguard_peer_stats_vec *out, sb_err *err) {
    return NOT_IMPLEMENTED(err);
}
int sb_wireguard_runtime_options(sb_wireguard *wg, sb_wireguard_options *out, sb_err *err) {
    sb_wireguard_options_copy(out, &wg->options);
    return 0;
}
char *sb_wireguard_server_public_key(sb_wireguard *wg, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
int sb_wireguard_stats(sb_wireguard *wg, sb_wireguard_peer_stats_vec *out, sb_err *err) {
    return NOT_IMPLEMENTED(err);
}
char *sb_wireguard_client_config(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
int sb_wireguard_client_endpoint(sb_wireguard *wg, const sb_host *host, sbj **out, sb_err *err) { return 0; }
char *sb_wireguard_qr_svg(sb_wireguard *wg, const sb_wireguard_peer *peer, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
char *sb_wireguard_server_config(sb_wireguard *wg, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
int sb_wireguard_provision_host(sb_wireguard *wg, const sb_host *host, bool set_default_clash, sb_host *out,
                                sb_err *err) {
    return NOT_IMPLEMENTED(err);
}
int sb_wireguard_deprovision_host(sb_wireguard *wg, const char *host_id, sb_err *err) { return 0; }
char *sb_wireguard_host_config(sb_wireguard *wg, const sb_host *host, sb_err *err) {
    NOT_IMPLEMENTED(err);
    return NULL;
}
int sb_wireguard_startup(sb_wireguard *wg, sb_err *err) { return wg->options.enabled ? NOT_IMPLEMENTED(err) : 0; }
int sb_wireguard_sync(sb_wireguard *wg, sb_err *err) { return wg->options.enabled ? NOT_IMPLEMENTED(err) : 0; }
void sb_wireguard_shutdown(sb_wireguard *wg) {}
void sb_wireguard_remove_peer(sb_wireguard *wg, const char *public_key) {}
