#include "sb/wg_migration.h"
#include "sb/wireguard.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static const char *text_field(const sbj *value, const char *key, bool optional, size_t max,
                              sb_err *err) {
    const sbj *field = sbj_get(value, key);
    if ((!field || sbj_is_null(field)) && optional) return NULL;
    if (!sbj_is_string(field) || !field->v.str.len || field->v.str.len > max ||
        memchr(field->v.str.ptr, '\0', field->v.str.len)) {
        sb_fail(err, SB_ERR_VALIDATION, "wg-easy field %s must be a bounded nonempty string", key);
        return NULL;
    }
    for (size_t i = 0; i < field->v.str.len; ++i) {
        unsigned char c = (unsigned char)field->v.str.ptr[i];
        if (c < 32 || c == 127) {
            sb_fail(err, SB_ERR_VALIDATION, "wg-easy field %s contains a control character", key);
            return NULL;
        }
    }
    return field->v.str.ptr;
}

static bool valid_key(const char *key) {
    if (!key || strlen(key) != 44 || key[43] != '=') return false;
    unsigned char decoded[36] = {0}, encoded[48] = {0};
    if (EVP_DecodeBlock(decoded, (const unsigned char *)key, 44) != 33) return false;
    EVP_EncodeBlock(encoded, decoded, 32);
    bool nonzero = false;
    for (size_t i = 0; i < 32; ++i) if (decoded[i]) nonzero = true;
    return nonzero && memcmp(encoded, key, 44) == 0;
}

static bool valid_ip_or_cidr(const char *value, bool require_prefix) {
    char *copy = sb_strdup(value), *slash = strchr(copy, '/');
    if (require_prefix && !slash) { free(copy); return false; }
    unsigned prefix = 0;
    if (slash) {
        *slash++ = '\0';
        if (!*slash) { free(copy); return false; }
        for (const char *p = slash; *p; ++p) {
            if (*p < '0' || *p > '9' || prefix > 128) { free(copy); return false; }
            prefix = prefix * 10 + (unsigned)(*p - '0');
        }
    }
    struct in_addr v4; struct in6_addr v6;
    bool valid = (inet_pton(AF_INET, copy, &v4) == 1 && (!slash || prefix <= 32)) ||
                 (inet_pton(AF_INET6, copy, &v6) == 1 && (!slash || prefix <= 128));
    free(copy);
    return valid;
}

static bool valid_ip_list(const char *input, bool cidr) {
    if (!input || !*input || strlen(input) > 2048) return false;
    const char *start = input;
    for (;;) {
        const char *end = strchr(start, ',');
        char *raw = sb_strndup(start, end ? (size_t)(end - start) : strlen(start));
        char *value = sb_trim_dup(raw); free(raw);
        bool valid = valid_ip_or_cidr(value, cidr); free(value);
        if (!valid) return false;
        if (!end) return true;
        start = end + 1;
    }
}

sbj *sb_wg_easy_v14_normalize(const sbj *configuration, const sbj *options,
                              const char *default_dns, sb_err *err) {
    const sbj *server = sbj_get(configuration, "server"), *clients = sbj_get(configuration, "clients");
    if (!sbj_is_object(configuration) || !sbj_is_object(server) || !sbj_is_object(clients) ||
        sbj_obj_len(clients) > 4096 || (options && !sbj_is_object(options))) {
        sb_fail(err, SB_ERR_VALIDATION, "Expected wg-easy v14 wg0.json with server and clients objects (maximum 4096 clients)");
        return NULL;
    }
    const char *private_key = text_field(server, "privateKey", false, 44, err);
    const char *public_key = text_field(server, "publicKey", false, 44, err);
    const char *address = text_field(server, "address", false, 15, err);
    if (!private_key || !public_key || !address) return NULL;
    struct in_addr server_ip;
    if (!valid_key(private_key) || !valid_key(public_key) || inet_pton(AF_INET, address, &server_ip) != 1) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid wg-easy server key or IPv4 address"); return NULL;
    }
    uint32_t server_number = ntohl(server_ip.s_addr);
    if ((server_number & 255) == 0 || (server_number & 255) == 255 ||
        (server_number >> 24) == 0 || (server_number >> 24) == 127 || (server_number >> 24) >= 224) {
        sb_fail(err, SB_ERR_VALIDATION, "wg-easy server address must be a usable IPv4 host in a /24 subnet"); return NULL;
    }
    char *derived = sb_wireguard_public_key_from_private(private_key, err);
    bool matching = derived && strcmp(derived, public_key) == 0; free(derived);
    if (!matching) { sb_fail(err, SB_ERR_VALIDATION, "wg-easy server public and private keys do not match"); return NULL; }
    const char *dns = sbj_get_str(options, "dns", default_dns && *default_dns ? default_dns : "1.1.1.1");
    const char *allowed = sbj_get_str(options, "allowed_ips", "0.0.0.0/0, ::/0");
    int64_t keepalive = sbj_get_int(options, "persistent_keepalive", 25);
    if ((sbj_has(options, "dns") && !text_field(options, "dns", false, 2048, err)) ||
        (sbj_has(options, "allowed_ips") && !text_field(options, "allowed_ips", false, 2048, err)) ||
        (sbj_has(options, "persistent_keepalive") && !sbj_is_integer(sbj_get(options, "persistent_keepalive"))) ||
        keepalive < 0 || keepalive > 65535 || !valid_ip_list(dns, false) || !valid_ip_list(allowed, true)) {
        sb_fail(err, SB_ERR_VALIDATION, "Migration DNS must be IP addresses, allowed_ips must be CIDRs, and keepalive must be 0..65535"); return NULL;
    }
    sbj *batch = sbj_object(), *settings = sbj_object(), *keys = sbj_object(), *interface = sbj_object();
    sbj_set_str(keys, "private_key", private_key); sbj_set_str(keys, "public_key", public_key);
    sbj_set(settings, "wg_server_key", keys);
    char *cidr = sb_asprintf("%s/24", address); sbj_set_str(interface, "address", cidr); free(cidr);
    sbj_set(settings, "wireguard_interface", interface); sbj_set(batch, "app_settings", settings);
    sbj *defaults = sbj_object(); sbj_set_str(defaults, "dns", dns);
    sbj_set_str(defaults, "allowed_ips", allowed); sbj_set_int(defaults, "persistent_keepalive", keepalive);
    sbj_set(batch, "client_defaults", defaults);
    sbj *peers = sbj_array(); sbj_set(batch, "wireguard_peers", peers);
    sbj *seen_addresses = sbj_object(), *seen_keys = sbj_object();
    const char *id; const sbj *client;
    SBJ_OBJ_FOREACH(clients, index, id, client) {
        if (!*id || strlen(id) > 128 || strlen(id) != clients->v.obj.key_lens[index] || !sbj_is_object(client)) {
            sb_fail(err, SB_ERR_VALIDATION, "Invalid wg-easy client identifier"); goto fail;
        }
        for (const char *p = id; *p; ++p) if (!isalnum((unsigned char)*p) && *p != '-') {
            sb_fail(err, SB_ERR_VALIDATION, "Invalid wg-easy client identifier"); goto fail;
        }
        const char *name = text_field(client, "name", false, 256, err);
        const char *ip = text_field(client, "address", false, 15, err);
        const char *pub = text_field(client, "publicKey", false, 44, err);
        const char *priv = text_field(client, "privateKey", true, 44, err);
        const char *psk = text_field(client, "preSharedKey", true, 44, err);
        if (!name || !ip || !pub || (sbj_get(client, "privateKey") && !sbj_is_null(sbj_get(client, "privateKey")) && !priv) ||
            (sbj_get(client, "preSharedKey") && !sbj_is_null(sbj_get(client, "preSharedKey")) && !psk)) goto fail;
        struct in_addr peer_ip;
        if (inet_pton(AF_INET, ip, &peer_ip) != 1 || !valid_key(pub) ||
            (priv && !valid_key(priv)) || (psk && !valid_key(psk))) {
            sb_fail(err, SB_ERR_VALIDATION, "Invalid wg-easy client key or IPv4 address at entry %zu", index + 1); goto fail;
        }
        uint32_t peer_number = ntohl(peer_ip.s_addr);
        if ((peer_number & 0xffffff00u) != (server_number & 0xffffff00u) || peer_number == server_number ||
            !(peer_number & 255) || (peer_number & 255) == 255 || sbj_has(seen_addresses, ip) || sbj_has(seen_keys, pub)) {
            sb_fail(err, SB_ERR_VALIDATION, "Duplicate or out-of-subnet wg-easy client at entry %zu", index + 1); goto fail;
        }
        if (priv) {
            char *peer_derived = sb_wireguard_public_key_from_private(priv, err);
            bool same = peer_derived && strcmp(peer_derived, pub) == 0; free(peer_derived);
            if (!same) { sb_fail(err, SB_ERR_VALIDATION, "wg-easy client public and private keys do not match at entry %zu", index + 1); goto fail; }
        }
        const sbj *enabled = sbj_get(client, "enabled");
        if (enabled && !sbj_is_bool(enabled)) { sb_fail(err, SB_ERR_VALIDATION, "wg-easy client enabled must be boolean"); goto fail; }
        sbj_set_bool(seen_addresses, ip, true); sbj_set_bool(seen_keys, pub, true);
        sbj *peer = sbj_object(); char *mapped_id = sb_asprintf("wg-easy-%s", id);
        sbj_set_str(peer, "id", mapped_id); free(mapped_id);
        sbj_set_str(peer, "name", name);
        sbj_set(peer, "address", sbj_str_take(sb_asprintf("%s/24", ip)));
        sbj_set_str(peer, "private_key", priv ? priv : ""); sbj_set_str(peer, "public_key", pub);
        sbj_set(peer, "preshared_key", psk ? sbj_str(psk) : sbj_null());
        sbj_set_bool(peer, "enabled", !enabled || enabled->v.b);
        sbj_set_str(peer, "dns", dns); sbj_set_str(peer, "allowed_ips", allowed);
        sbj_set_int(peer, "persistent_keepalive", keepalive); sbj_set_int(peer, "quota_bytes", 0);
        sbj_set_str(peer, "notes", "Imported from wg-easy v14");
        sbj_arr_push(peers, peer);
    }
    sbj_free(seen_addresses); sbj_free(seen_keys);
    return batch;
fail:
    sbj_free(batch); sbj_free(seen_addresses); sbj_free(seen_keys);
    return NULL;
}
