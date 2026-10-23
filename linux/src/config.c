#include "SBEasyCore.h"
#include "desktop.h"
#include <stdlib.h>
#include <string.h>
static sbj* named(sbj* array, const char* tag) {
    for (size_t i = 0; i < sbj_arr_len(array); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(array, i), "tag"), tag))
            return sbj_arr_at(array, i);
    return NULL;
}
static bool contains_text(const sbj* value, const char* text) {
    if (sbj_string_is(value, text))
        return true;
    for (size_t i = 0; i < sbj_arr_len(value); ++i)
        if (sbj_string_is(sbj_arr_at(value, i), text))
            return true;
    return false;
}
static bool protected_rule(const sbj* rule, sbj* root, bool dns) {
    const char* target = sbj_get_str(rule, "outbound", "");
    if (dns) {
        const sbj* server = named(sbj_get(sbj_get(root, "dns"), "servers"),
                                  sbj_get_str(rule, "server", ""));
        target = sbj_get_str(server, "detour", "");
    }
    return strcmp(sbj_get_str(rule, "action", "route"), "route") ||
           sbj_get(rule, "domain") || sbj_get(rule, "ip_cidr") ||
           sbj_get(rule, "source_ip_cidr") || sbj_get(rule, "ip_is_private") ||
           sbj_get(rule, "type") || sbj_get(rule, "rules") ||
           contains_text(sbj_get(rule, "rule_set"), "geosite-private") ||
           named(sbj_get(root, "endpoints"), target);
}
static bool string_list(const sbj* array, size_t max, bool path) {
    if (!sbj_is_array(array) || !sbj_arr_len(array) || sbj_arr_len(array) > 128)
        return false;
    for (size_t i = 0; i < sbj_arr_len(array); ++i) {
        const sbj* v = sbj_arr_at(array, i);
        if (!sbj_is_string(v) || !v->v.str.len || v->v.str.len > max ||
            memchr(v->v.str.ptr, 0, v->v.str.len) || strpbrk(v->v.str.ptr, "\r\n\t") ||
            (path && *v->v.str.ptr != '/'))
            return false;
    }
    return true;
}
static bool supported_source(const sbj* root) {
    static const char* allowed[] = {"direct", "selector", "urltest", "shadowsocks",
                                    "vmess",  "vless",    "trojan",  "hysteria2",
                                    "tuic",   "socks",    "http"};
    const sbj* outbounds = sbj_get(root, "outbounds");
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        const char* type = sbj_get_str(sbj_arr_at(outbounds, i), "type", "");
        bool found = false;
        for (size_t j = 0; j < G_N_ELEMENTS(allowed); ++j)
            if (!strcmp(type, allowed[j]))
                found = true;
        if (!found)
            return false;
    }
    /* Remote configuration cannot introduce additional top-level subsystems. */
    for (size_t i = 0; i < sbj_obj_len(root); ++i) {
        const char* key = sbj_obj_key(root, i);
        if (strcmp(key, "log") && strcmp(key, "dns") && strcmp(key, "route") &&
            strcmp(key, "inbounds") && strcmp(key, "outbounds") &&
            strcmp(key, "endpoints") && strcmp(key, "experimental") &&
            strcmp(key, "services"))
            return false;
    }
    return true;
}
char* sbl_build(const sbj* profile, bool tun, uid_t uid, int proxy_port, int clash_port,
                const char* secret, const char* cache_path, sb_err* err) {
    if (!sbj_is_object(profile) || proxy_port <= 0 || proxy_port > 65535 ||
        clash_port <= 0 || clash_port > 65535 || proxy_port == clash_port || !secret ||
        strlen(secret) != 64 || !cache_path || *cache_path != '/' || (tun && !uid))
        goto bad;
    const sbj* settings = sbj_get(profile, "settings");
    if (!sbj_is_object(settings))
        goto bad;
    for (size_t i = 0; i < sbj_obj_len(settings); ++i) {
        const char* key = sbj_obj_key(settings, i);
        if (strcmp(key, "selected_tag") && strcmp(key, "local_groups") &&
            strcmp(key, "process_rules") && strcmp(key, "selector_choices"))
            goto bad;
    }
    sbj* base_prefs = sbj_object();
    if (sbj_get(settings, "selected_tag"))
        sbj_set(base_prefs, "selected_tag",
                sbj_clone(sbj_get(settings, "selected_tag")));
    if (sbj_get(settings, "local_groups"))
        sbj_set(base_prefs, "local_groups",
                sbj_clone(sbj_get(settings, "local_groups")));
    char *prefs = sbj_dump(base_prefs, -1),
         *subscriptions = sbj_dump(sbj_get(profile, "subscriptions"), -1);
    sbj_free(base_prefs);
    const char* source = sbj_string_is(sbj_get(profile, "mode"), "managed")
                             ? sbj_get_str(profile, "source", "")
                             : NULL;
    if (source && !*source) {
        free(prefs);
        free(subscriptions);
        sb_fail(err, SB_ERR_VALIDATION, "Sync this managed profile before connecting");
        return NULL;
    }
    sbj* original = source ? sbl_parse(source, 1024u * 1024u, NULL) : NULL;
    if (source && (!original || !supported_source(original))) {
        sbj_free(original);
        free(prefs);
        free(subscriptions);
        goto bad;
    }
    sbj_free(original);
    char *host = source ? sbl_url_host(sbj_get_str(profile, "server", "")) : NULL,
         *private_error = NULL;
    char* raw = sba_build_runtime(source, subscriptions, prefs, host, &private_error);
    free(host);
    free(subscriptions);
    free(prefs);
    if (!raw) {
        sb_fail(err, SB_ERR_VALIDATION, "%s",
                private_error ? private_error : "Cannot build runtime");
        free(private_error);
        return NULL;
    }
    free(private_error);
    sbj* root = sbl_parse(raw, SBL_MAX_STATE, err);
    free(raw);
    if (!root)
        return NULL;
    sbj *outbounds = sbj_get(root, "outbounds"), *route = sbj_get(root, "route");
    sbj* final = named(outbounds, sbj_get_str(route, "final", ""));
    /* Imported nodes remain selectable in the managed default group. */
    if (final && sbj_string_is(sbj_get(final, "type"), "selector")) {
        sbj* members = sbj_get_or_array(final, "outbounds");
        for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
            const char* tag = sbj_get_str(sbj_arr_at(outbounds, i), "tag", "");
            bool present = false;
            for (size_t j = 0; j < sbj_arr_len(members); ++j)
                if (sbj_string_is(sbj_arr_at(members, j), tag))
                    present = true;
            if (sb_starts_with(tag, "local-") && !present)
                sbj_arr_push(members, sbj_str(tag));
        }
    }
    const sbj* choices = sbj_get(settings, "selector_choices");
    if (choices && (!sbj_is_object(choices) || sbj_obj_len(choices) > 128)) {
        sbj_free(root);
        goto bad;
    }
    for (size_t i = 0; i < sbj_obj_len(choices); ++i) {
        sbj* group = named(outbounds, sbj_obj_key(choices, i));
        const char* choice = sbj_as_str(sbj_obj_val(choices, i), NULL);
        bool found = false;
        for (size_t j = 0; j < sbj_arr_len(sbj_get(group, "outbounds")); ++j)
            if (sbj_string_is(sbj_arr_at(sbj_get(group, "outbounds"), j), choice))
                found = true;
        if (!group || !choice || !sbj_string_is(sbj_get(group, "type"), "selector") ||
            !found) {
            sbj_free(root);
            sb_fail(err, SB_ERR_VALIDATION,
                    "A selected node is no longer available; select a replacement");
            return NULL;
        }
        sbj_set_str(group, "default", choice);
    }
    const sbj* processes = sbj_get(settings, "process_rules");
    if (processes && (!sbj_is_array(processes) || sbj_arr_len(processes) > 128)) {
        sbj_free(root);
        goto bad;
    }
    sbj* rules = sbj_get(route, "rules");
    sbj *dns = sbj_get(root, "dns"), *dns_rules = sbj_get(dns, "rules"),
        *dns_servers = sbj_get(dns, "servers");
    size_t insert = 0, dns_insert = 0;
    for (size_t i = 0; i < sbj_arr_len(rules); ++i)
        if (protected_rule(sbj_arr_at(rules, i), root, false))
            insert = i + 1;
    for (size_t i = 0; i < sbj_arr_len(dns_rules); ++i)
        if (protected_rule(sbj_arr_at(dns_rules, i), root, true))
            dns_insert = i + 1;
    if (tun && !source) {
        sbj* private = sbj_object();
        sbj_set_bool(private, "ip_is_private", true);
        sbj_set_str(private, "outbound", SBL_DIRECT);
        sbj_arr_insert(rules, insert++, private);
    }
    for (size_t i = 0; i < sbj_arr_len(processes); ++i) {
        const sbj* rule = sbj_arr_at(processes, i);
        const char* target = sbj_get_str(rule, "outbound", "");
        sbj* out = named(outbounds, target);
        const sbj *names = sbj_get(rule, "process_name"),
                  *paths = sbj_get(rule, "process_path");
        if (!out || (!names && !paths) || (names && !string_list(names, 128, false)) ||
            (paths && !string_list(paths, 4096, true))) {
            sbj_free(root);
            goto bad;
        }
        for (size_t j = 0; j < sbj_obj_len(rule); ++j) {
            const char* key = sbj_obj_key(rule, j);
            if (strcmp(key, "outbound") && strcmp(key, "process_name") &&
                strcmp(key, "process_path")) {
                sbj_free(root);
                goto bad;
            }
        }
        sbj_arr_insert(rules, insert++, sbj_clone(rule));
        char* dns_tag = sb_asprintf("sb-easy-linux-process-%zu", i);
        sbj* server = sbj_object();
        sbj_set_str(server, "type", "https");
        sbj_set_str(server, "tag", dns_tag);
        sbj_set_str(server, "server", "1.1.1.1");
        sbj_set_str(server, "path", "/dns-query");
        if (!sbj_string_is(sbj_get(out, "type"), "direct"))
            sbj_set_str(server, "detour", target);
        sbj_arr_push(dns_servers, server);
        sbj* dns_rule = sbj_clone(rule);
        sbj_del(dns_rule, "outbound");
        sbj_set_str(dns_rule, "server", dns_tag);
        sbj_arr_insert(dns_rules, dns_insert++, dns_rule);
        free(dns_tag);
    }
    sbj* inbounds = sbj_get(root, "inbounds");
    if (tun) {
        sbj *in = sbj_arr_at(inbounds, 0), *uids = sbj_array();
        sbj_arr_push(uids, sbj_int((int64_t)uid));
        sbj_set(in, "include_uid", uids);
        sbj_set_str(in, "interface_name", "sbeasy0");
        /* The upstream auto_redirect implementation owns a global nftables
         * table named "sing-box". Keep this app isolated from other cores. */
        sbj_set_bool(in, "auto_redirect", false);
        sbj_set_int(in, "iproute2_table_index", 42041);
        sbj_set_int(in, "iproute2_rule_index", 12040);
        sbj_set_str(in, "dns_mode", "hijack");
        sbj* addresses = sbj_array();
        sbj_arr_push(addresses, sbj_str("198.18.252.1/30"));
        sbj_arr_push(addresses, sbj_str("fd7e:5342:4541:5359::1/126"));
        sbj_set(in, "address", addresses);
    } else {
        sbj_set(root, "inbounds", sbj_array());
        inbounds = sbj_get(root, "inbounds");
    }
    sbj *mixed = sbj_object(), *users = sbj_array(), *user = sbj_object();
    sbj_set_str(mixed, "type", "mixed");
    sbj_set_str(mixed, "tag", "sb-easy-linux-proxy");
    sbj_set_str(mixed, "listen", "127.0.0.1");
    sbj_set_int(mixed, "listen_port", proxy_port);
    sbj_set_str(user, "username", "sbeasy");
    sbj_set_str(user, "password", secret);
    sbj_arr_push(users, user);
    sbj_set(mixed, "users", users);
    sbj_arr_push(inbounds, mixed);
    sbj *experimental = sbj_get(root, "experimental"), *clash = sbj_object();
    char* controller = sb_asprintf("127.0.0.1:%d", clash_port);
    sbj_set_str(clash, "external_controller", controller);
    free(controller);
    sbj_set_str(clash, "secret", secret);
    sbj_set_str(clash, "default_mode", "rule");
    sbj_set(experimental, "clash_api", clash);
    sbj_set_str(sbj_get(experimental, "cache_file"), "path", cache_path);
    char* result = sbj_dump(root, -1);
    sbj_free(root);
    return result;
bad:
    sb_fail(err, SB_ERR_VALIDATION, "Invalid or unsupported desktop configuration");
    return NULL;
}
