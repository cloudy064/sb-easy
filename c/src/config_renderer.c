#include "sb/config_renderer.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* ---- nlohmann-compatible accessors ------------------------------------ */
/* These reproduce nlohmann::json::value(key, default) semantics, including
 * the type_error exceptions it raises on malformed input. */

static int type_error_value(const sbj *object, sb_err *err) {
    return sb_fail(err, SB_ERR_GENERIC, "[json.exception.type_error.306] cannot use value() with %s",
                   sbj_type_name(object));
}

/* value(key, fallback) for strings. *out is borrowed. */
static int value_str(const sbj *object, const char *key, const char *fallback, const char **out,
                     sb_err *err) {
    if (!sbj_is_object(object)) return type_error_value(object, err);
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

static int value_bool(const sbj *object, const char *key, bool fallback, bool *out, sb_err *err) {
    if (!sbj_is_object(object)) return type_error_value(object, err);
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_bool(found))
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.302] type must be boolean, but is %s",
                       sbj_type_name(found));
    *out = found->v.b;
    return 0;
}

/* value(key, 0) converted to int (nlohmann accepts numbers and booleans). */
static int value_int(const sbj *object, const char *key, int fallback, int *out, sb_err *err) {
    if (!sbj_is_object(object)) return type_error_value(object, err);
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    switch (found->type) {
    case SBJ_INT: *out = (int)found->v.i; return 0;
    case SBJ_UINT: *out = (int)found->v.u; return 0;
    case SBJ_FLOAT: *out = (int)found->v.f; return 0;
    case SBJ_BOOL: *out = found->v.b ? 1 : 0; return 0;
    default:
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.302] type must be number, but is %s",
                       sbj_type_name(found));
    }
}

/* Tag of a generated outbound (always an object with a string tag, or none). */
static const char *outbound_tag(const sbj *outbound) {
    return sbj_get_str(outbound, "tag", "");
}

static sbj *value_or_null(const sbj *value, const char *key) {
    const sbj *found = sbj_get(value, key);
    return found ? sbj_clone(found) : sbj_null();
}

static void copy_if_present(sbj *destination, const sbj *source, const char *key) {
    const sbj *found = sbj_get(source, key);
    if (found) sbj_set(destination, key, sbj_clone(found));
}

static const char *string_or(const sbj *value, const char *key, const char *fallback) {
    const sbj *found = sbj_get(value, key);
    if (!sbj_is_string(found)) return fallback;
    return found->v.str.ptr;
}

/* nlohmann `obj[key]`: inserts null when missing. Returns the (borrowed) slot. */
static sbj *index_or_null(sbj *object, const char *key) {
    sbj *found = sbj_get(object, key);
    if (!found) {
        sbj_set(object, key, sbj_null());
        found = sbj_get(object, key);
    }
    return found;
}

/* Replaces object[key] with value and returns the stored (borrowed) value. */
static sbj *set_get(sbj *object, const char *key, sbj *value) {
    sbj_set(object, key, value);
    return sbj_get(object, key);
}

/* ---- sorted string set (std::set<std::string>) ------------------------ */

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void strset_normalize(sb_strvec *v) {
    if (v->len == 0) return;
    qsort(v->items, v->len, sizeof *v->items, cmp_str);
    size_t out = 1;
    for (size_t i = 1; i < v->len; ++i) {
        if (strcmp(v->items[i], v->items[out - 1]) == 0) {
            free(v->items[i]);
        } else {
            v->items[out++] = v->items[i];
        }
    }
    v->len = out;
}

static bool strset_contains(const sb_strvec *v, const char *s) {
    return v->len && bsearch(&s, v->items, v->len, sizeof *v->items, cmp_str) != NULL;
}

/* ---- rule validation --------------------------------------------------- */

static int validate_rule_tags(const sbj *rules, const sb_strvec *allowed, sb_err *err) {
    const sbj *rule;
    SBJ_ARR_FOREACH(rules, i, rule) {
        const sbj *outbound = sbj_get(rule, "outbound");
        if (sbj_is_string(outbound) && !strset_contains(allowed, outbound->v.str.ptr)) {
            return sb_fail(err, SB_ERR_SCRIPT, "generated rule references unknown outbound tag: %s",
                           outbound->v.str.ptr);
        }
        const sbj *nested = sbj_get(rule, "rules");
        if (sbj_is_array(nested) && validate_rule_tags(nested, allowed, err) != 0) return -1;
    }
    return 0;
}

/* ---- clash API -------------------------------------------------------- */

static void inject_clash_api(sbj *config, const char *controller, const char *secret) {
    if (sb_str_empty(controller) || !sbj_is_object(config)) return;
    sbj *existing = sbj_get(config, "experimental");
    if (sbj_is_object(existing) && sbj_has(existing, "clash_api")) return;

    sbj *experimental = index_or_null(config, "experimental");
    if (sbj_is_null(experimental)) experimental = set_get(config, "experimental", sbj_object());
    if (!sbj_is_object(experimental)) return;

    sbj *clash_api = sbj_object();
    sbj_set_str(clash_api, "external_controller", controller);
    if (!sb_str_empty(secret)) sbj_set_str(clash_api, "secret", secret);
    sbj_set(experimental, "clash_api", clash_api);
}

static void disable_clash_dashboard(sbj *config) {
    sbj *experimental = sbj_get(config, "experimental");
    if (!sbj_is_object(experimental)) return;
    sbj *api = sbj_get(experimental, "clash_api");
    if (!sbj_is_object(api)) return;
    sbj_del(api, "external_ui");
    sbj_del(api, "external_ui_download_url");
    sbj_del(api, "external_ui_download_detour");
}

/* ---- control plane route ---------------------------------------------- */

static char *url_host(const char *input) {
    const char *value = input ? input : "";
    const char *scheme = strstr(value, "://");
    if (scheme) value = scheme + 3;
    size_t len = strcspn(value, "/?#");
    char *host = sb_strndup(value, len);
    if (host[0] == '[') {
        char *closing = strchr(host, ']');
        char *result = closing ? sb_strndup(host + 1, (size_t)(closing - host - 1)) : sb_strdup("");
        free(host);
        return result;
    }
    char *last = strrchr(host, ':');
    if (last && strchr(host, ':') == last) *last = '\0';
    return host;
}

static sbj *direct_rule(const char *key, char *value_take) {
    sbj *rule = sbj_object();
    sbj *arr = sbj_array();
    sbj_arr_push(arr, sbj_str_take(value_take));
    sbj_set(rule, key, arr);
    sbj_set_str(rule, "outbound", "direct");
    return rule;
}

/* NULL when the server has no usable host. */
static sbj *control_plane_route(const char *server) {
    char *host = url_host(server);
    if (!*host) {
        free(host);
        return NULL;
    }
    struct in_addr ipv4;
    struct in6_addr ipv6;
    sbj *rule;
    if (inet_pton(AF_INET, host, &ipv4) == 1) {
        rule = direct_rule("ip_cidr", sb_asprintf("%s/32", host));
    } else if (inet_pton(AF_INET6, host, &ipv6) == 1) {
        rule = direct_rule("ip_cidr", sb_asprintf("%s/128", host));
    } else {
        rule = direct_rule("domain", sb_strdup(host));
    }
    free(host);
    return rule;
}

/* ---- managed DNS / geo policy ----------------------------------------- */

static void normalize_managed_dns_detours(sbj *config, bool has_auto,
                                          const char *android_selector) {
    sbj *dns = sbj_get(config, "dns");
    if (!sbj_is_object(dns)) return;
    sbj *servers = index_or_null(dns, "servers"); /* nlohmann operator[] inserts null */
    if (!sbj_is_array(servers)) return;
    const char *target = !has_auto ? "direct" : (android_selector ? android_selector : "auto");
    sbj *server;
    SBJ_ARR_FOREACH(servers, i, server) {
        const sbj *detour = sbj_get(server, "detour");
        if (!sbj_is_object(server) || !sbj_is_string(detour)) continue;
        if (strcmp(detour->v.str.ptr, "Proxy") == 0 || strcmp(detour->v.str.ptr, "Auto") == 0) {
            sbj_set_str(server, "detour", target);
        }
    }
}

static const char meta_rules_base[] =
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/";

static bool rule_set_tag_matches(const sbj *value, const char *tag) {
    if (sbj_is_string(value)) return strcmp(value->v.str.ptr, tag) == 0;
    if (!sbj_is_array(value)) return false;
    const sbj *item;
    SBJ_ARR_FOREACH(value, i, item) {
        if (sbj_is_string(item) && strcmp(item->v.str.ptr, tag) == 0) return true;
    }
    return false;
}

static bool has_rule_for_set(const sbj *rules, const char *tag) {
    if (!sbj_is_array(rules)) return false;
    const sbj *rule;
    SBJ_ARR_FOREACH(rules, i, rule) {
        const sbj *found = sbj_is_object(rule) ? sbj_get(rule, "rule_set") : NULL;
        if (found && rule_set_tag_matches(found, tag)) return true;
    }
    return false;
}

/* 1 / 0, or -1 on a type error (non-boolean ip_is_private). */
static int has_private_ip_rule(const sbj *rules, sb_err *err) {
    if (!sbj_is_array(rules)) return 0;
    const sbj *rule;
    SBJ_ARR_FOREACH(rules, i, rule) {
        if (!sbj_is_object(rule)) continue;
        bool flag = false;
        if (value_bool(rule, "ip_is_private", false, &flag, err) != 0) return -1;
        if (flag) return 1;
    }
    return 0;
}

static int add_remote_rule_set(sbj *rule_sets, const char *tag, const char *relative_url,
                               sb_err *err) {
    const sbj *item;
    SBJ_ARR_FOREACH(rule_sets, i, item) {
        if (!sbj_is_object(item)) continue;
        const char *existing = NULL;
        if (value_str(item, "tag", "", &existing, err) != 0) return -1;
        if (strcmp(existing, tag) == 0) return 0;
    }
    sbj *entry = sbj_object();
    sbj_set_str(entry, "type", "remote");
    sbj_set_str(entry, "tag", tag);
    sbj_set_str(entry, "format", "binary");
    sbj_set(entry, "url", sbj_str_take(sb_asprintf("%s%s", meta_rules_base, relative_url)));
    sbj_set_str(entry, "download_detour", "direct");
    sbj_set_str(entry, "update_interval", "7d");
    sbj_arr_push(rule_sets, entry);
    return 0;
}

static sbj *rule_set_rule(const char *tag) {
    sbj *rule = sbj_object();
    sbj *arr = sbj_array();
    sbj_arr_push(arr, sbj_str(tag));
    sbj_set(rule, "rule_set", arr);
    sbj_set_str(rule, "outbound", "direct");
    return rule;
}

static int inject_managed_geo_policy(sbj *config, sb_err *err) {
    sbj *route = index_or_null(config, "route");
    if (sbj_is_null(route)) route = set_get(config, "route", sbj_object());
    if (!sbj_is_object(route))
        return sb_fail(err, SB_ERR_VALIDATION, "managed route must be a JSON object");
    sbj *rules = index_or_null(route, "rules");
    if (sbj_is_null(rules)) rules = set_get(route, "rules", sbj_array());
    if (!sbj_is_array(rules))
        return sb_fail(err, SB_ERR_VALIDATION, "managed route rules must be an array");
    sbj *rule_sets = index_or_null(route, "rule_set");
    if (sbj_is_null(rule_sets)) rule_sets = set_get(route, "rule_set", sbj_array());
    if (!sbj_is_array(rule_sets))
        return sb_fail(err, SB_ERR_VALIDATION, "managed route rule_set must be an array");

    if (add_remote_rule_set(rule_sets, "geosite-private", "geosite/private.srs", err) != 0 ||
        add_remote_rule_set(rule_sets, "geosite-cn", "geosite/cn.srs", err) != 0 ||
        add_remote_rule_set(rule_sets, "geoip-cn", "geoip/cn.srs", err) != 0)
        return -1;

    /* Explicit Profile / QuickJS rules are already at the front of the list.
     * Append the managed defaults so users can still override any destination. */
    if (!has_rule_for_set(rules, "geosite-private"))
        sbj_arr_push(rules, rule_set_rule("geosite-private"));
    int has_private = has_private_ip_rule(rules, err);
    if (has_private < 0) return -1;
    if (!has_private) {
        sbj *rule = sbj_object();
        sbj_set_bool(rule, "ip_is_private", true);
        sbj_set_str(rule, "outbound", "direct");
        sbj_arr_push(rules, rule);
    }
    if (!has_rule_for_set(rules, "geosite-cn")) sbj_arr_push(rules, rule_set_rule("geosite-cn"));
    if (!has_rule_for_set(rules, "geoip-cn")) sbj_arr_push(rules, rule_set_rule("geoip-cn"));

    sbj *experimental = index_or_null(config, "experimental");
    if (sbj_is_null(experimental)) experimental = set_get(config, "experimental", sbj_object());
    if (sbj_is_object(experimental)) {
        sbj *cache = index_or_null(experimental, "cache_file");
        if (sbj_is_null(cache)) cache = set_get(experimental, "cache_file", sbj_object());
        if (sbj_is_object(cache)) sbj_set_bool(cache, "enabled", true);
    }
    return 0;
}

/* ---- public API -------------------------------------------------------- */

int sb_config_renderer_init(sb_config_renderer *renderer, const sb_script_limits *limits,
                            sb_err *err) {
    return sb_rule_script_engine_init(&renderer->scripts, limits, err);
}

static sbj *outbound_base(const char *type, const sb_proxy_node *node) {
    sbj *o = sbj_object();
    sbj_set_str(o, "type", type);
    sbj_set_str(o, "tag", node->tag);
    sbj_set_str(o, "server", node->server);
    sbj_set_int(o, "server_port", node->server_port);
    return o;
}

sbj *sb_config_generate_outbound(const sb_proxy_node *node, sb_err *err) {
    const sbj *config = node->protocol_config;
    const char *type = node->type ? node->type : "";
    sbj *outbound;

    if (strcmp(type, "shadowsocks") == 0) {
        outbound = outbound_base("shadowsocks", node);
        sbj_set(outbound, "method", value_or_null(config, "method"));
        sbj_set(outbound, "password", value_or_null(config, "password"));
    } else if (strcmp(type, "vmess") == 0) {
        int alter_id = 0;
        if (value_int(config, "alter_id", 0, &alter_id, err) != 0) return NULL;
        outbound = outbound_base("vmess", node);
        sbj_set(outbound, "uuid", value_or_null(config, "uuid"));
        sbj_set_int(outbound, "alter_id", alter_id);
        sbj_set_str(outbound, "security", string_or(config, "security", "auto"));
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (strcmp(type, "trojan") == 0) {
        outbound = outbound_base("trojan", node);
        sbj_set(outbound, "password", value_or_null(config, "password"));
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (strcmp(type, "vless") == 0) {
        outbound = outbound_base("vless", node);
        sbj_set(outbound, "uuid", value_or_null(config, "uuid"));
        sbj_set_str(outbound, "flow", string_or(config, "flow", ""));
        sbj_set_str(outbound, "packet_encoding", string_or(config, "packet_encoding", "xudp"));
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (strcmp(type, "hysteria2") == 0) {
        outbound = outbound_base("hysteria2", node);
        sbj_set(outbound, "password", value_or_null(config, "password"));
        copy_if_present(outbound, config, "tls");
        copy_if_present(outbound, config, "obfs");
    } else if (strcmp(type, "tuic") == 0) {
        outbound = outbound_base("tuic", node);
        sbj_set(outbound, "uuid", value_or_null(config, "uuid"));
        sbj_set(outbound, "password", value_or_null(config, "password"));
        sbj_set_str(outbound, "congestion_control",
                    string_or(config, "congestion_control", "bbr"));
        sbj_set_str(outbound, "udp_relay_mode", string_or(config, "udp_relay_mode", "native"));
        copy_if_present(outbound, config, "tls");
    } else if (strcmp(type, "http") == 0) {
        outbound = outbound_base("http", node);
        copy_if_present(outbound, config, "username");
        copy_if_present(outbound, config, "password");
        copy_if_present(outbound, config, "tls");
    } else {
        outbound = sbj_object();
        sbj_set_str(outbound, "type", "direct");
        sbj_set_str(outbound, "tag", node->tag);
    }
    return outbound;
}

sbj *sb_config_generate_outbounds(const sb_proxy_node *nodes, size_t count, sb_err *err) {
    /* std::map<std::string, unsigned> seen: parallel arrays, linear lookup. */
    sb_strvec seen_tags = {0};
    unsigned *seen_counts = NULL;
    sbj *outbounds = sbj_array();
    sbj *auto_tags = sbj_array();

    for (size_t i = 0; i < count; ++i) {
        const sb_proxy_node *node = &nodes[i];
        if (!node->enabled) continue;
        sbj *outbound = sb_config_generate_outbound(node, err);
        if (!outbound) {
            sbj_free(outbounds);
            sbj_free(auto_tags);
            sb_strvec_free(&seen_tags);
            free(seen_counts);
            return NULL;
        }
        size_t slot = 0;
        while (slot < seen_tags.len && strcmp(seen_tags.items[slot], node->tag) != 0) ++slot;
        if (slot == seen_tags.len) {
            sb_strvec_push(&seen_tags, node->tag);
            seen_counts = sb_xrealloc(seen_counts, seen_tags.cap * sizeof *seen_counts);
            seen_counts[slot] = 0;
        }
        unsigned occurrence = ++seen_counts[slot];
        char *tag = occurrence == 1 ? sb_strdup(node->tag)
                                    : sb_asprintf("%s #%u", node->tag, occurrence);
        sbj_set_str(outbound, "tag", tag);
        sbj_arr_push(auto_tags, sbj_str_take(tag));
        sbj_arr_push(outbounds, outbound);
    }
    sb_strvec_free(&seen_tags);
    free(seen_counts);

    if (sbj_arr_len(auto_tags) > 0) {
        sbj *urltest = sbj_object();
        sbj_set_str(urltest, "type", "urltest");
        sbj_set_str(urltest, "tag", "auto");
        sbj_set(urltest, "outbounds", auto_tags);
        sbj_set_str(urltest, "url", "https://www.gstatic.com/generate_204");
        sbj_set_str(urltest, "interval", "24h");
        /* libbox requires the test interval to be no greater than the idle
         * timeout. Keep both long so mobile clients still effectively test
         * once at startup without waking up for frequent background tests. */
        sbj_set_str(urltest, "idle_timeout", "24h");
        sbj_arr_push(outbounds, urltest);
    } else {
        sbj_free(auto_tags);
    }
    return outbounds;
}

static bool outbounds_have_tag(const sbj *outbounds, const char *tag) {
    const sbj *o;
    SBJ_ARR_FOREACH(outbounds, i, o) {
        if (strcmp(outbound_tag(o), tag) == 0) return true;
    }
    return false;
}

/* Managed-mode outbound/selector/DNS/final handling. Sets *has_proxy. */
static int render_managed(const sb_render_request *request, sbj *config, bool *has_proxy,
                          sb_err *err) {
    sbj *outbounds = sb_config_generate_outbounds(request->nodes.items, request->nodes.len, err);
    if (!outbounds) return -1;
    const bool has_auto = outbounds_have_tag(outbounds, "auto");
    *has_proxy = has_auto;

    /* host_context.value("capabilities", json::object()) */
    if (!sbj_is_object(request->host_context)) {
        sbj_free(outbounds);
        return type_error_value(request->host_context, err);
    }
    const sbj *capabilities = sbj_get(request->host_context, "capabilities");
    bool is_android = false;
    if (sbj_is_object(capabilities)) {
        const char *platform = "";
        if (value_str(capabilities, "platform", "", &platform, err) != 0) {
            sbj_free(outbounds);
            return -1;
        }
        is_android = strcmp(platform, "android") == 0;
    }
    if (!outbounds_have_tag(outbounds, "direct")) {
        sbj *direct = sbj_object();
        sbj_set_str(direct, "type", "direct");
        sbj_set_str(direct, "tag", "direct");
        sbj_arr_push(outbounds, direct);
    }
    char *android_selector = NULL;
    if (has_auto && is_android) {
        char *selector_tag = sb_strdup("Proxy");
        while (outbounds_have_tag(outbounds, selector_tag)) {
            char *next = sb_asprintf("%s group", selector_tag);
            free(selector_tag);
            selector_tag = next;
        }
        sbj *selector_outbounds = sbj_array();
        sbj_arr_push(selector_outbounds, sbj_str("auto"));
        const sbj *o;
        SBJ_ARR_FOREACH(outbounds, i, o) {
            const char *tag = outbound_tag(o);
            if (*tag && strcmp(tag, "auto") != 0) sbj_arr_push(selector_outbounds, sbj_str(tag));
        }
        sbj *selector = sbj_object();
        sbj_set_str(selector, "type", "selector");
        sbj_set_str(selector, "tag", selector_tag);
        sbj_set(selector, "outbounds", selector_outbounds);
        sbj_set_str(selector, "default", "auto");
        sbj_arr_push(outbounds, selector);
        android_selector = selector_tag;
    }
    sbj_set(config, "outbounds", outbounds);
    normalize_managed_dns_detours(config, has_auto, android_selector);

    sbj *route = sbj_get(config, "route");
    if (sbj_is_object(route)) {
        const sbj *final_value = sbj_get(route, "final");
        if (sbj_is_string(final_value)) {
            char *current = sb_strdup(final_value->v.str.ptr);
            const bool legacy = strcmp(current, "Proxy") == 0 || strcmp(current, "Auto") == 0;
            if (!has_auto) {
                sbj_set_str(route, "final", "direct");
            } else if (android_selector && (legacy || strcmp(current, "auto") == 0)) {
                sbj_set_str(route, "final", android_selector);
            } else if (legacy) {
                sbj_set_str(route, "final", "auto");
            }
            free(current);
        }
    }
    free(android_selector);
    return 0;
}

static int render_rule_script(const sb_config_renderer *renderer,
                              const sb_render_request *request, sbj *config, sb_err *err) {
    sbj *route = sbj_get(config, "route");
    if (!sbj_is_object(route)) route = set_get(config, "route", sbj_object());

    sb_strvec allowed = {0};
    sb_strvec_push(&allowed, "direct");
    sb_strvec_push(&allowed, "block");
    sb_strvec_push(&allowed, "dns");
    sb_strvec_push(&allowed, "reject");
    const sbj *outbounds = sbj_get(config, "outbounds");
    if (sbj_is_array(outbounds)) {
        const sbj *o;
        SBJ_ARR_FOREACH(outbounds, i, o) {
            const sbj *tag = sbj_get(o, "tag");
            if (sbj_is_string(tag)) sb_strvec_push(&allowed, tag->v.str.ptr);
        }
    }
    for (size_t i = 0; i < request->external_route_tags.len; ++i)
        sb_strvec_push(&allowed, request->external_route_tags.items[i]);
    strset_normalize(&allowed);

    sbj *context = sbj_object();
    sbj_set(context, "host", sbj_clone(request->host_context));
    sbj *tags = sbj_array();
    for (size_t i = 0; i < allowed.len; ++i) sbj_arr_push(tags, sbj_str(allowed.items[i]));
    sbj_set(context, "outboundTags", tags);
    const sbj *current_rules = sbj_get(route, "rules");
    sbj_set(context, "currentRules", current_rules ? sbj_clone(current_rules) : sbj_array());

    sbj *rules =
        sb_rule_script_engine_build_rules(&renderer->scripts, request->rule_script, context, err);
    sbj_free(context);
    if (!rules || validate_rule_tags(rules, &allowed, err) != 0) {
        sbj_free(rules);
        sb_strvec_free(&allowed);
        return -1;
    }
    sb_strvec_free(&allowed);
    sbj_set(route, "rules", rules);
    return 0;
}

sbj *sb_config_renderer_render(const sb_config_renderer *renderer,
                               const sb_render_request *request, sb_err *err) {
    if (!sbj_is_object(request->profile)) {
        sb_fail(err, SB_ERR_VALIDATION, "profile template must be a JSON object");
        return NULL;
    }

    sbj *config = sbj_clone(request->profile);
    bool managed_has_proxy = false;
    if (request->mode == SB_PROFILE_MANAGED &&
        render_managed(request, config, &managed_has_proxy, err) != 0)
        goto fail;

    if (request->rule_script && *request->rule_script &&
        render_rule_script(renderer, request, config, err) != 0)
        goto fail;

    if (managed_has_proxy && inject_managed_geo_policy(config, err) != 0) goto fail;

    sbj *protected_rules = sbj_array();
    sbj *control_rule = control_plane_route(request->control_plane_server);
    if (control_rule) sbj_arr_push(protected_rules, control_rule);
    if (sbj_is_array(request->priority_route_rules)) {
        const sbj *rule;
        SBJ_ARR_FOREACH(request->priority_route_rules, i, rule)
            sbj_arr_push(protected_rules, sbj_clone(rule));
    }
    if (sbj_arr_len(protected_rules) > 0) {
        sbj *route = sbj_get(config, "route");
        if (!sbj_is_object(route)) route = set_get(config, "route", sbj_object());
        sbj *rules = index_or_null(route, "rules");
        if (!sbj_is_array(rules)) rules = set_get(route, "rules", sbj_array());
        size_t n = sbj_arr_len(protected_rules);
        for (size_t i = 0; i < n; ++i)
            sbj_arr_insert(rules, i, sbj_arr_take(protected_rules, 0));
    }
    sbj_free(protected_rules);

    /* These fields remain under server control even when scripting is enabled. */
    inject_clash_api(config, request->clash_controller, request->clash_secret);
    disable_clash_dashboard(config);
    return config;

fail:
    sbj_free(config);
    return NULL;
}
