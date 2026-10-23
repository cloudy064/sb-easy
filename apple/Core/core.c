#include "SBEasyCore.h"
#include "sb/proxy_parser.h"
#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SBA_LIMIT (1024u * 1024u)
#ifndef SBA_PLATFORM_PREFIX
#define SBA_PLATFORM_PREFIX "sb-easy-apple-"
#endif
#ifndef SBA_PLATFORM_LABEL
#define SBA_PLATFORM_LABEL "Apple"
#endif
#define DEFAULT_SELECTOR SBA_PLATFORM_PREFIX "default"
#define DIRECT SBA_PLATFORM_PREFIX "direct"
#define BOOTSTRAP SBA_PLATFORM_PREFIX "bootstrap"
#define REMOTE_DNS SBA_PLATFORM_PREFIX "remote-dns"

static char *failure(char **error, const char *message) {
    if (error)
        *error = sb_strdup(message);
    return NULL;
}
static bool text(const sbj *value, size_t max, bool empty) {
    if (!sbj_is_string(value) || value->v.str.len > max || (!empty && !value->v.str.len) ||
        memchr(value->v.str.ptr, 0, value->v.str.len))
        return false;
    for (size_t i = 0; i < value->v.str.len; ++i)
        if ((unsigned char)value->v.str.ptr[i] < 32 || (unsigned char)value->v.str.ptr[i] == 127)
            return false;
    return sbj_validate_utf8(value, NULL) == 0;
}
static sbj *parse(const char *raw, size_t max) {
    if (!raw || !*raw || strlen(raw) > max)
        return NULL;
    unsigned depth = 0;
    bool string = false, escape = false;
    for (const char *p = raw; *p; ++p) {
        if (string) {
            if (escape)
                escape = false;
            else if (*p == '\\')
                escape = true;
            else if (*p == '"')
                string = false;
        } else if (*p == '"')
            string = true;
        else if (*p == '{' || *p == '[') {
            if (++depth > 32)
                return NULL;
        } else if (*p == '}' || *p == ']') {
            if (!depth)
                return NULL;
            --depth;
        }
    }
    if (depth || string)
        return NULL;
    sbj *json = sbj_parse_strict(raw, strlen(raw), NULL, 0);
    if (json && sbj_validate_utf8(json, NULL)) {
        sbj_free(json);
        return NULL;
    }
    return json;
}
static bool safe_keys(const sbj *value, unsigned depth, bool managed) {
    if (depth > 32)
        return false;
    if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value); ++i)
            if (!safe_keys(sbj_arr_at(value, i), depth + 1, managed))
                return false;
    } else if (sbj_is_object(value)) {
        static const char *forbidden[] = {"certificate_path",
                                          "key_path",
                                          "private_key_path",
                                          "client_certificate_path",
                                          "client_key_path",
                                          "certificate_directory_path",
                                          "known_hosts_path",
                                          "config_path",
                                          "acme",
                                          "certificate_providers",
                                          "protect_path",
                                          "inet4_bind_address",
                                          "inet6_bind_address",
                                          "plugin",
                                          "plugin_opts",
                                          "bind_interface",
                                          "routing_mark",
                                          "netns",
                                          "network_namespace",
#ifndef SBA_ALLOW_PROCESS_RULES
                                          "process_name",
                                          "process_path",
                                          "process_path_regex",
#endif
                                          "package_name",
                                          "user",
                                          "user_id",
                                          "user_id_range",
                                          "include_uid",
                                          "exclude_uid",
                                          "include_package",
                                          "exclude_package",
                                          "interface_name",
                                          "auto_redirect",
                                          "set_system_proxy",
                                          "script",
                                          "command",
                                          "exec"};
        for (size_t i = 0; i < sbj_obj_len(value); ++i) {
            const char *key = sbj_obj_key(value, i);
            if (strlen(key) != value->v.obj.key_lens[i])
                return false;
            for (size_t j = 0; j < sizeof forbidden / sizeof *forbidden; ++j)
                if (!strcmp(key, forbidden[j]))
                    return false;
            if ((!managed && !strcmp(key, "detour")) || !safe_keys(sbj_obj_val(value, i), depth + 1, managed))
                return false;
        }
    } else if (sbj_is_string(value) && !text(value, SBA_LIMIT, true))
        return false;
    return true;
}
static bool node_valid(const sbj *node) {
    const char *type = sbj_get_str(node, "type", "");
    bool supported = !strcmp(type, "shadowsocks") || !strcmp(type, "vmess") || !strcmp(type, "vless") ||
                     !strcmp(type, "trojan") || !strcmp(type, "hysteria2") || !strcmp(type, "tuic") ||
                     !strcmp(type, "socks") || !strcmp(type, "http");
    const sbj *port = sbj_get(node, "server_port");
    return supported && sbj_validate_utf8(node, NULL) == 0 && text(sbj_get(node, "tag"), 256, false) &&
           text(sbj_get(node, "server"), 253, false) && sbj_is_integer(port) && sbj_as_int(port, 0) > 0 &&
           sbj_as_int(port, 0) <= 65535 && safe_keys(node, 0, false);
}
/* Account for base64 wrappers before applying mobile input limits. */
static bool subscription_resource_bound(const char *body, size_t length) {
    sb_buf normalized = {0};
    bool base64 = true;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)body[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        if (!(isalnum(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '=')) {
            base64 = false;
            break;
        }
        sb_buf_putc(&normalized, c == '-' ? '+' : c == '_' ? '/' : (char)c);
    }
    unsigned char *decoded = NULL;
    size_t decoded_length = 0;
    if (base64 && normalized.len && normalized.len % 4 != 1) {
        while (normalized.len % 4)
            sb_buf_putc(&normalized, '=');
        decoded = sb_base64_decode_strict(normalized.p, normalized.len, &decoded_length);
    }
    sb_buf_free(&normalized);
    const char *input = decoded ? (const char *)decoded : body;
    size_t count = decoded ? decoded_length : length, lines = 1;
    bool valid = !memchr(input, 0, count);
    for (size_t i = 0; i < count && valid; ++i)
        if (input[i] == '\n' && ++lines > 8192)
            valid = false;
    free(decoded);
    return valid;
}
char *sba_import_subscription(const char *body, size_t length, char **error) {
    if (error)
        *error = NULL;
    if (!body || !length || length > 512u * 1024u || memchr(body, 0, length))
        return failure(error, "订阅必须是非空 UTF-8 文本，最大 512 KB");
    if (!subscription_resource_bound(body, length))
        return failure(error, "订阅文本超过移动端的安全解析限制");
    sb_proxy_import imported;
    sb_err ignored = {0};
    if (sb_parse_subscription_report(body, length, &imported, &ignored)) {
        sb_proxy_import_free(&imported);
        return failure(error, "订阅格式无效或没有兼容节点");
    }
    sbj *nodes = sbj_array(), *warnings = sbj_array();
    for (size_t i = 0; i < imported.skipped.len && i < 128; ++i)
        sbj_arr_push(warnings, sbj_str(imported.skipped.items[i]));
    size_t skipped = imported.skipped.len;
    sb_strvec tags = {0};
    for (size_t i = 0; i < imported.nodes.len; ++i) {
        const sb_parsed_node *item = &imported.nodes.items[i];
        sbj *node = sbj_clone(item->protocol_config);
        sbj_set_str(node, "type", item->node_type);
        sbj_set_str(node, "tag", item->tag);
        sbj_set_str(node, "server", item->server);
        sbj_set_int(node, "server_port", item->server_port);
        if (!node_valid(node) || sbj_arr_len(nodes) >= 256) {
            ++skipped;
            if (sbj_arr_len(warnings) < 128)
                sbj_arr_push(warnings, sbj_str("Proxy entry: unsupported " SBA_PLATFORM_LABEL " option or node limit"));
            sbj_free(node);
            continue;
        }
        char *tag = sb_strdup(item->tag);
        unsigned suffix = 1;
        while (sb_strvec_contains(&tags, tag)) {
            free(tag);
            size_t prefix = strlen(item->tag);
            if (prefix > 220)
                prefix = 220;
            while (prefix && ((unsigned char)item->tag[prefix] & 0xc0u) == 0x80u)
                --prefix;
            tag = sb_asprintf("%.*s (%u)", (int)prefix, item->tag, ++suffix);
        }
        sbj_set_str(node, "tag", tag);
        sb_strvec_push_take(&tags, tag);
        sbj_arr_push(nodes, node);
    }
    sb_strvec_free(&tags);
    sb_proxy_import_free(&imported);
    if (!sbj_arr_len(nodes)) {
        sbj_free(nodes);
        sbj_free(warnings);
        return failure(error, "没有可用于 " SBA_PLATFORM_LABEL " 客户端的兼容节点");
    }
    sbj *result = sbj_object(), *report = sbj_object();
    sbj_set_int(report, "imported", (int64_t)sbj_arr_len(nodes));
    sbj_set_int(report, "skipped", (int64_t)skipped);
    sbj_set(report, "warnings", warnings);
    sbj_set_str(report, "notice", "仅导入代理节点；远端规则、脚本和监听服务不导入");
    sbj_set(result, "nodes", nodes);
    sbj_set(result, "report", report);
    char *out = sbj_dump(result, -1);
    sbj_free(result);
    return out;
}
static bool domain_valid(const sbj *value) {
    if (!text(value, 253, false))
        return false;
    const char *name = value->v.str.ptr, *label = name;
    if (!strchr(name, '.') || strspn(name, "0123456789.") == strlen(name))
        return false;
    for (const char *p = name;; ++p) {
        if (*p && *p != '.') {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-'))
                return false;
            continue;
        }
        size_t n = (size_t)(p - label);
        if (!n || n > 63 || *label == '-' || p[-1] == '-')
            return false;
        if (!*p)
            break;
        label = p + 1;
    }
    return true;
}
static bool domain_overlap(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    return !strcmp(a, b) || (al > bl && a[al - bl - 1] == '.' && !strcmp(a + al - bl, b)) ||
           (bl > al && b[bl - al - 1] == '.' && !strcmp(b + bl - al, a));
}
static bool settings_valid(const sbj *settings) {
    if (!sbj_is_object(settings))
        return false;
    const sbj *selected = sbj_get(settings, "selected_tag"), *groups = sbj_get(settings, "local_groups");
    if (selected && !text(selected, 512, true))
        return false;
    for (size_t i = 0; i < sbj_obj_len(settings); ++i)
        if (strcmp(sbj_obj_key(settings, i), "selected_tag") &&
            strcmp(sbj_obj_key(settings, i), "local_groups"))
            return false;
    if (!groups)
        return true;
    if (!sbj_is_array(groups) || sbj_arr_len(groups) > 32)
        return false;
    sb_strvec ids = {0}, domains = {0};
    bool ok = true;
    for (size_t i = 0; i < sbj_arr_len(groups) && ok; ++i) {
        const sbj *g = sbj_arr_at(groups, i), *id = sbj_get(g, "id"), *ds = sbj_get(g, "domains");
        if (!text(id, 48, false) ||
            strspn(id->v.str.ptr, "abcdefghijklmnopqrstuvwxyz0123456789-") != id->v.str.len ||
            sb_strvec_contains(&ids, id->v.str.ptr) || !text(sbj_get(g, "name"), 128, false) ||
            !text(sbj_get(g, "outbound"), 512, false) || !sbj_is_array(ds) || !sbj_arr_len(ds) ||
            sbj_arr_len(ds) > 256) {
            ok = false;
            break;
        }
        sb_strvec_push(&ids, id->v.str.ptr);
        for (size_t j = 0; j < sbj_arr_len(ds) && ok; ++j) {
            const sbj *d = sbj_arr_at(ds, j);
            if (!domain_valid(d)) {
                ok = false;
                break;
            }
            for (size_t k = 0; k < domains.len; ++k)
                if (domain_overlap(domains.items[k], d->v.str.ptr))
                    ok = false;
            sb_strvec_push(&domains, d->v.str.ptr);
        }
    }
    sb_strvec_free(&ids);
    sb_strvec_free(&domains);
    return ok;
}
char *sba_validate_settings(const char *settings, char **error) {
    if (error)
        *error = NULL;
    sbj *value = parse(settings ? settings : "{}", SBA_LIMIT);
    if (!settings_valid(value)) {
        sbj_free(value);
        return failure(error, "本地设置无效；分组域名必须唯一且不互相覆盖");
    }
    char *result = sbj_dump(value, -1);
    sbj_free(value);
    return result;
}
static sbj *array_of(const char *value) {
    sbj *a = sbj_array();
    sbj_arr_push(a, sbj_str(value));
    return a;
}
static sbj *outbound_named(const sbj *outbounds, const char *tag) {
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        sbj *o = sbj_arr_at(outbounds, i);
        if (sbj_string_is(sbj_get(o, "tag"), tag))
            return o;
    }
    return NULL;
}
static sbj *dns_server(const char *tag, const char *detour) {
    sbj *dns = sbj_object();
    sbj_set_str(dns, "tag", tag);
    sbj_set_str(dns, "type", "https");
    sbj_set_str(dns, "server", "1.1.1.1");
    sbj_set_str(dns, "path", "/dns-query");
    /* sing-box 1.14 rejects detours to an empty direct outbound. The DNS
     * transport's own dialer already connects directly when detour is absent. */
    if (detour && strcmp(detour, DIRECT))
        sbj_set_str(dns, "detour", detour);
    return dns;
}
static int control_address_family(const char *host) {
    unsigned char address[16];
    if (host && inet_pton(AF_INET, host, address) == 1)
        return AF_INET;
    if (host && inet_pton(AF_INET6, host, address) == 1)
        return AF_INET6;
    return 0;
}
static bool control_host_valid(const char *host) {
    if (!host || !*host || control_address_family(host))
        return true;
    if (strspn(host, "0123456789.") == strlen(host))
        return false;
    char *qualified = strchr(host, '.') ? sb_strdup(host) : sb_asprintf("%s.invalid", host);
    sbj *value = sbj_str_take(qualified);
    bool valid = domain_valid(value);
    sbj_free(value);
    return valid;
}
static bool has_text(const sbj *value, const char *text_value) {
    if (sbj_string_is(value, text_value))
        return true;
    for (size_t i = 0; i < sbj_arr_len(value); ++i)
        if (sbj_string_is(sbj_arr_at(value, i), text_value))
            return true;
    return false;
}
static bool protected_rule(const sbj *rule, const sbj *root, bool dns_rule) {
    const char *action = sbj_get_str(rule, "action", "route");
    const char *target = sbj_get_str(rule, "outbound", "");
    if (dns_rule) {
        const sbj *server =
            outbound_named(sbj_get(sbj_get(root, "dns"), "servers"), sbj_get_str(rule, "server", ""));
        target = sbj_get_str(server, "detour", "");
    }
    if (outbound_named(sbj_get(root, "endpoints"), target))
        return true;
    return strcmp(action, "route") || sbj_get(rule, "ip_cidr") || sbj_get(rule, "source_ip_cidr") ||
           sbj_get(rule, "ip_is_private") || sbj_get(rule, "domain") || sbj_get(rule, "type") ||
           sbj_get(rule, "rules") || has_text(sbj_get(rule, "rule_set"), "geosite-private");
}
static size_t protect_rule_prefix(sbj *rules, const sbj *root, bool dns_rule) {
    size_t count = 0;
    for (size_t i = 0; i < sbj_arr_len(rules); ++i) {
        if (protected_rule(sbj_arr_at(rules, i), root, dns_rule)) {
            sbj *rule = sbj_arr_take(rules, i);
            sbj_arr_insert(rules, count++, rule);
        }
    }
    return count;
}
static bool rule_sets_valid(const sbj *root) {
    const sbj *sets = sbj_get(sbj_get(root, "route"), "rule_set");
    if (!sets)
        return true;
    if (!sbj_is_array(sets) || sbj_arr_len(sets) > 256)
        return false;
    for (size_t i = 0; i < sbj_arr_len(sets); ++i) {
        const sbj *rule = sbj_arr_at(sets, i);
        const char *url = sbj_get_str(rule, "url", "");
        if (!sbj_string_is(sbj_get(rule, "type"), "remote") || sbj_get(rule, "path") ||
            !sb_starts_with(url, "https://") || strchr(url, '\\') || strchr(url, '#') ||
            !text(sbj_get(rule, "url"), 4096, false))
            return false;
        const char *end = strchr(url + 8, '/');
        size_t authority = end ? (size_t)(end - (url + 8)) : strlen(url + 8);
        if (!authority || memchr(url + 8, '@', authority) || memchr(url + 8, '?', authority))
            return false;
    }
    return true;
}
char *sba_build_runtime(const char *source, const char *subscriptions, const char *settings,
                        const char *control_host, char **error) {
    if (error)
        *error = NULL;
    sbj *root = source && *source ? parse(source, SBA_LIMIT) : sbj_object();
    bool managed = source && *source;
    sbj *subs = parse(subscriptions ? subscriptions : "[]", SBA_LIMIT),
        *prefs = parse(settings ? settings : "{}", SBA_LIMIT);
    const char *message = "配置无效或包含 " SBA_PLATFORM_LABEL " 不支持的进程、文件、服务或接口选项";
    if (!sbj_is_object(root) || !sbj_is_array(subs) || sbj_arr_len(subs) > 32 || !settings_valid(prefs) ||
        !control_host_valid(control_host))
        goto bad;
    /* OS interface/listener setup is owned by NetworkExtension, not a remote
     * server config. Remove only those replacement sections before scanning. */
    sbj *old_inbounds = sbj_take(root, "inbounds");
    char *tun_tag = sb_strdup("sb-easy-tun");
    for (size_t i = 0; i < sbj_arr_len(old_inbounds); ++i) {
        const sbj *in = sbj_arr_at(old_inbounds, i);
        if (sbj_string_is(sbj_get(in, "type"), "tun") && text(sbj_get(in, "tag"), 128, false)) {
            sb_str_set(&tun_tag, sbj_get_str(in, "tag", "sb-easy-tun"));
            break;
        }
    }
    sbj_free(old_inbounds);
    sbj_del(root, "experimental");
    sbj_del(root, "log");
    const sbj *services = sbj_get(root, "services");
    if (!safe_keys(root, 0, true) || !rule_sets_valid(root) ||
        (services && (!sbj_is_array(services) || sbj_arr_len(services)))) {
        free(tun_tag);
        goto bad;
    }
    sbj_del(root, "services");
    const sbj *endpoints = sbj_get(root, "endpoints");
    if (endpoints && (!sbj_is_array(endpoints) || sbj_arr_len(endpoints) > 32)) {
        free(tun_tag);
        goto bad;
    }
    for (size_t i = 0; i < sbj_arr_len(endpoints); ++i)
        if (!sbj_string_is(sbj_get(sbj_arr_at(endpoints, i), "type"), "wireguard") ||
            sbj_get_bool(sbj_arr_at(endpoints, i), "system", false) ||
            sbj_get_int(sbj_arr_at(endpoints, i), "listen_port", 0) != 0) {
            free(tun_tag);
            goto bad;
        }
    sbj *outbounds = sbj_get(root, "outbounds");
    if (!outbounds) {
        outbounds = sbj_array();
        sbj_set(root, "outbounds", outbounds);
    }
    if (!sbj_is_array(outbounds) || sbj_arr_len(outbounds) > 512) {
        free(tun_tag);
        goto bad;
    }
    sb_strvec names = {0};
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        const sbj *o = sbj_arr_at(outbounds, i);
        const char *tag = sbj_get_str(o, "tag", "");
        if (!text(sbj_get(o, "tag"), 512, false) || sb_strvec_contains(&names, tag) ||
            sb_starts_with(tag, SBA_PLATFORM_PREFIX)) {
            free(tun_tag);
            sb_strvec_free(&names);
            goto bad;
        }
        sb_strvec_push(&names, tag);
    }
    sbj *leafs = sbj_array();
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj *sub = sbj_arr_at(subs, i), *id = sbj_get(sub, "id"), *nodes = sbj_get(sub, "nodes");
        if (!text(id, 64, false) ||
            strspn(id->v.str.ptr, "abcdefghijklmnopqrstuvwxyz0123456789-") != id->v.str.len ||
            !sbj_is_array(nodes) || sbj_arr_len(nodes) > 256) {
            free(tun_tag);
            sb_strvec_free(&names);
            sbj_free(leafs);
            goto bad;
        }
        for (size_t j = 0; j < sbj_arr_len(nodes); ++j) {
            const sbj *node = sbj_arr_at(nodes, j);
            if (!node_valid(node) || sbj_arr_len(outbounds) >= 512) {
                free(tun_tag);
                sb_strvec_free(&names);
                sbj_free(leafs);
                goto bad;
            }
            char *tag = sb_asprintf("local-%s/%s", id->v.str.ptr, sbj_get_str(node, "tag", ""));
            if (sb_strvec_contains(&names, tag)) {
                free(tag);
                free(tun_tag);
                sb_strvec_free(&names);
                sbj_free(leafs);
                goto bad;
            }
            sb_strvec_push(&names, tag);
            sbj *copy = sbj_clone(node);
            sbj_set_str(copy, "tag", tag);
            sbj_arr_push(outbounds, copy);
            sbj_arr_push(leafs, sbj_str(tag));
            free(tag);
        }
    }
    sb_strvec_free(&names);
    sbj *direct = sbj_object();
    sbj_set_str(direct, "type", "direct");
    sbj_set_str(direct, "tag", DIRECT);
    sbj_arr_push(outbounds, direct);
    sbj *route = sbj_get_or_object(root, "route");
    if (!sbj_is_object(route)) {
        free(tun_tag);
        sbj_free(leafs);
        goto bad;
    }
    if (!managed) {
        if (!sbj_arr_len(leafs)) {
            message = "独立模式需要至少一个订阅节点";
            free(tun_tag);
            sbj_free(leafs);
            goto bad;
        }
        sbj *selector = sbj_object();
        sbj_set_str(selector, "type", "selector");
        sbj_set_str(selector, "tag", DEFAULT_SELECTOR);
        sbj_set(selector, "outbounds", leafs);
        leafs = NULL;
        sbj_arr_push(outbounds, selector);
        sbj_set_str(route, "final", DEFAULT_SELECTOR);
    }
    sbj_free(leafs);
    const char *final = sbj_get_str(route, "final", "");
    sbj *final_outbound = outbound_named(outbounds, final);
    if (!final_outbound)
        final_outbound = outbound_named(endpoints, final);
    if (!final_outbound) {
        message = "默认出口不存在";
        free(tun_tag);
        goto bad;
    }
    const char *selected = sbj_get_str(prefs, "selected_tag", "");
    if (*selected) {
        if (!outbound_named(outbounds, selected) ||
            !sbj_string_is(sbj_get(final_outbound, "type"), "selector")) {
            message = "已选择的节点不再可用，请重新选择";
            free(tun_tag);
            goto bad;
        }
        sbj *candidates = sbj_get(final_outbound, "outbounds");
        bool found = false;
        for (size_t i = 0; i < sbj_arr_len(candidates); ++i)
            if (sbj_string_is(sbj_arr_at(candidates, i), selected))
                found = true;
        if (!found && sb_starts_with(selected, "local-")) {
            sbj_arr_push(candidates, sbj_str(selected));
            found = true;
        }
        if (!found) {
            message = "节点不属于默认策略组";
            free(tun_tag);
            goto bad;
        }
        sbj_set_str(final_outbound, "default", selected);
    }
    sbj *dns = sbj_get_or_object(root, "dns");
    if (!sbj_is_object(dns)) {
        free(tun_tag);
        goto bad;
    }
    sbj *servers = sbj_get_or_array(dns, "servers");
    if (!sbj_is_array(servers)) {
        free(tun_tag);
        goto bad;
    }
    for (size_t i = 0; i < sbj_arr_len(servers); ++i)
        if (sb_starts_with(sbj_get_str(sbj_arr_at(servers, i), "tag", ""), SBA_PLATFORM_PREFIX)) {
            free(tun_tag);
            goto bad;
        }
    sbj_arr_push(servers, dns_server(BOOTSTRAP, DIRECT));
    if (!sbj_get(route, "default_domain_resolver"))
        sbj_set_str(route, "default_domain_resolver", BOOTSTRAP);
    if (!managed) {
        sbj_arr_push(servers, dns_server(REMOTE_DNS, DEFAULT_SELECTOR));
        sbj_set_str(dns, "final", REMOTE_DNS);
        sbj_set_str(dns, "strategy", "prefer_ipv4");
    }
    sbj *rules = sbj_get_or_array(route, "rules"), *dns_rules = sbj_get_or_array(dns, "rules");
    if (!sbj_is_array(rules) || !sbj_is_array(dns_rules)) {
        free(tun_tag);
        goto bad;
    }
    size_t protected_routes = protect_rule_prefix(rules, root, false);
    size_t protected_dns = protect_rule_prefix(dns_rules, root, true);
    const sbj *groups = sbj_get(prefs, "local_groups");
    for (size_t i = sbj_arr_len(groups); i > 0; --i) {
        const sbj *g = sbj_arr_at(groups, i - 1);
        const char *target = sbj_get_str(g, "outbound", "");
        sbj *candidate = outbound_named(outbounds, target);
        if (!candidate || sbj_string_is(sbj_get(candidate, "type"), "selector") ||
            sbj_string_is(sbj_get(candidate, "type"), "urltest")) {
            message = "本地域名分组的节点已失效";
            free(tun_tag);
            goto bad;
        }
        sbj *rule = sbj_object();
        sbj_set(rule, "domain_suffix", sbj_clone(sbj_get(g, "domains")));
        sbj_set_str(rule, "outbound", target);
        sbj_arr_insert(rules, protected_routes, rule);
        char *dns_tag = sb_asprintf(SBA_PLATFORM_PREFIX "group-%s", sbj_get_str(g, "id", ""));
        sbj_arr_push(servers, dns_server(dns_tag,
                                       sbj_string_is(sbj_get(candidate, "type"), "direct")
                                           ? NULL
                                           : target));
        rule = sbj_object();
        sbj_set(rule, "domain_suffix", sbj_clone(sbj_get(g, "domains")));
        sbj_set_str(rule, "server", dns_tag);
        sbj_arr_insert(dns_rules, protected_dns, rule);
        free(dns_tag);
    }
    if (control_host && *control_host) {
        int family = control_address_family(control_host);
        bool ip = family != 0;
        char *match =
            ip ? sb_asprintf("%s/%d", control_host, family == AF_INET ? 32 : 128) : sb_strdup(control_host);
        sbj *rule = sbj_object();
        sbj_set(rule, ip ? "ip_cidr" : "domain", array_of(match));
        free(match);
        sbj_set_str(rule, "outbound", DIRECT);
        sbj_arr_insert(rules, 0, rule);
        if (!ip) {
            rule = sbj_object();
            sbj_set(rule, "domain", array_of(control_host));
            sbj_set_str(rule, "server", BOOTSTRAP);
            sbj_arr_insert(dns_rules, 0, rule);
        }
    }
    sbj *hijack = sbj_object();
    sbj_set_str(hijack, "protocol", "dns");
    sbj_set_str(hijack, "action", "hijack-dns");
    sbj_arr_insert(rules, 0, hijack);
    sbj *sniff = sbj_object();
    sbj_set_str(sniff, "action", "sniff");
    sbj_arr_insert(rules, 0, sniff);
    sbj_set_bool(route, "auto_detect_interface", true);
    sbj *tun = sbj_object(), *inbounds = sbj_array();
    sbj_set_str(tun, "type", "tun");
    sbj_set_str(tun, "tag", tun_tag);
    free(tun_tag);
    sbj *addresses = array_of("172.19.0.1/30");
    sbj_arr_push(addresses, sbj_str("fdfe:dcba:9876::1/126"));
    sbj_set(tun, "address", addresses);
    sbj_set_bool(tun, "auto_route", true);
    sbj_set_bool(tun, "strict_route", true);
    sbj_set_int(tun, "mtu", 1500);
    sbj_set_str(tun, "stack", "gvisor");
    sbj_arr_push(inbounds, tun);
    sbj_set(root, "inbounds", inbounds);
    sbj *log = sbj_object();
    sbj_set_str(log, "level", "warn");
    sbj_set(root, "log", log);
    sbj *experimental = sbj_object(), *cache = sbj_object();
    sbj_set_bool(cache, "enabled", true);
    sbj_set_str(cache, "path", "cache.db");
    sbj_set(experimental, "cache_file", cache);
    sbj_set(root, "experimental", experimental);
    char *result = sbj_dump(root, -1);
    sbj_free(root);
    sbj_free(subs);
    sbj_free(prefs);
    return result;
bad:
    sbj_free(root);
    sbj_free(subs);
    sbj_free(prefs);
    return failure(error, message);
}
char *sba_subscription_metadata(const char *header, long long now_seconds) {
    sbj *out = sbj_object();
    bool valid = header && *header && strlen(header) <= 2048;
    uint64_t values[4] = {0};
    bool present[4] = {false};
    const char *names[] = {"upload", "download", "total", "expire"};
    sb_strvec parts = sb_split(header ? header : "", ';');
    for (size_t i = 0; i < parts.len && valid; ++i) {
        char *part = sb_trim_dup(parts.items[i]), *equal = strchr(part, '=');
        if (!equal) {
            free(part);
            valid = false;
            break;
        }
        *equal = 0;
        char *name = sb_trim_dup(part), *number = sb_trim_dup(equal + 1);
        int field = -1;
        for (int j = 0; j < 4; ++j)
            if (!strcmp(name, names[j]))
                field = j;
        if (field >= 0) {
            if (present[field] || !*number)
                valid = false;
            uint64_t n = 0;
            for (const char *p = number; *p && valid; ++p) {
                if (*p < '0' || *p > '9' || n > (UINT64_C(9007199254740991) - (unsigned)(*p - '0')) / 10)
                    valid = false;
                else
                    n = n * 10 + (unsigned)(*p - '0');
            }
            values[field] = n;
            present[field] = true;
        }
        free(name);
        free(number);
        free(part);
    }
    sb_strvec_free(&parts);
    valid = valid && (present[0] || present[1] || present[2] || present[3]);
    if (values[0] > UINT64_C(9007199254740991) - values[1])
        valid = false;
    sbj_set_bool(out, "available", valid);
    if (valid) {
        uint64_t used = values[0] + values[1];
        bool usage = present[0] && present[1];
        if (usage)
            sbj_set_int(out, "used_bytes", (int64_t)used);
        if (present[2])
            sbj_set_int(out, "total_bytes", (int64_t)values[2]);
        if (usage && present[2] && values[2] > 0) {
            sbj_set_int(out, "remaining_bytes", values[2] > used ? (int64_t)(values[2] - used) : 0);
            sbj_set_bool(out, "quota_exhausted", used >= values[2]);
        }
        if (present[3]) {
            sbj_set_int(out, "expires_at", (int64_t)values[3]);
            sbj_set_bool(out, "expired",
                         values[3] > 0 && now_seconds >= 0 && values[3] <= (uint64_t)now_seconds);
        }
    }
    char *result = sbj_dump(out, -1);
    sbj_free(out);
    return result;
}
