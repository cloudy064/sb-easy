#include "dashboard.h"
#include <stdlib.h>
#include <string.h>

static const char *text(const sbj *source, const char *key) {
    const sbj *value = sbj_get(source, key);
    return sbw_json_string(value, 128, true) ? value->v.str.ptr : "";
}
static sbj *strings(const sbj *source, size_t limit) {
    sbj *result = sbj_array();
    for (size_t i = 0; i < sbj_arr_len(source) && i < limit; ++i) {
        const sbj *value = sbj_arr_at(source, i);
        if (sbw_json_string(value, 128, false)) sbj_arr_push(result, sbj_clone(value));
    }
    return result;
}
static int64_t counter(const sbj *source, const char *key) {
    int64_t value = sbj_get_int(source, key, 0);
    return value >= 0 && value <= INT64_C(9007199254740991) ? value : 0;
}
static void match_value(sb_buf *buffer, const sbj *value) {
    if (sbw_json_string(value, 128, true)) sb_buf_puts(buffer, value->v.str.ptr);
    else if (sbj_is_string(value)) sb_buf_puts(buffer, "…");
    else if (sbj_is_bool(value)) sb_buf_puts(buffer, value->v.b ? "true" : "false");
    else if (sbj_is_integer(value)) sb_buf_printf(buffer, "%lld", (long long)sbj_as_int(value, 0));
    else if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value) && i < 3; ++i) {
            if (i) sb_buf_puts(buffer, ", ");
            const sbj *item = sbj_arr_at(value, i);
            if (!sbj_is_array(item) && !sbj_is_object(item)) match_value(buffer, item);
        }
        if (sbj_arr_len(value) > 3) sb_buf_puts(buffer, ", …");
    }
}
static char *matches(const sbj *rule) {
    const char *keys[] = {"domain", "domain_suffix", "domain_keyword", "ip_cidr", "source_ip_cidr",
        "ip_is_private", "port", "network", "protocol", "process_name", "package_name", "rule_set", "clash_mode"};
    sb_buf buffer = {0};
    if (sbj_string_is(sbj_get(rule, "type"), "logical")) {
        sb_buf_printf(&buffer, "logical %s · %zu subrules", text(rule, "mode"), sbj_arr_len(sbj_get(rule, "rules")));
    }
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const sbj *value = sbj_get(rule, keys[i]);
        if (!value) continue;
        sb_buf part = {0}; sb_buf_puts(&part, keys[i]); sb_buf_puts(&part, ": "); match_value(&part, value);
        if (buffer.len + part.len > 512) { sb_buf_free(&part); sb_buf_puts(&buffer, " · …"); break; }
        if (buffer.len) sb_buf_puts(&buffer, " · ");
        sb_buf_append(&buffer, part.p, part.len); sb_buf_free(&part);
    }
    bool additional = false;
    for (size_t i = 0; i < sbj_obj_len(rule); ++i) {
        const char *key = sbj_obj_key(rule, i);
        bool known = !strcmp(key, "action") || !strcmp(key, "outbound") || !strcmp(key, "type") || !strcmp(key, "mode") || !strcmp(key, "rules");
        for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); ++k) if (!strcmp(key, keys[k])) known = true;
        if (!known) additional = true;
    }
    if (additional) sb_buf_puts(&buffer, buffer.len ? " · additional conditions" : "additional conditions");
    if (!buffer.len) sb_buf_puts(&buffer, "all traffic");
    return sb_buf_detach(&buffer);
}
sbj *sbw_config_catalog(const sbj *snapshot) {
    const sbj *content = sbj_get(snapshot, "content");
    if (!sbw_json_string(content, 8U * 1024U * 1024U, false)) return sbj_null();
    sbj *config = sbw_json_parse(content->v.str.ptr, content->v.str.len, 32, NULL);
    if (!sbj_is_object(config)) { sbj_free(config); return sbj_null(); }
    sbj *result = sbj_object(), *nodes = sbj_array(), *rules = sbj_array(), *inbounds = sbj_array();
    const sbj *outbounds = sbj_get(config, "outbounds"), *route = sbj_get(config, "route");
    const sbj *source_rules = sbj_get(route, "rules"), *source_inbounds = sbj_get(config, "inbounds");
    sbj_set_str(result, "etag", sbj_get_str(snapshot, "etag", ""));
    sbj_set_str(result, "final", text(route, "final"));
    for (size_t i = 0; i < sbj_arr_len(outbounds) && i < 128; ++i) {
        const sbj *source = sbj_arr_at(outbounds, i); sbj *node = sbj_object();
        sbj_set_str(node, "tag", text(source, "tag")); sbj_set_str(node, "type", text(source, "type"));
        sbj_set_str(node, "selected", text(source, "default"));
        sbj_set(node, "members", strings(sbj_get(source, "outbounds"), 16));
        sbj_set_int(node, "member_count", (int64_t)sbj_arr_len(sbj_get(source, "outbounds")));
        sbj_arr_push(nodes, node);
    }
    for (size_t i = 0; i < sbj_arr_len(source_rules) && i < 128; ++i) {
        const sbj *source = sbj_arr_at(source_rules, i); sbj *rule = sbj_object();
        char *match = matches(source);
        sbj_set_int(rule, "index", (int64_t)i + 1); sbj_set_str(rule, "match", match); free(match);
        sbj_set_str(rule, "action", sbj_get_str(source, "action", "route"));
        /* Enforce display bounds even for malformed but downloaded configs. */
        if (!sbw_json_string(sbj_get(rule, "action"), 128, true)) sbj_set_str(rule, "action", "unknown");
        sbj_set_str(rule, "outbound", text(source, "outbound")); sbj_arr_push(rules, rule);
    }
    for (size_t i = 0; i < sbj_arr_len(source_inbounds) && i < 16; ++i) {
        const sbj *source = sbj_arr_at(source_inbounds, i); sbj *inbound = sbj_object();
        sbj_set_str(inbound, "type", text(source, "type")); sbj_set_str(inbound, "listen", "127.0.0.1");
        sbj_set_int(inbound, "port", counter(source, "listen_port"));
        sbj_set_bool(inbound, "auto_route", sbj_get_bool(source, "auto_route", false)); sbj_arr_push(inbounds, inbound);
    }
    sbj_set_int(result, "node_count", (int64_t)sbj_arr_len(outbounds));
    sbj_set_int(result, "rule_count", (int64_t)sbj_arr_len(source_rules));
    sbj_set(result, "nodes", nodes); sbj_set(result, "rules", rules); sbj_set(result, "inbounds", inbounds);
    sbj_free(config); return result;
}
sbj *sbw_dashboard_snapshot(const sbj *connections, const sbj *proxies) {
    sbj *result = sbj_object(), *rows = sbj_array(), *nodes = sbj_array();
    const sbj *source_rows = sbj_get(connections, "connections"), *source_nodes = sbj_get(proxies, "proxies");
    sbj_set_int(result, "upload_total", counter(connections, "uploadTotal"));
    sbj_set_int(result, "download_total", counter(connections, "downloadTotal"));
    sbj_set_int(result, "connection_count", (int64_t)sbj_arr_len(source_rows));
    for (size_t i = 0; i < sbj_arr_len(source_rows) && i < 128; ++i) {
        const sbj *source = sbj_arr_at(source_rows, i), *metadata = sbj_get(source, "metadata");
        sbj *row = sbj_object();
        sbj_set_str(row, "id", text(source, "id")); sbj_set_str(row, "host", text(metadata, "host"));
        sbj_set_str(row, "destination", text(metadata, "destinationIP"));
        sbj_set_str(row, "port", text(metadata, "destinationPort"));
        sbj_set_str(row, "network", text(metadata, "network")); sbj_set_str(row, "type", text(metadata, "type"));
        const char *process = text(metadata, "processPath"), *base = process;
        for (const char *p = process; *p; ++p) if (*p == '/' || *p == '\\') base = p + 1;
        sbj_set_str(row, "process", *base ? base : text(metadata, "process"));
        sbj_set_str(row, "rule", text(source, "rule"));
        sbj_set(row, "chains", strings(sbj_get(source, "chains"), 8));
        sbj_set_int(row, "upload", counter(source, "upload")); sbj_set_int(row, "download", counter(source, "download"));
        sbj_arr_push(rows, row);
    }
    for (size_t i = 0; i < sbj_obj_len(source_nodes) && sbj_arr_len(nodes) < 128; ++i) {
        const sbj *source = sbj_obj_val(source_nodes, i);
        const char *tag = text(source, "name");
        if (!strcmp(tag, "GLOBAL") || !strcmp(tag, "sb-easy-control-direct")) continue;
        sbj *node = sbj_object();
        sbj_set_str(node, "tag", tag); sbj_set_str(node, "type", text(source, "type"));
        sbj_set_str(node, "selected", text(source, "now"));
        sbj_set(node, "members", strings(sbj_get(source, "all"), 16));
        sbj_set_int(node, "member_count", (int64_t)sbj_arr_len(sbj_get(source, "all")));
        const sbj *history = sbj_get(source, "history"), *last = sbj_arr_at(history, sbj_arr_len(history) ? sbj_arr_len(history) - 1 : 0);
        int64_t delay = counter(last, "delay");
        sbj_set(node, "delay", delay > 0 && delay <= 65535 ? sbj_int(delay) : sbj_null());
        sbj_arr_push(nodes, node);
    }
    sbj_set(result, "connections", rows); sbj_set(result, "nodes", nodes); return result;
}
