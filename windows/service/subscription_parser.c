#include "subscriptions.h"
#include "sb/proxy_parser.h"
#include <winhttp.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Small shared-parser ownership boundary; the Windows service deliberately
 * does not link the Linux store, crypto client or configuration renderer. */
void sb_parsed_node_init(sb_parsed_node *node) {
    memset(node, 0, sizeof(*node));
    node->node_type = sb_strdup("");
    node->tag = sb_strdup("");
    node->server = sb_strdup("");
    node->protocol_config = sbj_object();
}
void sb_parsed_node_free(sb_parsed_node *node) {
    free(node->node_type);
    free(node->tag);
    free(node->server);
    sbj_free(node->protocol_config);
    memset(node, 0, sizeof(*node));
}
sb_parsed_node *sb_parsed_node_vec_push(sb_parsed_node_vec *v) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof(*v->items));
    }
    sb_parsed_node *node = &v->items[v->len++];
    sb_parsed_node_init(node);
    return node;
}
void sb_parsed_node_vec_free(sb_parsed_node_vec *v) {
    for (size_t i = 0; i < v->len; ++i)
        sb_parsed_node_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof(*v));
}
void sb_strvec_push_take(sb_strvec *v, char *s) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof(*v->items));
    }
    v->items[v->len++] = s;
}
void sb_strvec_push(sb_strvec *v, const char *s) { sb_strvec_push_take(v, sb_strdup(s)); }
void sb_strvec_free(sb_strvec *v) {
    for (size_t i = 0; i < v->len; ++i)
        free(v->items[i]);
    free(v->items);
    memset(v, 0, sizeof(*v));
}
static void warning(sbj *warnings, size_t row, const char *reason) {
    if (sbj_arr_len(warnings) >= 256)
        return;
    sbj *w = sbj_object();
    sbj_set_int(w, "position", (int64_t)row);
    sbj_set_str(w, "reason", reason);
    sbj_arr_push(warnings, w);
}
static bool builtin(const sbj *node) {
    const char *type = sbj_get_str(node, "type", "");
    return !strcmp(type, "direct") || !strcmp(type, "block") || !strcmp(type, "dns") ||
           !strcmp(type, "selector") || !strcmp(type, "urltest");
}
static bool append_node(sbj *nodes, sbj *node, sbj *warnings, size_t position) {
    if (!sbw_subscription_node_valid(node)) {
        warning(warnings, position, "unsupported_protocol_or_unsafe_parameters");
        sbj_free(node);
        return false;
    }
    const char *tag = sbj_get_str(node, "tag", "");
    char *original = sb_strdup(tag);
    unsigned suffix = 1;
    for (;;) {
        bool duplicate = false;
        for (size_t i = 0; i < sbj_arr_len(nodes); ++i)
            if (sbj_string_is(sbj_get(sbj_arr_at(nodes, i), "tag"), tag))
                duplicate = true;
        if (!duplicate)
            break;
        size_t prefix = strlen(original);
        if (prefix > 60)
            prefix = 60;
        while (prefix && ((unsigned char)original[prefix] & 0xc0U) == 0x80U)
            --prefix;
        char replacement[81];
        int n = sprintf_s(replacement, sizeof(replacement), "%.*s (%u)", (int)prefix, original, ++suffix);
        if (n < 1) {
            free(original);
            sbj_free(node);
            return false;
        }
        sbj_set_str(node, "tag", replacement);
        tag = sbj_get_str(node, "tag", "");
    }
    if (suffix > 1)
        warning(warnings, position, "duplicate_name_renamed");
    free(original);
    sbj_arr_push(nodes, node);
    return true;
}
static char *base64_body(const char *body, size_t length) {
    sb_buf normalized = {0};
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)body[i];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t')
            continue;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' ||
              c == '/' || c == '_' || c == '-' || c == '=')) {
            sb_buf_free(&normalized);
            return NULL;
        }
        sb_buf_putc(&normalized, c == '-' ? '+' : c == '_' ? '/' : (char)c);
    }
    if (!normalized.len || normalized.len % 4 == 1) {
        sb_buf_free(&normalized);
        return NULL;
    }
    while (normalized.len % 4)
        sb_buf_putc(&normalized, '=');
    size_t padding = 0;
    while (padding < normalized.len && normalized.p[normalized.len - padding - 1] == '=')
        ++padding;
    if (padding > 2 || memchr(normalized.p, '=', normalized.len - padding)) {
        sb_buf_free(&normalized);
        return NULL;
    }
    DWORD bytes = (DWORD)(normalized.len * 3 / 4 + 1);
    char *decoded = sb_xcalloc((size_t)bytes + 1, 1);
    if (!CryptStringToBinaryA(normalized.p, (DWORD)normalized.len, CRYPT_STRING_BASE64, (BYTE *)decoded,
                              &bytes, NULL, NULL) ||
        memchr(decoded, 0, bytes)) {
        free(decoded);
        decoded = NULL;
    }
    sb_buf_free(&normalized);
    return decoded;
}
sbj *sbw_subscription_parse(const char *body, size_t length, sbw_error *error) {
    if (!body || !length || length > 256U * 1024U || memchr(body, 0, length) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body, (int)length, NULL, 0))
        goto invalid;
    char *text = sb_strndup(body, length), *decoded = NULL;
    size_t decoded_length = 0;
    char *start = text;
    while (*start == ' ' || *start == '\r' || *start == '\n' || *start == '\t')
        ++start;
    if (!strstr(start, "://") && *start != '{' && *start != '[' && !strstr(start, "proxies:")) {
        decoded = base64_body(start, strlen(start));
        if (decoded) {
            start = decoded;
            decoded_length = strlen(decoded);
        }
    }
    sbj *nodes = sbj_array(), *warnings = sbj_array();
    const char *format = "uri";
    size_t skipped = 0;
    if (*start == '{' || *start == '[') {
        format = "sing-box-json";
        sbj *json = sbw_json_parse(start, strlen(start), 32, NULL);
        const sbj *outbounds = sbj_is_array(json) ? json : sbj_get(json, "outbounds");
        if (!sbj_is_array(outbounds)) {
            sbj_free(json);
            goto parse_failed;
        }
        for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
            const sbj *node = sbj_arr_at(outbounds, i);
            if (builtin(node))
                continue;
            if (sbj_arr_len(nodes) >= 256 || !append_node(nodes, sbj_clone(node), warnings, i + 1))
                ++skipped;
        }
        if (sbj_is_object(json) &&
            (sbj_has(json, "route") || sbj_has(json, "dns") || sbj_has(json, "inbounds")))
            warning(warnings, 0, "routing_dns_and_inbounds_not_imported");
        sbj_free(json);
    } else if (strstr(start, "proxies:")) {
        format = "clash-yaml";
        sb_proxy_import imported;
        sb_err ignored = {0};
        int rc = sb_parse_subscription_report(start, strlen(start), &imported, &ignored);
        if (rc) {
            sb_proxy_import_free(&imported);
            goto parse_failed;
        }
        for (size_t i = 0; i < imported.nodes.len; ++i) {
            const sb_parsed_node *item = &imported.nodes.items[i];
            sbj *node = sbj_clone(item->protocol_config);
            sbj_set_str(node, "type", item->node_type);
            sbj_set_str(node, "tag", item->tag);
            sbj_set_str(node, "server", item->server);
            sbj_set_int(node, "server_port", item->server_port);
            if (sbj_arr_len(nodes) >= 256) {
                sbj_free(node);
                ++skipped;
            } else if (!append_node(nodes, node, warnings, i + 1))
                ++skipped;
        }
        for (size_t i = 0; i < imported.skipped.len; ++i) {
            ++skipped;
            warning(warnings, 0, "unsupported_yaml_entry");
        }
        warning(warnings, 0, "routing_dns_and_scripts_not_imported");
        sb_proxy_import_free(&imported);
    } else {
        char *line = start;
        size_t position = 0;
        while (line && *line) {
            ++position;
            char *next = strchr(line, '\n');
            if (next)
                *next++ = 0;
            while (*line == ' ' || *line == '\t' || *line == '\r')
                ++line;
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t'))
                line[--n] = 0;
            if (n && *line != '#' && strncmp(line, "//", 2)) {
                sbj *node = NULL;
                if (!node) {
                    sb_proxy_import imported;
                    sb_err ignored = {0};
                    if (!sb_parse_subscription_report(line, n, &imported, &ignored) &&
                        imported.nodes.len == 1) {
                        const sb_parsed_node *item = &imported.nodes.items[0];
                        node = sbj_clone(item->protocol_config);
                        sbj_set_str(node, "type", item->node_type);
                        sbj_set_str(node, "tag", item->tag);
                        sbj_set_str(node, "server", item->server);
                        sbj_set_int(node, "server_port", item->server_port);
                    }
                    sb_proxy_import_free(&imported);
                }
                if (!node) {
                    ++skipped;
                    warning(warnings, position, "unsupported_uri_or_invalid_parameters");
                } else if (sbj_arr_len(nodes) >= 256) {
                    sbj_free(node);
                    ++skipped;
                    warning(warnings, position, "node_limit_reached");
                } else if (!append_node(nodes, node, warnings, position))
                    ++skipped;
            }
            line = next;
        }
    }
    if (!sbj_arr_len(nodes))
        goto parse_failed;
    sbj *result = sbj_object(), *report = sbj_object();
    sbj_set_int(report, "imported", (int64_t)sbj_arr_len(nodes));
    sbj_set_int(report, "skipped", (int64_t)skipped);
    sbj_set_str(report, "format", format);
    sbj_set_bool(report, "base64", decoded != NULL);
    sbj_set(report, "warnings", warnings);
    sbj_set(result, "report", report);
    sbj_set(result, "nodes", nodes);
    SecureZeroMemory(text, length + 1);
    free(text);
    if (decoded) {
        SecureZeroMemory(decoded, decoded_length + 1);
        free(decoded);
    }
    return result;
parse_failed:
    sbj_free(nodes);
    sbj_free(warnings);
    SecureZeroMemory(text, length + 1);
    free(text);
    if (decoded) {
        SecureZeroMemory(decoded, decoded_length + 1);
        free(decoded);
    }
invalid:
    sbw_fail(error, "SUBSCRIPTION_INVALID",
             "No compatible nodes were found in this UTF-8 subscription (maximum 256 KB).");
    return NULL;
}
