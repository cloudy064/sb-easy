#include "sb/tailscale.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

static bool text_is_safe(const sbj *v, size_t limit) {
    return sbj_is_string(v) && v->v.str.len <= limit &&
           memchr(v->v.str.ptr, '\0', v->v.str.len) == NULL;
}

static int validate_cidrs(const sbj *value, bool advertised, sb_err *err) {
    if (!sbj_is_array(value) || sbj_arr_len(value) > 128)
        return sb_fail(err, SB_ERR_VALIDATION, "Tailscale routes must be an array of at most 128 CIDRs");
    const sbj *item;
    SBJ_ARR_FOREACH(value, i, item) {
        if (!text_is_safe(item, 64))
            return sb_fail(err, SB_ERR_VALIDATION, "Tailscale routes must contain CIDR strings");
        char *copy = sb_strdup(item->v.str.ptr);
        char *slash = strchr(copy, '/');
        unsigned char address[16];
        bool valid = false;
        if (slash && slash[1]) {
            *slash++ = '\0';
            const bool ipv6 = strchr(copy, ':') != NULL;
            unsigned bits = 0;
            valid = inet_pton(ipv6 ? AF_INET6 : AF_INET, copy, address) == 1;
            for (const char *p = slash; *p && valid; ++p) {
                if (*p < '0' || *p > '9') valid = false;
                else { bits = bits * 10 + (unsigned)(*p - '0'); if (bits > 128) valid = false; }
            }
            valid = valid && bits <= (ipv6 ? 128U : 32U) && (!advertised || bits != 0);
        }
        free(copy);
        if (!valid) return sb_fail(err, SB_ERR_VALIDATION,
            "Invalid Tailscale CIDR (use advertise_exit_node for advertised default routes)");
    }
    return 0;
}

static bool control_url_valid(const char *text) {
    if (!*text) return true;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p <= 32 || *p == 127) return false;
    CURLU *url = curl_url();
    if (!url) return false;
    char *scheme = NULL, *host = NULL, *user = NULL, *query = NULL, *fragment = NULL;
    bool valid = curl_url_set(url, CURLUPART_URL, text, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
        (strcmp(scheme, "https") == 0 || strcmp(scheme, "http") == 0) &&
        curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK && *host;
    if (curl_url_get(url, CURLUPART_USER, &user, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_QUERY, &query, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0) == CURLUE_OK) valid = false;
    curl_free(scheme); curl_free(host); curl_free(user); curl_free(query); curl_free(fragment);
    curl_url_cleanup(url);
    return valid;
}

int sb_tailscale_validate(const sbj *settings, sb_err *err) {
    if (!sbj_is_object(settings)) return sb_fail(err, SB_ERR_VALIDATION, "tailscale must be a JSON object");
    const char *key;
    const sbj *value;
    SBJ_OBJ_FOREACH(settings, i, key, value) {
        if (strlen(key) != settings->v.obj.key_lens[i])
            return sb_fail(err, SB_ERR_VALIDATION, "Invalid Tailscale setting name");
        if (sb_streq(key, "enabled") || sb_streq(key, "accept_routes") ||
            sb_streq(key, "advertise_exit_node") || sb_streq(key, "has_auth_key")) {
            if (!sbj_is_bool(value)) return sb_fail(err, SB_ERR_VALIDATION, "tailscale.%s must be a boolean", key);
        } else if (sb_streq(key, "auth_key")) {
            if (!text_is_safe(value, 4096)) return sb_fail(err, SB_ERR_VALIDATION, "tailscale.auth_key must be a string without NUL bytes (max 4096 bytes)");
            for (size_t j = 0; j < value->v.str.len; ++j)
                if ((unsigned char)value->v.str.ptr[j] <= 32 || (unsigned char)value->v.str.ptr[j] == 127)
                    return sb_fail(err, SB_ERR_VALIDATION, "tailscale.auth_key must not contain whitespace or control characters");
        } else if (sb_streq(key, "hostname")) {
            if (!text_is_safe(value, 63)) return sb_fail(err, SB_ERR_VALIDATION, "tailscale.hostname must be a DNS label (max 63 bytes)");
            for (size_t j = 0; j < value->v.str.len; ++j) {
                unsigned char ch = (unsigned char)value->v.str.ptr[j];
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                      (ch >= '0' && ch <= '9') || (ch == '-' && j && j + 1 < value->v.str.len)))
                    return sb_fail(err, SB_ERR_VALIDATION, "tailscale.hostname must be a DNS label");
            }
        } else if (sb_streq(key, "control_url")) {
            if (!text_is_safe(value, 2048) || !control_url_valid(value->v.str.ptr))
                return sb_fail(err, SB_ERR_VALIDATION, "tailscale.control_url must be an HTTP(S) URL without credentials, query or fragment");
        } else if (sb_streq(key, "route_cidrs") || sb_streq(key, "advertise_routes")) {
            if (validate_cidrs(value, sb_streq(key, "advertise_routes"), err) != 0) return -1;
        } else return sb_fail(err, SB_ERR_VALIDATION, "Unknown Tailscale setting: %s", key);
    }
    return 0;
}

bool sb_tailscale_enabled(const sbj *settings) { return sbj_get_bool(settings, "enabled", false); }

int sb_tailscale_update(sbj **settings, const sbj *patch, sb_err *err) {
    if (sb_tailscale_validate(patch, err) != 0) return -1;
    sbj *next = sbj_is_object(*settings) ? sbj_clone(*settings) : sbj_object();
    sbj_update(next, patch);
    sbj_del(next, "has_auth_key");
    if (sb_tailscale_validate(next, err) != 0) { sbj_free(next); return -1; }
    sbj_free(*settings);
    *settings = next;
    return 0;
}

sbj *sb_tailscale_public(const sbj *settings) {
    sbj *result = sbj_is_object(settings) ? sbj_clone(settings) : sbj_object();
    const sbj *key = sbj_get(result, "auth_key");
    bool has_key = sbj_is_string(key) && key->v.str.len != 0;
    sbj_del(result, "auth_key");
    sbj_set_bool(result, "enabled", sb_tailscale_enabled(settings));
    sbj_set_bool(result, "has_auth_key", has_key);
    return result;
}

static bool tag_in_use(const sb_render_request *r, const char *tag) {
    const char *arrays[] = {"endpoints", "outbounds"};
    for (size_t i = 0; i < 2; ++i) {
        const sbj *item;
        SBJ_ARR_FOREACH(sbj_get(r->profile, arrays[i]), j, item)
            if (sbj_string_is(sbj_get(item, "tag"), tag)) return true;
    }
    for (size_t i = 0; i < r->nodes.len; ++i)
        if (sb_strn_eq(r->nodes.items[i].tag, r->nodes.items[i].tag_len, tag)) return true;
    return false;
}

static char *free_tag(const sb_render_request *r, const char *base) {
    sb_buf tag = {0};
    sb_buf_puts(&tag, base);
    while (tag_in_use(r, tag.p)) sb_buf_puts(&tag, "-next");
    return sb_buf_detach(&tag);
}

int sb_tailscale_render(sb_render_request *r, const sbj *settings, const char *host_id, sb_err *err) {
    if (sb_tailscale_validate(settings, err) != 0) return -1;
    if (!sb_tailscale_enabled(settings)) return 0;
    const sbj *existing = sbj_get(r->profile, "endpoints");
    if (existing && !sbj_is_array(existing))
        return sb_fail(err, SB_ERR_VALIDATION, "Tailscale requires profile.endpoints to be an array");
    char *tag = free_tag(r, "sb-easy-tailscale");
    char *direct = free_tag(r, "sb-easy-tailscale-direct");
    sbj *outbound = sbj_object();
    sbj_set_str(outbound, "type", "direct"); sbj_set_str(outbound, "tag", direct);
    sbj_arr_push(r->network_outbounds, outbound);
    sbj *endpoint = sbj_object();
    sbj_set_str(endpoint, "type", "tailscale");
    sbj_set_str(endpoint, "tag", tag);
    sbj_set_str(endpoint, "state_directory", "data/tailscale");
    /* No detour: the endpoint's native dialer connects directly. sing-box
     * 1.14 rejects detours to empty direct outbounds. */
    const char *hostname = sbj_get_str(settings, "hostname", "");
    char generated[64] = "sb-easy-";
    size_t n = strlen(generated);
    for (const unsigned char *p = (const unsigned char *)(host_id ? host_id : "host"); *p && n < 62; ++p)
        if (isalnum(*p) && *p < 128) generated[n++] = (char)tolower(*p);
    if (n == 8) generated[n++] = '0';
    generated[n] = '\0';
    sbj_set_str(endpoint, "hostname", *hostname ? hostname : generated);
    const char *copied[] = {"auth_key", "control_url", "accept_routes", "advertise_routes", "advertise_exit_node"};
    for (size_t i = 0; i < sizeof copied / sizeof copied[0]; ++i) {
        const sbj *v = sbj_get(settings, copied[i]);
        if (v && !(sbj_is_string(v) && v->v.str.len == 0)) sbj_set(endpoint, copied[i], sbj_clone(v));
    }
    sbj_arr_push(sbj_get_or_array(r->profile, "endpoints"), endpoint);
    sbj_arr_push(r->external_route_tags, sbj_str(tag));
    /* Incoming tailnet connections are forwarded to loopback/local subnets.
     * Match these first so the destination tailnet rule cannot loop them. */
    sbj *incoming = sbj_object();
    sbj_set(incoming, "inbound", sbj_str(tag));
    sbj_set_str(incoming, "outbound", direct);
    sbj_arr_push(r->priority_route_rules, incoming);
    sbj *route = sbj_object(), *cidrs = sbj_array();
    sbj_arr_push(cidrs, sbj_str("100.64.0.0/10"));
    sbj_arr_push(cidrs, sbj_str("fd7a:115c:a1e0::/48"));
    const sbj *cidr;
    SBJ_ARR_FOREACH(sbj_get(settings, "route_cidrs"), i, cidr) sbj_arr_push(cidrs, sbj_clone(cidr));
    sbj_set(route, "ip_cidr", cidrs); sbj_set_str(route, "outbound", tag);
    sbj_arr_push(r->priority_route_rules, route);
    if (sbj_get_bool(settings, "accept_routes", false)) {
        route = sbj_object();
        sbj_set_str(route, "preferred_by", tag); sbj_set_str(route, "outbound", tag);
        sbj_arr_push(r->priority_route_rules, route);
    }
    free(tag); free(direct);
    return 0;
}
