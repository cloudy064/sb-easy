/* Port of cpp/src/proxy_parser.cpp. Behaviour (including nlohmann quirks the
 * C++ code relies on) is reproduced; see comments marked "C++:". */
#include "sb/proxy_parser.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <yaml.h>

/* ---- string helpers ---------------------------------------------------- */

typedef struct {
    const char *p;
    size_t n;
} sv;

/* Owned, NUL-terminated byte string with exact length (may contain NULs). */
typedef struct {
    char *p;
    size_t n;
} str;

static sv sv_of(const char *s) { return (sv){s, s ? strlen(s) : 0}; }
static sv sv_str(const str *s) { return (sv){s->p, s->n}; }
static sv sv_sub(sv v, size_t off, size_t len) {
    if (off > v.n) off = v.n;
    if (len > v.n - off) len = v.n - off;
    return (sv){v.p + off, len};
}
static sv sv_from(sv v, size_t off) { return sv_sub(v, off, SIZE_MAX); }
static bool sv_eq(sv v, const char *s) {
    size_t n = strlen(s);
    return v.n == n && memcmp(v.p, s, n) == 0;
}
static bool sv_starts(sv v, const char *s) {
    size_t n = strlen(s);
    return v.n >= n && memcmp(v.p, s, n) == 0;
}
#define NPOS SIZE_MAX
static size_t sv_find(sv v, char c) {
    for (size_t i = 0; i < v.n; ++i)
        if (v.p[i] == c) return i;
    return NPOS;
}
static size_t sv_rfind(sv v, char c) {
    for (size_t i = v.n; i > 0; --i)
        if (v.p[i - 1] == c) return i - 1;
    return NPOS;
}
static bool is_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}
static bool is_alnum(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static sv sv_trim(sv v) {
    while (v.n && is_space((unsigned char)v.p[0])) { ++v.p; --v.n; }
    while (v.n && is_space((unsigned char)v.p[v.n - 1])) --v.n;
    return v;
}

static str str_from(sv v) {
    str s;
    s.p = sb_xmalloc(v.n + 1);
    if (v.n) memcpy(s.p, v.p, v.n);
    s.p[v.n] = '\0';
    s.n = v.n;
    return s;
}
static str str_empty(void) { return str_from((sv){"", 0}); }
static void str_free(str *s) {
    free(s->p);
    s->p = NULL;
    s->n = 0;
}
static sbj *sbj_sv(sv v) { return sbj_strn(v.p, v.n); }

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static str percent_decode(sv v, bool plus_as_space) {
    sb_buf b = {0};
    for (size_t i = 0; i < v.n; ++i) {
        if (v.p[i] == '%' && i + 2 < v.n) {
            int hi = hex_value(v.p[i + 1]), lo = hex_value(v.p[i + 2]);
            if (hi >= 0 && lo >= 0) {
                sb_buf_putc(&b, (char)((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        sb_buf_putc(&b, plus_as_space && v.p[i] == '+' ? ' ' : v.p[i]);
    }
    str s = {b.p, b.len};
    if (!s.p) s = str_empty();
    return s;
}

static bool decode_base64(sv enc, str *out) {
    sb_buf norm = {0};
    for (size_t i = 0; i < enc.n; ++i) {
        char c = enc.p[i];
        if (is_space((unsigned char)c)) continue;
        sb_buf_putc(&norm, c == '-' ? '+' : c == '_' ? '/' : c);
    }
    if (norm.len == 0 || norm.len % 4 == 1 || norm.len > (size_t)INT_MAX) {
        sb_buf_free(&norm);
        return false;
    }
    while (norm.len % 4 != 0) sb_buf_putc(&norm, '=');
    for (size_t i = 0; i < norm.len; ++i) {
        unsigned char c = (unsigned char)norm.p[i];
        if (!(is_alnum(c) || c == '+' || c == '/' || c == '=')) {
            sb_buf_free(&norm);
            return false;
        }
    }
    unsigned char *buf = sb_xmalloc((norm.len / 4) * 3 + 1);
    int decoded = EVP_DecodeBlock(buf, (const unsigned char *)norm.p, (int)norm.len);
    if (decoded < 0) {
        free(buf);
        sb_buf_free(&norm);
        return false;
    }
    size_t size = (size_t)decoded;
    if (norm.len >= 2 && norm.p[norm.len - 1] == '=' && norm.p[norm.len - 2] == '=')
        size -= 2;
    else if (norm.p[norm.len - 1] == '=')
        size -= 1;
    buf[size] = '\0';
    out->p = (char *)buf;
    out->n = size;
    sb_buf_free(&norm);
    return true;
}

/* std::from_chars<unsigned> + 1..65535 check. */
static bool parse_port(sv v, uint16_t *out) {
    if (v.n == 0) return false;
    unsigned long long port = 0;
    for (size_t i = 0; i < v.n; ++i) {
        if (v.p[i] < '0' || v.p[i] > '9') return false;
        port = port * 10 + (unsigned)(v.p[i] - '0');
        if (port > UINT_MAX) return false; /* from_chars overflow */
    }
    if (port == 0 || port > 65535) return false;
    *out = (uint16_t)port;
    return true;
}

static bool parse_host_port(sv v, uint16_t default_port, str *host, uint16_t *port) {
    if (v.n == 0) return false;
    if (v.p[0] == '[') {
        size_t close = sv_find(v, ']');
        if (close == NPOS || close == 1) return false;
        sv h = sv_sub(v, 1, close - 1);
        if (close + 1 == v.n) {
            *host = str_from(h);
            *port = default_port;
            return true;
        }
        if (v.p[close + 1] != ':') return false;
        if (!parse_port(sv_from(v, close + 2), port)) return false;
        *host = str_from(h);
        return true;
    }
    size_t colon = sv_rfind(v, ':');
    if (colon == NPOS) {
        *host = str_from(v);
        *port = default_port;
        return true;
    }
    if (!parse_port(sv_from(v, colon + 1), port)) return false;
    if (colon == 0) return false;
    *host = str_from(sv_sub(v, 0, colon));
    return true;
}

/* ---- structured URIs --------------------------------------------------- */

typedef struct {
    str user_info, host, fragment;
    uint16_t port;
    str *keys, *vals;
    size_t nq;
} suri;

static void suri_free(suri *u) {
    str_free(&u->user_info);
    str_free(&u->host);
    str_free(&u->fragment);
    for (size_t i = 0; i < u->nq; ++i) {
        str_free(&u->keys[i]);
        str_free(&u->vals[i]);
    }
    free(u->keys);
    free(u->vals);
}

static bool parse_structured_uri(sv uri, const char *scheme, uint16_t default_port, suri *out) {
    memset(out, 0, sizeof *out);
    char prefix[32];
    snprintf(prefix, sizeof prefix, "%s://", scheme);
    if (!sv_starts(uri, prefix)) return false;
    uri = sv_from(uri, strlen(prefix));
    size_t hash = sv_find(uri, '#');
    if (hash != NPOS) {
        out->fragment = percent_decode(sv_from(uri, hash + 1), false);
        uri = sv_sub(uri, 0, hash);
    } else {
        out->fragment = str_empty();
    }
    sv query = {"", 0};
    size_t q = sv_find(uri, '?');
    if (q != NPOS) {
        query = sv_from(uri, q + 1);
        uri = sv_sub(uri, 0, q);
    }
    size_t slash = sv_find(uri, '/');
    if (slash != NPOS) uri = sv_sub(uri, 0, slash);
    size_t at = sv_rfind(uri, '@');
    if (at == NPOS) {
        suri_free(out);
        return false;
    }
    out->user_info = percent_decode(sv_sub(uri, 0, at), false);
    if (!parse_host_port(sv_from(uri, at + 1), default_port, &out->host, &out->port)) {
        suri_free(out);
        return false;
    }
    while (query.n) {
        size_t amp = sv_find(query, '&');
        sv pair = sv_sub(query, 0, amp);
        size_t eq = sv_find(pair, '=');
        str key = percent_decode(sv_sub(pair, 0, eq), true);
        str val = eq == NPOS ? str_empty() : percent_decode(sv_from(pair, eq + 1), true);
        out->keys = sb_xrealloc(out->keys, (out->nq + 1) * sizeof(str));
        out->vals = sb_xrealloc(out->vals, (out->nq + 1) * sizeof(str));
        out->keys[out->nq] = key;
        out->vals[out->nq] = val;
        out->nq++;
        if (amp == NPOS) break;
        query = sv_from(query, amp + 1);
    }
    return true;
}

/* std::map insert_or_assign: the last occurrence wins. */
static sv query_value(const suri *u, const char *key) {
    size_t kn = strlen(key);
    for (size_t i = u->nq; i > 0; --i) {
        const str *k = &u->keys[i - 1];
        if (k->n == kn && memcmp(k->p, key, kn) == 0) return sv_str(&u->vals[i - 1]);
    }
    return (sv){"", 0};
}

static bool query_true(const suri *u, const char *key) {
    sv v = query_value(u, key);
    if (v.n == 1) return v.p[0] == '1';
    if (v.n != 4) return false;
    char low[4];
    for (int i = 0; i < 4; ++i) {
        char c = v.p[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    return memcmp(low, "true", 4) == 0;
}

static sbj *split_alpn(sv remaining) {
    sbj *arr = sbj_array();
    while (remaining.n) {
        size_t comma = sv_find(remaining, ',');
        sbj_arr_push(arr, sbj_sv(sv_trim(sv_sub(remaining, 0, comma))));
        if (comma == NPOS) break;
        remaining = sv_from(remaining, comma + 1);
    }
    return arr;
}

static sbj *utls(sbj *fingerprint) {
    sbj *u = sbj_object();
    sbj_set_bool(u, "enabled", true);
    sbj_set(u, "fingerprint", fingerprint);
    return u;
}

static sbj *tls_from_uri(const suri *u) {
    sbj *tls = sbj_object();
    sbj_set_bool(tls, "enabled", true);
    sv sni = query_value(u, "sni");
    if (!sni.n) sni = query_value(u, "servername");
    if (sni.n) sbj_set(tls, "server_name", sbj_sv(sni));
    sv alpn = query_value(u, "alpn");
    if (alpn.n) sbj_set(tls, "alpn", split_alpn(alpn));
    sv fp = query_value(u, "fp");
    if (!fp.n) fp = query_value(u, "fingerprint");
    if (fp.n) sbj_set(tls, "utls", utls(sbj_sv(fp)));
    if (query_true(u, "allowInsecure") || query_true(u, "skip-cert-verify") ||
        query_true(u, "insecure"))
        sbj_set_bool(tls, "insecure", true);
    return tls;
}

static bool has_nonempty_string(const sbj *v, const char *field) {
    const sbj *f = sbj_get(v, field);
    return sbj_is_string(f) && f->v.str.len > 0;
}

static bool has_required_secret(const char *type, const sbj *pc) {
    if (!strcmp(type, "shadowsocks"))
        return has_nonempty_string(pc, "method") && has_nonempty_string(pc, "password");
    if (!strcmp(type, "vmess") || !strcmp(type, "vless")) return has_nonempty_string(pc, "uuid");
    if (!strcmp(type, "trojan") || !strcmp(type, "hysteria2"))
        return has_nonempty_string(pc, "password");
    if (!strcmp(type, "tuic"))
        return has_nonempty_string(pc, "uuid") && has_nonempty_string(pc, "password");
    if (!strcmp(type, "http")) return true;
    return false;
}

/* Fills *out (taking ownership of config) and applies has_required_secret.
 * Returns 1 when accepted, 0 otherwise (out is left freed/initialised). */
static int finish_node(sb_parsed_node *out, const char *type, sv tag, sv server, uint16_t port,
                       sbj *config, bool check_secret) {
    if (check_secret && !has_required_secret(type, config)) {
        sbj_free(config);
        return 0;
    }
    sb_parsed_node_free(out);
    out->node_type = sb_strdup(type);
    out->tag = sb_strndup(tag.p, tag.n);
    out->server = sb_strndup(server.p, server.n);
    out->server_port = port;
    out->protocol_config = config;
    return 1;
}

static void vec_push_move(sb_parsed_node_vec *v, sb_parsed_node *node) {
    sb_parsed_node *slot = sb_parsed_node_vec_push(v);
    sb_parsed_node_free(slot);
    *slot = *node;
}

/* ---- nlohmann value()/get() emulation ---------------------------------- */

static int type_error(sb_err *err, const char *want, const sbj *v) {
    return sb_fail(err, SB_ERR_GENERIC, "[json.exception.type_error.302] type must be %s, but is %s",
                   want, sbj_type_name(v));
}

/* json.value(key, std::string default) */
static int value_string(const sbj *obj, const char *key, sv fallback, sv *out, sb_err *err) {
    const sbj *f = sbj_get(obj, key);
    if (!f) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(f)) return type_error(err, "string", f);
    *out = (sv){f->v.str.ptr, f->v.str.len};
    return 0;
}

/* json.value(key, int default): get<int> accepts any number or boolean. */
static int value_int(const sbj *obj, const char *key, int fallback, int *out, sb_err *err) {
    const sbj *f = sbj_get(obj, key);
    if (!f) {
        *out = fallback;
        return 0;
    }
    switch (f->type) {
    case SBJ_BOOL: *out = f->v.b ? 1 : 0; return 0;
    case SBJ_INT: *out = (int)(uint32_t)(uint64_t)f->v.i; return 0;
    case SBJ_UINT: *out = (int)(uint32_t)f->v.u; return 0;
    case SBJ_FLOAT: {
        double d = f->v.f;
        /* static_cast<int>: x86 yields INT_MIN for out-of-range values. */
        *out = (d > -2147483649.0 && d < 2147483648.0) ? (int)d : INT_MIN;
        return 0;
    }
    default: return type_error(err, "number", f);
    }
}

/* ---- URI parsers -------------------------------------------------------- */

static int parse_shadowsocks(sv uri, sb_parsed_node *out) {
    uri = sv_from(uri, 5);
    str tag = str_empty();
    size_t hash = sv_find(uri, '#');
    if (hash != NPOS) {
        str_free(&tag);
        tag = percent_decode(sv_from(uri, hash + 1), false);
        uri = sv_sub(uri, 0, hash);
    }
    size_t q = sv_find(uri, '?');
    if (q != NPOS) uri = sv_sub(uri, 0, q);

    str credentials = {0}, decoded = {0}, host = {0};
    sv host_port;
    int result = 0;
    size_t at = sv_rfind(uri, '@');
    if (at != NPOS) {
        if (!decode_base64(sv_sub(uri, 0, at), &credentials)) goto done;
        host_port = sv_from(uri, at + 1);
    } else {
        if (!decode_base64(uri, &decoded)) goto done;
        size_t dat = sv_rfind(sv_str(&decoded), '@');
        if (dat == NPOS) goto done;
        credentials = str_from(sv_sub(sv_str(&decoded), 0, dat));
        host_port = sv_from(sv_str(&decoded), dat + 1);
    }
    size_t colon = sv_find(sv_str(&credentials), ':');
    if (colon == NPOS) goto done;
    uint16_t port;
    if (!parse_host_port(host_port, 8388, &host, &port)) goto done;
    sbj *config = sbj_object();
    sbj_set(config, "method", sbj_sv(sv_sub(sv_str(&credentials), 0, colon)));
    sbj_set(config, "password", sbj_sv(sv_from(sv_str(&credentials), colon + 1)));
    if (tag.n == 0) {
        /* host may contain NULs; build the tag byte-exactly. */
        sb_buf b = {0};
        sb_buf_append(&b, host.p, host.n);
        sb_buf_printf(&b, ":%u", (unsigned)port);
        str_free(&tag);
        tag.p = b.p;
        tag.n = b.len;
    }
    result = finish_node(out, "shadowsocks", sv_str(&tag), sv_str(&host), port, config, true);
done:
    str_free(&tag);
    str_free(&credentials);
    str_free(&decoded);
    str_free(&host);
    return result;
}

static int parse_vmess(sv uri, sb_parsed_node *out, sb_err *err) {
    uri = sv_from(uri, 8);
    str decoded;
    if (!decode_base64(uri, &decoded)) return 0;
    /* nlohmann's parser skips a leading UTF-8 BOM. */
    size_t skip = decoded.n >= 3 && !memcmp(decoded.p, "\xEF\xBB\xBF", 3) ? 3 : 0;
    sbj *value = sbj_parse(decoded.p + skip, decoded.n - skip, NULL, 0);
    str_free(&decoded);
    int result = 0;
    sbj *config = NULL;
    if (!sbj_is_object(value)) goto done;
    const sbj *server_value = sbj_get(value, "add");
    if (!sbj_is_string(server_value)) server_value = sbj_get(value, "host");
    if (!sbj_is_string(server_value) || server_value->v.str.len == 0) goto done;
    uint16_t port = 0;
    bool have_port = false;
    const sbj *p = sbj_get(value, "port");
    if (p) {
        if (p->type == SBJ_UINT) {
            if (p->v.u > 0 && p->v.u <= 65535) { port = (uint16_t)p->v.u; have_port = true; }
        } else if (p->type == SBJ_INT) {
            if (p->v.i > 0 && p->v.i <= 65535) { port = (uint16_t)p->v.i; have_port = true; }
        } else if (p->type == SBJ_STRING) {
            have_port = parse_port((sv){p->v.str.ptr, p->v.str.len}, &port);
        }
    }
    if (!have_port) goto done;
    sv server = {server_value->v.str.ptr, server_value->v.str.len};
    /* C++: value.value("ps", value.value("name", "vmess")) — inner first. */
    sv name, tag, id, scy, net, tlsv;
    int aid;
    if (value_string(value, "name", sv_of("vmess"), &name, err) ||
        value_string(value, "ps", name, &tag, err) ||
        value_string(value, "id", sv_of(""), &id, err) ||
        value_int(value, "aid", 0, &aid, err) ||
        value_string(value, "scy", sv_of("auto"), &scy, err)) {
        result = -1;
        goto done;
    }
    config = sbj_object();
    sbj_set(config, "uuid", sbj_sv(id));
    sbj_set_int(config, "alter_id", aid);
    sbj_set(config, "security", sbj_sv(scy));
    if (value_string(value, "net", sv_of("tcp"), &net, err)) {
        result = -1;
        goto done;
    }
    if (!sv_eq(net, "tcp")) {
        sbj *transport = sbj_object();
        sbj_set(transport, "type", sbj_sv(net));
        const sbj *path = sbj_get(value, "path");
        if (sbj_is_string(path)) sbj_set(transport, "path", sbj_clone(path));
        const sbj *host = sbj_get(value, "host");
        if (sbj_is_string(host)) {
            sbj *headers = sbj_object();
            sbj_set(headers, "Host", sbj_clone(host));
            sbj_set(transport, "headers", headers);
        }
        sbj_set(config, "transport", transport);
    }
    if (value_string(value, "tls", sv_of(""), &tlsv, err)) {
        result = -1;
        goto done;
    }
    if (sv_eq(tlsv, "tls")) {
        sbj *tls = sbj_object();
        sbj_set_bool(tls, "enabled", true);
        const sbj *sni = sbj_get(value, "sni");
        if (sbj_is_string(sni)) sbj_set(tls, "server_name", sbj_clone(sni));
        sbj_set(config, "tls", tls);
    }
    result = finish_node(out, "vmess", tag, server, port, config, true);
    config = NULL;
done:
    sbj_free(config);
    sbj_free(value);
    return result;
}

static sv frag_or(const suri *u, const char *fallback) {
    return u->fragment.n ? sv_str(&u->fragment) : sv_of(fallback);
}

static int parse_trojan(sv uri, sb_parsed_node *out) {
    suri u;
    if (!parse_structured_uri(uri, "trojan", 443, &u)) return 0;
    sbj *config = sbj_object();
    sbj_set(config, "password", sbj_sv(sv_str(&u.user_info)));
    sbj_set(config, "tls", tls_from_uri(&u));
    int r = finish_node(out, "trojan", frag_or(&u, "trojan"), sv_str(&u.host), u.port, config, true);
    suri_free(&u);
    return r;
}

static int parse_vless(sv uri, sb_parsed_node *out) {
    suri u;
    if (!parse_structured_uri(uri, "vless", 443, &u)) return 0;
    sbj *config = sbj_object();
    sbj_set(config, "uuid", sbj_sv(sv_str(&u.user_info)));
    sbj_set(config, "flow", sbj_sv(query_value(&u, "flow")));
    sbj_set_str(config, "packet_encoding", "xudp");
    sv network = query_value(&u, "type");
    if (!network.n) network = query_value(&u, "network");
    if (network.n && !sv_eq(network, "tcp")) {
        sbj *transport = sbj_object();
        sbj_set(transport, "type", sbj_sv(network));
        sv path = query_value(&u, "path");
        if (path.n) sbj_set(transport, "path", sbj_sv(path));
        sv host = query_value(&u, "host");
        if (host.n) {
            sbj *headers = sbj_object();
            sbj_set(headers, "Host", sbj_sv(host));
            sbj_set(transport, "headers", headers);
        }
        sbj_set(config, "transport", transport);
    }
    sv security = query_value(&u, "security");
    if (sv_eq(security, "tls") || sv_eq(security, "reality"))
        sbj_set(config, "tls", tls_from_uri(&u));
    int r = finish_node(out, "vless", frag_or(&u, "vless"), sv_str(&u.host), u.port, config, true);
    suri_free(&u);
    return r;
}

static int parse_hysteria2(sv uri, sb_parsed_node *out) {
    sb_buf norm = {0};
    if (sv_starts(uri, "hy2://")) {
        sb_buf_puts(&norm, "hysteria2://");
        sb_buf_append(&norm, uri.p + 6, uri.n - 6);
    } else {
        sb_buf_append(&norm, uri.p, uri.n);
    }
    suri u;
    bool ok = parse_structured_uri((sv){norm.p, norm.len}, "hysteria2", 443, &u);
    sb_buf_free(&norm);
    if (!ok) return 0;
    sbj *config = sbj_object();
    sbj_set(config, "password", sbj_sv(sv_str(&u.user_info)));
    sbj *tls = tls_from_uri(&u);
    if (sbj_obj_len(tls) > 1) sbj_set(config, "tls", tls);
    else sbj_free(tls);
    sv obfs = query_value(&u, "obfs");
    if (obfs.n) {
        sbj *o = sbj_object();
        sbj_set(o, "type", sbj_sv(obfs));
        sv pw = query_value(&u, "obfs-password");
        if (pw.n) sbj_set(o, "password", sbj_sv(pw));
        sbj_set(config, "obfs", o);
    }
    int r = finish_node(out, "hysteria2", frag_or(&u, "hysteria2"), sv_str(&u.host), u.port, config,
                        true);
    suri_free(&u);
    return r;
}

static int parse_tuic(sv uri, sb_parsed_node *out) {
    suri u;
    if (!parse_structured_uri(uri, "tuic", 443, &u)) return 0;
    size_t colon = sv_find(sv_str(&u.user_info), ':');
    if (colon == NPOS) {
        suri_free(&u);
        return 0;
    }
    sbj *config = sbj_object();
    sbj_set(config, "uuid", sbj_sv(sv_sub(sv_str(&u.user_info), 0, colon)));
    sbj_set(config, "password", sbj_sv(sv_from(sv_str(&u.user_info), colon + 1)));
    sbj_set_str(config, "congestion_control", "bbr");
    sbj_set_str(config, "udp_relay_mode", "native");
    sbj_set_str(config, "heartbeat", "10s");
    sv cc = query_value(&u, "congestion_control");
    if (!cc.n) cc = query_value(&u, "congestion");
    if (cc.n) sbj_set(config, "congestion_control", sbj_sv(cc));
    sbj *tls = tls_from_uri(&u);
    if (sbj_obj_len(tls) > 1) sbj_set(config, "tls", tls);
    else sbj_free(tls);
    int r = finish_node(out, "tuic", frag_or(&u, "tuic"), sv_str(&u.host), u.port, config, true);
    suri_free(&u);
    return r;
}

int sb_parse_proxy_uri_ex(const char *uri, size_t len, sb_parsed_node *out, sb_err *err) {
    sb_parsed_node_init(out);
    sv v = sv_trim((sv){uri ? uri : "", uri ? len : 0});
    if (sv_starts(v, "ss://")) return parse_shadowsocks(v, out);
    if (sv_starts(v, "vmess://")) return parse_vmess(v, out, err);
    if (sv_starts(v, "trojan://")) return parse_trojan(v, out);
    if (sv_starts(v, "vless://")) return parse_vless(v, out);
    if (sv_starts(v, "hysteria2://") || sv_starts(v, "hy2://")) return parse_hysteria2(v, out);
    if (sv_starts(v, "tuic://")) return parse_tuic(v, out);
    return 0;
}

int sb_parse_proxy_uri(const char *uri, sb_parsed_node *out) {
    int r = sb_parse_proxy_uri_ex(uri, uri ? strlen(uri) : 0, out, NULL);
    return r == 1 ? 1 : 0;
}

/* ---- YAML (libyaml) → tree, mirroring yaml-cpp's node model ------------- */

enum { Y_NULL, Y_SCALAR, Y_SEQ, Y_MAP };

typedef struct ynode {
    int kind;
    char *s;
    size_t slen;
    struct ynode **items; /* seq: elements; map: key,value,key,value... */
    size_t n, cap;
} ynode;

typedef struct {
    yaml_parser_t parser;
    ynode **all;
    size_t nall, capall;
    char **anchor_names;
    ynode **anchor_nodes;
    size_t nanchors;
    bool sanitized;
    char *buffer; /* sanitized input, if any */
} yload;

static ynode *ynew(yload *L, int kind) {
    ynode *n = sb_xcalloc(1, sizeof *n);
    n->kind = kind;
    if (L->nall == L->capall) {
        L->capall = L->capall ? L->capall * 2 : 64;
        L->all = sb_xrealloc(L->all, L->capall * sizeof *L->all);
    }
    L->all[L->nall++] = n;
    return n;
}

static void ypush(ynode *parent, ynode *child) {
    if (parent->n == parent->cap) {
        parent->cap = parent->cap ? parent->cap * 2 : 8;
        parent->items = sb_xrealloc(parent->items, parent->cap * sizeof *parent->items);
    }
    parent->items[parent->n++] = child;
}

static void yanchor(yload *L, const yaml_char_t *name, ynode *node) {
    if (!name) return;
    L->anchor_names = sb_xrealloc(L->anchor_names, (L->nanchors + 1) * sizeof(char *));
    L->anchor_nodes = sb_xrealloc(L->anchor_nodes, (L->nanchors + 1) * sizeof(ynode *));
    L->anchor_names[L->nanchors] = sb_strdup((const char *)name);
    L->anchor_nodes[L->nanchors] = node;
    L->nanchors++;
}

static void yload_free(yload *L) {
    for (size_t i = 0; i < L->nall; ++i) {
        free(L->all[i]->s);
        free(L->all[i]->items);
        free(L->all[i]);
    }
    free(L->all);
    for (size_t i = 0; i < L->nanchors; ++i) free(L->anchor_names[i]);
    free(L->anchor_names);
    free(L->anchor_nodes);
    free(L->buffer);
    yaml_parser_delete(&L->parser);
}

static bool is_null_string(const char *s, size_t n) {
    return n == 0 || (n == 1 && s[0] == '~') ||
           (n == 4 && (!memcmp(s, "null", 4) || !memcmp(s, "Null", 4) || !memcmp(s, "NULL", 4)));
}

/* yaml-cpp passes arbitrary bytes (control characters, invalid UTF-8) into
 * scalars and only breaks lines on \n / \r, while libyaml rejects such
 * streams and also breaks on NEL, U+2028 and U+2029. To keep yaml-cpp's
 * acceptance, every byte libyaml would reject or treat differently is
 * re-encoded before parsing as the plane-15 private-use code point
 * U+F0000+byte; genuine code points in U+F0000..U+F00FF or equal to the
 * escape U+F0100 are written as U+F0100 followed by themselves. Scalars are
 * decoded back afterwards. */
#define YS_RAW_BASE 0xF0000u
#define YS_ESCAPE 0xF0100u

static size_t utf8_decode(const unsigned char *p, size_t n, uint32_t *cp) {
    unsigned char c = p[0];
    size_t len;
    uint32_t v, min;
    if (c < 0x80) { *cp = c; return 1; }
    if (c >= 0xC2 && c <= 0xDF) { len = 2; v = c & 0x1F; min = 0x80; }
    else if (c >= 0xE0 && c <= 0xEF) { len = 3; v = c & 0x0F; min = 0x800; }
    else if (c >= 0xF0 && c <= 0xF4) { len = 4; v = c & 0x07; min = 0x10000; }
    else return 0;
    if (n < len) return 0;
    for (size_t i = 1; i < len; ++i) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        v = (v << 6) | (p[i] & 0x3F);
    }
    if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return 0;
    *cp = v;
    return len;
}

static void utf8_put(sb_buf *b, uint32_t v) {
    char e[4];
    size_t n;
    if (v < 0x80) { e[0] = (char)v; n = 1; }
    else if (v < 0x800) { e[0] = (char)(0xC0 | (v >> 6)); e[1] = (char)(0x80 | (v & 0x3F)); n = 2; }
    else if (v < 0x10000) {
        e[0] = (char)(0xE0 | (v >> 12)); e[1] = (char)(0x80 | ((v >> 6) & 0x3F));
        e[2] = (char)(0x80 | (v & 0x3F)); n = 3;
    } else {
        e[0] = (char)(0xF0 | (v >> 18)); e[1] = (char)(0x80 | ((v >> 12) & 0x3F));
        e[2] = (char)(0x80 | ((v >> 6) & 0x3F)); e[3] = (char)(0x80 | (v & 0x3F)); n = 4;
    }
    sb_buf_append(b, e, n);
}

/* Code points libyaml accepts and treats like yaml-cpp does. */
static bool yaml_plain_ok(uint32_t v) {
    return v == 0x09 || v == 0x0A || v == 0x0D || (v >= 0x20 && v <= 0x7E) ||
           (v >= 0xA0 && v <= 0xD7FF && v != 0x2028 && v != 0x2029) ||
           (v >= 0xE000 && v <= 0xFFFD) || (v >= 0x10000 && v <= 0x10FFFF);
}
static bool yaml_needs_escape(uint32_t v) {
    return (v >= YS_RAW_BASE && v <= YS_RAW_BASE + 0xFF) || v == YS_ESCAPE;
}

/* Returns a malloc'd rewritten copy, or NULL when the input needs none. */
static char *yaml_sanitize(const char *text, size_t len, size_t *out_len) {
    const unsigned char *p = (const unsigned char *)text;
    bool needed = false;
    for (size_t i = 0; i < len && !needed;) {
        uint32_t cp;
        size_t n = utf8_decode(p + i, len - i, &cp);
        if (!n || !yaml_plain_ok(cp) || yaml_needs_escape(cp)) needed = true;
        i += n ? n : 1;
    }
    if (!needed) return NULL;
    sb_buf b = {0};
    for (size_t i = 0; i < len;) {
        uint32_t cp;
        size_t n = utf8_decode(p + i, len - i, &cp);
        if (n && yaml_needs_escape(cp)) {
            utf8_put(&b, YS_ESCAPE);
            sb_buf_append(&b, p + i, n);
        } else if (n && yaml_plain_ok(cp)) {
            sb_buf_append(&b, p + i, n);
        } else {
            /* Invalid sequence or rejected code point: one raw byte at a time. */
            if (!n) n = 1;
            for (size_t k = 0; k < n; ++k) utf8_put(&b, YS_RAW_BASE + p[i + k]);
        }
        i += n;
    }
    *out_len = b.len;
    return sb_buf_detach(&b);
}

/* Reverses yaml_sanitize inside a scalar (in place; output never grows). */
static size_t yaml_unsanitize(char *s, size_t n) {
    const unsigned char *u = (const unsigned char *)s;
    size_t w = 0;
    for (size_t r = 0; r < n;) {
        uint32_t cp;
        size_t len = utf8_decode(u + r, n - r, &cp);
        if (len == 4 && cp == YS_ESCAPE && r + 4 < n) {
            uint32_t next;
            size_t nl = utf8_decode(u + r + 4, n - r - 4, &next);
            if (nl) {
                memmove(s + w, s + r + 4, nl);
                w += nl;
                r += 4 + nl;
                continue;
            }
        }
        if (len == 4 && cp >= YS_RAW_BASE && cp <= YS_RAW_BASE + 0xFF) {
            s[w++] = (char)(cp - YS_RAW_BASE);
            r += 4;
            continue;
        }
        if (!len) len = 1;
        memmove(s + w, s + r, len);
        w += len;
        r += len;
    }
    s[w] = '\0';
    return w;
}

/* yaml-cpp's DepthGuard<500>. */
#define YAML_MAX_DEPTH 500

/* Consumes the node starting at *ev (already parsed; this function deletes
 * it). Returns NULL on error. */
static ynode *yparse_node(yload *L, yaml_event_t *ev, int depth) {
    ynode *node = NULL;
    if (depth > YAML_MAX_DEPTH) {
        yaml_event_delete(ev);
        return NULL;
    }
    switch (ev->type) {
    case YAML_ALIAS_EVENT: {
        const char *name = (const char *)ev->data.alias.anchor;
        for (size_t i = L->nanchors; i > 0; --i)
            if (!strcmp(L->anchor_names[i - 1], name)) {
                node = L->anchor_nodes[i - 1];
                break;
            }
        yaml_event_delete(ev);
        return node;
    }
    case YAML_SCALAR_EVENT: {
        const char *value = (const char *)ev->data.scalar.value;
        size_t len = ev->data.scalar.length;
        if (ev->data.scalar.style == YAML_PLAIN_SCALAR_STYLE && !ev->data.scalar.tag &&
            is_null_string(value, len)) {
            node = ynew(L, Y_NULL);
        } else {
            node = ynew(L, Y_SCALAR);
            node->s = sb_strndup(value, len);
            node->slen = L->sanitized ? yaml_unsanitize(node->s, len) : len;
        }
        yanchor(L, ev->data.scalar.anchor, node);
        yaml_event_delete(ev);
        return node;
    }
    case YAML_SEQUENCE_START_EVENT:
    case YAML_MAPPING_START_EVENT: {
        bool is_seq = ev->type == YAML_SEQUENCE_START_EVENT;
        yaml_event_type_t end = is_seq ? YAML_SEQUENCE_END_EVENT : YAML_MAPPING_END_EVENT;
        node = ynew(L, is_seq ? Y_SEQ : Y_MAP);
        yanchor(L, is_seq ? ev->data.sequence_start.anchor : ev->data.mapping_start.anchor, node);
        yaml_event_delete(ev);
        for (;;) {
            yaml_event_t child;
            if (!yaml_parser_parse(&L->parser, &child)) return NULL;
            if (child.type == end) {
                yaml_event_delete(&child);
                return node;
            }
            ynode *c = yparse_node(L, &child, depth + 1);
            if (!c) return NULL;
            ypush(node, c);
        }
    }
    default:
        yaml_event_delete(ev);
        return NULL;
    }
}

static ynode *yload_attempt(yload *L, const char *text, size_t len, bool *ok) {
    *ok = false;
    if (!yaml_parser_initialize(&L->parser)) return NULL;
    yaml_parser_set_input_string(&L->parser, (const unsigned char *)text, len);
    yaml_event_t ev;
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    yaml_event_delete(&ev); /* STREAM_START */
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    if (ev.type == YAML_STREAM_END_EVENT) {
        yaml_event_delete(&ev);
        *ok = true;
        return ynew(L, Y_NULL);
    }
    yaml_event_delete(&ev); /* DOCUMENT_START */
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    ynode *root = yparse_node(L, &ev, 1);
    *ok = root != NULL;
    return root;
}

static void yload_reset(yload *L) {
    bool sanitized = L->sanitized;
    char *buffer = L->buffer;
    L->buffer = NULL;
    yload_free(L);
    memset(L, 0, sizeof *L);
    L->sanitized = sanitized;
    L->buffer = buffer;
}

/* YAML::Load: the first document only; *ok=false on a parse error. */
static ynode *yload_first(yload *L, const char *text, size_t len, bool *ok) {
    memset(L, 0, sizeof *L);
    *ok = false;
    /* yaml-cpp mis-scans NUL bytes in nearly every context (it reports an
     * error); treat any NUL as a YAML error. */
    if (memchr(text, '\0', len)) {
        yaml_parser_initialize(&L->parser);
        return NULL;
    }
    size_t slen = 0;
    L->buffer = yaml_sanitize(text, len, &slen);
    if (L->buffer) {
        L->sanitized = true;
        text = L->buffer;
        len = slen;
    }
    ynode *root = yload_attempt(L, text, len, ok);
    if (*ok) return root;
    /* yaml-cpp accepts a final line without ':' after a block mapping as a
     * key with a null value ("a: 1\nfoo" -> {a: 1, foo: ~}); libyaml fails
     * with "could not find expected ':'" at the end of input. Retry with the
     * ':' appended. */
    size_t end = len;
    while (end && is_space((unsigned char)text[end - 1])) --end;
    if (L->parser.problem && !strcmp(L->parser.problem, "could not find expected ':'") &&
        L->parser.problem_mark.index >= end) {
        sb_buf fixed = {0};
        sb_buf_append(&fixed, text, end);
        sb_buf_puts(&fixed, ":\n");
        yload_reset(L);
        root = yload_attempt(L, fixed.p, fixed.len, ok);
        /* libyaml copies scalar values, so the buffer can go now. */
        sb_buf_free(&fixed);
        if (*ok) return root;
    }
    return NULL;
}

static sbj *yaml_to_json(const ynode *n) {
    switch (n->kind) {
    case Y_SCALAR: return sbj_strn(n->s, n->slen);
    case Y_SEQ: {
        sbj *a = sbj_array();
        for (size_t i = 0; i < n->n; ++i) sbj_arr_push(a, yaml_to_json(n->items[i]));
        return a;
    }
    case Y_MAP: {
        sbj *o = sbj_object();
        for (size_t i = 0; i + 1 < n->n; i += 2) {
            const ynode *k = n->items[i];
            if (k->kind == Y_SCALAR) sbj_set(o, k->s, yaml_to_json(n->items[i + 1]));
        }
        return o;
    }
    default: return sbj_null();
    }
}

/* ---- Clash proxies ------------------------------------------------------ */

/* string_value(): malloc'd string or NULL (std::nullopt). */
static char *string_value(const sbj *v, const char *field) {
    const sbj *f = sbj_get(v, field);
    if (!f || f->type == SBJ_NULL) return NULL;
    if (f->type == SBJ_STRING) return sb_strndup(f->v.str.ptr, f->v.str.len);
    if (f->type == SBJ_BOOL) return sb_strdup(f->v.b ? "true" : "false");
    if (sbj_is_number(f)) return sbj_dump(f, -1);
    return NULL;
}

static char *string_value_or(const sbj *v, const char *field, const char *fallback) {
    char *s = string_value(v, field);
    return s ? s : sb_strdup(fallback);
}

static bool integer_value(const sbj *v, const char *field, int64_t *out) {
    const sbj *f = sbj_get(v, field);
    if (!f) return false;
    if (f->type == SBJ_INT) {
        *out = f->v.i;
        return true;
    }
    if (f->type == SBJ_UINT) {
        *out = (int64_t)f->v.u;
        return true;
    }
    if (f->type == SBJ_STRING) {
        const char *s = f->v.str.ptr;
        size_t n = f->v.str.len, i = 0;
        bool neg = false;
        if (n && s[0] == '-') { neg = true; i = 1; }
        if (i == n) return false;
        uint64_t mag = 0;
        for (; i < n; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            unsigned d = (unsigned)(s[i] - '0');
            if (mag > (UINT64_MAX - d) / 10) return false;
            mag = mag * 10 + d;
        }
        if (neg) {
            if (mag > (uint64_t)INT64_MAX + 1) return false;
            *out = mag == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)mag;
        } else {
            if (mag > (uint64_t)INT64_MAX) return false;
            *out = (int64_t)mag;
        }
        return true;
    }
    return false;
}

static bool boolean_value(const sbj *v, const char *field) {
    const sbj *f = sbj_get(v, field);
    if (!f) return false;
    if (f->type == SBJ_BOOL) return f->v.b;
    if (f->type == SBJ_STRING) {
        char *low = sb_lower_dup(f->v.str.ptr);
        bool r = f->v.str.len == strlen(low) && (!strcmp(low, "true") || !strcmp(low, "1"));
        free(low);
        return r;
    }
    return false;
}

static sbj *clash_transport(const sbj *proxy) {
    char *network = string_value_or(proxy, "network", "");
    sbj *t = NULL;
    if (!strcmp(network, "ws")) {
        t = sbj_object();
        sbj_set_str(t, "type", "ws");
        const sbj *opts = sbj_get(proxy, "ws-opts");
        if (sbj_is_object(opts)) {
            if (sbj_has(opts, "path")) sbj_set(t, "path", sbj_clone(sbj_get(opts, "path")));
            if (sbj_has(opts, "headers")) sbj_set(t, "headers", sbj_clone(sbj_get(opts, "headers")));
        } else {
            char *path = string_value(proxy, "ws-path");
            if (path) sbj_set(t, "path", sbj_str_take(path));
        }
    } else if (!strcmp(network, "grpc")) {
        t = sbj_object();
        sbj_set_str(t, "type", "grpc");
        const sbj *opts = sbj_get(proxy, "grpc-opts");
        if (sbj_is_object(opts)) {
            char *name = string_value(opts, "grpc-service-name");
            if (name) sbj_set(t, "service_name", sbj_str_take(name));
        }
    } else if (!strcmp(network, "h2") || !strcmp(network, "http")) {
        t = sbj_object();
        sbj_set_str(t, "type", "http");
        const sbj *opts = sbj_get(proxy, !strcmp(network, "h2") ? "h2-opts" : "http-opts");
        if (sbj_is_object(opts)) {
            if (sbj_has(opts, "host")) sbj_set(t, "host", sbj_clone(sbj_get(opts, "host")));
            const sbj *path = sbj_get(opts, "path");
            if (path) {
                if (sbj_is_array(path) && sbj_arr_len(path) > 0)
                    sbj_set(t, "path", sbj_clone(sbj_arr_at(path, 0)));
                else if (sbj_is_string(path))
                    sbj_set(t, "path", sbj_clone(path));
            }
        }
    }
    free(network);
    return t;
}

static sbj *clash_tls(const sbj *proxy, bool enabled) {
    if (!enabled) return NULL;
    sbj *tls = sbj_object();
    sbj_set_bool(tls, "enabled", true);
    char *sni = string_value(proxy, "sni");
    if (!sni || !*sni) {
        free(sni);
        sni = string_value(proxy, "servername");
    }
    if (sni && *sni) sbj_set(tls, "server_name", sbj_str_take(sni));
    else free(sni);
    if (boolean_value(proxy, "skip-cert-verify")) sbj_set_bool(tls, "insecure", true);
    const sbj *alpn = sbj_get(proxy, "alpn");
    if (sbj_is_array(alpn))
        sbj_set(tls, "alpn", sbj_clone(alpn));
    else if (sbj_is_string(alpn))
        sbj_set(tls, "alpn", split_alpn((sv){alpn->v.str.ptr, alpn->v.str.len}));
    char *fp = string_value(proxy, "client-fingerprint");
    if (fp && *fp) sbj_set(tls, "utls", utls(sbj_str_take(fp)));
    else free(fp);
    const sbj *reality = sbj_get(proxy, "reality-opts");
    if (sbj_is_object(reality)) {
        sbj *r = sbj_object();
        sbj_set_bool(r, "enabled", true);
        char *key = string_value(reality, "public-key");
        if (key) sbj_set(r, "public_key", sbj_str_take(key));
        char *id = string_value(reality, "short-id");
        if (id) sbj_set(r, "short_id", sbj_str_take(id));
        sbj_set(tls, "reality", r);
        if (!sbj_has(tls, "utls")) sbj_set(tls, "utls", utls(sbj_str("chrome")));
    }
    return tls;
}

static void set_opt(sbj *config, const char *key, sbj *value) {
    if (value) sbj_set(config, key, value);
}

static int clash_proxy(const sbj *proxy, sb_parsed_node *out) {
    if (!sbj_is_object(proxy)) return 0;
    char *raw_type = string_value_or(proxy, "type", "");
    const char *type = raw_type;
    if (!strcmp(type, "ss") || !strcmp(type, "shadowsocks")) type = "shadowsocks";
    else if (!strcmp(type, "hy2")) type = "hysteria2";
    char *server = string_value_or(proxy, "server", "");
    int64_t raw_port = 0;
    if (!integer_value(proxy, "port", &raw_port)) raw_port = 0;
    int result = 0;
    char *tag = NULL;
    sbj *config = NULL;
    if (!*server || raw_port <= 0 || raw_port > 65535) goto done;
    uint16_t port = (uint16_t)raw_port;
    tag = string_value_or(proxy, "name", "");
    if (!*tag) {
        free(tag);
        tag = sb_asprintf("%s:%u", server, (unsigned)port);
    }

    if (!strcmp(type, "shadowsocks")) {
        config = sbj_object();
        sbj_set(config, "method", sbj_str_take(string_value_or(proxy, "cipher", "")));
        sbj_set(config, "password", sbj_str_take(string_value_or(proxy, "password", "")));
    } else if (!strcmp(type, "vmess")) {
        config = sbj_object();
        sbj_set(config, "uuid", sbj_str_take(string_value_or(proxy, "uuid", "")));
        int64_t aid;
        if (!integer_value(proxy, "alterId", &aid) && !integer_value(proxy, "alterid", &aid)) aid = 0;
        sbj_set_int(config, "alter_id", aid);
        sbj_set(config, "security", sbj_str_take(string_value_or(proxy, "cipher", "auto")));
        set_opt(config, "transport", clash_transport(proxy));
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls")));
    } else if (!strcmp(type, "vless")) {
        config = sbj_object();
        sbj_set(config, "uuid", sbj_str_take(string_value_or(proxy, "uuid", "")));
        sbj_set(config, "flow", sbj_str_take(string_value_or(proxy, "flow", "")));
        sbj_set_str(config, "packet_encoding", "xudp");
        set_opt(config, "transport", clash_transport(proxy));
        bool reality = sbj_has(proxy, "reality-opts");
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls") || reality));
    } else if (!strcmp(type, "trojan")) {
        config = sbj_object();
        sbj_set(config, "password", sbj_str_take(string_value_or(proxy, "password", "")));
        set_opt(config, "transport", clash_transport(proxy));
        sbj_set(config, "tls", clash_tls(proxy, true));
    } else if (!strcmp(type, "hysteria2")) {
        char *password = string_value_or(proxy, "password", "");
        if (!*password) {
            free(password);
            password = string_value_or(proxy, "auth", "");
        }
        if (!*password) {
            free(password);
            password = string_value_or(proxy, "auth-str", "");
        }
        config = sbj_object();
        sbj_set(config, "password", sbj_str_take(password));
        sbj_set(config, "tls", clash_tls(proxy, true));
        char *obfs = string_value(proxy, "obfs");
        if (obfs && *obfs) {
            sbj *o = sbj_object();
            sbj_set(o, "type", sbj_str_take(obfs));
            char *pw = string_value(proxy, "obfs-password");
            if (pw) sbj_set(o, "password", sbj_str_take(pw));
            sbj_set(config, "obfs", o);
        } else {
            free(obfs);
        }
    } else if (!strcmp(type, "tuic")) {
        config = sbj_object();
        sbj_set(config, "uuid", sbj_str_take(string_value_or(proxy, "uuid", "")));
        sbj_set(config, "password", sbj_str_take(string_value_or(proxy, "password", "")));
        sbj_set(config, "congestion_control",
                sbj_str_take(string_value_or(proxy, "congestion-controller", "bbr")));
        sbj_set(config, "udp_relay_mode",
                sbj_str_take(string_value_or(proxy, "udp-relay-mode", "native")));
        sbj_set(config, "tls", clash_tls(proxy, true));
    } else if (!strcmp(type, "http")) {
        config = sbj_object();
        char *user = string_value(proxy, "username");
        if (user && *user) sbj_set(config, "username", sbj_str_take(user));
        else free(user);
        char *pw = string_value(proxy, "password");
        if (pw && *pw) sbj_set(config, "password", sbj_str_take(pw));
        else free(pw);
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls")));
    } else {
        goto done;
    }
    result = finish_node(out, type, sv_of(tag), sv_of(server), port, config, true);
    config = NULL;
done:
    sbj_free(config);
    free(tag);
    free(server);
    free(raw_type);
    return result;
}

static bool likely_base64(sv body) {
    sv v = sv_trim(body);
    if (v.n <= 20) return false;
    for (size_t i = 0; i < v.n; ++i) {
        unsigned char c = (unsigned char)v.p[i];
        if (!(is_alnum(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '=')) return false;
    }
    return true;
}

/* Returns 1 when the YAML branch produced the result, 0 to fall through. */
static int parse_clash_yaml(sv text, sb_parsed_node_vec *out) {
    yload L;
    bool ok;
    ynode *root = yload_first(&L, text.p, text.n, &ok);
    int handled = 0;
    if (ok && root->kind == Y_MAP) {
        const ynode *proxies = NULL;
        for (size_t i = 0; i + 1 < root->n; i += 2) {
            const ynode *k = root->items[i];
            if (k->kind == Y_SCALAR && k->slen == 7 && !memcmp(k->s, "proxies", 7)) {
                proxies = root->items[i + 1];
                break;
            }
        }
        if (proxies && proxies->kind == Y_SEQ && proxies->n > 0) {
            handled = 1;
            for (size_t i = 0; i < proxies->n; ++i) {
                sbj *proxy = yaml_to_json(proxies->items[i]);
                sb_parsed_node node;
                sb_parsed_node_init(&node);
                if (clash_proxy(proxy, &node)) {
                    vec_push_move(out, &node);
                } else {
                    sb_parsed_node_free(&node);
                }
                sbj_free(proxy);
            }
        }
    }
    yload_free(&L);
    return handled;
}

int sb_parse_subscription_body_ex(const char *body, size_t len, sb_parsed_node_vec *out,
                                  sb_err *err) {
    memset(out, 0, sizeof *out);
    sv input = {body ? body : "", body ? len : 0};
    str decoded = {0};
    sv text = input;
    if (likely_base64(input) && decode_base64(sv_trim(input), &decoded)) text = sv_str(&decoded);

    if (parse_clash_yaml(text, out)) {
        str_free(&decoded);
        return 0;
    }

    int rc = 0;
    while (text.n) {
        size_t nl = sv_find(text, '\n');
        sv line = sv_trim(sv_sub(text, 0, nl));
        text = nl == NPOS ? (sv){"", 0} : sv_from(text, nl + 1);
        if (!line.n || line.p[0] == '#' || sv_starts(line, "//")) continue;
        sb_parsed_node node;
        int r = sb_parse_proxy_uri_ex(line.p, line.n, &node, err);
        if (r == 1) {
            vec_push_move(out, &node);
            continue;
        }
        sb_parsed_node_free(&node);
        if (r < 0) {
            rc = -1;
            sb_parsed_node_vec_free(out);
            memset(out, 0, sizeof *out);
            break;
        }
    }
    str_free(&decoded);
    return rc;
}

sb_parsed_node_vec sb_parse_subscription_body(const char *body, size_t len) {
    sb_parsed_node_vec v;
    sb_parse_subscription_body_ex(body, len, &v, NULL);
    return v;
}

/* ---- sing-box outbound import ------------------------------------------ */

static bool outbound_port(const sbj *outbound, uint16_t *out) {
    const sbj *f = sbj_get(outbound, "server_port");
    if (!f) return false;
    if (f->type == SBJ_UINT) {
        if (f->v.u > 0 && f->v.u <= 65535) { *out = (uint16_t)f->v.u; return true; }
    } else if (f->type == SBJ_INT) {
        if (f->v.i > 0 && f->v.i <= 65535) { *out = (uint16_t)f->v.i; return true; }
    } else if (f->type == SBJ_STRING) {
        return parse_port((sv){f->v.str.ptr, f->v.str.len}, out);
    }
    return false;
}

/* C++: outbound.value(key, json{default}) — json{x} is a one-element array
 * [x] (nlohmann initializer-list semantics), so a missing key yields [x]. */
static sbj *value_or_wrapped(const sbj *obj, const char *key, sbj *fallback) {
    const sbj *f = sbj_get(obj, key);
    if (f) {
        sbj_free(fallback);
        return sbj_clone(f);
    }
    sbj *arr = sbj_array();
    sbj_arr_push(arr, fallback);
    return arr;
}

static void copy_if(sbj *config, const sbj *outbound, const char *key) {
    const sbj *f = sbj_get(outbound, key);
    if (f) sbj_set(config, key, sbj_clone(f));
}

/* Returns 1 parsed, 0 nullopt, -1 error. */
static int parse_outbound(const sbj *outbound, sb_parsed_node *out, sb_err *err) {
    const sbj *t = sbj_get(outbound, "type"), *s = sbj_get(outbound, "server");
    if (!sbj_is_object(outbound) || !sbj_is_string(t) || !sbj_is_string(s)) return 0;
    const char *type = t->v.str.ptr;
    sv server = {s->v.str.ptr, s->v.str.len};
    uint16_t port;
    if (!outbound_port(outbound, &port) || server.n == 0) return 0;
    sv tag;
    if (value_string(outbound, "tag", server, &tag, err)) return -1;
    sbj *config = sbj_object();
    if (!strcmp(type, "shadowsocks")) {
        sbj_set(config, "method", value_or_wrapped(outbound, "method", sbj_null()));
        sbj_set(config, "password", value_or_wrapped(outbound, "password", sbj_null()));
    } else if (!strcmp(type, "vmess")) {
        sbj_set(config, "uuid", value_or_wrapped(outbound, "uuid", sbj_null()));
        sbj_set(config, "alter_id", value_or_wrapped(outbound, "alter_id", sbj_int(0)));
        sbj_set(config, "security", value_or_wrapped(outbound, "security", sbj_str("auto")));
    } else if (!strcmp(type, "vless")) {
        sbj_set(config, "uuid", value_or_wrapped(outbound, "uuid", sbj_null()));
        sbj_set(config, "flow", value_or_wrapped(outbound, "flow", sbj_str("")));
        sbj_set(config, "packet_encoding",
                value_or_wrapped(outbound, "packet_encoding", sbj_str("xudp")));
    } else if (!strcmp(type, "trojan")) {
        sbj_set(config, "password", value_or_wrapped(outbound, "password", sbj_null()));
    } else if (!strcmp(type, "hysteria2")) {
        sbj_set(config, "password", value_or_wrapped(outbound, "password", sbj_null()));
        copy_if(config, outbound, "obfs");
    } else if (!strcmp(type, "tuic")) {
        sbj_set(config, "uuid", value_or_wrapped(outbound, "uuid", sbj_null()));
        sbj_set(config, "password", value_or_wrapped(outbound, "password", sbj_null()));
        copy_if(config, outbound, "congestion_control");
        copy_if(config, outbound, "udp_relay_mode");
    } else if (!strcmp(type, "http")) {
        copy_if(config, outbound, "username");
        copy_if(config, outbound, "password");
    } else {
        sbj_free(config);
        return 0;
    }
    if (strcmp(type, "shadowsocks") != 0) {
        copy_if(config, outbound, "tls");
        copy_if(config, outbound, "transport");
    }
    return finish_node(out, type, tag, server, port, config, false);
}

void sb_proxy_import_init(sb_proxy_import *imp) { memset(imp, 0, sizeof *imp); }

void sb_proxy_import_free(sb_proxy_import *imp) {
    sb_parsed_node_vec_free(&imp->nodes);
    sb_strvec_free(&imp->skipped);
    memset(imp, 0, sizeof *imp);
}

int sb_parse_outbound_config(const sbj *config, sb_proxy_import *out, sb_err *err) {
    sb_proxy_import_init(out);
    const sbj *outbounds = NULL;
    if (sbj_is_object(config) && sbj_is_array(sbj_get(config, "outbounds")))
        outbounds = sbj_get(config, "outbounds");
    else if (sbj_is_array(config))
        outbounds = config;
    if (!outbounds) return 0;

    static const char *const supported[] = {"shadowsocks", "vmess", "vless", "trojan",
                                            "hysteria2",   "tuic",  "http"};
    const sbj *outbound;
    SBJ_ARR_FOREACH(outbounds, i, outbound) {
        sv type = {"", 0};
        if (sbj_is_object(outbound) && value_string(outbound, "type", type, &type, err)) goto fail;
        bool known = false;
        for (size_t k = 0; k < sizeof supported / sizeof *supported; ++k)
            if (sv_eq(type, supported[k])) known = true;
        if (!known) continue;
        sb_parsed_node node;
        sb_parsed_node_init(&node);
        int r = parse_outbound(outbound, &node, err);
        if (r < 0) {
            sb_parsed_node_free(&node);
            goto fail;
        }
        if (r == 1) {
            vec_push_move(&out->nodes, &node);
        } else {
            sb_parsed_node_free(&node);
            sv tag;
            if (value_string(outbound, "tag", sv_of("?"), &tag, err)) goto fail;
            sb_buf b = {0};
            sb_buf_append(&b, tag.p, tag.n);
            sb_buf_puts(&b, " (");
            sb_buf_append(&b, type.p, type.n);
            sb_buf_puts(&b, ")");
            sb_strvec_push_take(&out->skipped, sb_buf_detach(&b));
        }
    }
    return 0;
fail:
    sb_proxy_import_free(out);
    return -1;
}
