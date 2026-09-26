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

/* ---- YAML: libyaml -> tree, mirroring yaml-cpp -------------------------- */
/* The C++ code loaded subscriptions with yaml-cpp's YAML::Load and read the
 * node tree through yaml_to_json(): scalars become JSON strings, null nodes
 * become null, maps keep only scalar keys (last duplicate wins) and only the
 * first document is read. yaml-cpp implements neither merge keys ("<<" is an
 * ordinary key) nor implicit typing, and neither does this loader. libyaml is
 * stricter than yaml-cpp in a few places; the preprocessing below restores
 * yaml-cpp's behaviour for input encodings, raw bytes and a trailing
 * colon-less key line. */

enum { Y_NULL, Y_SCALAR, Y_SEQ, Y_MAP };

typedef struct ynode {
    int kind;
    bool visiting; /* yaml_to_json cycle guard */
    char *s;
    size_t slen;
    struct ynode **items; /* seq: elements; map: key,value,key,value... */
    size_t n, cap;
} ynode;

/* An open collection while parsing (for trailing_key_fix). */
typedef struct {
    bool map, flow;
    size_t column;
} yopen;

typedef struct {
    yaml_parser_t parser;
    bool parser_live;
    ynode **all;
    size_t nall, capall;
    char **anchor_names;
    ynode **anchor_nodes;
    size_t nanchors;
    yopen *open;
    size_t nopen, capopen;
    bool sanitized;
    char *buffer; /* preprocessed input, if any */
    char *fixed;  /* input of the latest rewrite-and-retry round, if any */
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

/* Releases the tree, anchors and parser; keeps the input buffers. */
static void yload_clear(yload *L) {
    for (size_t i = 0; i < L->nall; ++i) {
        free(L->all[i]->s);
        free(L->all[i]->items);
        free(L->all[i]);
    }
    free(L->all);
    for (size_t i = 0; i < L->nanchors; ++i) free(L->anchor_names[i]);
    free(L->anchor_names);
    free(L->anchor_nodes);
    if (L->parser_live) yaml_parser_delete(&L->parser);
    free(L->open);
    L->open = NULL;
    L->nopen = L->capopen = 0;
    L->all = NULL;
    L->nall = L->capall = 0;
    L->anchor_names = NULL;
    L->anchor_nodes = NULL;
    L->nanchors = 0;
    L->parser_live = false;
}

static void yload_free(yload *L) {
    yload_clear(L);
    free(L->buffer);
    free(L->fixed);
    L->buffer = L->fixed = NULL;
}

static bool is_null_string(const char *s, size_t n) {
    return n == 0 || (n == 1 && s[0] == '~') ||
           (n == 4 && (!memcmp(s, "null", 4) || !memcmp(s, "Null", 4) || !memcmp(s, "NULL", 4)));
}

/* -- input encoding: yaml-cpp's Stream ------------------------------------ */
/* yaml-cpp guesses the encoding from the first bytes (UTF-8/16/32 BOMs, and
 * NUL patterns for BOM-less UTF-16/32) and transcodes to UTF-8 with its own
 * rules. The tables are copied from yaml-cpp's stream.cpp. */
enum {
    uis_start, uis_utfbe_b1, uis_utf32be_b2, uis_utf32be_bom3, uis_utf32be, uis_utf16be,
    uis_utf16be_bom1, uis_utfle_bom1, uis_utf16le_bom2, uis_utf32le_bom3, uis_utf16le,
    uis_utf32le, uis_utf8_imp, uis_utf16le_imp, uis_utf32le_imp3, uis_utf8_bom1, uis_utf8_bom2,
    uis_utf8, uis_error
};
static const bool intro_final[] = {false, false, false, false, true,  true,  false,
                                   false, false, false, true,  true,  false, false,
                                   false, false, false, true,  true};
static const unsigned char intro_transitions[][8] = {
    {uis_utfbe_b1, uis_utf8, uis_utf8, uis_utf8_bom1, uis_utf16be_bom1, uis_utfle_bom1,
     uis_utf8_imp, uis_utf8},
    {uis_utf32be_b2, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf16be, uis_utf8},
    {uis_utf32be, uis_utf8, uis_utf8, uis_utf8, uis_utf32be_bom3, uis_utf8, uis_utf8, uis_utf8},
    {uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf32be, uis_utf8, uis_utf8},
    {uis_utf32be, uis_utf32be, uis_utf32be, uis_utf32be, uis_utf32be, uis_utf32be, uis_utf32be,
     uis_utf32be},
    {uis_utf16be, uis_utf16be, uis_utf16be, uis_utf16be, uis_utf16be, uis_utf16be, uis_utf16be,
     uis_utf16be},
    {uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf16be, uis_utf8, uis_utf8},
    {uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf16le_bom2, uis_utf8, uis_utf8, uis_utf8},
    {uis_utf32le_bom3, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le,
     uis_utf16le, uis_utf16le},
    {uis_utf32le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le,
     uis_utf16le},
    {uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le,
     uis_utf16le},
    {uis_utf32le, uis_utf32le, uis_utf32le, uis_utf32le, uis_utf32le, uis_utf32le, uis_utf32le,
     uis_utf32le},
    {uis_utf16le_imp, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8},
    {uis_utf32le_imp3, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le,
     uis_utf16le, uis_utf16le},
    {uis_utf32le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le, uis_utf16le,
     uis_utf16le},
    {uis_utf8, uis_utf8_bom2, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8},
    {uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8},
    {uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8, uis_utf8},
};
static const unsigned char intro_unget[][8] = {
    {0, 1, 1, 0, 0, 0, 0, 1}, {0, 2, 2, 2, 2, 2, 2, 2}, {3, 3, 3, 3, 0, 3, 3, 3},
    {4, 4, 4, 4, 4, 0, 4, 4}, {1, 1, 1, 1, 1, 1, 1, 1}, {1, 1, 1, 1, 1, 1, 1, 1},
    {2, 2, 2, 2, 2, 0, 2, 2}, {2, 2, 2, 2, 0, 2, 2, 2}, {0, 1, 1, 1, 1, 1, 1, 1},
    {0, 2, 2, 2, 2, 2, 2, 2}, {1, 1, 1, 1, 1, 1, 1, 1}, {1, 1, 1, 1, 1, 1, 1, 1},
    {0, 2, 2, 2, 2, 2, 2, 2}, {0, 3, 3, 3, 3, 3, 3, 3}, {4, 4, 4, 4, 4, 4, 4, 4},
    {2, 0, 2, 2, 2, 2, 2, 2}, {3, 3, 0, 3, 3, 3, 3, 3}, {1, 1, 1, 1, 1, 1, 1, 1},
};

static int intro_char_type(int ch) {
    switch (ch) {
    case -1: return 7; /* EOF: uictOther */
    case 0: return 0;
    case 0xBB: return 1;
    case 0xBF: return 2;
    case 0xEF: return 3;
    case 0xFE: return 4;
    case 0xFF: return 5;
    default: return 6; /* uictAscii: every other byte */
    }
}

/* yaml-cpp's Utf8Adjust + QueueUnicodeCodepoint (no validation). */
static void yamlcpp_queue(sb_buf *b, unsigned long ch) {
    if (ch == 0x04) ch = 0xFFFD; /* Stream::eof() may not be queued */
    unsigned char e[4];
    size_t n;
    if (ch < 0x80) {
        e[0] = (unsigned char)ch;
        n = 1;
    } else if (ch < 0x800) {
        e[0] = (unsigned char)(0xC0 | ((ch >> 6) & 0x1F));
        e[1] = (unsigned char)(0x80 | (ch & 0x3F));
        n = 2;
    } else if (ch < 0x10000) {
        e[0] = (unsigned char)(0xE0 | ((ch >> 12) & 0x0F));
        e[1] = (unsigned char)(0x80 | ((ch >> 6) & 0x3F));
        e[2] = (unsigned char)(0x80 | (ch & 0x3F));
        n = 3;
    } else {
        e[0] = (unsigned char)(0xF0 | ((ch >> 18) & 0x07));
        e[1] = (unsigned char)(0x80 | ((ch >> 12) & 0x3F));
        e[2] = (unsigned char)(0x80 | ((ch >> 6) & 0x3F));
        e[3] = (unsigned char)(0x80 | (ch & 0x3F));
        n = 4;
    }
    sb_buf_append(b, e, n);
}

/* Returns a malloc'd UTF-8 transcoding of UTF-16/32 input, or NULL for UTF-8
 * input, in which case *skip is the length of a consumed UTF-8 BOM. */
static char *yamlcpp_decode(const unsigned char *in, size_t n, size_t *skip, size_t *out_len) {
    int intro[4];
    int used = 0, state = uis_start;
    size_t pos = 0;
    while (!intro_final[state]) {
        int ch = pos < n ? in[pos++] : -1;
        intro[used++] = ch;
        int type = intro_char_type(ch);
        int next = intro_transitions[state][type];
        for (int u = intro_unget[state][type]; u > 0; --u)
            if (intro[--used] >= 0) --pos;
        state = next;
    }
    *skip = 0;
    if (state != uis_utf16le && state != uis_utf16be && state != uis_utf32le &&
        state != uis_utf32be) {
        *skip = pos;
        return NULL;
    }
    sb_buf b = {0};
    if (state == uis_utf16le || state == uis_utf16be) {
        int big = state == uis_utf16be ? 0 : 1; /* index of the high byte */
        while (pos + 2 <= n) {
            unsigned long ch = ((unsigned long)in[pos + (size_t)big] << 8) | in[pos + (size_t)(big ^ 1)];
            pos += 2;
            if (ch >= 0xDC00 && ch < 0xE000) { /* low surrogate first */
                yamlcpp_queue(&b, 0xFFFD);
                continue;
            }
            if (ch >= 0xD800 && ch < 0xDC00) {
                bool done = false;
                for (;;) {
                    if (pos + 2 > n) { /* input ended inside the pair */
                        pos = n;
                        yamlcpp_queue(&b, 0xFFFD);
                        done = true;
                        break;
                    }
                    unsigned long low =
                        ((unsigned long)in[pos + (size_t)big] << 8) | in[pos + (size_t)(big ^ 1)];
                    pos += 2;
                    if (low < 0xDC00 || low >= 0xE000) {
                        yamlcpp_queue(&b, 0xFFFD);
                        if (low < 0xD800 || low >= 0xE000) {
                            /* yaml-cpp queues the high surrogate, not `low`. */
                            yamlcpp_queue(&b, ch);
                            done = true;
                            break;
                        }
                        ch = low;
                        continue;
                    }
                    ch = ((ch & 0x3FF) << 10 | (low & 0x3FF)) + 0x10000;
                    break;
                }
                if (done) continue;
            }
            yamlcpp_queue(&b, ch);
        }
    } else {
        bool be = state == uis_utf32be;
        while (pos + 4 <= n) {
            unsigned long ch = 0;
            for (int i = 0; i < 4; ++i) ch = (ch << 8) | in[pos + (size_t)(be ? i : 3 - i)];
            pos += 4;
            yamlcpp_queue(&b, ch);
        }
    }
    *out_len = b.len;
    return b.p ? sb_buf_detach(&b) : sb_strdup("");
}

/* -- raw bytes ------------------------------------------------------------ */
/* yaml-cpp passes arbitrary bytes (control characters, invalid UTF-8,
 * U+FEFF) into scalars and only breaks lines on \n and \r, whereas libyaml
 * rejects such streams, skips U+FEFF at the start of a line and also breaks
 * on NEL, U+2028 and U+2029. Every byte libyaml would reject or treat
 * differently is therefore re-encoded as the plane-15 private-use code point
 * U+F0000+byte before parsing; genuine code points U+F0000..U+F00FF and the
 * escape U+F0100 itself are written as U+F0100 followed by the code point.
 * Scalars are decoded back afterwards. */
#define YS_RAW_BASE 0xF0000u
#define YS_ESCAPE 0xF0100u

static size_t utf8_decode(const unsigned char *p, size_t n, uint32_t *cp) {
    unsigned char c = p[0];
    size_t len;
    uint32_t v, min;
    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        len = 2;
        v = c & 0x1F;
        min = 0x80;
    } else if (c >= 0xE0 && c <= 0xEF) {
        len = 3;
        v = c & 0x0F;
        min = 0x800;
    } else if (c >= 0xF0 && c <= 0xF4) {
        len = 4;
        v = c & 0x07;
        min = 0x10000;
    } else {
        return 0;
    }
    if (n < len) return 0;
    for (size_t i = 1; i < len; ++i) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        v = (v << 6) | (p[i] & 0x3F);
    }
    if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return 0;
    *cp = v;
    return len;
}

/* Code points libyaml accepts and treats exactly like yaml-cpp does. */
static bool yaml_plain_ok(uint32_t v) {
    return v == 0x09 || v == 0x0A || v == 0x0D || (v >= 0x20 && v <= 0x7E) ||
           (v >= 0xA0 && v <= 0xD7FF && v != 0x2028 && v != 0x2029) ||
           (v >= 0xE000 && v <= 0xFFFD && v != 0xFEFF) || (v >= 0x10000 && v <= 0x10FFFF);
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
            yamlcpp_queue(&b, YS_ESCAPE);
            sb_buf_append(&b, p + i, n);
        } else if (n && yaml_plain_ok(cp)) {
            sb_buf_append(&b, p + i, n);
        } else {
            if (!n) n = 1; /* invalid sequence: one raw byte at a time */
            for (size_t k = 0; k < n; ++k) yamlcpp_queue(&b, YS_RAW_BASE + p[i + k]);
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

/* -- events -> tree ------------------------------------------------------- */

/* yaml-cpp's DepthGuard<500>. */
#define YAML_MAX_DEPTH 500

static bool scalar_has_nul(const ynode *n) { return memchr(n->s, '\0', n->slen) != NULL; }

/* Consumes the node starting at *ev (this function deletes the event).
 * Returns NULL on error. */
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
        return node; /* undefined anchor: an error, as in yaml-cpp */
    }
    case YAML_SCALAR_EVENT: {
        const char *value = (const char *)ev->data.scalar.value;
        size_t len = ev->data.scalar.length;
        yaml_scalar_style_t style = ev->data.scalar.style;
        /* yaml-cpp: an untagged plain scalar spelled ~, null, Null, NULL or
         * nothing is a null node; everything else is a string scalar. */
        if (style == YAML_PLAIN_SCALAR_STYLE && !ev->data.scalar.tag && is_null_string(value, len)) {
            node = ynew(L, Y_NULL);
        } else {
            node = ynew(L, Y_SCALAR);
            node->s = sb_strndup(value, len);
            node->slen = L->sanitized ? yaml_unsanitize(node->s, len) : len;
            /* yaml-cpp scans plain and block scalars with NUL as their escape
             * character, so a raw NUL there fails (unless followed by an
             * escape letter; not emulated). Quoted scalars keep it. */
            if ((style == YAML_PLAIN_SCALAR_STYLE || style == YAML_LITERAL_SCALAR_STYLE ||
                 style == YAML_FOLDED_SCALAR_STYLE) &&
                scalar_has_nul(node)) {
                yaml_event_delete(ev);
                return NULL;
            }
        }
        yanchor(L, ev->data.scalar.anchor, node);
        yaml_event_delete(ev);
        return node;
    }
    case YAML_SEQUENCE_START_EVENT:
    case YAML_MAPPING_START_EVENT: {
        bool is_seq = ev->type == YAML_SEQUENCE_START_EVENT;
        yaml_event_type_t end = is_seq ? YAML_SEQUENCE_END_EVENT : YAML_MAPPING_END_EVENT;
        bool flow = is_seq ? ev->data.sequence_start.style == YAML_FLOW_SEQUENCE_STYLE
                           : ev->data.mapping_start.style == YAML_FLOW_MAPPING_STYLE;
        node = ynew(L, is_seq ? Y_SEQ : Y_MAP);
        /* Registered before the children, like yaml-cpp: an alias inside the
         * collection refers to the collection itself. */
        yanchor(L, is_seq ? ev->data.sequence_start.anchor : ev->data.mapping_start.anchor, node);
        if (L->nopen == L->capopen) {
            L->capopen = L->capopen ? L->capopen * 2 : 16;
            L->open = sb_xrealloc(L->open, L->capopen * sizeof *L->open);
        }
        L->open[L->nopen++] = (yopen){!is_seq, flow, ev->start_mark.column};
        yaml_event_delete(ev);
        for (;;) {
            yaml_event_t child;
            if (!yaml_parser_parse(&L->parser, &child)) return NULL;
            if (child.type == end) {
                yaml_event_delete(&child);
                L->nopen--;
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

/* Parses the first document of text. */
static ynode *yload_attempt(yload *L, const char *text, size_t len, bool *ok) {
    *ok = false;
    if (!yaml_parser_initialize(&L->parser)) return NULL;
    L->parser_live = true;
    yaml_parser_set_encoding(&L->parser, YAML_UTF8_ENCODING);
    yaml_parser_set_input_string(&L->parser, (const unsigned char *)text, len);
    yaml_event_t ev;
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    yaml_event_delete(&ev); /* STREAM-START */
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    if (ev.type == YAML_STREAM_END_EVENT) {
        yaml_event_delete(&ev);
        *ok = true;
        return ynew(L, Y_NULL);
    }
    yaml_event_delete(&ev); /* DOCUMENT-START */
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    ynode *root = yparse_node(L, &ev, 1);
    if (!root) return NULL;
    /* yaml-cpp scans the token after the root node before returning, so a
     * scanner error right after the document (e.g. a stray ':') still fails
     * the load; libyaml does the same when producing DOCUMENT-END. */
    if (!yaml_parser_parse(&L->parser, &ev)) return NULL;
    yaml_event_delete(&ev);
    *ok = true;
    return root;
}

/* Byte offset of character number `index` (libyaml marks count characters)
 * in valid UTF-8 text. */
static size_t char_to_byte(const char *t, size_t n, size_t index) {
    size_t b = 0;
    while (index > 0 && b < n) {
        ++b;
        while (b < n && ((unsigned char)t[b] & 0xC0) == 0x80) ++b;
        --index;
    }
    return b;
}

static bool is_blank_c(char c) { return c == ' ' || c == '\t'; }
static bool is_break_c(char c) { return c == '\n' || c == '\r'; }
static size_t break_len(const char *t, size_t i, size_t n) {
    if (t[i] == '\r' && i + 1 < n && t[i + 1] == '\n') return 2;
    return 1;
}

/* End (one past the closing quote) of the quoted scalar starting at t[i], or
 * 0 if it is not closed. */
static size_t quoted_end(const char *t, size_t i, size_t n) {
    char q = t[i++];
    while (i < n) {
        if (q == '"' && t[i] == '\\') {
            i += 2;
            continue;
        }
        if (t[i] == q) {
            if (q == '\'' && i + 1 < n && t[i + 1] == '\'') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        ++i;
    }
    return 0;
}

/* End of the flow collection starting at t[i] (multi-line, with comments and
 * quoted scalars), or 0 if it is not closed. */
static size_t flow_end(const char *t, size_t i, size_t n) {
    int depth = 0;
    while (i < n) {
        char c = t[i];
        if (c == '"' || c == '\'') {
            size_t e = quoted_end(t, i, n);
            if (!e) return 0;
            i = e;
            continue;
        }
        if (c == '#' && (i == 0 || is_blank_c(t[i - 1]) || is_break_c(t[i - 1]))) {
            while (i < n && !is_break_c(t[i])) ++i;
            continue;
        }
        if (c == '[' || c == '{') {
            ++depth;
        } else if (c == ']' || c == '}') {
            if (--depth == 0) return i + 1;
        }
        ++i;
    }
    return 0;
}

/* yaml-cpp's ScanToNextToken after a token that is a pending simple key: the
 * key survives only if the input ends before any line break is eaten
 * (blanks and one trailing comment are allowed). */
static bool only_comment_to_eof(const char *t, size_t i, size_t n) {
    while (i < n && is_blank_c(t[i])) ++i;
    if (i < n && t[i] == '#')
        while (i < n && !is_break_c(t[i])) ++i;
    return i == n;
}

static bool doc_indicator_at(const char *t, size_t i, size_t n) {
    return n - i >= 3 && (!memcmp(t + i, "---", 3) || !memcmp(t + i, "...", 3)) &&
           (i + 3 == n || is_blank_c(t[i + 3]) || is_break_c(t[i + 3]));
}

/* yaml-cpp's ScanScalarEnd in block context: ':' + blank/break/EOF, or a
 * blank/break followed by '#'. */
static bool plain_end_at(const char *t, size_t i, size_t n) {
    if (t[i] == ':') return i + 1 == n || is_blank_c(t[i + 1]) || is_break_c(t[i + 1]);
    return (is_blank_c(t[i]) || is_break_c(t[i])) && i + 1 < n && t[i + 1] == '#';
}

/* Simulates yaml-cpp's ScanPlainScalar (block context, indent = K + 1) for a
 * pending simple key starting at t[i], then the tokens up to the end of the
 * input. Returns true when yaml-cpp would keep the key (see
 * trailing_key_fix); *stop is where the scalar scan stopped. */
static bool plain_key_survives(const char *t, size_t i, size_t n, size_t indent, size_t *stop) {
    size_t col = 0;
    for (size_t b = i; b > 0 && !is_break_c(t[b - 1]); --b) ++col; /* byte column, as yaml-cpp */
    for (;;) {
        /* phase 1: to the end of the line */
        while (i < n && !plain_end_at(t, i, n) && !is_break_c(t[i])) {
            ++i;
            ++col;
        }
        if (i == n) {
            *stop = i;
            return true;
        }
        if (plain_end_at(t, i, n)) {
            *stop = i;
            if (t[i] == ':') return false; /* a value indicator on a later line */
            if (is_break_c(t[i])) return false; /* "\n#": ScanToNextToken eats the break */
            return only_comment_to_eof(t, i, n);
        }
        /* phase 2: the line break */
        i += break_len(t, i, n);
        col = 0;
        /* phase 3: indentation */
        while (i < n && t[i] == ' ' && col < indent && !plain_end_at(t, i, n)) {
            ++i;
            ++col;
        }
        while (i < n && is_blank_c(t[i])) {
            if (t[i] == '\t' && col < indent) return false; /* illegal tab in indentation */
            if (plain_end_at(t, i, n)) break;
            ++i;
            ++col;
        }
        if (i == n) {
            *stop = i;
            return true;
        }
        bool empty_line = is_break_c(t[i]);
        if (!empty_line && col < indent) { /* done via indentation */
            *stop = i;
            if (col == 0 && doc_indicator_at(t, i, n)) return true;
            return only_comment_to_eof(t, i, n) && (is_blank_c(t[i]) || t[i] == '#');
        }
    }
}

/* yaml-cpp keeps a potential simple key that is still pending at the end of
 * the input ("a: 1\nfoo" loads as {a: 1, foo: ~}); libyaml fails with "could
 * not find expected ':'". yaml-cpp's rule: the key survives if it sits at the
 * column of the enclosing block mapping and no line break is consumed by
 * ScanToNextToken after it (plain scalars swallow their own trailing breaks
 * and continuation lines). If instead the key closes the root collection,
 * yaml-cpp's first document simply ends before it. The first case is
 * rewritten as an explicit "? key\n:" entry (no 1024-character limit), the
 * second by cutting the input before the key's line. Returns the rewritten
 * text or NULL when yaml-cpp would fail too. */
static char *trailing_key_fix(const yload *L, const char *t, size_t n, size_t *out_n) {
    const yaml_parser_t *p = &L->parser;
    if (!p->problem || strcmp(p->problem, "could not find expected ':'") != 0 || !p->context ||
        strcmp(p->context, "while scanning a simple key") != 0)
        return NULL;
    size_t K = p->context_mark.column;
    size_t kb = char_to_byte(t, n, p->context_mark.index);
    if (kb >= n) return NULL;
    size_t depth = L->nopen;
    for (size_t i = 0; i < depth; ++i)
        if (L->open[i].flow) return NULL;
    /* yaml-cpp's PopIndentToHere */
    while (depth && (L->open[depth - 1].column > K ||
                     (L->open[depth - 1].column == K && !L->open[depth - 1].map)))
        --depth;
    sb_buf b = {0};
    if (depth == 0) { /* the key closed the root collection */
        size_t line = kb;
        while (line > 0 && !is_break_c(t[line - 1])) --line;
        sb_buf_append(&b, t, line);
        *out_n = b.len;
        return b.p ? sb_buf_detach(&b) : sb_strdup("");
    }
    if (!L->open[depth - 1].map || L->open[depth - 1].column != K) return NULL;

    size_t k = kb;
    while (k < n && (t[k] == '!' || t[k] == '&')) { /* node properties */
        if (t[k] == '!' && k + 1 < n && t[k + 1] == '<') {
            while (k < n && t[k] != '>' && !is_break_c(t[k])) ++k;
            if (k < n && t[k] == '>') ++k;
        }
        while (k < n && !is_blank_c(t[k]) && !is_break_c(t[k])) ++k;
        while (k < n && is_blank_c(t[k])) ++k;
    }
    size_t stop;
    if (k == n || is_break_c(t[k]) || t[k] == '#') { /* properties only: empty node */
        stop = k;
        if (!only_comment_to_eof(t, k, n)) return NULL;
    } else if (t[k] == '"' || t[k] == '\'' || t[k] == '[' || t[k] == '{' || t[k] == '*') {
        if (t[k] == '*') {
            stop = k + 1;
            while (stop < n && !is_blank_c(t[stop]) && !is_break_c(t[stop])) ++stop;
        } else {
            stop = (t[k] == '"' || t[k] == '\'') ? quoted_end(t, k, n) : flow_end(t, k, n);
        }
        if (!stop || !only_comment_to_eof(t, stop, n)) return NULL;
    } else if (!plain_key_survives(t, k, n, K + 1, &stop)) {
        return NULL;
    }
    sb_buf_append(&b, t, kb);
    sb_buf_puts(&b, "? ");
    sb_buf_append(&b, t + kb, stop - kb);
    sb_buf_putc(&b, '\n');
    for (size_t i = 0; i < K; ++i) sb_buf_putc(&b, ' ');
    sb_buf_puts(&b, ":\n");
    sb_buf_append(&b, t + stop, n - stop);
    *out_n = b.len;
    return sb_buf_detach(&b);
}

/* yaml-cpp also accepts the escape \' in double-quoted scalars, which libyaml
 * rejects ("found unknown escape character"). The failing escape is replaced
 * by a plain quote (throughout that scalar) and the parse retried. Returns
 * the rewritten text or NULL. */
static char *quote_escape_fix(const yaml_parser_t *p, const char *t, size_t n, size_t *out_n) {
    if (!p->problem || strcmp(p->problem, "found unknown escape character") != 0) return NULL;
    size_t at = char_to_byte(t, n, p->problem_mark.index);
    if (at + 1 >= n || t[at] != '\\' || t[at + 1] != '\'') return NULL;
    sb_buf b = {0};
    sb_buf_append(&b, t, at);
    size_t i = at;
    while (i < n) { /* rest of this double-quoted scalar */
        if (t[i] == '\\' && i + 1 < n) {
            if (t[i + 1] == '\'') sb_buf_putc(&b, '\'');
            else sb_buf_append(&b, t + i, 2);
            i += 2;
            continue;
        }
        sb_buf_putc(&b, t[i]);
        if (t[i++] == '"') break;
    }
    sb_buf_append(&b, t + i, n - i);
    *out_n = b.len;
    return sb_buf_detach(&b);
}

/* In flow context yaml-cpp starts a plain scalar at ':' when the next
 * character is not a blank, a break or ",[]{}?" (e.g. {server: ::1}); libyaml
 * treats every ':' in flow context as a value indicator ("did not find
 * expected node content"). The scalar (to yaml-cpp's in-flow scalar end on
 * that line) is rewritten as an equivalent double-quoted scalar. */
static char *flow_colon_fix(const yload *L, const char *t, size_t n, size_t *out_n) {
    const yaml_parser_t *p = &L->parser;
    if (!p->problem || strcmp(p->problem, "did not find expected node content") != 0) return NULL;
    if (!L->nopen || !L->open[L->nopen - 1].flow) return NULL;
    size_t at = char_to_byte(t, n, p->problem_mark.index);
    if (at + 1 >= n || t[at] != ':' || is_blank_c(t[at + 1]) || is_break_c(t[at + 1]) ||
        strchr(",[]{}?", t[at + 1]))
        return NULL;
    size_t e = at + 1;
    while (e < n && !is_break_c(t[e]) && !strchr(",?[]{}", t[e])) {
        if (t[e] == ':' && (e + 1 == n || is_blank_c(t[e + 1]) || is_break_c(t[e + 1]) ||
                            strchr(",]}", t[e + 1])))
            break;
        if (is_blank_c(t[e]) && e + 1 < n && t[e + 1] == '#') break;
        ++e;
    }
    while (e > at && is_blank_c(t[e - 1])) --e;
    sb_buf b = {0};
    sb_buf_append(&b, t, at);
    sb_buf_putc(&b, '"');
    for (size_t i = at; i < e; ++i) {
        if (t[i] == '"' || t[i] == '\\') sb_buf_putc(&b, '\\');
        sb_buf_putc(&b, t[i]);
    }
    sb_buf_putc(&b, '"');
    sb_buf_append(&b, t + e, n - e);
    *out_n = b.len;
    return sb_buf_detach(&b);
}

static char *splice(const char *t, size_t n, size_t at, size_t del, const char *ins, size_t ins_n,
                    size_t *out_n) {
    sb_buf b = {0};
    sb_buf_append(&b, t, at);
    sb_buf_append(&b, ins, ins_n);
    sb_buf_append(&b, t + at + del, n - at - del);
    *out_n = b.len;
    return b.p ? sb_buf_detach(&b) : sb_strdup("");
}

static bool problem_is(const yaml_parser_t *p, const char *problem, const char *context) {
    return p->problem && !strcmp(p->problem, problem) &&
           (!context || (p->context && !strcmp(p->context, context)));
}

/* yaml-cpp accepts a quoted scalar left open at the end of the input (a
 * truncated download) when the input ends right after the opening quote or
 * after a line break followed by blanks only; otherwise it throws "illegal
 * EOF in scalar". Accepted cases get the closing quote appended. */
static char *unterminated_quote_fix(const yaml_parser_t *p, const char *t, size_t n, size_t *out_n) {
    if (!problem_is(p, "found unexpected end of stream", "while scanning a quoted scalar")) return NULL;
    size_t at = char_to_byte(t, n, p->context_mark.index);
    if (at >= n || (t[at] != '"' && t[at] != '\'')) return NULL;
    size_t tail = n;
    while (tail > at + 1 && !is_break_c(t[tail - 1])) --tail;
    if (tail == at + 1) {
        if (n != at + 1) return NULL; /* content after the quote on its line */
    } else {
        for (size_t i = tail; i < n; ++i)
            if (!is_blank_c(t[i])) return NULL;
    }
    return splice(t, n, n, 0, t + at, 1, out_n);
}

/* yaml-cpp reads a block-mapping entry without a key (": x") as a null key;
 * libyaml fails with "did not find expected key". */
static char *empty_key_fix(const yaml_parser_t *p, const char *t, size_t n, size_t *out_n) {
    if (!problem_is(p, "did not find expected key", "while parsing a block mapping")) return NULL;
    size_t at = char_to_byte(t, n, p->problem_mark.index);
    if (at >= n || t[at] != ':' || !(at + 1 == n || is_blank_c(t[at + 1]) || is_break_c(t[at + 1])))
        return NULL;
    return splice(t, n, at, 0, "~", 1, out_n);
}

/* yaml-cpp eats tabs between tokens where libyaml refuses them ("found
 * character that cannot start any token"), e.g. a tab-only line or a tab
 * before a comment. After a tab yaml-cpp forbids a simple key, a block entry
 * and an explicit key on the rest of the line, so the tab is only replaced by
 * a space when the rest of the line has none of those. */
static char *tab_fix(const yaml_parser_t *p, const char *t, size_t n, size_t *out_n) {
    if (!problem_is(p, "found character that cannot start any token", NULL)) return NULL;
    size_t at = char_to_byte(t, n, p->problem_mark.index);
    if (at >= n || t[at] != '\t') return NULL;
    size_t e = at;
    while (e < n && is_blank_c(t[e])) ++e;
    if (e < n && !is_break_c(t[e]) && t[e] != '#') {
        if ((t[e] == '-' || t[e] == '?' || t[e] == ':') &&
            (e + 1 == n || is_blank_c(t[e + 1]) || is_break_c(t[e + 1])))
            return NULL;
        for (size_t i = e; i < n && !is_break_c(t[i]); ++i)
            if (t[i] == ':' && (i + 1 == n || is_blank_c(t[i + 1]) || is_break_c(t[i + 1])))
                return NULL;
    }
    char *r = splice(t, n, 0, 0, "", 0, out_n);
    for (size_t i = at; i < e; ++i)
        if (r[i] == '\t') r[i] = ' ';
    return r;
}

/* yaml-cpp anchor and alias names are any run of characters other than
 * blanks, breaks and "[]{},"; libyaml only allows [0-9A-Za-z_-]. A name
 * libyaml rejects is renamed (deterministically, so its aliases match) and
 * the parse retried. */
static char *anchor_fix(const yaml_parser_t *p, const char *t, size_t n, size_t *out_n) {
    if (!problem_is(p, "did not find expected alphabetic or numeric character", NULL) ||
        !p->context ||
        (strcmp(p->context, "while scanning an anchor") != 0 &&
         strcmp(p->context, "while scanning an alias") != 0))
        return NULL;
    size_t at = char_to_byte(t, n, p->context_mark.index);
    if (at >= n || (t[at] != '&' && t[at] != '*')) return NULL;
    size_t e = at + 1;
    while (e < n && !is_blank_c(t[e]) && !is_break_c(t[e]) && !strchr("[]{},", t[e])) ++e;
    if (e == at + 1 || (e < n && (t[e] == '[' || t[e] == '{'))) return NULL; /* yaml-cpp fails too */
    static const char hex[] = "0123456789abcdef";
    sb_buf name = {0};
    sb_buf_putc(&name, t[at]);
    sb_buf_puts(&name, "__sbx_");
    for (size_t i = at + 1; i < e; ++i) {
        sb_buf_putc(&name, hex[(unsigned char)t[i] >> 4]);
        sb_buf_putc(&name, hex[(unsigned char)t[i] & 15]);
    }
    char *r = splice(t, n, at, e - at, name.p, name.len, out_n);
    sb_buf_free(&name);
    return r;
}

/* Bounds on rewrite-and-retry rounds (each fixes one construct libyaml
 * rejects but yaml-cpp accepts) and on the total bytes re-parsed. */
#define YAML_MAX_FIX_ROUNDS 1024
#define YAML_MAX_FIX_BYTES ((size_t)256 * 1024 * 1024)

/* YAML::Load: the first document only; *ok=false where yaml-cpp throws. */
static ynode *yload_first(yload *L, const char *text, size_t len, bool *ok) {
    memset(L, 0, sizeof *L);
    *ok = false;
    size_t skip = 0, dlen = 0;
    char *decoded = yamlcpp_decode((const unsigned char *)text, len, &skip, &dlen);
    if (decoded) {
        L->buffer = decoded;
        text = decoded;
        len = dlen;
    } else {
        text += skip;
        len -= skip;
    }
    size_t slen = 0;
    char *sanitized = yaml_sanitize(text, len, &slen);
    if (sanitized) {
        free(L->buffer);
        L->buffer = sanitized;
        L->sanitized = true;
        text = sanitized;
        len = slen;
    }
    size_t work = 0;
    for (int round = 0;; ++round) {
        ynode *root = yload_attempt(L, text, len, ok);
        if (*ok) return root;
        work += len;
        if (round == YAML_MAX_FIX_ROUNDS || work > YAML_MAX_FIX_BYTES) return NULL;
        const yaml_parser_t *p = &L->parser;
        size_t flen = 0;
        char *fixed = quote_escape_fix(p, text, len, &flen);
        if (!fixed) fixed = flow_colon_fix(L, text, len, &flen);
        if (!fixed) fixed = unterminated_quote_fix(p, text, len, &flen);
        if (!fixed) fixed = empty_key_fix(p, text, len, &flen);
        if (!fixed) fixed = tab_fix(p, text, len, &flen);
        if (!fixed) fixed = anchor_fix(p, text, len, &flen);
        if (!fixed) fixed = trailing_key_fix(L, text, len, &flen);
        if (!fixed) return NULL;
        yload_clear(L);
        free(L->fixed);
        L->fixed = fixed;
        text = fixed;
        len = flen;
    }
}

/* Conversion limits: yaml-cpp's yaml_to_json recursed through alias cycles
 * (crashing) and expanded shared aliases exponentially; the C loader instead
 * yields null for a cycle and stops expanding past these bounds. */
#define YAML_CONVERT_BUDGET 2000000
#define YAML_CONVERT_DEPTH 1000

static sbj *yaml_to_json(ynode *n, size_t *budget, int depth) {
    if (*budget == 0 || n->visiting || depth > YAML_CONVERT_DEPTH) return sbj_null();
    --*budget;
    switch (n->kind) {
    case Y_SCALAR: return sbj_strn(n->s, n->slen);
    case Y_SEQ: {
        n->visiting = true;
        sbj *a = sbj_array();
        for (size_t i = 0; i < n->n; ++i) sbj_arr_push(a, yaml_to_json(n->items[i], budget, depth + 1));
        n->visiting = false;
        return a;
    }
    case Y_MAP: {
        n->visiting = true;
        sbj *o = sbj_object();
        for (size_t i = 0; i + 1 < n->n; i += 2) {
            const ynode *k = n->items[i];
            /* sbj keys are C strings: a key containing NUL cannot be kept. */
            if (k->kind == Y_SCALAR && !memchr(k->s, '\0', k->slen))
                sbj_set(o, k->s, yaml_to_json(n->items[i + 1], budget, depth + 1));
        }
        n->visiting = false;
        return o;
    }
    default: return sbj_null();
    }
}

/* ---- Clash proxies ------------------------------------------------------ */
/* Values are handled as (pointer, length) strings so embedded NULs compare
 * and copy exactly as std::string did. */

/* string_value(): true and a malloc'd copy, or false for std::nullopt. */
static bool string_value(const sbj *v, const char *field, str *out) {
    const sbj *f = sbj_get(v, field);
    if (!f || f->type == SBJ_NULL) return false;
    if (f->type == SBJ_STRING) {
        *out = str_from((sv){f->v.str.ptr, f->v.str.len});
        return true;
    }
    if (f->type == SBJ_BOOL) {
        *out = str_from(sv_of(f->v.b ? "true" : "false"));
        return true;
    }
    if (sbj_is_number(f)) {
        char *d = sbj_dump(f, -1);
        *out = (str){d, strlen(d)};
        return true;
    }
    return false;
}

static str string_value_or(const sbj *v, const char *field, const char *fallback) {
    str s;
    if (!string_value(v, field, &s)) s = str_from(sv_of(fallback));
    return s;
}

static sbj *sbj_take_str(str *s) {
    sbj *j = sbj_strn(s->p, s->n);
    str_free(s);
    return j;
}

static bool integer_value(const sbj *v, const char *field, int64_t *out) {
    const sbj *f = sbj_get(v, field);
    if (!f) return false;
    if (f->type == SBJ_INT) {
        *out = f->v.i;
        return true;
    }
    if (f->type == SBJ_UINT) {
        *out = (int64_t)f->v.u; /* nlohmann get<int64_t> */
        return true;
    }
    if (f->type == SBJ_STRING) { /* std::from_chars<int64_t>: optional '-', digits */
        const char *s = f->v.str.ptr;
        size_t n = f->v.str.len, i = 0;
        bool neg = false;
        if (n && s[0] == '-') {
            neg = true;
            i = 1;
        }
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

static bool ascii_ieq(sv v, const char *lower) {
    size_t n = strlen(lower);
    if (v.n != n) return false;
    for (size_t i = 0; i < n; ++i) {
        char c = v.p[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != lower[i]) return false;
    }
    return true;
}

static bool boolean_value(const sbj *v, const char *field) {
    const sbj *f = sbj_get(v, field);
    if (!f) return false;
    if (f->type == SBJ_BOOL) return f->v.b;
    if (f->type == SBJ_STRING) {
        sv s = {f->v.str.ptr, f->v.str.len};
        return ascii_ieq(s, "true") || sv_eq(s, "1");
    }
    return false;
}

static sbj *clash_transport(const sbj *proxy) {
    str network = string_value_or(proxy, "network", "");
    sv net = sv_str(&network);
    sbj *t = NULL;
    if (sv_eq(net, "ws")) {
        t = sbj_object();
        sbj_set_str(t, "type", "ws");
        const sbj *opts = sbj_get(proxy, "ws-opts");
        if (sbj_is_object(opts)) {
            if (sbj_has(opts, "path")) sbj_set(t, "path", sbj_clone(sbj_get(opts, "path")));
            if (sbj_has(opts, "headers")) sbj_set(t, "headers", sbj_clone(sbj_get(opts, "headers")));
        } else {
            str path;
            if (string_value(proxy, "ws-path", &path)) sbj_set(t, "path", sbj_take_str(&path));
        }
    } else if (sv_eq(net, "grpc")) {
        t = sbj_object();
        sbj_set_str(t, "type", "grpc");
        const sbj *opts = sbj_get(proxy, "grpc-opts");
        str name;
        if (sbj_is_object(opts) && string_value(opts, "grpc-service-name", &name))
            sbj_set(t, "service_name", sbj_take_str(&name));
    } else if (sv_eq(net, "h2") || sv_eq(net, "http")) {
        t = sbj_object();
        sbj_set_str(t, "type", "http");
        const sbj *opts = sbj_get(proxy, sv_eq(net, "h2") ? "h2-opts" : "http-opts");
        if (sbj_is_object(opts)) {
            if (sbj_has(opts, "host")) sbj_set(t, "host", sbj_clone(sbj_get(opts, "host")));
            const sbj *path = sbj_get(opts, "path");
            if (sbj_is_array(path) && sbj_arr_len(path) > 0)
                sbj_set(t, "path", sbj_clone(sbj_arr_at(path, 0)));
            else if (sbj_is_string(path))
                sbj_set(t, "path", sbj_clone(path));
        }
    }
    str_free(&network);
    return t;
}

static sbj *clash_tls(const sbj *proxy, bool enabled) {
    if (!enabled) return NULL;
    sbj *tls = sbj_object();
    sbj_set_bool(tls, "enabled", true);
    str sni;
    bool have = string_value(proxy, "sni", &sni);
    if (!have || sni.n == 0) {
        if (have) str_free(&sni);
        have = string_value(proxy, "servername", &sni);
    }
    if (have && sni.n) sbj_set(tls, "server_name", sbj_take_str(&sni));
    else if (have) str_free(&sni);
    if (boolean_value(proxy, "skip-cert-verify")) sbj_set_bool(tls, "insecure", true);
    const sbj *alpn = sbj_get(proxy, "alpn");
    if (sbj_is_array(alpn))
        sbj_set(tls, "alpn", sbj_clone(alpn));
    else if (sbj_is_string(alpn))
        sbj_set(tls, "alpn", split_alpn((sv){alpn->v.str.ptr, alpn->v.str.len}));
    str fp;
    if (string_value(proxy, "client-fingerprint", &fp)) {
        if (fp.n) sbj_set(tls, "utls", utls(sbj_take_str(&fp)));
        else str_free(&fp);
    }
    const sbj *reality = sbj_get(proxy, "reality-opts");
    if (sbj_is_object(reality)) {
        sbj *r = sbj_object();
        sbj_set_bool(r, "enabled", true);
        str key, id;
        if (string_value(reality, "public-key", &key)) sbj_set(r, "public_key", sbj_take_str(&key));
        if (string_value(reality, "short-id", &id)) sbj_set(r, "short_id", sbj_take_str(&id));
        sbj_set(tls, "reality", r);
        if (!sbj_has(tls, "utls")) sbj_set(tls, "utls", utls(sbj_str("chrome")));
    }
    return tls;
}

static void set_opt(sbj *config, const char *key, sbj *value) {
    if (value) sbj_set(config, key, value);
}

static void set_str(sbj *config, const char *key, str s) {
    sbj_set(config, key, sbj_take_str(&s));
}

static int clash_proxy(const sbj *proxy, sb_parsed_node *out) {
    if (!sbj_is_object(proxy)) return 0;
    str raw_type = string_value_or(proxy, "type", "");
    sv t = sv_str(&raw_type);
    const char *type = NULL; /* clash_type(), for the supported types */
    if (sv_eq(t, "ss") || sv_eq(t, "shadowsocks")) type = "shadowsocks";
    else if (sv_eq(t, "hy2") || sv_eq(t, "hysteria2")) type = "hysteria2";
    else if (sv_eq(t, "vmess")) type = "vmess";
    else if (sv_eq(t, "vless")) type = "vless";
    else if (sv_eq(t, "trojan")) type = "trojan";
    else if (sv_eq(t, "tuic")) type = "tuic";
    else if (sv_eq(t, "http")) type = "http";
    str server = string_value_or(proxy, "server", "");
    int64_t raw_port = 0;
    if (!integer_value(proxy, "port", &raw_port)) raw_port = 0;
    int result = 0;
    str tag = {0};
    sbj *config = NULL;
    if (server.n == 0 || raw_port <= 0 || raw_port > 65535) goto done;
    uint16_t port = (uint16_t)raw_port;
    tag = string_value_or(proxy, "name", "");
    if (tag.n == 0) {
        sb_buf b = {0};
        sb_buf_append(&b, server.p, server.n);
        sb_buf_printf(&b, ":%u", (unsigned)port);
        str_free(&tag);
        tag.n = b.len;
        tag.p = sb_buf_detach(&b);
    }
    if (!type) goto done;

    config = sbj_object();
    if (!strcmp(type, "shadowsocks")) {
        set_str(config, "method", string_value_or(proxy, "cipher", ""));
        set_str(config, "password", string_value_or(proxy, "password", ""));
    } else if (!strcmp(type, "vmess")) {
        set_str(config, "uuid", string_value_or(proxy, "uuid", ""));
        int64_t aid;
        if (!integer_value(proxy, "alterId", &aid) && !integer_value(proxy, "alterid", &aid)) aid = 0;
        sbj_set_int(config, "alter_id", aid);
        set_str(config, "security", string_value_or(proxy, "cipher", "auto"));
        set_opt(config, "transport", clash_transport(proxy));
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls")));
    } else if (!strcmp(type, "vless")) {
        set_str(config, "uuid", string_value_or(proxy, "uuid", ""));
        set_str(config, "flow", string_value_or(proxy, "flow", ""));
        sbj_set_str(config, "packet_encoding", "xudp");
        set_opt(config, "transport", clash_transport(proxy));
        bool reality = sbj_has(proxy, "reality-opts");
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls") || reality));
    } else if (!strcmp(type, "trojan")) {
        set_str(config, "password", string_value_or(proxy, "password", ""));
        set_opt(config, "transport", clash_transport(proxy));
        sbj_set(config, "tls", clash_tls(proxy, true));
    } else if (!strcmp(type, "hysteria2")) {
        str password = string_value_or(proxy, "password", "");
        if (password.n == 0) {
            str_free(&password);
            password = string_value_or(proxy, "auth", "");
        }
        if (password.n == 0) {
            str_free(&password);
            password = string_value_or(proxy, "auth-str", "");
        }
        set_str(config, "password", password);
        sbj_set(config, "tls", clash_tls(proxy, true));
        str obfs;
        if (string_value(proxy, "obfs", &obfs)) {
            if (obfs.n) {
                sbj *o = sbj_object();
                sbj_set(o, "type", sbj_take_str(&obfs));
                str pw;
                if (string_value(proxy, "obfs-password", &pw)) sbj_set(o, "password", sbj_take_str(&pw));
                sbj_set(config, "obfs", o);
            } else {
                str_free(&obfs);
            }
        }
    } else if (!strcmp(type, "tuic")) {
        set_str(config, "uuid", string_value_or(proxy, "uuid", ""));
        set_str(config, "password", string_value_or(proxy, "password", ""));
        set_str(config, "congestion_control", string_value_or(proxy, "congestion-controller", "bbr"));
        set_str(config, "udp_relay_mode", string_value_or(proxy, "udp-relay-mode", "native"));
        sbj_set(config, "tls", clash_tls(proxy, true));
    } else { /* http */
        str user, pw;
        if (string_value(proxy, "username", &user)) {
            if (user.n) sbj_set(config, "username", sbj_take_str(&user));
            else str_free(&user);
        }
        if (string_value(proxy, "password", &pw)) {
            if (pw.n) sbj_set(config, "password", sbj_take_str(&pw));
            else str_free(&pw);
        }
        set_opt(config, "tls", clash_tls(proxy, boolean_value(proxy, "tls")));
    }
    result = finish_node(out, type, sv_str(&tag), sv_str(&server), port, config, true);
    config = NULL;
done:
    sbj_free(config);
    str_free(&tag);
    str_free(&server);
    str_free(&raw_type);
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
        ynode *proxies = NULL; /* yaml["proxies"]: the first matching key */
        for (size_t i = 0; i + 1 < root->n; i += 2) {
            const ynode *k = root->items[i];
            if (k->kind == Y_SCALAR && k->slen == 7 && !memcmp(k->s, "proxies", 7)) {
                proxies = root->items[i + 1];
                break;
            }
        }
        if (proxies && proxies->kind == Y_SEQ && proxies->n > 0) {
            handled = 1;
            size_t budget = YAML_CONVERT_BUDGET;
            proxies->visiting = true;
            for (size_t i = 0; i < proxies->n; ++i) {
                sbj *proxy = yaml_to_json(proxies->items[i], &budget, 1);
                sb_parsed_node node;
                sb_parsed_node_init(&node);
                if (clash_proxy(proxy, &node)) vec_push_move(out, &node);
                else sb_parsed_node_free(&node);
                sbj_free(proxy);
            }
            proxies->visiting = false;
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
