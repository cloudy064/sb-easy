/* Panel HTTP server core: port of the framework parts of
 * cpp/src/http_server.cpp (register_http_routes / run_http_server) on top of
 * civetweb, reproducing the Drogon behaviours the C++ server relies on.
 * See http_internal.h for the contract shared with the route groups. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "civetweb.h"
#include "http_internal.h"
#include "http_wire.h"
#include "sb/clash_client.h"
#include "sb/config_etag.h"
#include "sb/config_renderer.h"
#include "sb/singbox_supervisor.h"
#include "sb/subscription_fetcher.h"
#include "sb/subscription_service.h"
#include "sb/observability.h"
#include "sb/proxy_runtime.h"
#include "sb/proxy_users.h"
#include "sb/wireguard.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

/* ---- options ---------------------------------------------------------- */

void sb_http_server_options_init(sb_http_server_options *o) {
    memset(o, 0, sizeof *o);
    o->address = sb_strdup("127.0.0.1");
    o->port = 51821;
    o->threads = 1;
    o->public_server = sb_strdup("");
    o->config_hash_seed = sb_strdup("");
    o->legacy_agent_token = sb_strdup("");
    o->jwt_secret = sb_strdup("");
    o->admin_password = sb_strdup("admin");
    o->clash_api_url = sb_strdup("http://127.0.0.1:9090");
    o->clash_api_secret = sb_strdup("");
    o->subscription_auto_refresh = true;
    o->singbox_managed = false;
    o->singbox_binary = sb_strdup("sing-box");
    o->self_singbox_config_path = sb_strdup("");
    o->self_singbox_interval_seconds = 10;
    o->singbox_validate_config = true;
    o->wireguard_enabled = false;
    o->wireguard_interface = sb_strdup("wg0");
    o->wireguard_port = 51820;
    o->wireguard_address = sb_strdup("10.59.32.1/24");
    o->wireguard_dns = sb_strdup("10.59.32.1");
    o->wireguard_mtu = 1420;
    o->wireguard_egress = sb_strdup("eth0");
    o->external_hostname = sb_strdup("127.0.0.1");
    o->wireguard_config_directory = sb_strdup("/etc/wireguard");
    o->static_directory = sb_strdup("frontend/dist");
    o->cors_origins = sb_strdup("");
    o->log_level = sb_strdup("info");
}

void sb_http_server_options_free(sb_http_server_options *o) {
    if (!o) return;
    free(o->address);
    free(o->public_server);
    free(o->config_hash_seed);
    free(o->legacy_agent_token);
    free(o->jwt_secret);
    free(o->admin_password);
    free(o->clash_api_url);
    free(o->clash_api_secret);
    free(o->singbox_binary);
    free(o->self_singbox_config_path);
    free(o->wireguard_interface);
    free(o->wireguard_address);
    free(o->wireguard_dns);
    free(o->wireguard_egress);
    free(o->external_hostname);
    free(o->wireguard_config_directory);
    free(o->static_directory);
    free(o->cors_origins);
    free(o->log_level);
    memset(o, 0, sizeof *o);
}

/* NULL members of src become "" so every copied member is non-NULL. */
static char *opt_dup(const char *s) { return sb_strdup(s ? s : ""); }

void sb_http_server_options_copy(sb_http_server_options *dst, const sb_http_server_options *src) {
    sb_http_server_options tmp = *src;
    tmp.address = opt_dup(src->address);
    tmp.public_server = opt_dup(src->public_server);
    tmp.config_hash_seed = opt_dup(src->config_hash_seed);
    tmp.legacy_agent_token = opt_dup(src->legacy_agent_token);
    tmp.jwt_secret = opt_dup(src->jwt_secret);
    tmp.admin_password = opt_dup(src->admin_password);
    tmp.clash_api_url = opt_dup(src->clash_api_url);
    tmp.clash_api_secret = opt_dup(src->clash_api_secret);
    tmp.singbox_binary = opt_dup(src->singbox_binary);
    tmp.self_singbox_config_path = opt_dup(src->self_singbox_config_path);
    tmp.wireguard_interface = opt_dup(src->wireguard_interface);
    tmp.wireguard_address = opt_dup(src->wireguard_address);
    tmp.wireguard_dns = opt_dup(src->wireguard_dns);
    tmp.wireguard_egress = opt_dup(src->wireguard_egress);
    tmp.external_hostname = opt_dup(src->external_hostname);
    tmp.wireguard_config_directory = opt_dup(src->wireguard_config_directory);
    tmp.static_directory = opt_dup(src->static_directory);
    tmp.cors_origins = opt_dup(src->cors_origins);
    tmp.log_level = opt_dup(src->log_level);
    *dst = tmp;
}

/* ---- small helpers (C++ anonymous namespace) -------------------------- */

static bool is_space(unsigned char c) { return isspace(c) != 0; }

char *sb_http_trim(const char *s) {
    return sb_http_trim_n(s, s ? strlen(s) : 0, NULL);
}

char *sb_http_trim_n(const char *s, size_t len, size_t *out_len) {
    if (!s) { s = ""; len = 0; }
    size_t start = 0, end = len;
    while (start < end && is_space((unsigned char)s[start])) ++start;
    while (end > start && is_space((unsigned char)s[end - 1])) --end;
    if (out_len) *out_len = end - start;
    return sb_strndup(s + start, end - start);
}

char *sb_http_trim_trailing_slashes(const char *s) {
    char *v = sb_http_trim(s);
    size_t n = strlen(v);
    while (n > 0 && v[n - 1] == '/') v[--n] = '\0';
    return v;
}

char *sb_http_clash_controller_address(const char *url) {
    char *v = sb_http_trim_trailing_slashes(url);
    static const char *const prefixes[] = {"https://", "http://", "wss://", "ws://"};
    for (size_t i = 0; i < sizeof prefixes / sizeof prefixes[0]; ++i) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(v, prefixes[i], n) == 0) {
            memmove(v, v + n, strlen(v + n) + 1);
            break;
        }
    }
    return v;
}

char *sb_http_encode_component(const char *s) {
    return sb_http_encode_component_n(s, s ? strlen(s) : 0);
}

char *sb_http_encode_component_n(const char *s, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    sb_buf b = {0};
    for (const unsigned char *p = (const unsigned char *)s; len; ++p, --len) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            sb_buf_putc(&b, (char)*p);
        } else {
            char enc[3] = {'%', hex[*p >> 4], hex[*p & 0x0f]};
            sb_buf_append(&b, enc, 3);
        }
    }
    return sb_buf_detach(&b);
}

char *sb_http_secure_token(size_t bytes) {
    if (bytes == 0) return NULL;
    unsigned char *random = sb_xmalloc(bytes);
    if (sb_random_bytes(random, bytes) != 0) {
        free(random);
        return NULL;
    }
    char *hex = sb_hex_encode(random, bytes);
    free(random);
    return hex;
}

char *sb_http_utc_now(void) {
    time_t now = time(NULL);
    struct tm utc;
    if (!gmtime_r(&now, &utc)) return NULL;
    char buf[32];
    strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &utc);
    return sb_strdup(buf);
}

char *sb_http_truncate_utf8(const char *s, size_t max_bytes) {
    size_t len = s ? strlen(s) : 0;
    if (len <= max_bytes) return sb_strndup(s ? s : "", len);
    size_t end = max_bytes;
    while (end > 0 && (((unsigned char)s[end]) & 0xc0u) == 0x80u) --end;
    return sb_strndup(s, end);
}

/* ---- response helpers ------------------------------------------------- */

void sb_resp_json(sb_http_resp *resp, int status, sbj *body) {
    resp->status = status;
    sbj_free(resp->json);
    resp->json = body;
}

void sb_resp_error(sb_http_resp *resp, int status, const char *message) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", message ? message : "");
    sb_resp_json(resp, status, body);
}

void sb_resp_text(sb_http_resp *resp, int status, const char *content_type, char *body, size_t len) {
    resp->status = status;
    sbj_free(resp->json);
    resp->json = NULL;
    free(resp->body);
    resp->body = body;
    resp->body_len = body ? len : 0;
    sb_str_set(&resp->content_type, content_type);
}

void sb_resp_header(sb_http_resp *resp, const char *name, const char *value) {
    sb_resp_header_n(resp, name, value, value ? strlen(value) : 0);
}

void sb_resp_header_n(sb_http_resp *resp, const char *name, const char *value, size_t len) {
    if (!resp->headers) resp->headers = sbj_array();
    sbj *header = sbj_object();
    sbj_set_str(header, "name", name);
    sbj_set(header, "value", sbj_strn(value ? value : "", value ? len : 0));
    sbj_arr_push(resp->headers, header);
}

void sb_resp_attachment(sb_http_resp *resp, const char *name, size_t len, const char *suffix) {
    sb_buf value = {0};
    sb_buf_puts(&value, "attachment; filename=\"");
    for (size_t i = 0; i < len; ++i) sb_buf_putc(&value, name[i] == ' ' ? '_' : name[i]);
    sb_buf_puts(&value, suffix);
    sb_buf_putc(&value, '"');
    sb_resp_header_n(resp, "Content-Disposition", value.p, value.len);
    sb_buf_free(&value);
}

/* ---- per-request state -------------------------------------------------- */

#define SB_HTTP_MAX_BODY (1024u * 1024u) /* Drogon's default client_max_body_size */

/* Drogon utils::urlDecode: '+' -> ' ', "%XX" -> byte, anything else kept. */
static char *drogon_url_decode(const char *s, size_t len, size_t *out_len) {
    char *out = sb_xmalloc(len + 1);
    size_t o = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '+') {
            out[o++] = ' ';
        } else if (c == '%' && i + 2 < len && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            char hex[3] = {s[i + 1], s[i + 2], 0};
            out[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    if (out_len) *out_len = o;
    return out;
}

/* ---- request helpers -------------------------------------------------- */

const char *sb_req_header(const sb_http_req *req, const char *name) {
    const http_exchange *ex = exchange_of(req);
    if (ex) {
        for (size_t i = 0; i < ex->header_count; ++i)
            if (strcasecmp(ex->header_names[i], name) == 0) return ex->header_values[i];
        return NULL;
    }
    return (req && req->conn) ? mg_get_header(req->conn, name) : NULL;
}

/* One pass of HttpRequestImpl::parseParameters() over `input` for `name`:
 * "k=v" pairs assign (last wins), a bare "k" only creates an empty value. */
static void scan_parameters(const char *input, size_t len, const char *name, char **value) {
    size_t pos = 0;
    while (pos < len && (input[pos] == '?' || isspace((unsigned char)input[pos]))) ++pos;
    while (pos <= len) {
        const char *amp = memchr(input + pos, '&', len - pos);
        size_t end = amp ? (size_t)(amp - input) : len;
        if (!amp && end == pos) break;
        const char *pair = input + pos;
        size_t pair_len = end - pos;
        const char *eq = memchr(pair, '=', pair_len);
        if (eq) {
            const char *key = pair;
            size_t key_len = (size_t)(eq - pair);
            while (key_len > 0 && isspace((unsigned char)*key)) {
                ++key;
                --key_len;
            }
            char *decoded_key = drogon_url_decode(key, key_len, NULL);
            if (strcmp(decoded_key, name) == 0) {
                free(*value);
                *value = drogon_url_decode(eq + 1, pair_len - key_len - (size_t)(key - pair) - 1, NULL);
            }
            free(decoded_key);
        } else {
            char *decoded_key = drogon_url_decode(pair, pair_len, NULL);
            if (strcmp(decoded_key, name) == 0 && !*value) *value = sb_strdup("");
            free(decoded_key);
        }
        if (!amp) break;
        pos = end + 1;
    }
}

char *sb_req_query_param(const sb_http_req *req, const char *name) {
    if (!req || !name) return NULL;
    char *value = NULL;
    const http_exchange *ex = exchange_of(req);
    const char *query = ex ? ex->query : req->query;
    if (query) scan_parameters(query, strlen(query), name, &value);
    /* Drogon also parses urlencoded bodies (or bodies without a type). */
    if (req->body && req->body_len > 0) {
        const char *type = sb_req_header(req, "content-type");
        char *lowered = ascii_lower_dup(type ? type : "", strlen(type ? type : ""));
        if (!*lowered || strstr(lowered, "application/x-www-form-urlencoded"))
            scan_parameters(req->body, req->body_len, name, &value);
        free(lowered);
    }
    return value;
}

sbj *sb_req_json_object(const sb_http_req *req, sb_err *err) {
    sbj *body = sbj_parse(req->body, req->body_len, NULL, 0);
    if (!sbj_is_object(body)) {
        sbj_free(body);
        sb_fail(err, SB_ERR_VALIDATION, "Request body must be a JSON object");
        return NULL;
    }
    return body;
}

const char *sb_json_required_string(const sbj *body, const char *field, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!sbj_is_string(found) || found->v.str.len == 0) {
        sb_fail(err, SB_ERR_VALIDATION, "%s must be a non-empty string", field);
        return NULL;
    }
    return found->v.str.ptr;
}

const sbj *sb_json_required_object(const sbj *body, const char *field, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!sbj_is_object(found)) {
        sb_fail(err, SB_ERR_VALIDATION, "%s must be a JSON object", field);
        return NULL;
    }
    return found;
}

int sb_json_assign_string(const sbj *body, const char *field, char **dest, sb_err *err) {
    return sb_json_assign_string_n(body, field, dest, NULL, err);
}

int sb_json_assign_string_n(const sbj *body, const char *field, char **dest, size_t *dest_len,
                             sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) return 0;
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    sb_str_setn(dest, found->v.str.ptr, found->v.str.len);
    if (dest_len) *dest_len = found->v.str.len;
    return 0;
}

int sb_json_assign_bool(const sbj *body, const char *field, bool *dest, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) return 0;
    if (!sbj_is_bool(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a boolean", field);
    *dest = found->v.b;
    return 0;
}

int sb_json_required_string_array(const sbj *body, const char *field, sb_strvec *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!sbj_is_array(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an array", field);
    sb_strvec values = {0};
    const sbj *item;
    SBJ_ARR_FOREACH(found, i, item) {
        if (!sbj_is_string(item)) {
            sb_strvec_free(&values);
            return sb_fail(err, SB_ERR_VALIDATION, "%s must contain only strings", field);
        }
        sb_strvec_push(&values, item->v.str.ptr);
    }
    sb_strvec_free(out);
    *out = values;
    return 0;
}

int sb_json_integer_field(const sbj *body, const char *field, int64_t *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found) {
        *out = 0;
        return 0;
    }
    if (!sbj_is_integer(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an integer", field);
    *out = found->type == SBJ_UINT ? (int64_t)found->v.u : found->v.i;
    return 0;
}

const sb_auth_claims *sb_req_claims(const sb_http_req *req, sb_err *err) {
    if (!req || !req->claims) {
        sb_fail(err, SB_ERR_AUTH, "Invalid or expired token");
        return NULL;
    }
    return req->claims;
}

int sb_require_admin(const sb_http_req *req, sb_err *err) {
    if (!req || !req->claims) return sb_fail(err, SB_ERR_AUTH, "Invalid or expired token");
    if (!sb_streq(req->claims->role, "admin")) return sb_fail(err, SB_ERR_FORBIDDEN, "Admin role required");
    return 0;
}

/* ---- store lookups ---------------------------------------------------- */

int sb_http_require_host(sb_http_server *srv, const char *id, sb_host *out, sb_err *err) {
    int rc = sb_store_find_host(srv->store, id ? id : "", out, err);
    if (rc < 0) return -1;
    if (rc == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    return 0;
}

int sb_http_require_profile(sb_http_server *srv, const char *id, sb_config_profile *out, sb_err *err) {
    int rc = sb_store_find_profile(srv->store, id ? id : "", out, err);
    if (rc < 0) return -1;
    if (rc == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Profile not found");
    return 0;
}

int sb_http_require_proxy(sb_http_server *srv, const char *id, sb_proxy_record *out, sb_err *err) {
    int rc = sb_store_find_proxy_node(srv->store, id ? id : "", out, err);
    if (rc < 0) return -1;
    if (rc == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Node not found");
    return 0;
}

void sb_http_sync_wireguard_best_effort(sb_http_server *srv) {
    sb_err e = {0};
    if (srv->wireguard && sb_wireguard_sync(srv->wireguard, &e) != 0) SB_ERROR("WireGuard sync failed: %s", e.msg);
}

/* civetweb connection tuning; times in milliseconds, sizes in bytes. */
#define SB_HTTP_KEEP_ALIVE_TIMEOUT_MS "15000"
#define SB_HTTP_REQUEST_TIMEOUT_MS "60000"
#define SB_HTTP_MAX_REQUEST_BYTES "131072"
/* ---- methods ----------------------------------------------------------- */

static const char *const method_names[M_COUNT] = {"GET",   "POST", "HEAD", "PUT",   "DELETE",  "OPTIONS",
                                                  "PATCH", "COPY", "MOVE", "MKCOL", "PROPFIND"};

static int method_index(const char *name, size_t len) {
    for (int i = 0; i < M_COUNT; ++i)
        if (strlen(method_names[i]) == len && memcmp(method_names[i], name, len) == 0) return i;
    return -1;
}

/* safe_method(): GET, HEAD and OPTIONS (HEAD is routed as GET, like Drogon). */
static bool safe_method(int method) { return method == M_GET || method == M_HEAD || method == M_OPTIONS; }

/* ---- router ------------------------------------------------------------ */

/* Mirrors Drogon's HttpControllersRouter for registerHandler(): paths without
 * {param} live in a case-insensitive exact map (a hit with an unregistered
 * method is 405), parameterised paths are tried in registration order and
 * only match when they have a handler for the request method (regex routes
 * compiled with icase; {param} is "([^/]*)", possibly empty). */
typedef struct {
    char *pattern;       /* first registration, as given */
    char *key;           /* exact: lowercased path; parameterised: {x} -> {} */
    bool parameterised;
    sb_strvec segments;  /* pattern split on '/' ("{...}" marks a parameter) */
    sb_http_handler handlers[M_COUNT];
} route_item;

typedef struct {
    pthread_rwlock_t lock;
    route_item *items;
    size_t len, cap;
} router;

static bool segment_is_param(const char *segment) {
    size_t n = strlen(segment);
    return n >= 2 && segment[0] == '{' && segment[n - 1] == '}';
}

static router *router_of(sb_http_server *srv) { return (router *)srv->routes; }

void sb_http_route(sb_http_server *srv, const char *methods, const char *pattern,
                   sb_http_handler handler) {
    if (!srv || !pattern || !handler) return;
    router *r = router_of(srv);
    sb_strvec segments = sb_split(pattern[0] == '/' ? pattern + 1 : pattern, '/');
    bool parameterised = false;
    sb_buf key = {0};
    for (size_t i = 0; i < segments.len; ++i) {
        sb_buf_putc(&key, '/');
        if (segment_is_param(segments.items[i])) {
            parameterised = true;
            sb_buf_puts(&key, "{}");
        } else {
            sb_buf_puts(&key, segments.items[i]);
        }
    }
    char *key_text = sb_buf_detach(&key);
    if (!parameterised) {
        char *lowered = ascii_lower_dup(key_text, strlen(key_text));
        free(key_text);
        key_text = lowered;
    }

    pthread_rwlock_wrlock(&r->lock);
    route_item *item = NULL;
    for (size_t i = 0; i < r->len && !item; ++i)
        if (r->items[i].parameterised == parameterised && strcmp(r->items[i].key, key_text) == 0) item = &r->items[i];
    if (!item) {
        if (r->len == r->cap) {
            r->cap = r->cap ? r->cap * 2 : 64;
            r->items = sb_xrealloc(r->items, r->cap * sizeof *r->items);
        }
        item = &r->items[r->len++];
        memset(item, 0, sizeof *item);
        item->pattern = sb_strdup(pattern);
        item->key = key_text;
        key_text = NULL;
        item->parameterised = parameterised;
        item->segments = segments;
        segments = (sb_strvec){0};
    }
    sb_strvec list = sb_split(methods ? methods : "", ',');
    for (size_t i = 0; i < list.len; ++i) {
        char *name = sb_http_trim(list.items[i]);
        for (char *p = name; *p; ++p) *p = (char)toupper((unsigned char)*p);
        int m = method_index(name, strlen(name));
        if (m >= 0) item->handlers[m] = handler; /* later registrations win, as in Drogon */
        else SB_ERROR("sb_http_route: unknown method '%s' for %s", name, pattern);
        free(name);
    }
    srv->route_count = r->len;
    srv->route_cap = r->cap;
    pthread_rwlock_unlock(&r->lock);
    sb_strvec_free(&list);
    sb_strvec_free(&segments);
    free(key_text);
}

typedef enum { ROUTE_NOT_FOUND, ROUTE_FOUND, ROUTE_METHOD_NOT_ALLOWED } route_result;

/* Looks the decoded path up. On ROUTE_FOUND *handler is set and the
 * parameter values (malloc'd) are appended to params. */
static route_result router_lookup(sb_http_server *srv, const char *path, int method, sb_http_handler *handler,
                                  char **params, size_t *param_count) {
    router *r = router_of(srv);
    route_result result = ROUTE_NOT_FOUND;
    char *lowered = ascii_lower_dup(path, strlen(path));
    sb_strvec parts = sb_split(path[0] == '/' ? path + 1 : path, '/');
    pthread_rwlock_rdlock(&r->lock);
    for (size_t i = 0; i < r->len; ++i) {
        const route_item *item = &r->items[i];
        if (item->parameterised || strcmp(item->key, lowered) != 0) continue;
        if (item->handlers[method]) {
            *handler = item->handlers[method];
            result = ROUTE_FOUND;
        } else {
            result = ROUTE_METHOD_NOT_ALLOWED;
        }
        break;
    }
    if (result == ROUTE_NOT_FOUND && path[0] == '/') {
        for (size_t i = 0; i < r->len && result == ROUTE_NOT_FOUND; ++i) {
            const route_item *item = &r->items[i];
            if (!item->parameterised || !item->handlers[method] || item->segments.len != parts.len) continue;
            bool match = true;
            for (size_t s = 0; s < parts.len && match; ++s)
                if (!segment_is_param(item->segments.items[s]) &&
                    strcasecmp(item->segments.items[s], parts.items[s]) != 0)
                    match = false;
            if (!match) continue;
            *param_count = 0;
            for (size_t s = 0; s < parts.len; ++s)
                if (segment_is_param(item->segments.items[s]) && *param_count < 8)
                    params[(*param_count)++] = sb_strdup(parts.items[s]);
            *handler = item->handlers[method];
            result = ROUTE_FOUND;
        }
    }
    pthread_rwlock_unlock(&r->lock);
    sb_strvec_free(&parts);
    free(lowered);
    return result;
}

static void router_free(router *r) {
    if (!r) return;
    for (size_t i = 0; i < r->len; ++i) {
        free(r->items[i].pattern);
        free(r->items[i].key);
        sb_strvec_free(&r->items[i].segments);
    }
    free(r->items);
    pthread_rwlock_destroy(&r->lock);
    free(r);
}

/* ---- wire responses ---------------------------------------------------- */

static const char *status_reason(int status) {
    switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "Non-Authoritative Information";
    case 204: return "No Content";
    case 205: return "Reset Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 408: return "Request Time-out";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Request Entity Too Large";
    case 414: return "Request-URI Too Large";
    case 415: return "Unsupported Media Type";
    case 416: return "Requested Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Time-out";
    case 505: return "HTTP Version Not Supported";
    default: return "Unknown";
    }
}

static bool content_length_allowed(int status) { return (status >= 200 || status < 100) && status != 204; }

/* ---- CORS / auth / audit advice ------------------------------------------ */

static void cors_init(sb_http_server *srv, const char *configured) {
    char *origins = sb_http_trim(configured);
    srv->cors_wildcard = !*origins || strcmp(origins, "*") == 0;
    if (!srv->cors_wildcard) {
        sb_strvec parts = sb_split(origins, ',');
        for (size_t i = 0; i < parts.len; ++i) {
            char *origin = sb_http_trim(parts.items[i]);
            if (strcmp(origin, "*") == 0) {
                free(origin);
                srv->cors_wildcard = true;
                sb_strvec_free(&srv->cors_origins);
                break;
            }
            if (*origin) sb_strvec_push_take(&srv->cors_origins, origin);
            else free(origin);
        }
        sb_strvec_free(&parts);
    }
    free(origins);
}

/* CorsPolicy::apply() (pre-sending advice and the preflight response). */
static void cors_apply(const http_exchange *ex, wire_response *w) {
    const sb_http_server *srv = ex->srv;
    const char *existing = wire_header(w, "access-control-allow-origin");
    if (existing && *existing) return;
    char *origin = sb_http_trim(sb_req_header(&ex->req, "origin"));
    if (!*origin || (!srv->cors_wildcard && !sb_strvec_contains(&srv->cors_origins, origin))) {
        free(origin);
        return;
    }
    wire_set_header(w, "Access-Control-Allow-Origin", srv->cors_wildcard ? "*" : origin);
    free(origin);
    wire_set_header(w, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    char *headers = sb_http_trim(sb_req_header(&ex->req, "access-control-request-headers"));
    wire_set_header(w, "Access-Control-Allow-Headers", *headers ? headers : "Authorization, Content-Type");
    free(headers);
    wire_set_header(w, "Access-Control-Expose-Headers",
                    "ETag, Content-Disposition, X-SB-Easy-Rule-Source, X-SB-Easy-Profile-Id, "
                    "X-SB-Easy-Profile-Name");
    wire_set_header(w, "Access-Control-Max-Age", "600");
    if (!srv->cors_wildcard) wire_set_header(w, "Vary", "Origin");
}

static bool clash_websocket_path(const char *path) {
    static const char prefix[] = "/api/sing-box/ws/";
    if (strncmp(path, prefix, sizeof prefix - 1) != 0) return false;
    const char *kind = path + sizeof prefix - 1;
    return strcmp(kind, "traffic") == 0 || strcmp(kind, "logs") == 0 || strcmp(kind, "connections") == 0 ||
           strcmp(kind, "memory") == 0;
}

static bool public_api_path(const char *path) {
    return strcmp(path, "/api/health") == 0 ||
           strcmp(path, "/api/metrics") == 0 || /* handler requires its own read-only scrape credential */
           sb_starts_with(path, "/api/proxy-self/") || /* independent proxy claim/device credentials */
           strcmp(path, "/api/devices/enroll") == 0 || strcmp(path, "/api/auth/login") == 0 ||
           strcmp(path, "/api/auth/login/mfa") == 0 || strcmp(path, "/api/auth/oidc") == 0 ||
           strcmp(path, "/api/auth/oidc/start") == 0 || strcmp(path, "/api/auth/oidc/finish") == 0 ||
           sb_starts_with(path, "/api/agent/");
}

/* bearer_token(): "Bearer " prefix (case-sensitive), trimmed, non-empty. */
static char *bearer_token(const http_exchange *ex) {
    const char *authorization = sb_req_header(&ex->req, "authorization");
    if (!authorization || strncmp(authorization, "Bearer ", 7) != 0) return NULL;
    char *token = sb_http_trim(authorization + 7);
    if (!*token) {
        free(token);
        return NULL;
    }
    return token;
}

static bool verify_into(http_exchange *ex, const char *token) {
    sb_auth_claims claims;
    memset(&claims, 0, sizeof claims);
    if (!token || !*token || !sb_auth_security_verify(ex->srv->security, token, &claims, NULL)) {
        sb_auth_claims_free(&claims);
        return false;
    }
    ex->claims = claims;
    ex->has_claims = true;
    return true;
}

/* The JWT pre-routing advice. Returns false when the request was rejected
 * (*w filled). The /api/ prefix and public-path checks use the ASCII
 * lowercased path: Drogon routes case-insensitively, and the C++ advice's
 * case-sensitive check let e.g. "GET /Api/hosts" through unauthenticated. */
static bool auth_advice(http_exchange *ex, wire_response *w) {
    if (clash_websocket_path(ex->path)) {
        char *raw = sb_req_query_param(&ex->req, "token");
        char *token = sb_http_trim(raw);
        free(raw);
        bool ok = verify_into(ex, token);
        free(token);
        if (!ok) {
            wire_error(w, 401, "Invalid or expired token");
            return false;
        }
        ex->req.claims = &ex->claims;
        sb_err error = {0};
        if (sb_http_security_authorize(&ex->req, &error) != 0) {
            wire_error(w, 403, error.msg); return false;
        }
        return true;
    }
    char *lowered = ascii_lower_dup(ex->path, strlen(ex->path));
    bool protected_path = sb_starts_with(lowered, "/api/") && !public_api_path(lowered);
    free(lowered);
    if (!protected_path) return true;
    char *token = bearer_token(ex);
    bool ok = verify_into(ex, token);
    free(token);
    if (!ok) {
        wire_error(w, 401, "Invalid or expired token");
        return false;
    }
    ex->req.claims = &ex->claims;
    sb_err error = {0};
    if (sb_http_security_authorize(&ex->req, &error) != 0) {
        wire_error(w, 403, error.msg); return false;
    }
    return true;
}

/* Post-handling advice: audit successful unsafe requests of authenticated users. */
static void audit_advice(const http_exchange *ex, int status) {
    if (safe_method(ex->method) || !ex->req.claims || status < 200 || status >= 300) return;
    sb_err e = {0};
    if (sb_store_record_audit_n(ex->srv->store, ex->claims.username, ex->claims.username_len,
                              method_names[ex->method], ex->path, &e) != 0)
        SB_ERROR("audit write failed: %s", e.msg);
}

/* ---- handler invocation --------------------------------------------------- */

static void resp_release(sb_http_resp *resp) {
    sbj_free(resp->json);
    free(resp->body);
    free(resp->content_type);
    sbj_free(resp->headers);
    free(resp->file_path);
    memset(resp, 0, sizeof *resp);
}

/* handle_response(): exception kind -> status + JSON body. */
static void map_error(const sb_err *err, wire_response *w) {
    switch (err->code) {
    case SB_ERR_AUTH: wire_error(w, 401, err->msg); break;
    case SB_ERR_UNAVAILABLE: wire_error(w, 503, err->msg); break;
    case SB_ERR_FORBIDDEN: wire_error(w, 403, err->msg); break;
    case SB_ERR_NOT_FOUND: wire_error(w, 404, err->msg); break;
    case SB_ERR_CONFLICT: wire_error(w, 409, err->msg); break;
    case SB_ERR_VALIDATION: wire_error(w, 400, err->msg); break;
    case SB_ERR_SCRIPT: {
        sbj *body = sbj_object();
        sbj_set_str(body, "error", err->msg);
        sbj_set_str(body, "kind", "rule_script");
        wire_json(w, 422, body);
        break;
    }
    case SB_ERR_BAD_JSON: {
        char *message = sb_asprintf("Invalid JSON request: %s", err->msg);
        wire_error(w, 400, message);
        free(message);
        break;
    }
    default:
        SB_ERROR("HTTP handler failed: %s", err->msg);
        wire_error(w, 500, "Internal server error");
        break;
    }
}

static void resp_to_wire(sb_http_resp *resp, wire_response *w) {
    int status = resp->status ? resp->status : 200;
    if (resp->file_path) {
        static_file_response(w, resp->file_path, resp->immutable);
    } else if (resp->json) {
        sbj *json = resp->json;
        resp->json = NULL;
        wire_json(w, status, json);
    } else {
        w->status = status;
        w->body = resp->body ? resp->body : sb_strdup("");
        w->body_len = resp->body ? resp->body_len : 0;
        resp->body = NULL;
        sb_str_set(&w->content_type, resp->content_type ? resp->content_type : "text/plain; charset=utf-8");
    }
    const sbj *header;
    SBJ_ARR_FOREACH(resp->headers, i, header) {
        char *name = sb_http_trim(sbj_get_str(header, "name", ""));
        const sbj *raw = sbj_get(header, "value");
        size_t len = 0;
        char *value = sb_http_trim_n(raw->v.str.ptr, raw->v.str.len, &len);
        if (strcasecmp(name, "content-type") == 0) sb_str_set(&w->content_type, value);
        else if (strcasecmp(name, "content-length") != 0) wire_set_header_n(w, name, value, len);
        free(name);
        free(value);
    }
}

/* Runs a routed handler plus the post-handling advice. Returns true when the
 * handler already wrote the response itself. */
static bool run_handler(http_exchange *ex, sb_http_handler handler, wire_response *w) {
    sb_http_resp resp;
    memset(&resp, 0, sizeof resp);
    resp.status = 200;
    sb_err err = {0};
    bool handled = false;
    if (handler(&ex->req, &resp, &err) != 0) {
        map_error(&err, w);
    } else if (resp.handled) {
        handled = true;
        w->status = resp.status ? resp.status : 200;
    } else {
        resp_to_wire(&resp, w);
    }
    resp_release(&resp);
    audit_advice(ex, w->status);
    return handled;
}

/* The three registerHandlerViaRegex() routes registered last by the C++
 * code (all icase; '.' does not match CR/LF). */
static bool no_line_breaks(const char *s) { return !strpbrk(s, "\r\n"); }

static int h_assets(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)err;
    const http_exchange *ex = exchange_of(req);
    const char *relative = req->path + strlen("/assets/");
    if (!safe_static_relative_path(relative, ex && ex->path_has_nul)) {
        sb_resp_error(resp, 404, "Static resource not found");
        return 0;
    }
    char *assets = sb_path_join(req->server->opts.static_directory, "assets");
    resp->file_path = sb_path_join(assets, relative);
    resp->immutable = true;
    free(assets);
    return 0;
}

/* Public branding files live beside index.html, outside Vite's hashed assets. */
static int h_public_asset(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)err;
    resp->file_path = sb_path_join(req->server->opts.static_directory, req->path + 1);
    resp->immutable = false;
    return 0;
}

static int h_api_not_found(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)req;
    (void)err;
    sb_resp_error(resp, 404, "API route not found");
    return 0;
}

static int h_spa(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)err;
    resp->file_path = sb_path_join(req->server->opts.static_directory, "index.html");
    resp->immutable = false;
    return 0;
}

static bool starts_with_ci(const char *s, const char *prefix) { return strncasecmp(s, prefix, strlen(prefix)) == 0; }

static sb_http_handler builtin_route(const http_exchange *ex) {
    const char *path = ex->path;
    if (!no_line_breaks(path)) return NULL;
    if (ex->method == M_GET && starts_with_ci(path, "/assets/")) return h_assets;
    if (ex->method == M_GET && (strcmp(path, "/sb-easy-mark.svg") == 0 || strcmp(path, "/favicon.svg") == 0))
        return h_public_asset;
    if ((ex->method == M_GET || ex->method == M_POST || ex->method == M_PUT || ex->method == M_DELETE ||
         ex->method == M_PATCH) &&
        (strcasecmp(path, "/api") == 0 || starts_with_ci(path, "/api/")))
        return h_api_not_found;
    if (ex->method == M_GET && path[0] == '/') {
        const char *rest = path + 1;
        bool excluded = strcasecmp(rest, "api") == 0 || starts_with_ci(rest, "api/") ||
                        strcasecmp(rest, "assets") == 0 || starts_with_ci(rest, "assets/") ||
                        starts_with_ci(rest, "downloads/");
        if (!excluded) return h_spa;
    }
    return NULL;
}

/* ---- request dispatch ----------------------------------------------------- */

/* Drogon's isWebSocket(): GET with Connection containing "upgrade" and
 * Upgrade == "websocket" (both lowercased). */
static bool drogon_is_websocket(const http_exchange *ex, int original_method) {
    if (original_method != M_GET) return false;
    const char *upgrade = sb_req_header(&ex->req, "upgrade");
    const char *connection = sb_req_header(&ex->req, "connection");
    if (!upgrade || !connection) return false;
    char *c = ascii_lower_dup(connection, strlen(connection));
    char *u = ascii_lower_dup(upgrade, strlen(upgrade));
    bool yes = strstr(c, "upgrade") && strcmp(u, "websocket") == 0;
    free(c);
    free(u);
    return yes;
}

/* civetweb's should_switch_to_protocol() == websocket: some Connection
 * header contains "upgrade" and Upgrade contains "websocket". */
static bool civetweb_websocket_upgrade(const http_exchange *ex) {
    const struct mg_request_info *ri = ex->ri;
    bool upgrade = false;
    for (int i = 0; i < ri->num_headers && !upgrade; ++i)
        if (strcasecmp(ri->http_headers[i].name, "Connection") == 0 && strcasestr(ri->http_headers[i].value, "upgrade"))
            upgrade = true;
    const char *to = mg_get_header(ex->conn, "Upgrade");
    return upgrade && to && strcasestr(to, "websocket");
}

/* Everything after parsing for a plain HTTP request: advices, routing,
 * handler, static fallback. Returns true when a handler wrote directly. */
static bool dispatch_http(http_exchange *ex, wire_response *w) {
    bool handled = false;
    if (ex->method == M_OPTIONS && strcmp(ex->path, "/*") == 0) {
        w->status = 200;
        sb_str_set(&w->content_type, "text/plain; charset=utf-8");
        wire_set_header(w, "Allow", "GET,HEAD,POST,PUT,DELETE,OPTIONS,PATCH");
    } else if (ex->method == M_OPTIONS && *exchange_header(ex, "access-control-request-method")) {
        /* CORS preflight advice: answered before authentication. */
        wire_empty_html(w, 204);
        cors_apply(ex, w);
    } else if (auth_advice(ex, w)) {
        sb_http_handler handler = NULL;
        char *params[8] = {0};
        size_t count = 0;
        route_result result = router_lookup(ex->srv, ex->path, ex->method, &handler, params, &count);
        for (size_t i = 0; i < count; ++i) {
            ex->params[i] = params[i];
            ex->req.params[i] = params[i];
        }
        ex->req.param_count = count;
        if (result == ROUTE_FOUND) {
            handled = run_handler(ex, handler, w);
        } else if (result == ROUTE_METHOD_NOT_ALLOWED) {
            wire_empty_html(w, ex->method == M_OPTIONS ? 403 : 405);
        } else if ((handler = builtin_route(ex)) != NULL) {
            handled = run_handler(ex, handler, w);
        } else {
            static_router(ex, w);
        }
    }
    if (!handled) cors_apply(ex, w);
    return handled;
}

static bool header_has_token(const char *value, const char *token) {
    sb_strvec parts = sb_split(value, ',');
    bool found = false;
    for (size_t i = 0; i < parts.len && !found; ++i) {
        char *t = sb_http_trim(parts.items[i]);
        found = strcasecmp(t, token) == 0;
        free(t);
    }
    sb_strvec_free(&parts);
    return found;
}

/* Whether the connection stays open: civetweb's should_keep_alive() (it owns
 * the socket) combined with Drogon's keepAlive() rules. */
static bool compute_keep_alive(const http_exchange *ex) {
    const char *connection = mg_get_header(ex->conn, "Connection");
    bool civet = connection ? header_has_token(connection, "keep-alive") : !ex->http10;
    const char *value = sb_req_header(&ex->req, "connection");
    bool drogon = ex->http10 ? (value && (strcmp(value, "Keep-Alive") == 0 || strcmp(value, "keep-alive") == 0))
                             : !(value && strcmp(value, "close") == 0);
    return civet && drogon;
}

static void conn_write(struct mg_connection *conn, const void *data, size_t len) {
    const char *p = data;
    while (len > 0) {
        int chunk = len > (1u << 30) ? (1 << 30) : (int)len;
        int n = mg_write(conn, p, (size_t)chunk);
        if (n <= 0) return;
        p += n;
        len -= (size_t)n;
    }
}

static void write_response(const http_exchange *ex, const wire_response *w) {
    if (w->raw_close) {
        char *line = sb_asprintf("HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", w->status, status_reason(w->status));
        conn_write(ex->conn, line, strlen(line));
        free(line);
        return;
    }
    sb_buf out = {0};
    sb_buf_printf(&out, "HTTP/1.%c %d %s\r\n", ex->http10 ? '0' : '1', w->status, status_reason(w->status));
    bool body_allowed = content_length_allowed(w->status);
    uint64_t length = w->file ? w->file_length : (uint64_t)w->body_len;
    if (body_allowed) sb_buf_printf(&out, "content-length: %llu\r\n", (unsigned long long)length);
    if (!wire_header(w, "connection")) {
        if (!ex->keep_alive) sb_buf_puts(&out, "connection: close\r\n");
        else if (ex->http10) sb_buf_puts(&out, "connection: Keep-Alive\r\n");
    }
    if (w->content_type && *w->content_type) sb_buf_printf(&out, "content-type: %s\r\n", w->content_type);
    for (size_t i = 0; i < w->names.len; ++i) {
        sb_buf_printf(&out, "%s: ", w->names.items[i]);
        sb_buf_append(&out, w->values.items[i], w->value_lens[i]);
        sb_buf_puts(&out, "\r\n");
    }
    char date[64];
    http_date(time(NULL), date, sizeof date);
    sb_buf_printf(&out, "date: %s\r\n\r\n", date);
    bool send_body = body_allowed && !ex->head;
    if (send_body && !w->file && w->body_len > 0 && w->body_len <= 65536) {
        sb_buf_append(&out, w->body, w->body_len);
        send_body = false;
    }
    conn_write(ex->conn, out.p, out.len);
    sb_buf_free(&out);
    if (!send_body) return;
    if (!w->file) {
        conn_write(ex->conn, w->body, w->body_len);
        return;
    }
    FILE *f = fopen(w->file, "rb");
    if (!f) return;
    if (fseeko(f, (off_t)w->file_offset, SEEK_SET) == 0) {
        char chunk[65536];
        uint64_t remaining = w->file_length;
        while (remaining > 0) {
            size_t want = remaining < sizeof chunk ? (size_t)remaining : sizeof chunk;
            size_t got = fread(chunk, 1, want, f);
            if (got == 0) break;
            conn_write(ex->conn, chunk, got);
            remaining -= got;
        }
    }
    fclose(f);
}

/* Makes civetweb close the connection after this request, as Drogon does
 * after a parser error: should_keep_alive() then sees "Connection: close"
 * (the request header array is civetweb's public request_info), and the
 * caller returns -1 from begin_request so no unread body is drained. */
static void force_close(http_exchange *ex) {
    struct mg_request_info *ri = (struct mg_request_info *)mg_get_request_info(ex->conn);
    for (int i = 0; i < ri->num_headers; ++i) {
        if (strcasecmp(ri->http_headers[i].name, "Connection") == 0) {
            ri->http_headers[i].value = "close";
            return;
        }
    }
    if (ri->num_headers < (int)(sizeof ri->http_headers / sizeof ri->http_headers[0])) {
        ri->http_headers[ri->num_headers].name = "Connection";
        ri->http_headers[ri->num_headers].value = "close";
        ri->num_headers++;
    }
}

static void exchange_free(http_exchange *ex) {
    for (size_t i = 0; i < ex->header_count; ++i) free(ex->header_values[i]);
    for (size_t i = 0; i < 8; ++i) free(ex->params[i]);
    free(ex->path);
    free(ex->query);
    sb_buf_free(&ex->body);
    if (ex->has_claims) sb_auth_claims_free(&ex->claims);
}

/* Decodes the raw path like HttpRequestImpl::setPath(); NUL bytes (from
 * %00) cannot live in C strings and are kept visible as "%00". */
static void exchange_set_path(http_exchange *ex, const char *raw) {
    if (!raw || !*raw) raw = "/";
    size_t raw_len = strlen(raw);
    if (!strpbrk(raw, "%+")) {
        ex->path = sb_strndup(raw, raw_len);
        return;
    }
    size_t len = 0;
    char *decoded = drogon_url_decode(raw, raw_len, &len);
    if (!memchr(decoded, '\0', len)) {
        ex->path = decoded;
        return;
    }
    ex->path_has_nul = true;
    sb_buf b = {0};
    for (size_t i = 0; i < len; ++i) {
        if (decoded[i]) sb_buf_putc(&b, decoded[i]);
        else sb_buf_puts(&b, "%00");
    }
    free(decoded);
    ex->path = sb_buf_detach(&b);
}

/* Reads the request body with Drogon's limits. Returns 0, or the status of a
 * bare parser error (413/400/417) that closes the connection. */
static int exchange_read_body(http_exchange *ex) {
    const struct mg_request_info *ri = ex->ri;
    const char *te = mg_get_header(ex->conn, "Transfer-Encoding");
    bool chunked = te && strcasecmp(te, "chunked") == 0;
    long long content_length = ri->content_length;
    if (content_length > (long long)SB_HTTP_MAX_BODY) return 413;
    const char *expect = sb_req_header(&ex->req, "expect");
    if (expect && *expect) {
        if (strcmp(expect, "100-continue") == 0 && !ex->http10) {
            if (content_length <= 0) return 400;
            /* Drogon renders the interim response like any other one. */
            char date[64];
            http_date(time(NULL), date, sizeof date);
            char *cont = sb_asprintf("HTTP/1.1 100 Continue\r\ncontent-type: text/html; charset=utf-8\r\n"
                                     "date: %s\r\n\r\n",
                                     date);
            conn_write(ex->conn, cont, strlen(cont));
            free(cont);
        } else if (strcmp(expect, "100-continue") != 0) {
            return 417;
        }
    }
    if (content_length > 0 || chunked) {
        char chunk[16384];
        for (;;) {
            int n = mg_read(ex->conn, chunk, sizeof chunk);
            if (n <= 0) break;
            sb_buf_append(&ex->body, chunk, (size_t)n);
            if (ex->body.len > SB_HTTP_MAX_BODY) return 413;
        }
    }
    return 0;
}

/* civetweb begin_request callback: every request is answered here, except
 * accepted WebSocket upgrades (returns 0 so civetweb runs the WS handler). */
static int begin_request(struct mg_connection *conn) {
    sb_http_server *srv = mg_get_user_data(mg_get_context(conn));
    const struct mg_request_info *ri = mg_get_request_info(conn);
    http_exchange *ex = sb_xcalloc(1, sizeof *ex);
    ex->srv = srv;
    ex->conn = conn;
    ex->ri = ri;
    ex->req.server = srv;
    ex->req.conn = conn;
    ex->req.core = ex;
    ex->req.remote_addr = ri->remote_addr;
    ex->http10 = ri->http_version && strcmp(ri->http_version, "1.0") == 0;
    for (int i = 0; i < ri->num_headers && ex->header_count < SB_HTTP_MAX_HEADERS; ++i) {
        const char *name = ri->http_headers[i].name;
        bool seen = false;
        for (size_t j = 0; j < ex->header_count && !seen; ++j) seen = strcasecmp(ex->header_names[j], name) == 0;
        if (seen) continue;
        ex->header_names[ex->header_count] = name;
        ex->header_values[ex->header_count++] = sb_http_trim(ri->http_headers[i].value);
    }
    ex->keep_alive = compute_keep_alive(ex);

    wire_response w;
    wire_init(&w, 200);
    bool handled = false, pass_to_civetweb = false;
    int original = method_index(ri->request_method, strlen(ri->request_method));
    if (original < 0) {
        w.status = 405;
        w.raw_close = true;
    } else {
        ex->head = original == M_HEAD;
        ex->method = ex->head ? M_GET : original;
        ex->req.method = method_names[ex->method];
        exchange_set_path(ex, ri->local_uri_raw);
        ex->req.path = ex->path;
        ex->query = ri->query_string ? sb_strdup(ri->query_string) : NULL;
        ex->req.query = ex->query;
        int parse_error = exchange_read_body(ex);
        sb_buf_append(&ex->body, "", 0);
        ex->req.body = ex->body.p ? ex->body.p : "";
        ex->req.body_len = ex->body.len;
        if (parse_error) {
            w.status = parse_error;
            w.raw_close = true;
        } else if (original == M_GET && civetweb_websocket_upgrade(ex) && clash_websocket_path(ex->path)) {
            /* The Clash bridge (clash_websocket.c) authenticates ?token=
             * itself and performs the upgrade. */
            pass_to_civetweb = true;
        } else if (drogon_is_websocket(ex, original)) {
            /* Drogon routes other upgrade requests to its WebSocket
             * controllers only: after the advices they end in a 404 page. */
            if (auth_advice(ex, &w)) {
                wire_not_found_page(&w);
                ex->keep_alive = false;
            }
            cors_apply(ex, &w);
        } else {
            handled = dispatch_http(ex, &w);
        }
    }
    int status = w.status > 0 ? w.status : 200;
    if (!handled && !pass_to_civetweb) write_response(ex, &w);
    bool close_now = w.raw_close;
    if (close_now) force_close(ex);
    wire_free(&w);
    exchange_free(ex);
    free(ex);
    if (pass_to_civetweb) return 0;
    return close_now ? -1 : status;
}

static int log_civetweb_message(const struct mg_connection *conn, const char *message) {
    (void)conn;
    SB_DEBUG("civetweb: %s", message);
    return 1;
}

/* ---- server log ring (ServerLogBuffer) ------------------------------------ */

#define SB_HTTP_LOG_CAPACITY 1000

/* Global state: the log sink is process-wide, so at most one server (the
 * owner) feeds its log ring from it. `g_sink_owner` is guarded by
 * `g_sink_owner_mutex`. */
static pthread_mutex_t g_sink_owner_mutex = PTHREAD_MUTEX_INITIALIZER;
static sb_http_server *g_sink_owner;

static void log_ring_append(sb_http_server *srv, const char *text) {
    pthread_mutex_lock(&srv->log_mutex);
    const char *start = text;
    for (;;) {
        const char *end = strchr(start, '\n');
        size_t len = end ? (size_t)(end - start) : strlen(start);
        if (len > 0) {
            char *line = sb_strndup(start, len);
            if (srv->log_lines.len < SB_HTTP_LOG_CAPACITY) {
                sb_strvec_push_take(&srv->log_lines, line);
            } else {
                free(srv->log_lines.items[srv->log_head]);
                srv->log_lines.items[srv->log_head] = line;
                srv->log_head = (srv->log_head + 1) % SB_HTTP_LOG_CAPACITY;
            }
        }
        if (!end) break;
        start = end + 1;
    }
    pthread_mutex_unlock(&srv->log_mutex);
}

static void log_sink(sb_log_level level, const char *line, void *user) {
    (void)level;
    log_ring_append((sb_http_server *)user, line);
}

/* log_level(): LOG_LEVEL parsing with the C++ std::invalid_argument message. */
static int parse_log_level(const char *configured, sb_log_level *out, sb_err *err) {
    char *value = sb_http_trim(configured);
    for (char *p = value; *p; ++p) *p = (char)tolower((unsigned char)*p);
    int rc = 0;
    if (strcmp(value, "trace") == 0) *out = SB_LOG_TRACE;
    else if (strcmp(value, "debug") == 0) *out = SB_LOG_DEBUG;
    else if (strcmp(value, "warn") == 0 || strcmp(value, "warning") == 0) *out = SB_LOG_WARN;
    else if (strcmp(value, "error") == 0 || strcmp(value, "fatal") == 0) *out = SB_LOG_ERROR;
    else if (!*value || strcmp(value, "info") == 0) *out = SB_LOG_INFO;
    else rc = sb_fail(err, SB_ERR_VALIDATION, "LOG_LEVEL must be trace, debug, info, warn, error, or fatal");
    free(value);
    return rc;
}

/* ---- server lifecycle ------------------------------------------------- */

static void wireguard_options_from(const sb_http_server_options *o, sb_wireguard_options *w) {
    sb_wireguard_options_init(w);
    w->enabled = o->wireguard_enabled;
    sb_str_set(&w->interface, o->wireguard_interface);
    w->port = o->wireguard_port;
    sb_str_set(&w->address, o->wireguard_address);
    sb_str_set(&w->dns, o->wireguard_dns);
    w->mtu = o->wireguard_mtu;
    sb_str_set(&w->external_hostname, o->external_hostname);
    sb_str_set(&w->egress_interface, o->wireguard_egress);
    sb_str_set(&w->config_directory, o->wireguard_config_directory);
}

/* register_http_routes(): enrollment server normalisation. */
static char *normalized_enrollment_server(const sb_http_server_options *o) {
    char *server = sb_http_trim_trailing_slashes(o->public_server);
    if (sb_starts_with(server, "http://") || sb_starts_with(server, "https://")) return server;
    size_t len = strlen(server);
    char *out;
    if (!strchr(server, ':') || (len > 0 && server[0] == '[' && server[len - 1] == ']'))
        out = sb_asprintf("http://%s:%u", server, (unsigned)o->port);
    else
        out = sb_asprintf("http://%s", server);
    free(server);
    return out;
}

sb_http_server *sb_http_server_new(sb_store *store, const sb_http_server_options *options,
                                   sb_err *err) {
    if (!store) {
        sb_fail(err, SB_ERR_VALIDATION, "HTTP store is required");
        return NULL;
    }
    sb_http_server_options defaults;
    if (!options) {
        sb_http_server_options_init(&defaults);
        options = &defaults;
    }
    sb_http_server *srv = NULL;
    sb_log_level level = SB_LOG_INFO;
    if (sb_store_ensure_default_admin(store, options->admin_password, err) != 0 ||
        parse_log_level(options->log_level, &level, err) != 0)
        goto fail;
    srv = sb_xcalloc(1, sizeof *srv);
    sb_http_server_options_copy(&srv->opts, options);
    srv->store = store;
    pthread_mutex_init(&srv->telemetry_mutex, NULL);
    srv->telemetry = sbj_object();
    pthread_mutex_init(&srv->log_mutex, NULL);
    pthread_mutex_init(&srv->self_singbox_mutex, NULL);
    pthread_condattr_t cond_attributes;
    pthread_condattr_init(&cond_attributes);
    pthread_condattr_setclock(&cond_attributes, CLOCK_MONOTONIC);
    pthread_cond_init(&srv->self_singbox_wakeup, &cond_attributes);
    pthread_condattr_destroy(&cond_attributes);
    router *r = sb_xcalloc(1, sizeof *r);
    pthread_rwlock_init(&r->lock, NULL);
    srv->routes = r;
    srv->fetcher = sb_subscription_fetcher_new(NULL, err);
    srv->clash = srv->fetcher ? sb_clash_client_new(NULL, err) : NULL;
    if (!srv->clash) goto fail;
    srv->subscriptions = sb_subscription_service_new(store, srv->fetcher);
    srv->security = sb_auth_security_new(sb_store_database(store), srv->opts.jwt_secret, false, err);
    if (!srv->security) goto fail;
    srv->observability = sb_observability_new(sb_store_database(store));
    /* A prior process's capability report must not authorize a newly started
     * external or disabled self runtime for the remainder of its freshness TTL. */
    sbj *no_proxy = sbj_array();
    int cleared_proxy = sb_proxy_runtime_report(sb_store_database(store), "self", no_proxy, sb_unix_now(), err);
    sbj_free(no_proxy); if (cleared_proxy) goto fail;
    sb_wireguard_options wg;
    wireguard_options_from(&srv->opts, &wg);
    srv->wireguard = sb_wireguard_new(store, &wg);
    sb_wireguard_options_free(&wg);

    pthread_mutex_lock(&g_sink_owner_mutex);
    g_sink_owner = srv;
    sb_log_set_sink(log_sink, srv);
    pthread_mutex_unlock(&g_sink_owner_mutex);
    SB_INFO("sb-easy C HTTP routes registered");

    srv->enrollment_server = normalized_enrollment_server(&srv->opts);
    srv->legacy_agent_token = sb_http_trim(srv->opts.legacy_agent_token);
    cors_init(srv, srv->opts.cors_origins);
    /* Same registration order as the C++ register_http_routes(). */
    sb_http_register_admin_routes(srv);
    sb_http_register_security_routes(srv);
    sb_http_register_preferences_routes(srv);
    sb_http_register_observability_routes(srv);
    sb_http_register_proxy_routes(srv);
    sb_http_register_proxy_user_routes(srv);
    sb_http_register_hosts_routes(srv);
    sb_log_set_level(level);
    if (options == &defaults) sb_http_server_options_free(&defaults);
    return srv;
fail:
    if (options == &defaults) sb_http_server_options_free(&defaults);
    sb_http_server_free(srv);
    return NULL;
}

/* civetweb "listening_ports" for Drogon's addListener(address, port). */
static char *listening_spec(const char *address, uint16_t port) {
    if (!address || !*address || strcmp(address, "::") == 0) return sb_asprintf("+%u", (unsigned)port);
    if (strchr(address, ':')) return sb_asprintf("[%s]:%u", address, (unsigned)port);
    return sb_asprintf("%s:%u", address, (unsigned)port);
}

int sb_http_server_start(sb_http_server *srv, sb_err *err) {
    if (!srv) return sb_fail(err, SB_ERR_VALIDATION, "HTTP server is required");
    if (srv->mg) return srv->bound_port;
    char *ports = listening_spec(srv->opts.address, srv->opts.port);
    size_t threads = srv->opts.threads > 64 ? srv->opts.threads : 64;
    char *thread_text = sb_asprintf("%zu", threads);
    const char *config[] = {"listening_ports", ports,
                            "num_threads", thread_text,
                            "decode_url", "no",
                            "decode_query_string", "no",
                            "enable_keep_alive", "yes",
                            "keep_alive_timeout_ms", SB_HTTP_KEEP_ALIVE_TIMEOUT_MS,
                            "request_timeout_ms", SB_HTTP_REQUEST_TIMEOUT_MS,
                            "tcp_nodelay", "1",
                            "max_request_size", SB_HTTP_MAX_REQUEST_BYTES,
                            "connection_queue", "256",
                            NULL};
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof callbacks);
    callbacks.begin_request = begin_request;
    callbacks.log_message = log_civetweb_message;
    struct mg_init_data init = {&callbacks, srv, config};
    char error_text[256] = "";
    struct mg_error_data error = {0, 0, error_text, sizeof error_text};
    srv->mg = mg_start2(&init, &error);
    free(thread_text);
    if (!srv->mg) {
        int rc = sb_fail(err, SB_ERR_IO, "HTTP server could not listen on %s: %s", ports,
                         error_text[0] ? error_text : "civetweb start failed");
        free(ports);
        return rc;
    }
    free(ports);
    struct mg_server_port bound[4];
    memset(bound, 0, sizeof bound);
    int count = mg_get_server_ports(srv->mg, 4, bound);
    srv->bound_port = count > 0 ? (uint16_t)bound[0].port : srv->opts.port;
    srv->stopping = 0;
    if (srv->opts.subscription_auto_refresh &&
        sb_subscription_service_start(srv->subscriptions, err) != 0) {
        sb_http_server_stop(srv);
        return -1;
    }
    sb_http_register_clash_websocket(srv);
    if (sb_observability_start(srv->observability, err) != 0) {
        sb_http_server_stop(srv); return -1;
    }
    return srv->bound_port;
}

uint16_t sb_http_server_port(const sb_http_server *srv) {
    if (!srv) return 0;
    return srv->mg ? srv->bound_port : srv->opts.port;
}

void sb_http_server_stop(sb_http_server *srv) {
    if (!srv) return;
    self_singbox_request_stop(srv);
    sb_proxy_runtime_stop(srv->self_proxy);
    if (!srv->mg) return;
    srv->stopping = 1;
    sb_subscription_service_stop(srv->subscriptions);
    sb_observability_stop(srv->observability);
    mg_stop(srv->mg);
    srv->mg = NULL;
}

void sb_http_server_free(sb_http_server *srv) {
    if (!srv) return;
    sb_http_server_stop(srv);
    self_singbox_join(srv);
    sb_proxy_runtime_free(srv->self_proxy);
    pthread_mutex_lock(&g_sink_owner_mutex);
    if (g_sink_owner == srv) {
        sb_log_set_sink(NULL, NULL);
        g_sink_owner = NULL;
    }
    pthread_mutex_unlock(&g_sink_owner_mutex);
    if (srv->wireguard) sb_wireguard_free(srv->wireguard);
    if (srv->clash) sb_clash_client_free(srv->clash);
    sb_subscription_service_free(srv->subscriptions);
    sb_auth_security_free(srv->security);
    sb_observability_free(srv->observability);
    if (srv->fetcher) sb_subscription_fetcher_free(srv->fetcher);
    router_free(router_of(srv));
    sbj_free(srv->telemetry);
    pthread_mutex_destroy(&srv->telemetry_mutex);
    sb_strvec_free(&srv->log_lines);
    pthread_mutex_destroy(&srv->log_mutex);
    pthread_mutex_destroy(&srv->self_singbox_mutex);
    pthread_cond_destroy(&srv->self_singbox_wakeup);
    sb_strvec_free(&srv->cors_origins);
    free(srv->enrollment_server);
    free(srv->legacy_agent_token);
    sb_http_server_options_free(&srv->opts);
    free(srv);
}

/* ---- run_http_server ---------------------------------------------------------- */

/* Global state: self-pipe for SIGINT/SIGTERM. Created in
 * wait_for_termination(). The signal handler only calls write() on the write
 * end, which is async-signal-safe, so there is no mutex. One per process. */
static int g_signal_pipe[2] = {-1, -1};

static void on_termination_signal(int signo) {
    int saved = errno;
    char c = (char)signo;
    if (g_signal_pipe[1] >= 0 && write(g_signal_pipe[1], &c, 1) < 0) {
    }
    errno = saved;
}

/* Blocks until SIGINT or SIGTERM (Drogon's app().run() quits on both). */
static void wait_for_termination(void) {
    if (pipe(g_signal_pipe) != 0) {
        SB_ERROR("could not create the signal pipe: %s", strerror(errno));
        pause();
        return;
    }
    fcntl(g_signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(g_signal_pipe[1], F_SETFD, FD_CLOEXEC);
    fcntl(g_signal_pipe[1], F_SETFL, O_NONBLOCK);
    struct sigaction action, old_int, old_term;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_termination_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    sigaction(SIGINT, &action, &old_int);
    sigaction(SIGTERM, &action, &old_term);
    char c = 0;
    for (;;) {
        ssize_t n = read(g_signal_pipe[0], &c, 1);
        if (n == 1 || (n < 0 && errno != EINTR)) break;
    }
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    close(g_signal_pipe[0]);
    close(g_signal_pipe[1]);
    g_signal_pipe[0] = g_signal_pipe[1] = -1;
    SB_INFO("received %s, shutting down", c == SIGINT ? "SIGINT" : "SIGTERM");
}

int sb_http_server_run(sb_store *store, const sb_http_server_options *options, sb_err *err) {
    if (!store || !options) return sb_fail(err, SB_ERR_VALIDATION, "HTTP store is required");
    /* The C++ code starts WireGuard with its own WireGuardService instance. */
    sb_wireguard_options wg_options;
    wireguard_options_from(options, &wg_options);
    sb_wireguard *wireguard = sb_wireguard_new(store, &wg_options);
    sb_wireguard_options_free(&wg_options);
    if (!wireguard) return sb_fail(err, SB_ERR_GENERIC, "WireGuard service could not be created");
    if (sb_wireguard_startup(wireguard, err) != 0) {
        sb_wireguard_free(wireguard);
        return -1;
    }
    sb_http_server *srv = sb_http_server_new(store, options, err);
    int rc = -1;
    if (srv) {
        if ((!options->singbox_managed || self_singbox_start(srv, err) == 0) && sb_http_server_start(srv, err) >= 0) {
            SB_INFO("sb-easy C HTTP server listening on %s:%u", srv->opts.address, (unsigned)srv->bound_port);
            wait_for_termination();
            rc = 0;
        }
        sb_http_server_stop(srv);
        self_singbox_request_stop(srv);
    }
    sb_wireguard_shutdown(wireguard);
    if (srv) {
        self_singbox_join(srv);
        sb_http_server_free(srv);
    }
    sb_wireguard_free(wireguard);
    return rc;
}
