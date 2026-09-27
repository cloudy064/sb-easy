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
#include "sb/clash_client.h"
#include "sb/config_etag.h"
#include "sb/config_renderer.h"
#include "sb/singbox_supervisor.h"
#include "sb/subscription_fetcher.h"
#include "sb/wireguard.h"

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

static char *ascii_lower_dup(const char *s, size_t len);
static void self_singbox_join(sb_http_server *srv);

/* ---- small helpers (C++ anonymous namespace) -------------------------- */

static bool is_space(unsigned char c) { return isspace(c) != 0; }

char *sb_http_trim(const char *s) {
    if (!s) return sb_strdup("");
    const char *b = s;
    while (*b && is_space((unsigned char)*b)) ++b;
    const char *e = b + strlen(b);
    while (e > b && is_space((unsigned char)e[-1])) --e;
    return sb_strndup(b, (size_t)(e - b));
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
    static const char hex[] = "0123456789ABCDEF";
    sb_buf b = {0};
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; ++p) {
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
    sb_strvec_push_take(&resp->headers, sb_asprintf("%s: %s", name, value ? value : ""));
}

/* ---- per-request state -------------------------------------------------- */

#define SB_HTTP_MAX_BODY (1024u * 1024u) /* Drogon's default client_max_body_size */
#define SB_HTTP_MAX_HEADERS 64

/* Everything the core keeps for one request; req.core points back here. */
typedef struct {
    sb_http_req req;
    sb_http_server *srv;
    struct mg_connection *conn;
    const struct mg_request_info *ri;
    int method;          /* routing method: HEAD is routed as GET (Drogon) */
    bool head;           /* the request was HEAD: send headers only */
    bool http10;
    bool keep_alive;     /* what civetweb will do with the connection */
    char *path;          /* decoded path; NUL bytes rendered as "%00" */
    bool path_has_nul;
    char *query;         /* raw query string (no '?') or NULL */
    sb_buf body;
    /* Request headers as Drogon stores them: value trimmed, first wins. */
    size_t header_count;
    const char *header_names[SB_HTTP_MAX_HEADERS];
    char *header_values[SB_HTTP_MAX_HEADERS];
    char *params[8];
    sb_auth_claims claims;
    bool has_claims;
} http_exchange;

static http_exchange *exchange_of(const sb_http_req *req) { return req ? (http_exchange *)req->core : NULL; }

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
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) return 0;
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    sb_str_set(dest, found->v.str.ptr);
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

/* ---- telemetry / diagnostics / logs (filled in below) ----------------- */

sbj *sb_http_default_telemetry(void) {
    sbj *t = sbj_object();
    sbj_set_str(t, "at", "");
    sbj_set_int(t, "up", 0);
    sbj_set_int(t, "down", 0);
    sbj_set_int(t, "up_total", 0);
    sbj_set_int(t, "down_total", 0);
    sbj_set_int(t, "conn_count", 0);
    sbj_set_null(t, "connections");
    sbj_set(t, "domain_stats", sbj_array());
    sbj_set(t, "logs", sbj_array());
    return t;
}

/* nlohmann get<int64_t>() on an integer value (unsigned wraps like static_cast). */
static int64_t json_int64(const sbj *v) { return v->type == SBJ_UINT ? (int64_t)v->v.u : v->v.i; }

/* bounded_string() lambda of normalize_telemetry(). */
static int bounded_string(const sbj *entry, const char *field, size_t maximum, bool required, sbj *out,
                          sb_err *err) {
    const sbj *found = sbj_get(entry, field);
    if (!found || found->type == SBJ_NULL) {
        if (required) return sb_fail(err, SB_ERR_VALIDATION, "%s is required", field);
        sbj_set_str(out, field, "");
        return 0;
    }
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    if ((required && found->v.str.len == 0) || found->v.str.len > maximum)
        return sb_fail(err, SB_ERR_VALIDATION, "%s has an invalid length", field);
    sbj_set(out, field, sbj_strn(found->v.str.ptr, found->v.str.len));
    return 0;
}

static sbj *normalize_domain_stats(const sbj *stats, sb_err *err) {
    if (!sbj_is_array(stats)) {
        sb_fail(err, SB_ERR_VALIDATION, "domain_stats must be an array");
        return NULL;
    }
    if (sbj_arr_len(stats) > 1000) {
        sb_fail(err, SB_ERR_VALIDATION, "domain_stats must contain at most 1000 entries");
        return NULL;
    }
    sbj *normalized = sbj_array();
    const sbj *entry;
    SBJ_ARR_FOREACH(stats, i, entry) {
        if (!sbj_is_object(entry)) {
            sb_fail(err, SB_ERR_VALIDATION, "domain_stats must contain only objects");
            goto fail;
        }
        sbj *chain = sbj_array();
        const sbj *value = sbj_get(entry, "chain");
        if (value) {
            if (!sbj_is_array(value) || sbj_arr_len(value) > 16) {
                sbj_free(chain);
                sb_fail(err, SB_ERR_VALIDATION, "domain_stats chain must be an array of at most 16 entries");
                goto fail;
            }
            const sbj *tag;
            SBJ_ARR_FOREACH(value, t, tag) {
                if (!sbj_is_string(tag) || tag->v.str.len > 256) {
                    sbj_free(chain);
                    sb_fail(err, SB_ERR_VALIDATION, "domain_stats chain contains an invalid tag");
                    goto fail;
                }
                sbj_arr_push(chain, sbj_clone(tag));
            }
        }
        static const char *const counters[] = {"connection_count", "uplink_total", "downlink_total", "first_seen",
                                               "last_seen"};
        int64_t values[5];
        for (size_t c = 0; c < 5; ++c) {
            if (sb_json_integer_field(entry, counters[c], &values[c], err) != 0) {
                sbj_free(chain);
                goto fail;
            }
        }
        for (size_t c = 0; c < 5; ++c) {
            if (values[c] < 0) {
                sbj_free(chain);
                sb_fail(err, SB_ERR_VALIDATION, "domain_stats counters must not be negative");
                goto fail;
            }
        }
        sbj *item = sbj_object();
        if (bounded_string(entry, "domain", 512, true, item, err) != 0 ||
            bounded_string(entry, "outbound", 256, false, item, err) != 0 ||
            bounded_string(entry, "outbound_type", 80, false, item, err) != 0 ||
            bounded_string(entry, "rule", 512, false, item, err) != 0) {
            sbj_free(item);
            sbj_free(chain);
            goto fail;
        }
        sbj_set(item, "chain", chain);
        for (size_t c = 0; c < 5; ++c) sbj_set_int(item, counters[c], values[c]);
        sbj_arr_push(normalized, item);
    }
    return normalized;
fail:
    sbj_free(normalized);
    return NULL;
}

/* Keeps the last `limit` entries of a string array ("<field> must be an
 * array" / "<field> must contain only strings"); truncates when max > 0. */
static sbj *tail_strings(const sbj *array, size_t limit, size_t max_bytes, sb_err *err) {
    if (!sbj_is_array(array)) {
        sb_fail(err, SB_ERR_VALIDATION, "logs must be an array");
        return NULL;
    }
    sbj *out = sbj_array();
    size_t len = sbj_arr_len(array);
    for (size_t i = len > limit ? len - limit : 0; i < len; ++i) {
        const sbj *item = sbj_arr_at(array, i);
        if (!sbj_is_string(item)) {
            sbj_free(out);
            sb_fail(err, SB_ERR_VALIDATION, "logs must contain only strings");
            return NULL;
        }
        if (max_bytes) sbj_arr_push(out, sbj_str_take(sb_http_truncate_utf8(item->v.str.ptr, max_bytes)));
        else sbj_arr_push(out, sbj_clone(item));
    }
    return out;
}

sbj *sb_http_normalize_telemetry(const sbj *body, sb_err *err) {
    sbj *telemetry = sb_http_default_telemetry();
    sbj_set(telemetry, "at", sbj_str_take(sb_http_utc_now()));
    static const char *const fields[] = {"up", "down", "up_total", "down_total"};
    for (size_t i = 0; i < 4; ++i) {
        int64_t value = 0;
        if (sb_json_integer_field(body, fields[i], &value, err) != 0) goto fail;
        sbj_set_int(telemetry, fields[i], value);
    }
    int64_t count = 0;
    if (sb_json_integer_field(body, "conn_count", &count, err) != 0) goto fail;
    if (count < 0) {
        sb_fail(err, SB_ERR_VALIDATION, "conn_count must not be negative");
        goto fail;
    }
    sbj_set_int(telemetry, "conn_count", count);
    const sbj *connections = sbj_get(body, "connections");
    if (connections) sbj_set(telemetry, "connections", sbj_clone(connections));
    const sbj *stats = sbj_get(body, "domain_stats");
    if (stats) {
        sbj *normalized = normalize_domain_stats(stats, err);
        if (!normalized) goto fail;
        sbj_set(telemetry, "domain_stats", normalized);
    }
    const sbj *logs = sbj_get(body, "logs");
    if (logs) {
        sbj *normalized = tail_strings(logs, 500, 0, err);
        if (!normalized) goto fail;
        sbj_set(telemetry, "logs", normalized);
    }
    return telemetry;
fail:
    sbj_free(telemetry);
    return NULL;
}

/* diagnostic_string(): absent/null -> fallback; else truncated string. */
static int diagnostic_string(const sbj *body, const char *field, const char *fallback, size_t max_bytes, sbj *out,
                             sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set_str(out, field, fallback);
        return 0;
    }
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    sbj_set(out, field, sbj_str_take(sb_http_truncate_utf8(found->v.str.ptr, max_bytes)));
    return 0;
}

static int diagnostic_object(const sbj *body, const char *field, sbj *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set(out, field, sbj_object());
        return 0;
    }
    if (!sbj_is_object(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a JSON object", field);
    sbj_set(out, field, sbj_clone(found));
    return 0;
}

static int diagnostic_count(const sbj *body, const char *field, sbj *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set_int(out, field, 0);
        return 0;
    }
    if (!sbj_is_integer(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an integer", field);
    int64_t value = json_int64(found);
    if (value < 0) return sb_fail(err, SB_ERR_VALIDATION, "%s must not be negative", field);
    sbj_set_int(out, field, value);
    return 0;
}

sbj *sb_http_normalize_diagnostic_report(const sbj *body, sb_err *err) {
    sbj *logs = NULL;
    const sbj *found = sbj_get(body, "logs");
    if (found) {
        logs = tail_strings(found, 1500, 4000, err);
        if (!logs) return NULL;
    } else {
        logs = sbj_array();
    }
    sbj *report = sbj_object();
    if (diagnostic_string(body, "reason", "manual", 80, report, err) != 0 ||
        diagnostic_string(body, "app_version", "", 80, report, err) != 0 ||
        diagnostic_string(body, "core_version", "", 120, report, err) != 0 ||
        diagnostic_object(body, "device", report, err) != 0 || diagnostic_object(body, "vpn", report, err) != 0 ||
        diagnostic_object(body, "network", report, err) != 0 || diagnostic_object(body, "config", report, err) != 0 ||
        diagnostic_count(body, "runtime_log_count", report, err) != 0 ||
        diagnostic_count(body, "connection_count", report, err) != 0) {
        sbj_free(report);
        sbj_free(logs);
        return NULL;
    }
    sbj_set(report, "logs", logs);
    return report;
}

void sb_http_telemetry_put(sb_http_server *srv, const char *host_id, sbj *telemetry) {
    pthread_mutex_lock(&srv->telemetry_mutex);
    sbj_set(srv->telemetry, host_id ? host_id : "", telemetry);
    pthread_mutex_unlock(&srv->telemetry_mutex);
}

sbj *sb_http_telemetry_get(sb_http_server *srv, const char *host_id) {
    pthread_mutex_lock(&srv->telemetry_mutex);
    const sbj *found = sbj_get(srv->telemetry, host_id ? host_id : "");
    sbj *copy = found ? sbj_clone(found) : sb_http_default_telemetry();
    pthread_mutex_unlock(&srv->telemetry_mutex);
    return copy;
}

sbj *sb_http_log_lines(sb_http_server *srv) {
    sbj *lines = sbj_array();
    pthread_mutex_lock(&srv->log_mutex);
    for (size_t i = 0; i < srv->log_lines.len; ++i) {
        size_t index = (srv->log_head + i) % srv->log_lines.len;
        sbj_arr_push(lines, sbj_str(srv->log_lines.items[index]));
    }
    pthread_mutex_unlock(&srv->log_mutex);
    return lines;
}

/* ---- methods ----------------------------------------------------------- */

/* The request methods Drogon's parser accepts (HttpRequestImpl::setMethod);
 * anything else is answered with a bare 405 and the connection is closed. */
enum {
    M_GET,
    M_POST,
    M_HEAD,
    M_PUT,
    M_DELETE,
    M_OPTIONS,
    M_PATCH,
    M_COPY,
    M_MOVE,
    M_MKCOL,
    M_PROPFIND,
    M_COUNT
};
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

static char *ascii_lower_dup(const char *s, size_t len) {
    char *out = sb_strndup(s, len);
    for (size_t i = 0; i < len; ++i) out[i] = (char)tolower((unsigned char)out[i]);
    return out;
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

/* What goes on the wire. Header names are stored lowercased with Drogon's
 * addHeader() replace semantics. */
typedef struct {
    int status;
    char *content_type; /* NULL: no content-type header */
    sb_strvec names, values;
    char *body;
    size_t body_len;
    char *file;         /* stream this file instead of body */
    uint64_t file_offset, file_length;
    bool raw_close;     /* bare parser error: status line + Connection: close */
} wire_response;

static void wire_init(wire_response *w, int status) {
    memset(w, 0, sizeof *w);
    w->status = status;
}

static void wire_free(wire_response *w) {
    free(w->content_type);
    sb_strvec_free(&w->names);
    sb_strvec_free(&w->values);
    free(w->body);
    free(w->file);
    memset(w, 0, sizeof *w);
}

static void wire_set_header(wire_response *w, const char *name, const char *value) {
    char *lowered = ascii_lower_dup(name, strlen(name));
    for (size_t i = 0; i < w->names.len; ++i) {
        if (strcmp(w->names.items[i], lowered) == 0) {
            free(lowered);
            sb_str_set(&w->values.items[i], value);
            return;
        }
    }
    sb_strvec_push_take(&w->names, lowered);
    sb_strvec_push(&w->values, value);
}

static const char *wire_header(const wire_response *w, const char *lowered_name) {
    for (size_t i = 0; i < w->names.len; ++i)
        if (strcmp(w->names.items[i], lowered_name) == 0) return w->values.items[i];
    return NULL;
}

static void wire_json(wire_response *w, int status, sbj *body) {
    w->status = status;
    free(w->body);
    sb_err encoding_error = {0};
    if (sbj_validate_utf8(body, &encoding_error) != 0) {
        sbj_free(body);
        body = sbj_object();
        char *message = sb_asprintf("Invalid JSON request: %s", encoding_error.msg);
        sbj_set_str(body, "error", message);
        free(message);
        w->status = 400;
    }
    w->body = sbj_dump(body, -1);
    w->body_len = strlen(w->body);
    sb_str_set(&w->content_type, "application/json; charset=utf-8");
    sbj_free(body);
}

static void wire_error(wire_response *w, int status, const char *message) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", message);
    wire_json(w, status, body);
}

/* Drogon's custom error handler default: empty text/html body. */
static void wire_empty_html(wire_response *w, int status) {
    w->status = status;
    sb_str_set(&w->content_type, "text/html; charset=utf-8");
}

/* HttpResponse::newNotFoundResponse(): the drogon::NotFound view. */
static void wire_not_found_page(wire_response *w) {
    static const char page[] =
        "<html>\n<head><title>404 Not Found</title></head>\n"
        "<body bgcolor=\"white\" text=\"black\">\n"
        "<center><h1>404 Not Found</h1></center>\n"
        "<hr><center>drogon/1.9.13</center>\n</body>\n</html>\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n";
    w->status = 404;
    sb_str_set(&w->content_type, "text/html; charset=utf-8");
    free(w->body);
    w->body = sb_strndup(page, sizeof page - 1);
    w->body_len = sizeof page - 1;
}

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

/* ---- static files (Drogon semantics) ------------------------------------ */

/* drogon::getContentType(fileName) + contentTypeToMime(): the extension after
 * the last '.' of the whole path, lowercased. */
static const char *drogon_mime_for(const char *path) {
    static const char *const table[][2] = {
        {"aac", "audio/aac"}, {"ac3", "audio/ac3"}, {"aif", "audio/aiff"}, {"aifc", "audio/aiff"},
        {"aiff", "audio/aiff"}, {"apg", "video/apg"}, {"ape", "audio/x-ape"}, {"apng", "image/apng"},
        {"av1", "video/av01"}, {"avi", "video/x-msvideo"}, {"avif", "image/avif"}, {"bmp", "image/bmp"},
        {"bz", "application/x-bzip"}, {"bz2", "application/x-bzip2"}, {"css", "text/css; charset=utf-8"},
        {"csv", "text/csv; charset=utf-8"}, {"doc", "application/msword"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"eot", "application/vnd.ms-fontobject"}, {"flac", "audio/flac"}, {"gif", "image/gif"},
        {"gz", "application/gzip"}, {"htm", "text/html; charset=utf-8"}, {"html", "text/html; charset=utf-8"},
        {"icns", "image/icns"}, {"ico", "image/vnd.microsoft.icon"}, {"j2k", "image/jp2"},
        {"jar", "application/java-archive"}, {"j2c", "image/jp2"}, {"jp2", "image/jp2"}, {"jpeg", "image/jpeg"},
        {"jpc", "image/jp2"}, {"jpf", "image/jp2"}, {"jpg", "image/jpeg"}, {"jpg2", "image/jp2"},
        {"jpm", "image/jp2"}, {"jpx", "image/jp2"}, {"js", "text/javascript; charset=utf-8"},
        {"json", "application/json; charset=utf-8"}, {"lzma", "application/x-xz"}, {"m1a", "audio/mpeg"},
        {"m1v", "video/mpeg"}, {"m2a", "audio/mpeg"}, {"m2ts", "video/mp2t"}, {"m2v", "video/mpeg"},
        {"m4a", "audio/mp4"}, {"m4v", "video/x-m4v"}, {"mjs", "text/javascript; charset=utf-8"},
        {"mka", "audio/matroska"}, {"mkv", "video/matroska"}, {"mng", "image/x-mng"},
        {"mov", "video/quicktime"}, {"mp1", "audio/mpeg"}, {"mp2", "audio/mpeg"}, {"mp3", "audio/mpeg"},
        {"mp4", "video/mp4"}, {"mpa", "audio/mpeg"}, {"mpe", "video/mpeg"}, {"mpeg", "video/mpeg"},
        {"mpg", "video/mpeg"}, {"mpv", "video/mpeg"}, {"oga", "audio/ogg"}, {"ogg", "audio/ogg"},
        {"ogv", "video/ogg"}, {"otf", "application/x-font-opentype"}, {"pdf", "application/pdf"},
        {"php", "application/x-httpd-php"}, {"png", "image/png"}, {"rar", "application/vnd.rar"},
        {"svg", "image/svg+xml"}, {"tar", "application/x-tar"}, {"targa", "image/x-tga"},
        {"tif", "image/tiff"}, {"tiff", "image/tiff"}, {"tga", "image/x-tga"}, {"tgz", "application/x-tgz"},
        {"ts", "video/mp2t"}, {"tta", "audio/x-tta"}, {"ttf", "application/x-font-truetype"},
        {"txt", "text/plain; charset=utf-8"}, {"w64", "audio/wav"}, {"wav", "audio/wav"},
        {"wave", "audio/wav"}, {"wasm", "application/wasm"}, {"weba", "audio/webm"}, {"webm", "video/webm"},
        {"webp", "image/webp"}, {"wma", "audio/x-ms-wma"}, {"woff", "application/font-woff"},
        {"woff2", "application/font-woff2"}, {"wv", "audio/x-wavpack"},
        {"xht", "application/xhtml+xml; charset=utf-8"}, {"xhtml", "application/xhtml+xml; charset=utf-8"},
        {"xml", "application/xml; charset=utf-8"}, {"xsl", "text/xsl; charset=utf-8"},
        {"xz", "application/x-xz"}, {"zip", "application/zip"}, {"7z", "application/x-7z-compressed"},
    };
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    for (size_t i = 0; i < sizeof table / sizeof table[0]; ++i)
        if (strcasecmp(table[i][0], dot + 1) == 0) return table[i][1];
    return "application/octet-stream";
}

/* StaticFileRouter::fileTypeSet_ defaults. */
static bool drogon_static_file_type(const char *lowered_extension) {
    static const char *const types[] = {"html", "js",  "css",   "xml",  "xsl", "txt", "svg",
                                        "ttf",  "otf", "woff2", "woff", "eot", "png", "jpg",
                                        "jpeg", "gif", "bmp",   "ico",  "icns"};
    for (size_t i = 0; i < sizeof types / sizeof types[0]; ++i)
        if (strcmp(types[i], lowered_extension) == 0) return true;
    return false;
}

/* HttpResponse::newFileResponse(path[, offset, length]): the file must be
 * readable, else Drogon answers with its 404 page. */
static bool wire_file(wire_response *w, const char *path, uint64_t offset, uint64_t length) {
    FILE *f = fopen(path, "rb");
    struct stat st;
    if (!f || fstat(fileno(f), &st) != 0) {
        if (f) fclose(f);
        wire_not_found_page(w);
        return false;
    }
    fclose(f);
    uint64_t size = (uint64_t)st.st_size;
    w->status = 200;
    sb_str_set(&w->file, path);
    w->file_offset = offset;
    w->file_length = length ? length : size - offset;
    sb_str_set(&w->content_type, drogon_mime_for(path));
    return true;
}

/* static_file_response() from the C++ anonymous namespace. */
static void static_file_response(wire_response *w, const char *path, bool immutable) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        wire_error(w, 404, "Static resource not found");
        return;
    }
    wire_file(w, path, 0, 0);
    wire_set_header(w, "Cache-Control", immutable ? "public, max-age=31536000, immutable" : "no-cache");
}

/* safe_static_relative_path(): non-empty, relative, no NUL, no ".." component. */
static bool safe_static_relative_path(const char *value, bool has_nul) {
    if (!value || !*value || value[0] == '/' || has_nul) return false;
    sb_strvec parts = sb_split(value, '/');
    bool ok = true;
    for (size_t i = 0; i < parts.len && ok; ++i)
        if (strcmp(parts.items[i], "..") == 0) ok = false;
    sb_strvec_free(&parts);
    return ok;
}

/* ---- Drogon StaticFileRouter fallback ------------------------------------ */

static void http_date(time_t t, char *buf, size_t size) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/* getFileStat(): regular file + its Last-Modified string. */
static bool file_stat(const char *path, struct stat *st, char *modified, size_t modified_size) {
    if (stat(path, st) != 0 || !S_ISREG(st->st_mode)) return false;
    http_date(st->st_mtime, modified, modified_size);
    return true;
}

typedef enum { RANGE_INVALID, RANGE_NOT_SATISFIABLE, RANGE_SINGLE, RANGE_MULTI } range_result;

/* drogon::parseRangeHeader(); only the first range is kept (Drogon answers
 * multi-part requests with the first part). */
static range_result parse_range_header(const char *text, uint64_t content_length, uint64_t *first_start,
                                       uint64_t *first_end) {
    const uint64_t max_ten = UINT64_MAX / 10, max_digit = UINT64_MAX % 10;
    if (strlen(text) < 7 || strncmp(text, "bytes=", 6) != 0) return RANGE_INVALID;
    const char *it = text + 6;
    uint64_t total = 0;
    size_t count = 0;
    for (;;) {
        uint64_t start = 0, end = 0;
        bool suffix = false;
        while (*it == ' ') ++it;
        if (*it == '-') {
            suffix = true;
            ++it;
        } else {
            if (!(*it >= '0' && *it <= '9')) return RANGE_INVALID;
            while (*it >= '0' && *it <= '9') {
                if (start > max_ten || (start >= max_ten && (uint64_t)(*it - '0') > max_digit))
                    return RANGE_NOT_SATISFIABLE;
                start = start * 10 + (uint64_t)(*it++ - '0');
            }
            while (*it == ' ') ++it;
            if (*it++ != '-') return RANGE_INVALID;
            while (*it == ' ') ++it;
            if (*it == ',' || *it == '\0') {
                end = content_length;
                if (start < end) {
                    if (total > UINT64_MAX - (end - start)) return RANGE_NOT_SATISFIABLE;
                    total += end - start;
                    if (count++ == 0) {
                        *first_start = start;
                        *first_end = end;
                    }
                }
                if (*it++ != ',') break;
                continue;
            }
        }
        if (!(*it >= '0' && *it <= '9')) return RANGE_INVALID;
        while (*it >= '0' && *it <= '9') {
            if (end > max_ten || (end >= max_ten && (uint64_t)(*it - '0') > max_digit)) return RANGE_NOT_SATISFIABLE;
            end = end * 10 + (uint64_t)(*it++ - '0');
        }
        while (*it == ' ') ++it;
        if (*it != ',' && *it != '\0') return RANGE_INVALID;
        if (suffix) {
            start = end < content_length ? content_length - end : 0;
            end = content_length - 1;
        }
        if (end >= content_length) end = content_length;
        else ++end;
        if (start < end) {
            if (count++ == 0) {
                *first_start = start;
                *first_end = end;
            }
            if (total > UINT64_MAX - (end - start)) return RANGE_NOT_SATISFIABLE;
            total += end - start;
            if (count > 100) return RANGE_INVALID;
        }
        if (*it++ != ',') break;
    }
    if (count == 0 || total > content_length) return RANGE_NOT_SATISFIABLE;
    return count == 1 ? RANGE_SINGLE : RANGE_MULTI;
}

static const char *exchange_header(const http_exchange *ex, const char *name) {
    const char *v = sb_req_header(&ex->req, name);
    return v ? v : "";
}

static bool file_is_regular(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* StaticFileRouter::sendStaticFileResponse() (no locations, no cache). */
static void send_static_file(const http_exchange *ex, wire_response *w, const char *file_path) {
    if (ex->method != M_GET) {
        wire_empty_html(w, 405);
        return;
    }
    struct stat st;
    char modified[64] = "";
    bool have_stat = false;
    const char *range = exchange_header(ex, "range");
    if (*range) {
        if (!file_stat(file_path, &st, modified, sizeof modified)) {
            wire_not_found_page(w);
            return;
        }
        have_stat = true;
        if (strcmp(exchange_header(ex, "if-modified-since"), modified) == 0) {
            w->status = 304;
            return;
        }
        const char *if_range = exchange_header(ex, "if-range");
        if (!*if_range || strcmp(if_range, modified) == 0) {
            uint64_t start = 0, end = 0, size = (uint64_t)st.st_size;
            switch (parse_range_header(range, size, &start, &end)) {
            case RANGE_SINGLE:
            case RANGE_MULTI:
                if (wire_file(w, file_path, start, end - start)) {
                    char content_range[128];
                    if (end - start < size) w->status = 206;
                    snprintf(content_range, sizeof content_range, "bytes %llu-%llu/%llu", (unsigned long long)start,
                             (unsigned long long)(end - 1), (unsigned long long)size);
                    wire_set_header(w, "Content-Range", content_range);
                    wire_set_header(w, "Last-Modified", modified);
                    wire_set_header(w, "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
                }
                return;
            case RANGE_NOT_SATISFIABLE: {
                char content_range[64];
                snprintf(content_range, sizeof content_range, "bytes */%llu", (unsigned long long)size);
                wire_empty_html(w, 416);
                wire_set_header(w, "Content-Range", content_range);
                return;
            }
            default:
                break;
            }
        }
    }
    if (!have_stat && !file_stat(file_path, &st, modified, sizeof modified)) {
        wire_not_found_page(w);
        return;
    }
    if (strcmp(exchange_header(ex, "if-modified-since"), modified) == 0) {
        w->status = 304;
        return;
    }
    const char *accept_encoding = exchange_header(ex, "accept-encoding");
    const char *encodings[][2] = {{"br", ".br"}, {"gzip", ".gz"}};
    bool served = false;
    for (size_t i = 0; i < 2 && !served; ++i) {
        if (!strstr(accept_encoding, encodings[i][0])) continue;
        char *compressed = sb_asprintf("%s%s", file_path, encodings[i][1]);
        if (file_is_regular(compressed)) {
            served = true;
            if (wire_file(w, compressed, 0, 0)) {
                sb_str_set(&w->content_type, drogon_mime_for(file_path));
                wire_set_header(w, "Content-Encoding", encodings[i][0]);
            }
        }
        free(compressed);
    }
    if (!served) wire_file(w, file_path, 0, 0);
    if (w->status != 404) {
        wire_set_header(w, "Last-Modified", modified);
        wire_set_header(w, "Expires", "Thu, 01 Jan 1970 00:00:00 GMT");
        wire_set_header(w, "accept-range", "bytes");
    }
}

/* StaticFileRouter::route() with Drogon's defaults: document root "./"
 * (the working directory), implicit page index.html, home page "/" ->
 * "/index.html", and only the default file types. */
static void static_router(const http_exchange *ex, wire_response *w) {
    const char *path = strcmp(ex->path, "/") == 0 ? "/index.html" : ex->path;
    if (ex->path_has_nul) {
        wire_not_found_page(w);
        return;
    }
    if (strstr(path, "..")) {
        sb_strvec parts = sb_split(path, '/');
        int depth = 0;
        bool forbidden = false;
        for (size_t i = 0; i < parts.len && !forbidden; ++i) {
            if (!*parts.items[i]) continue;
            if (strcmp(parts.items[i], "..") == 0) --depth;
            else if (strcmp(parts.items[i], ".") != 0) ++depth;
            if (depth < 0) forbidden = true;
        }
        sb_strvec_free(&parts);
        if (forbidden) {
            wire_empty_html(w, 403);
            return;
        }
    }
    char *directory_path = sb_asprintf("./%s", path);
    struct stat st;
    if (stat(directory_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char *file_path = sb_asprintf("%s/index.html", directory_path);
            send_static_file(ex, w, file_path);
            free(file_path);
            free(directory_path);
            return;
        }
        const char *dot = strrchr(path, '.');
        if (!dot) {
            free(directory_path);
            wire_empty_html(w, 403);
            return;
        }
        char *extension = ascii_lower_dup(dot + 1, strlen(dot + 1));
        bool allowed = drogon_static_file_type(extension);
        free(extension);
        if (allowed) {
            send_static_file(ex, w, directory_path);
            free(directory_path);
            return;
        }
    }
    free(directory_path);
    wire_not_found_page(w);
}

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
    return strcmp(path, "/api/health") == 0 || strcmp(path, "/api/system/status") == 0 ||
           strcmp(path, "/api/devices/enroll") == 0 || sb_starts_with(path, "/api/auth/") ||
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
    if (!token || !*token || !sb_auth_verify_token(ex->srv->opts.jwt_secret, token, &claims)) {
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
    if (sb_streq(ex->claims.role, "viewer") && !safe_method(ex->method)) {
        wire_error(w, 403, "Viewer role is read-only");
        return false;
    }
    ex->req.claims = &ex->claims;
    return true;
}

/* Post-handling advice: audit successful unsafe requests of authenticated users. */
static void audit_advice(const http_exchange *ex, int status) {
    if (safe_method(ex->method) || !ex->req.claims || status < 200 || status >= 300) return;
    sb_err e = {0};
    if (sb_store_record_audit(ex->srv->store, ex->claims.username ? ex->claims.username : "",
                              method_names[ex->method], ex->path, &e) != 0)
        SB_ERROR("audit write failed: %s", e.msg);
}

/* ---- handler invocation --------------------------------------------------- */

static void resp_release(sb_http_resp *resp) {
    sbj_free(resp->json);
    free(resp->body);
    free(resp->content_type);
    sb_strvec_free(&resp->headers);
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
    for (size_t i = 0; i < resp->headers.len; ++i) {
        const char *line = resp->headers.items[i];
        const char *colon = strchr(line, ':');
        if (!colon) continue;
        char *name = sb_strndup(line, (size_t)(colon - line));
        char *trimmed_name = sb_http_trim(name);
        char *value = sb_http_trim(colon + 1);
        if (strcasecmp(trimmed_name, "content-type") == 0) sb_str_set(&w->content_type, value);
        else if (strcasecmp(trimmed_name, "content-length") != 0) wire_set_header(w, trimmed_name, value);
        free(name);
        free(trimmed_name);
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
    for (size_t i = 0; i < w->names.len; ++i) sb_buf_printf(&out, "%s: %s\r\n", w->names.items[i], w->values.items[i]);
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
    sb_http_register_proxy_routes(srv);
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
                            "keep_alive_timeout_ms", "15000",
                            "request_timeout_ms", "60000",
                            "tcp_nodelay", "1",
                            "max_request_size", "131072",
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
    sb_http_register_clash_websocket(srv);
    return srv->bound_port;
}

uint16_t sb_http_server_port(const sb_http_server *srv) {
    if (!srv) return 0;
    return srv->mg ? srv->bound_port : srv->opts.port;
}

void sb_http_server_stop(sb_http_server *srv) {
    if (!srv || !srv->mg) return;
    srv->stopping = 1;
    mg_stop(srv->mg);
    srv->mg = NULL;
}

void sb_http_server_free(sb_http_server *srv) {
    if (!srv) return;
    sb_http_server_stop(srv);
    self_singbox_join(srv);
    pthread_mutex_lock(&g_sink_owner_mutex);
    if (g_sink_owner == srv) {
        sb_log_set_sink(NULL, NULL);
        g_sink_owner = NULL;
    }
    pthread_mutex_unlock(&g_sink_owner_mutex);
    if (srv->wireguard) sb_wireguard_free(srv->wireguard);
    if (srv->clash) sb_clash_client_free(srv->clash);
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

/* ---- managed self sing-box (run_self_singbox) ------------------------------ */

static bool self_singbox_stop_requested(sb_http_server *srv) {
    pthread_mutex_lock(&srv->self_singbox_mutex);
    bool stop = srv->self_singbox_stop;
    pthread_mutex_unlock(&srv->self_singbox_mutex);
    return stop;
}

/* capabilities.value("runs_singbox", false) with nlohmann's type errors. */
static int capability_flag(const sbj *capabilities, const char *key, bool *out, sb_err *err) {
    if (!sbj_is_object(capabilities))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(capabilities));
    const sbj *value = sbj_get(capabilities, key);
    if (!value) {
        *out = false;
        return 0;
    }
    if (!sbj_is_bool(value))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be boolean, but is %s",
                       sbj_type_name(value));
    *out = value->v.b;
    return 0;
}

/* One iteration of the C++ loop body up to (not including) ensure_alive().
 * Returns -1 with err set where the C++ code would throw. */
static int self_singbox_render(sb_http_server *srv, sb_singbox_supervisor *supervisor, char **last_etag,
                               sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int found = sb_store_find_host(srv->store, "self", &host, err);
    int rc = found < 0 ? -1 : 0;
    bool runs = false;
    if (found == 1 && host.enabled && capability_flag(host.capabilities, "runs_singbox", &runs, err) != 0) rc = -1;
    if (rc == 0 && found == 1 && host.enabled && runs) {
        sb_render_request request;
        sb_render_request_init(&request);
        sb_config_renderer renderer;
        sbj *config = NULL;
        char *body = NULL, *etag = NULL;
        rc = -1;
        if (sb_store_render_request_for_host(srv->store, "self", &request, err) == 0) {
            free(request.clash_controller);
            request.clash_controller = sb_http_clash_controller_address(srv->opts.clash_api_url);
            sb_str_set(&request.clash_secret, srv->opts.clash_api_secret);
            if (sb_config_renderer_init(&renderer, NULL, err) == 0 &&
                (config = sb_config_renderer_render(&renderer, &request, err)) != NULL) {
                body = sbj_dump(config, 2);
                etag = sb_config_etag("self", body, srv->opts.config_hash_seed);
                if (!etag) {
                    sb_fail(err, SB_ERR_GENERIC, "config ETag hashing failed");
                } else if (*last_etag && strcmp(*last_etag, etag) == 0) {
                    rc = 0;
                } else if (sb_singbox_supervisor_apply_config(supervisor, body, strlen(body), err) == 0) {
                    free(*last_etag);
                    *last_etag = sb_strdup(etag);
                    SB_INFO("managed sing-box config applied: %s", etag);
                    rc = 0;
                }
            }
        }
        free(etag);
        free(body);
        sbj_free(config);
        sb_render_request_free(&request);
    }
    sb_host_free(&host);
    return rc;
}

static void *self_singbox_main(void *arg) {
    sb_http_server *srv = arg;
    const sb_http_server_options *o = &srv->opts;
    char *config_path = sb_http_trim(o->self_singbox_config_path);
    if (!*config_path) sb_str_set(&config_path, "data/sing-box.gen.json");
    sb_singbox_supervisor_options so;
    sb_singbox_supervisor_options_init(&so);
    so.binary = o->singbox_binary;
    so.config_path = config_path;
    so.validate_config = o->singbox_validate_config;
    sb_err e = {0};
    sb_singbox_supervisor *supervisor = sb_singbox_supervisor_new(&so, &e);
    if (!supervisor) {
        /* C++ would terminate here (exception escaping the jthread). */
        SB_ERROR("managed sing-box cycle failed: %s", e.msg);
        free(config_path);
        return NULL;
    }
    uint64_t interval = o->self_singbox_interval_seconds < 2 ? 2 : o->self_singbox_interval_seconds;
    SB_INFO("managed sing-box enabled: binary=%s config=%s interval=%llus", o->singbox_binary, config_path,
            (unsigned long long)interval);
    char *last_etag = NULL, *logged_error = NULL;
    while (!self_singbox_stop_requested(srv)) {
        sb_err_clear(&e);
        if (self_singbox_render(srv, supervisor, &last_etag, &e) == 0) {
            sb_singbox_supervisor_ensure_alive(supervisor);
            const char *last_error = sb_singbox_supervisor_last_error(supervisor);
            if (last_error && !sb_streq(last_error, logged_error)) {
                SB_ERROR("%s", last_error);
                sb_str_set(&logged_error, last_error);
            } else if (!last_error) {
                free(logged_error);
                logged_error = NULL;
            }
        } else if (!sb_streq(logged_error, e.msg)) {
            SB_ERROR("managed sing-box cycle failed: %s", e.msg);
            sb_str_set(&logged_error, e.msg);
        }
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += (time_t)interval;
        pthread_mutex_lock(&srv->self_singbox_mutex);
        while (!srv->self_singbox_stop &&
               pthread_cond_timedwait(&srv->self_singbox_wakeup, &srv->self_singbox_mutex, &deadline) != ETIMEDOUT) {
        }
        pthread_mutex_unlock(&srv->self_singbox_mutex);
    }
    sb_singbox_supervisor_stop(supervisor);
    sb_singbox_supervisor_free(supervisor);
    free(last_etag);
    free(logged_error);
    free(config_path);
    return NULL;
}

static int self_singbox_start(sb_http_server *srv, sb_err *err) {
    srv->self_singbox_stop = false;
    if (pthread_create(&srv->self_singbox_thread, NULL, self_singbox_main, srv) != 0)
        return sb_fail(err, SB_ERR_GENERIC, "could not start the managed sing-box thread");
    srv->self_singbox_running = true;
    return 0;
}

static void self_singbox_request_stop(sb_http_server *srv) {
    if (!srv->self_singbox_running) return;
    pthread_mutex_lock(&srv->self_singbox_mutex);
    srv->self_singbox_stop = true;
    pthread_cond_broadcast(&srv->self_singbox_wakeup);
    pthread_mutex_unlock(&srv->self_singbox_mutex);
}

static void self_singbox_join(sb_http_server *srv) {
    if (!srv->self_singbox_running) return;
    self_singbox_request_stop(srv);
    pthread_join(srv->self_singbox_thread, NULL);
    srv->self_singbox_running = false;
}

/* ---- run_http_server ---------------------------------------------------------- */

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
