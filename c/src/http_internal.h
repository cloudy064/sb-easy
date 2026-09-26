/* Internal contract for the panel HTTP server (port of cpp/src/http_server.cpp
 * + clash_websocket.cpp). civetweb provides sockets/threads; this layer adds
 * the Drogon behaviours the C++ server relied on: routing with {param}
 * segments, pre-routing CORS preflight + JWT auth advice, post-handling audit,
 * pre-sending CORS headers, exception-kind -> status mapping, static files and
 * SPA fallback.
 *
 * File ownership:
 *   http_server.c        core: this framework, sb_http_server_new/run/free,
 *                        error mapping, auth/CORS/audit advice, static/SPA,
 *                        managed self sing-box loop (run_self_singbox),
 *                        telemetry store, log ring, shared helpers below.
 *   http_routes_admin.c  /api/health, /api/system/..., /api/auth/..., /api/users*,
 *                        /api/settings*, /api/wireguard/..., /api/one-time/...,
 *                        /api/config/sing-box/...
 *   http_routes_hosts.c  /api/hosts*, /api/devices/..., /api/agent/...
 *   http_routes_proxy.c  /api/proxy/nodes*, /api/subscriptions*,
 *                        /api/sing-box/... (Clash HTTP control)
 *   clash_websocket.c    /api/sing-box/ws/{traffic,logs,connections,memory}
 */
#ifndef SB_HTTP_INTERNAL_H
#define SB_HTTP_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "sb/auth.h"
#include "sb/http_server.h"
#include "sb/store.h"
#include "sb/json.h"
#include "sb/util.h"

struct mg_connection;
struct mg_context;
typedef struct sb_wireguard sb_wireguard;                       /* sb/wireguard.h */
typedef struct sb_clash_client sb_clash_client;                 /* sb/clash_client.h */
typedef struct sb_subscription_fetcher sb_subscription_fetcher; /* sb/subscription_fetcher.h */

/* ---- request / response --------------------------------------------- */

typedef struct sb_http_server sb_http_server;

typedef struct {
    sb_http_server *server;
    struct mg_connection *conn;
    const char *method;      /* "GET", ... (borrowed) */
    const char *path;        /* decoded path without query (borrowed) */
    const char *query;       /* raw query string or NULL (borrowed) */
    const char *body;        /* request body (NUL-terminated), never NULL */
    size_t body_len;
    const char *params[8];   /* {param} values in route order (decoded) */
    size_t param_count;
    sb_auth_claims *claims;  /* set by auth advice for protected routes, else NULL */
    const char *remote_addr; /* borrowed */
    void *core;              /* private to http_server.c (per-request state); NULL in
                              * hand-built requests */
} sb_http_req;

typedef struct {
    int status;              /* default 200 */
    sbj *json;               /* when set, body = compact dump, JSON content type */
    char *body;              /* raw body (used when json == NULL) */
    size_t body_len;
    char *content_type;      /* for raw body; default "text/plain; charset=utf-8" */
    sb_strvec headers;       /* extra "Name: value" lines */
    char *file_path;         /* serve this file instead of body (static) */
    bool immutable;          /* Cache-Control for file responses */
    bool handled;            /* handler wrote directly to the connection (e.g. streaming) */
} sb_http_resp;

/* Handlers return 0 with *resp filled, or -1 with err set; the core maps
 * err->code to a JSON {"error": msg} response exactly like handle_response():
 *   SB_ERR_AUTH 401, SB_ERR_UNAVAILABLE 503, SB_ERR_FORBIDDEN 403,
 *   SB_ERR_NOT_FOUND 404, SB_ERR_CONFLICT 409, SB_ERR_VALIDATION 400,
 *   SB_ERR_SCRIPT 422 {"error","kind":"rule_script"},
 *   SB_ERR_BAD_JSON 400 "Invalid JSON request: <msg>",
 *   anything else 500 {"error":"Internal server error"} (message logged). */
typedef int (*sb_http_handler)(sb_http_req *req, sb_http_resp *resp, sb_err *err);

/* Registers a route. `pattern` uses {name} for single path segments, e.g.
 * "/api/hosts/{id}/config". `methods` is a comma list "GET,POST". Exact
 * routes win over parameterised ones; otherwise first registered wins. */
void sb_http_route(sb_http_server *srv, const char *methods, const char *pattern,
                   sb_http_handler handler);

/* Response helpers (take ownership of `body`). */
void sb_resp_json(sb_http_resp *resp, int status, sbj *body);
void sb_resp_error(sb_http_resp *resp, int status, const char *message);
void sb_resp_text(sb_http_resp *resp, int status, const char *content_type, char *body, size_t len);
void sb_resp_header(sb_http_resp *resp, const char *name, const char *value);

/* Request helpers — port of the C++ helpers with identical messages. */
const char *sb_req_header(const sb_http_req *req, const char *name); /* borrowed or NULL */
char *sb_req_query_param(const sb_http_req *req, const char *name);  /* decoded, malloc'd or NULL */
/* request_object(): "Request body must be a JSON object" on failure. */
sbj *sb_req_json_object(const sb_http_req *req, sb_err *err);
/* required_string(): "<field> must be a non-empty string". Borrowed. */
const char *sb_json_required_string(const sbj *body, const char *field, sb_err *err);
/* required_object(): "<field> must be a JSON object". Borrowed. */
const sbj *sb_json_required_object(const sbj *body, const char *field, sb_err *err);
/* assign_optional_string / assign_string: absent or null leaves *dest
 * untouched; non-string -> "<field> must be a string". */
int sb_json_assign_string(const sbj *body, const char *field, char **dest, sb_err *err);
/* assign_boolean: "<field> must be a boolean". */
int sb_json_assign_bool(const sbj *body, const char *field, bool *dest, sb_err *err);
/* required_string_array: "<field> must be an array" /
 * "<field> must contain only strings". */
int sb_json_required_string_array(const sbj *body, const char *field, sb_strvec *out, sb_err *err);
/* integer_field(): absent -> 0; "<field> must be an integer". */
int sb_json_integer_field(const sbj *body, const char *field, int64_t *out, sb_err *err);
/* require_admin(): SB_ERR_FORBIDDEN "Admin role required". */
int sb_require_admin(const sb_http_req *req, sb_err *err);

/* Store lookups shared by several route groups (C++ require_host,
 * require_profile, require_proxy). `out` must be initialised by the caller.
 * 0 ok, -1 with SB_ERR_NOT_FOUND "Host not found" / "Profile not found" /
 * "Node not found" (or the store's error). */
int sb_http_require_host(sb_http_server *srv, const char *id, sb_host *out, sb_err *err);
int sb_http_require_profile(sb_http_server *srv, const char *id, sb_config_profile *out, sb_err *err);
int sb_http_require_proxy(sb_http_server *srv, const char *id, sb_proxy_record *out, sb_err *err);
/* sync_wireguard_best_effort(): sb_wireguard_sync, logging
 * "WireGuard sync failed: <msg>" at error level instead of failing. */
void sb_http_sync_wireguard_best_effort(sb_http_server *srv);

/* Misc helpers from the C++ anonymous namespace. */
char *sb_http_trim(const char *s);
char *sb_http_trim_trailing_slashes(const char *s);
char *sb_http_clash_controller_address(const char *url);
char *sb_http_encode_component(const char *s);
char *sb_http_secure_token(size_t bytes);
char *sb_http_utc_now(void); /* "%Y-%m-%dT%H:%M:%SZ" */
char *sb_http_truncate_utf8(const char *s, size_t max_bytes);

/* ---- shared server state -------------------------------------------- */

/* Handlers run on civetweb worker threads and may block (subscription
 * fetches, Clash calls, latency tests), unlike Drogon's async handlers, so the
 * core starts a worker pool of max(opts.threads, 32) threads. Everything in
 * this struct is shared by those threads: the store serialises internally,
 * the clients are thread-safe, and the mutable maps below have mutexes. */
struct sb_http_server {
    sb_http_server_options opts;      /* owned copy */
    sb_store *store;                  /* borrowed */
    sb_wireguard *wireguard;          /* owned */
    sb_clash_client *clash;           /* owned; shared ClashClient */
    sb_subscription_fetcher *fetcher; /* owned; shared SubscriptionFetcher */
    char *enrollment_server;     /* normalised public URL (see register_http_routes) */
    char *legacy_agent_token;    /* trimmed AGENT_TOKEN */

    /* TelemetryStore: host id -> telemetry JSON object. */
    pthread_mutex_t telemetry_mutex;
    sbj *telemetry;

    /* ServerLogBuffer: last 1000 non-empty lines. */
    pthread_mutex_t log_mutex;
    sb_strvec log_lines;
    size_t log_head; /* ring start when log_lines.len == capacity */

    /* CORS policy. */
    bool cors_wildcard;
    sb_strvec cors_origins;

    /* Router table (private to http_server.c). */
    void *routes;
    size_t route_count, route_cap;

    struct mg_context *mg;
    pthread_t self_singbox_thread;
    bool self_singbox_running;
    volatile int stopping;
};

/* default_telemetry(), normalize_telemetry(), normalize_diagnostic_report(). */
sbj *sb_http_default_telemetry(void);
sbj *sb_http_normalize_telemetry(const sbj *body, sb_err *err);
sbj *sb_http_normalize_diagnostic_report(const sbj *body, sb_err *err);
void sb_http_telemetry_put(sb_http_server *srv, const char *host_id, sbj *telemetry);
sbj *sb_http_telemetry_get(sb_http_server *srv, const char *host_id); /* clone */
sbj *sb_http_log_lines(sb_http_server *srv); /* JSON array of strings (clone) */

/* Route group registration (each implemented in its own file). */
void sb_http_register_admin_routes(sb_http_server *srv);
void sb_http_register_hosts_routes(sb_http_server *srv);
void sb_http_register_proxy_routes(sb_http_server *srv);
/* WebSocket bridge: registered on the civetweb context by the core after
 * mg_start (needs srv->mg). */
void sb_http_register_clash_websocket(sb_http_server *srv);

#endif
