/* Shared helpers for the panel HTTP contract tests (port of the harness in
 * cpp/tests/http_server_test.cpp): a temporary database + static directory,
 * an in-process server on an ephemeral port, JWT minting, a request helper
 * that captures the headers the contract checks, and a tiny scripted HTTP
 * fixture server used as a fake subscription source / Clash API.
 *
 * Header-only; include after test.h. Link against sb_core. */
#ifndef SB_HTTP_TEST_SUPPORT_H
#define SB_HTTP_TEST_SUPPORT_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sb/auth.h"
#include "sb/http_client.h"
#include "sb/http_server.h"
#include "sb/json.h"
#include "sb/store.h"
#include "sb/util.h"

#define SB_TEST_UNUSED __attribute__((unused))

/* ---- temporary files -------------------------------------------------- */

typedef struct {
    char *dir;        /* mkdtemp directory holding everything below */
    char *db_path;
    char *static_dir; /* index.html, assets/contract.js, downloads/ */
} sb_test_env;

SB_TEST_UNUSED static void sb_test_env_init(sb_test_env *env) {
    char tmpl[] = "/tmp/sb-easy-c-http-XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) abort();
    env->dir = sb_strdup(dir);
    env->db_path = sb_path_join(env->dir, "sb-easy.db");
    env->static_dir = sb_path_join(env->dir, "static");
    char *assets = sb_path_join(env->static_dir, "assets");
    char *downloads = sb_path_join(env->static_dir, "downloads");
    sb_mkdirs(assets, 0755);
    sb_mkdirs(downloads, 0755);
    char *index = sb_path_join(env->static_dir, "index.html");
    const char *html = "<!doctype html><title>sb-easy contract</title>";
    sb_write_file(index, html, strlen(html));
    char *asset = sb_path_join(assets, "contract.js");
    const char *js = "window.sbEasyContract = true;\n";
    sb_write_file(asset, js, strlen(js));
    free(asset);
    free(index);
    free(assets);
    free(downloads);
}

SB_TEST_UNUSED static void sb_test_env_free(sb_test_env *env) {
    if (env->dir) {
        char *cmd = sb_asprintf("rm -rf '%s'", env->dir);
        if (system(cmd) != 0) {
        }
        free(cmd);
    }
    free(env->dir);
    free(env->db_path);
    free(env->static_dir);
    memset(env, 0, sizeof *env);
}

SB_TEST_UNUSED static const char *sb_test_migrations_dir(void) {
    return sb_getenv_or("SB_EASY_MIGRATIONS", "migrations");
}

/* ---- in-process panel server ------------------------------------------ */

typedef struct {
    sb_test_env env;
    sb_store *store;
    sb_http_server *server;
    uint16_t port;
    char *base_url;   /* "http://127.0.0.1:<port>" */
    char *jwt_secret; /* copy of options.jwt_secret */
    char *token;      /* admin bearer token, sent by default */
} sb_test_server;

/* Mirrors run_contract()'s options. `customize` (optional) may adjust the
 * options (e.g. clash_api_url pointing at a fixture) before the server is
 * built; `prepare` (optional) runs against the opened store first (e.g. to
 * create hosts the options refer to). Returns 0 on success. */
typedef void (*sb_test_customize_fn)(sb_http_server_options *options, void *user);
typedef void (*sb_test_prepare_fn)(sb_store *store, void *user);

SB_TEST_UNUSED static int sb_test_server_start_ex(sb_test_server *t, sb_test_prepare_fn prepare,
                                                  sb_test_customize_fn customize, void *user) {
    memset(t, 0, sizeof *t);
    sb_test_env_init(&t->env);
    sb_err err = {0};
    t->store = sb_store_open(t->env.db_path, sb_test_migrations_dir(), &err);
    if (!t->store) {
        fprintf(stderr, "store open failed: %s\n", err.msg);
        return -1;
    }
    if (prepare) prepare(t->store, user);
    sb_http_server_options options;
    sb_http_server_options_init(&options);
    sb_str_set(&options.address, "127.0.0.1");
    options.port = 0;
    sb_str_set(&options.public_server, "https://panel.example.com");
    sb_str_set(&options.config_hash_seed, "contract-seed");
    sb_str_set(&options.legacy_agent_token, "legacy-self-token");
    sb_str_set(&options.jwt_secret, "contract-jwt-secret");
    sb_str_set(&options.admin_password, "contract-admin-password");
    sb_str_set(&options.clash_api_url, "http://127.0.0.1:9/local");
    sb_str_set(&options.clash_api_secret, "local-secret");
    sb_str_set(&options.external_hostname, "vpn.example.com");
    sb_str_set(&options.static_directory, t->env.static_dir);
    sb_str_set(&options.cors_origins, "https://allowed.example");
    sb_str_set(&options.log_level, "warn");
    if (customize) customize(&options, user);
    t->jwt_secret = sb_strdup(options.jwt_secret);
    t->server = sb_http_server_new(t->store, &options, &err);
    sb_http_server_options_free(&options);
    if (!t->server) {
        fprintf(stderr, "server creation failed: %s\n", err.msg);
        return -1;
    }
    /* sb_http_server_start returns the bound port (> 0) or -1. */
    if (sb_http_server_start(t->server, &err) < 0) {
        fprintf(stderr, "server start failed: %s\n", err.msg);
        return -1;
    }
    t->port = sb_http_server_port(t->server);
    t->base_url = sb_asprintf("http://127.0.0.1:%u", (unsigned)t->port);
    sb_user_account admin;
    sb_user_account_init(&admin);
    if (sb_store_find_user_by_username(t->store, "admin", &admin, &err) == 1)
        t->token = sb_auth_create_token(t->jwt_secret, admin.id, admin.username, admin.role);
    sb_user_account_free(&admin);
    return t->token ? 0 : -1;
}

SB_TEST_UNUSED static int sb_test_server_start(sb_test_server *t) {
    return sb_test_server_start_ex(t, NULL, NULL, NULL);
}

SB_TEST_UNUSED static void sb_test_server_stop(sb_test_server *t) {
    if (t->server) {
        sb_http_server_stop(t->server);
        sb_http_server_free(t->server);
    }
    if (t->store) sb_store_free(t->store);
    sb_test_env_free(&t->env);
    free(t->base_url);
    free(t->jwt_secret);
    free(t->token);
    memset(t, 0, sizeof *t);
}

/* Mints a token for an arbitrary identity (e.g. a viewer). malloc'd. */
SB_TEST_UNUSED static char *sb_test_token(sb_test_server *t, const char *user_id, const char *username,
                                          const char *role) {
    return sb_auth_create_token(t->jwt_secret, user_id, username, role);
}

/* ---- requests ----------------------------------------------------------- */

typedef struct {
    long status;
    char *body;  /* raw body */
    size_t body_len;
    sbj *json;   /* parsed body, NULL when empty or not JSON */
    char *etag, *content_type, *content_disposition, *cache_control;
    char *allow_origin; /* Access-Control-Allow-Origin */
    char *rule_source, *profile_id, *profile_name; /* X-SB-Easy-* */
    char *headers; /* raw header block */
} sb_test_response;

SB_TEST_UNUSED static void sb_test_response_free(sb_test_response *r) {
    free(r->body);
    sbj_free(r->json);
    free(r->etag);
    free(r->content_type);
    free(r->content_disposition);
    free(r->cache_control);
    free(r->allow_origin);
    free(r->rule_source);
    free(r->profile_id);
    free(r->profile_name);
    free(r->headers);
    memset(r, 0, sizeof *r);
}

/* Header lookup on a finished response (case-insensitive). malloc'd/NULL. */
SB_TEST_UNUSED static char *sb_test_response_header(const sb_test_response *r, const char *name) {
    sb_http_response tmp = {0};
    tmp.headers = r->headers;
    return sb_http_response_header(&tmp, name);
}

/* token: NULL -> the default admin token, "" -> no Authorization header.
 * headers: optional NULL-terminated "Name: value" list. body: JSON text or
 * any payload (sent as application/json), NULL for none.
 * Returns 0 when a response arrived; transport failures abort the test. */
SB_TEST_UNUSED static int sb_test_request_ex(sb_test_server *t, const char *method, const char *path,
                                             const char *body, const char *token,
                                             const char *const *headers, sb_test_response *out) {
    memset(out, 0, sizeof *out);
    const char *tok = token ? token : t->token;
    sb_strvec hv = {0};
    if (tok && *tok) sb_strvec_push_take(&hv, sb_asprintf("Authorization: Bearer %s", tok));
    if (body) sb_strvec_push(&hv, "Content-Type: application/json");
    for (const char *const *h = headers; h && *h; ++h) sb_strvec_push(&hv, *h);
    sb_strvec_push_take(&hv, NULL);
    char *url = sb_asprintf("%s%s", t->base_url, path);
    sb_http_request req = {0};
    req.method = method;
    req.url = url;
    req.headers = (const char *const *)hv.items;
    req.body = body;
    req.body_len = body ? strlen(body) : 0;
    req.timeout_ms = 10000;
    req.max_body_bytes = 64u * 1024u * 1024u;
    sb_http_response resp;
    sb_err err = {0};
    int rc = sb_http_perform(&req, &resp, &err);
    free(url);
    sb_strvec_free(&hv);
    if (rc != 0) {
        fprintf(stderr, "request %s %s failed: %s\n", method, path, err.msg);
        abort();
    }
    out->status = resp.status;
    out->body = resp.body;
    out->body_len = resp.body_len;
    resp.body = NULL;
    out->headers = resp.headers;
    resp.headers = NULL;
    out->etag = resp.etag;
    resp.etag = NULL;
    out->content_type = resp.content_type;
    resp.content_type = NULL;
    sb_http_response_free(&resp);
    out->content_disposition = sb_test_response_header(out, "Content-Disposition");
    out->cache_control = sb_test_response_header(out, "Cache-Control");
    out->allow_origin = sb_test_response_header(out, "Access-Control-Allow-Origin");
    out->rule_source = sb_test_response_header(out, "X-SB-Easy-Rule-Source");
    out->profile_id = sb_test_response_header(out, "X-SB-Easy-Profile-Id");
    out->profile_name = sb_test_response_header(out, "X-SB-Easy-Profile-Name");
    if (out->body_len) out->json = sbj_parse(out->body, out->body_len, NULL, 0);
    return 0;
}

SB_TEST_UNUSED static int sb_test_request(sb_test_server *t, const char *method, const char *path,
                                          const char *body, sb_test_response *out) {
    return sb_test_request_ex(t, method, path, body, NULL, NULL, out);
}

/* JSON body built from an sbj value (consumed). */
SB_TEST_UNUSED static int sb_test_request_json(sb_test_server *t, const char *method, const char *path,
                                               sbj *body, sb_test_response *out) {
    char *text = body ? sbj_dump(body, -1) : NULL;
    sbj_free(body);
    int rc = sb_test_request_ex(t, method, path, text, NULL, NULL, out);
    free(text);
    return rc;
}

/* ---- scripted fixture server ------------------------------------------ */

/* One request as seen by the fixture. */
typedef struct {
    char *method, *target, *headers, *body; /* target = path + query */
    size_t body_len;
} sb_fixture_request;

/* Produces the full raw HTTP response (status line, headers, body) for a
 * request; malloc'd. The fixture always adds nothing: include
 * Content-Length and "Connection: close" yourself (sb_fixture_response). */
typedef char *(*sb_fixture_handler)(const sb_fixture_request *req, void *user);

typedef struct {
    int listener;
    uint16_t port;
    pthread_t thread;
    sb_fixture_handler handler;
    void *user;
    volatile int stop;
    pthread_mutex_t mutex;
    sb_strvec seen; /* "METHOD target" of every request, in order */
} sb_fixture;

/* Formats a complete response with Content-Length and Connection: close. */
SB_TEST_UNUSED static char *sb_fixture_response(int status, const char *content_type, const char *body) {
    const char *reason = status == 200 ? "OK" : status == 204 ? "No Content" : status == 404 ? "Not Found"
                         : status == 401 ? "Unauthorized" : status == 500 ? "Internal Server Error" : "Status";
    return sb_asprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                       status, reason, content_type ? content_type : "application/json", strlen(body ? body : ""),
                       body ? body : "");
}

SB_TEST_UNUSED static void sb_fixture_request_free(sb_fixture_request *r) {
    free(r->method);
    free(r->target);
    free(r->headers);
    free(r->body);
}

SB_TEST_UNUSED static void *sb_fixture_main(void *arg) {
    sb_fixture *f = arg;
    while (!f->stop) {
        int c = accept(f->listener, NULL, NULL);
        if (c < 0) {
            if (f->stop) break;
            continue;
        }
        sb_buf in = {0};
        char chunk[8192];
        size_t header_end = 0, content_length = 0;
        for (;;) {
            ssize_t n = recv(c, chunk, sizeof chunk, 0);
            if (n <= 0) break;
            sb_buf_append(&in, chunk, (size_t)n);
            if (!header_end) {
                char *e = strstr(in.p, "\r\n\r\n");
                if (e) {
                    header_end = (size_t)(e - in.p) + 4;
                    for (char *l = in.p; l && l < e; l = strstr(l, "\r\n") ? strstr(l, "\r\n") + 2 : NULL)
                        if (strncasecmp(l, "Content-Length:", 15) == 0) content_length = strtoul(l + 15, NULL, 10);
                }
            }
            if (header_end && in.len >= header_end + content_length) break;
        }
        if (header_end) {
            sb_fixture_request req = {0};
            char *sp1 = strchr(in.p, ' ');
            char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
            req.method = sp1 ? sb_strndup(in.p, (size_t)(sp1 - in.p)) : sb_strdup("");
            req.target = (sp1 && sp2) ? sb_strndup(sp1 + 1, (size_t)(sp2 - sp1 - 1)) : sb_strdup("");
            req.headers = sb_strndup(in.p, header_end);
            req.body_len = in.len - header_end;
            req.body = sb_strndup(in.p + header_end, req.body_len);
            pthread_mutex_lock(&f->mutex);
            sb_strvec_push_take(&f->seen, sb_asprintf("%s %s", req.method, req.target));
            pthread_mutex_unlock(&f->mutex);
            char *out = f->handler(&req, f->user);
            if (out) {
                size_t len = strlen(out), off = 0;
                while (off < len) {
                    ssize_t w = send(c, out + off, len - off, MSG_NOSIGNAL);
                    if (w <= 0) break;
                    off += (size_t)w;
                }
                free(out);
            }
            sb_fixture_request_free(&req);
        }
        sb_buf_free(&in);
        shutdown(c, SHUT_RDWR);
        close(c);
    }
    return NULL;
}

SB_TEST_UNUSED static int sb_fixture_start(sb_fixture *f, sb_fixture_handler handler, void *user) {
    memset(f, 0, sizeof *f);
    f->handler = handler;
    f->user = user;
    pthread_mutex_init(&f->mutex, NULL);
    f->listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (f->listener < 0) return -1;
    int one = 1;
    setsockopt(f->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(f->listener, (struct sockaddr *)&a, sizeof a) != 0 || listen(f->listener, 16) != 0) return -1;
    socklen_t len = sizeof a;
    getsockname(f->listener, (struct sockaddr *)&a, &len);
    f->port = ntohs(a.sin_port);
    return pthread_create(&f->thread, NULL, sb_fixture_main, f) == 0 ? 0 : -1;
}

SB_TEST_UNUSED static void sb_fixture_stop(sb_fixture *f) {
    f->stop = 1;
    shutdown(f->listener, SHUT_RDWR);
    close(f->listener);
    pthread_join(f->thread, NULL);
    sb_strvec_free(&f->seen);
    pthread_mutex_destroy(&f->mutex);
}

/* True when the fixture has seen a request line starting with `prefix`
 * (e.g. "GET /remote/proxies"). */
SB_TEST_UNUSED static bool sb_fixture_saw(sb_fixture *f, const char *prefix) {
    bool found = false;
    pthread_mutex_lock(&f->mutex);
    for (size_t i = 0; i < f->seen.len && !found; ++i) found = sb_starts_with(f->seen.items[i], prefix);
    pthread_mutex_unlock(&f->mutex);
    return found;
}

#endif
