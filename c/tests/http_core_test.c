/* HTTP core tests: the Drogon behaviours reproduced by c/src/http_server.c
 * (routing, advices, error mapping, static files, SPA fallback, HEAD, body
 * limits, concurrency, log ring) plus the shared helpers from
 * http_internal.h. Test-only routes are registered with sb_http_route. */
#include "test.h"

#include "http_test_support.h"

#include <errno.h>
#include <poll.h>
#include <sys/time.h>

#include "../src/http_internal.h"
#include "civetweb.h"

/* ---- helpers ------------------------------------------------------------- */

static const char *jstr(const sbj *v, const char *key) {
    const sbj *f = sbj_get(v, key);
    return sbj_is_string(f) ? f->v.str.ptr : NULL;
}

#define CHECK_ERROR(resp, code, message)                                                           \
    do {                                                                                           \
        CHECK_EQ_INT((resp)->status, (code));                                                      \
        CHECK_STR((resp)->json ? jstr((resp)->json, "error") : NULL, (message));                   \
    } while (0)

/* HS256 token with an arbitrary expiry (sb_auth_create_token always issues
 * fresh ones). */
static char *mint_token(const char *secret, const char *role, int64_t exp_offset) {
    sbj *header = sbj_object();
    sbj_set_str(header, "alg", "HS256");
    sbj_set_str(header, "typ", "JWT");
    sbj *payload = sbj_object();
    int64_t now = sb_unix_now();
    sbj_set_str(payload, "sub", "user-id");
    sbj_set_str(payload, "username", "minted");
    sbj_set_str(payload, "role", role);
    sbj_set_int(payload, "iat", now);
    sbj_set_int(payload, "exp", now + exp_offset);
    char *h = sbj_dump(header, -1), *p = sbj_dump(payload, -1);
    char *he = sb_base64url_encode((const unsigned char *)h, strlen(h));
    char *pe = sb_base64url_encode((const unsigned char *)p, strlen(p));
    char *signing = sb_asprintf("%s.%s", he, pe);
    unsigned char mac[32];
    sb_hmac_sha256(secret, strlen(secret), signing, strlen(signing), mac);
    char *se = sb_base64url_encode(mac, 32);
    char *token = sb_asprintf("%s.%s", signing, se);
    free(h);
    free(p);
    free(he);
    free(pe);
    free(signing);
    free(se);
    sbj_free(header);
    sbj_free(payload);
    return token;
}

/* Raw HTTP exchange (HEAD, bad methods, oversized bodies): sends `request`
 * verbatim and returns everything read until the peer closes or `timeout_ms`
 * passes without data. */
static char *raw_exchange(uint16_t port, const char *request, size_t request_len, int timeout_ms, size_t *out_len) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof a) != 0) abort();
    size_t off = 0;
    while (off < request_len) {
        ssize_t n = send(fd, request + off, request_len - off, MSG_NOSIGNAL);
        if (n <= 0) break;
        off += (size_t)n;
    }
    sb_buf in = {0};
    char chunk[16384];
    for (;;) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, timeout_ms) <= 0) break;
        ssize_t n = recv(fd, chunk, sizeof chunk, 0);
        if (n <= 0) break;
        sb_buf_append(&in, chunk, (size_t)n);
    }
    close(fd);
    if (out_len) *out_len = in.len;
    return sb_buf_detach(&in);
}

static char *raw_request(sb_test_server *t, const char *method, const char *path, const char *extra_headers) {
    char *req = sb_asprintf("%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: Bearer %s\r\n%s\r\n",
                            method, path, t->token, extra_headers ? extra_headers : "");
    char *resp = raw_exchange(t->port, req, strlen(req), 5000, NULL);
    free(req);
    return resp;
}

/* Value of a header in a raw response head (case-insensitive name). */
static char *raw_header(const char *response, const char *name) {
    const char *end = strstr(response, "\r\n\r\n");
    size_t name_len = strlen(name);
    for (const char *line = strstr(response, "\r\n"); line && (!end || line < end); line = strstr(line + 2, "\r\n")) {
        const char *l = line + 2;
        if (strncasecmp(l, name, name_len) == 0 && l[name_len] == ':') {
            const char *v = l + name_len + 1;
            while (*v == ' ') ++v;
            const char *e = strstr(v, "\r\n");
            return sb_strndup(v, e ? (size_t)(e - v) : strlen(v));
        }
    }
    return NULL;
}

static const char *raw_body(const char *response) {
    const char *end = strstr(response, "\r\n\r\n");
    return end ? end + 4 : "";
}

/* ---- test-only routes ------------------------------------------------------ */

static int h_echo(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)err;
    sbj *out = sbj_object();
    sbj_set_str(out, "method", req->method);
    sbj_set_str(out, "path", req->path);
    sbj *params = sbj_array();
    for (size_t i = 0; i < req->param_count; ++i) sbj_arr_push(params, sbj_str(req->params[i]));
    sbj_set(out, "params", params);
    sbj_set(out, "body", sbj_strn(req->body, req->body_len));
    sbj_set_int(out, "body_len", (int64_t)req->body_len);
    static const char *const names[] = {"a", "b", "host"};
    for (size_t i = 0; i < 3; ++i) {
        char *v = sb_req_query_param(req, names[i]);
        char *key = sb_asprintf("q_%s", names[i]);
        if (v) sbj_set(out, key, sbj_str_take(v));
        free(key);
    }
    const char *custom = sb_req_header(req, "x-custom");
    if (custom) sbj_set_str(out, "x_custom", custom);
    if (req->claims) sbj_set_str(out, "user", req->claims->username);
    sb_resp_json(resp, 200, out);
    return 0;
}

static int h_fail(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    static const struct {
        const char *name;
        sb_code code;
    } kinds[] = {{"auth", SB_ERR_AUTH},         {"unavailable", SB_ERR_UNAVAILABLE}, {"forbidden", SB_ERR_FORBIDDEN},
                 {"not_found", SB_ERR_NOT_FOUND}, {"conflict", SB_ERR_CONFLICT},     {"validation", SB_ERR_VALIDATION},
                 {"script", SB_ERR_SCRIPT},       {"bad_json", SB_ERR_BAD_JSON},     {"generic", SB_ERR_GENERIC},
                 {"io", SB_ERR_IO},               {"upstream", SB_ERR_UPSTREAM}};
    sb_resp_text(resp, 200, NULL, sb_strdup("partial"), 7); /* discarded on failure */
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; ++i)
        if (strcmp(req->params[0], kinds[i].name) == 0) return sb_fail(err, kinds[i].code, "%s message", kinds[i].name);
    return sb_fail(err, SB_ERR_GENERIC, "unknown kind");
}

static int h_text(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)req;
    (void)err;
    sb_resp_text(resp, 201, "text/csv; charset=utf-8", sb_strdup("a,b\n"), 4);
    sb_resp_header(resp, "X-SB-Easy-Profile-Id", "p1");
    sb_resp_header(resp, "Content-Disposition", "attachment; filename=\"x.csv\"");
    return 0;
}

static int h_direct(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)err;
    static const char raw[] = "HTTP/1.1 202 Accepted\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect";
    mg_write(req->conn, raw, sizeof raw - 1);
    resp->handled = true;
    resp->status = 202;
    return 0;
}

static struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int entered;
    bool released;
} g_block = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, false};

static int h_block(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)req;
    (void)err;
    pthread_mutex_lock(&g_block.mutex);
    g_block.entered++;
    pthread_cond_broadcast(&g_block.cond);
    while (!g_block.released) pthread_cond_wait(&g_block.cond, &g_block.mutex);
    pthread_mutex_unlock(&g_block.mutex);
    sb_resp_json(resp, 200, sbj_str("released"));
    return 0;
}

static int h_invalid_utf8(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set_str(body, "name", "bad\xFF");
    sb_resp_json(resp, 200, body);
    return 0;
}

static void register_test_routes(sb_test_server *t) {
    sb_http_route(t->server, "GET,POST,PUT,DELETE,PATCH", "/api/test/echo", h_echo);
    sb_http_route(t->server, "GET", "/api/test/echo/{a}/x/{b}", h_echo);
    sb_http_route(t->server, "POST", "/api/test/fail/{kind}", h_fail);
    sb_http_route(t->server, "GET", "/api/test/text", h_text);
    sb_http_route(t->server, "GET", "/api/test/direct", h_direct);
    sb_http_route(t->server, "GET", "/api/test/invalid-utf8", h_invalid_utf8);
    sb_http_route(t->server, "GET", "/api/test/block", h_block);
    sb_http_route(t->server, "GET", "/api/test/{id}", h_echo);
    sb_http_route(t->server, "POST", "/api/test/{id}/post-only", h_echo);
}

static int start(sb_test_server *t) {
    if (sb_test_server_start(t) != 0) return -1;
    register_test_routes(t);
    return 0;
}

/* ---- CORS ------------------------------------------------------------------ */

TEST(cors_policy) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    const char *allowed[] = {"Origin: https://allowed.example", NULL};
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, NULL, allowed, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.allow_origin, "https://allowed.example");
    char *v = sb_test_response_header(&r, "Access-Control-Allow-Methods");
    CHECK_STR(v, "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    free(v);
    v = sb_test_response_header(&r, "Access-Control-Allow-Headers");
    CHECK_STR(v, "Authorization, Content-Type");
    free(v);
    v = sb_test_response_header(&r, "Access-Control-Expose-Headers");
    CHECK_STR(v, "ETag, Content-Disposition, X-SB-Easy-Rule-Source, X-SB-Easy-Profile-Id, X-SB-Easy-Profile-Name");
    free(v);
    v = sb_test_response_header(&r, "Access-Control-Max-Age");
    CHECK_STR(v, "600");
    free(v);
    v = sb_test_response_header(&r, "Vary");
    CHECK_STR(v, "Origin");
    free(v);
    sb_test_response_free(&r);

    const char *rejected[] = {"Origin: https://rejected.example", NULL};
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, NULL, rejected, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(r.allow_origin == NULL);
    sb_test_response_free(&r);

    /* Preflight completes before JWT authentication and echoes the headers. */
    const char *preflight[] = {"Origin: https://allowed.example", "Access-Control-Request-Method: DELETE",
                               "Access-Control-Request-Headers: authorization,x-custom", NULL};
    sb_test_request_ex(&t, "OPTIONS", "/api/hosts", NULL, "", preflight, &r);
    CHECK_EQ_INT(r.status, 204);
    CHECK_STR(r.allow_origin, "https://allowed.example");
    v = sb_test_response_header(&r, "Access-Control-Allow-Headers");
    CHECK_STR(v, "authorization,x-custom");
    free(v);
    CHECK_EQ_INT(r.body_len, 0);
    sb_test_response_free(&r);

    /* A preflight from a foreign origin is still 204, without CORS headers. */
    const char *foreign[] = {"Origin: https://evil.example", "Access-Control-Request-Method: GET", NULL};
    sb_test_request_ex(&t, "OPTIONS", "/api/hosts", NULL, "", foreign, &r);
    CHECK_EQ_INT(r.status, 204);
    CHECK(r.allow_origin == NULL);
    sb_test_response_free(&r);

    /* Error responses carry CORS headers too (pre-sending advice). */
    sb_test_request_ex(&t, "GET", "/api/hosts", NULL, "", allowed, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    CHECK_STR(r.allow_origin, "https://allowed.example");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

static void wildcard_cors(sb_http_server_options *o, void *user) {
    (void)user;
    sb_str_set(&o->cors_origins, " https://a.example , * ");
}

TEST(cors_wildcard) {
    sb_test_server t;
    REQUIRE(sb_test_server_start_ex(&t, NULL, wildcard_cors, NULL) == 0);
    sb_test_response r;
    const char *origin[] = {"Origin: https://anything.example", NULL};
    sb_test_request_ex(&t, "GET", "/api/test-missing", NULL, NULL, origin, &r);
    CHECK_EQ_INT(r.status, 404);
    CHECK_STR(r.allow_origin, "*");
    char *vary = sb_test_response_header(&r, "Vary");
    CHECK(vary == NULL);
    free(vary);
    sb_test_response_free(&r);
    /* No Origin header: no CORS headers even with the wildcard. */
    sb_test_request(&t, "GET", "/api/test-missing", NULL, &r);
    CHECK(r.allow_origin == NULL);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ---- authentication advice --------------------------------------------------- */

TEST(auth_advice) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, "", NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, "not-a-jwt", NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    char *expired = mint_token(t.jwt_secret, "admin", -60);
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, expired, NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    free(expired);
    char *foreign = mint_token("another-secret", "admin", 600);
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, foreign, NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    free(foreign);
    /* "Bearer " is case-sensitive, like the C++ bearer_token(). */
    char *lower = sb_asprintf("Authorization: bearer %s", t.token);
    const char *lower_headers[] = {lower, NULL};
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, "", lower_headers, &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);
    free(lower);

    /* Valid token: claims reach the handler. */
    sb_test_request(&t, "GET", "/api/test/echo", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "user"), "admin");
    sb_test_response_free(&r);

    /* Public paths skip authentication (the handler sees no claims). */
    sb_http_route(t.server, "GET", "/api/agent/test-public", h_echo);
    sb_test_request_ex(&t, "GET", "/api/agent/test-public", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(jstr(r.json, "user") == NULL);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/auth/login", "not json", "", NULL, &r);
    CHECK_ERROR(&r, 400, "Request body must be a JSON object");
    sb_test_response_free(&r);
    /* "/api" (no slash) is not under /api/: catch-all 404 without a token. */
    sb_test_request_ex(&t, "GET", "/api", NULL, "", NULL, &r);
    CHECK_ERROR(&r, 404, "API route not found");
    sb_test_response_free(&r);
    /* Case variants of /api/ are protected too (Drogon routes them). */
    sb_test_request_ex(&t, "GET", "/API/test/echo", NULL, "", NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);

    /* Viewers are read-only: GET/HEAD fine, unsafe methods 403. */
    char *viewer = sb_test_token(&t, "viewer-id", "viewer1", "viewer");
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, viewer, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "user"), "viewer1");
    sb_test_response_free(&r);
    static const char *const unsafe[] = {"POST", "PUT", "DELETE", "PATCH"};
    for (size_t i = 0; i < 4; ++i) {
        sb_test_request_ex(&t, unsafe[i], "/api/test/echo", "{}", viewer, NULL, &r);
        CHECK_ERROR(&r, 403, "Viewer role is read-only");
        sb_test_response_free(&r);
    }
    free(viewer);

    /* Clash WebSocket paths authenticate with ?token= only. */
    sb_test_request_ex(&t, "GET", "/api/sing-box/ws/traffic", NULL, NULL, NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    char *ws = sb_asprintf("/api/sing-box/ws/logs?level=info&token=%%20%s%%20", t.token);
    sb_test_request_ex(&t, "GET", ws, NULL, "", NULL, &r);
    CHECK_ERROR(&r, 404, "API route not found");
    sb_test_response_free(&r);
    free(ws);
    sb_test_request_ex(&t, "GET", "/api/sing-box/ws/logs?token=bad", NULL, NULL, NULL, &r);
    CHECK_ERROR(&r, 401, "Invalid or expired token");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ---- post-handling audit ------------------------------------------------------- */

TEST(audit_records_successful_unsafe_requests) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    sb_test_request(&t, "POST", "/api/test/echo", "{}", &r); /* audited */
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    sb_test_request(&t, "DELETE", "/api/test/echo", NULL, &r); /* audited */
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/test/echo", NULL, &r); /* safe */
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/test/fail/validation", "{}", &r); /* 400 */
    CHECK_EQ_INT(r.status, 400);
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/nope", "{}", &r); /* catch-all 404 */
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/test/text", "{}", &r); /* 405 */
    CHECK_EQ_INT(r.status, 405);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/auth/login",
                       "{\"username\":\"admin\",\"password\":\"contract-admin-password\"}", "", NULL, &r);
    CHECK_EQ_INT(r.status, 200); /* public: no claims, no audit */
    sb_test_response_free(&r);
    sb_test_request(&t, "PATCH", "/api/test/echo?x=1", "{}", &r); /* audited, path without query */
    sb_test_response_free(&r);

    sb_audit_entry_vec audit = {0};
    sb_err err = {0};
    REQUIRE(sb_store_list_audit(t.store, 200, &audit, &err) == 0);
    CHECK_EQ_INT(audit.len, 3);
    int post = 0, del = 0, patch = 0;
    for (size_t i = 0; i < audit.len; ++i) {
        CHECK_STR(audit.items[i].actor, "admin");
        CHECK_STR(audit.items[i].target, "/api/test/echo");
        post += sb_streq(audit.items[i].action, "POST");
        del += sb_streq(audit.items[i].action, "DELETE");
        patch += sb_streq(audit.items[i].action, "PATCH");
    }
    CHECK(post == 1 && del == 1 && patch == 1);
    sb_audit_entry_vec_free(&audit);
    sb_test_server_stop(&t);
}

/* ---- error mapping ---------------------------------------------------------------- */

TEST(error_kind_mapping) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    static const struct {
        const char *kind;
        int status;
        const char *error;
    } cases[] = {
        {"auth", 401, "auth message"},
        {"unavailable", 503, "unavailable message"},
        {"forbidden", 403, "forbidden message"},
        {"not_found", 404, "not_found message"},
        {"conflict", 409, "conflict message"},
        {"validation", 400, "validation message"},
        {"script", 422, "script message"},
        {"bad_json", 400, "Invalid JSON request: bad_json message"},
        {"generic", 500, "Internal server error"},
        {"io", 500, "Internal server error"},
        {"upstream", 500, "Internal server error"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        char *path = sb_asprintf("/api/test/fail/%s", cases[i].kind);
        sb_test_response r;
        sb_test_request(&t, "POST", path, "{}", &r);
        CHECK_ERROR(&r, cases[i].status, cases[i].error);
        CHECK_STR(r.content_type, "application/json; charset=utf-8");
        if (strcmp(cases[i].kind, "script") == 0) {
            CHECK_STR(jstr(r.json, "kind"), "rule_script");
            CHECK_EQ_INT(sbj_obj_len(r.json), 2);
        } else {
            CHECK_EQ_INT(sbj_obj_len(r.json), 1);
        }
        sb_test_response_free(&r);
        free(path);
    }
    sb_test_response invalid;
    sb_test_request(&t, "GET", "/api/test/invalid-utf8", NULL, &invalid);
    CHECK_ERROR(&invalid, 400,
                "Invalid JSON request: [json.exception.type_error.316] invalid UTF-8 byte at index 3: 0xFF");
    sb_test_response_free(&invalid);
    sb_test_server_stop(&t);
}

TEST(raw_and_direct_responses) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    sb_test_request(&t, "GET", "/api/test/text", NULL, &r);
    CHECK_EQ_INT(r.status, 201);
    CHECK_STR(r.content_type, "text/csv; charset=utf-8");
    CHECK_STR(r.body, "a,b\n");
    CHECK_STR(r.profile_id, "p1");
    CHECK_STR(r.content_disposition, "attachment; filename=\"x.csv\"");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/test/direct", NULL, &r);
    CHECK_EQ_INT(r.status, 202);
    CHECK_STR(r.body, "direct");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ---- routing ------------------------------------------------------------------------ */

TEST(api_catch_all_every_method) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    static const char *const methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH"};
    for (size_t i = 0; i < 5; ++i) {
        sb_test_response r;
        sb_test_request(&t, methods[i], "/api/definitely/not/here", i ? "{}" : NULL, &r);
        CHECK_ERROR(&r, 404, "API route not found");
        sb_test_response_free(&r);
    }
    char *head = raw_request(&t, "HEAD", "/api/definitely/not/here", NULL);
    CHECK(sb_starts_with(head, "HTTP/1.1 404 Not Found\r\n"));
    char *length = raw_header(head, "content-length");
    CHECK_STR(length, "31");
    CHECK_STR(raw_body(head), "");
    free(length);
    free(head);
    /* OPTIONS never reaches the catch-all: Drogon falls through to its
     * static-file router, whose 404 is an HTML page. */
    char *options = raw_request(&t, "OPTIONS", "/api/definitely/not/here", NULL);
    CHECK(sb_starts_with(options, "HTTP/1.1 404 Not Found\r\n"));
    CHECK_CONTAINS(options, "<title>404 Not Found</title>");
    free(options);
    sb_test_server_stop(&t);
}

TEST(method_rules_like_drogon) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    /* Exact path, unregistered method: 405 with an empty text/html body. */
    sb_test_request(&t, "DELETE", "/api/test/text", NULL, &r);
    CHECK_EQ_INT(r.status, 405);
    CHECK_EQ_INT(r.body_len, 0);
    CHECK_STR(r.content_type, "text/html; charset=utf-8");
    sb_test_response_free(&r);
    /* ... and 403 for OPTIONS (not a preflight: no request-method header). */
    sb_test_request(&t, "OPTIONS", "/api/test/text", NULL, &r);
    CHECK_EQ_INT(r.status, 403);
    sb_test_response_free(&r);
    /* Parameterised routes only match their methods; others fall through. */
    sb_test_request(&t, "GET", "/api/test/abc/post-only", NULL, &r);
    CHECK_ERROR(&r, 404, "API route not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/test/abc/post-only", "{}", &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "path"), "/api/test/abc/post-only");
    sb_test_response_free(&r);
    /* Exact routes win over parameterised ones; {param} may be empty. */
    sb_test_request(&t, "GET", "/api/test/text", NULL, &r);
    CHECK_EQ_INT(r.status, 201);
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/test/", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "path"), "/api/test/");
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "params")), 1);
    CHECK_STR(sbj_as_str(sbj_arr_at(sbj_get(r.json, "params"), 0), NULL), "");
    sb_test_response_free(&r);
    /* Literal segments match case-insensitively. */
    sb_test_request(&t, "GET", "/API/Test/Echo", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "path"), "/API/Test/Echo");
    sb_test_response_free(&r);
    /* An unknown method is rejected by the parser (civetweb: 400); methods
     * civetweb knows but Drogon does not get Drogon's bare 405 + close. */
    int64_t started = sb_monotonic_ms();
    const char *lock_request = "LOCK /api/test/text HTTP/1.1\r\nHost: x\r\n\r\n"; /* keep-alive by default */
    char *lock = raw_exchange(t.port, lock_request, strlen(lock_request), 5000, NULL);
    CHECK_STR(lock, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
    CHECK(sb_monotonic_ms() - started < 2000); /* the server closed the connection */
    free(lock);
    sb_test_server_stop(&t);
}

TEST(percent_encoded_params) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    sb_test_request(&t, "GET", "/api/test/echo/%E4%BD%A0%E5%A5%BD/x/a+b%20c%3F?a=1&a=2&b&host=h%2Bx+y", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    const sbj *params = sbj_get(r.json, "params");
    CHECK_EQ_INT(sbj_arr_len(params), 2);
    CHECK_STR(sbj_as_str(sbj_arr_at(params, 0), NULL), "你好");
    CHECK_STR(sbj_as_str(sbj_arr_at(params, 1), NULL), "a b c?");
    CHECK_STR(jstr(r.json, "path"), "/api/test/echo/你好/x/a b c?");
    CHECK_STR(jstr(r.json, "q_a"), "2");
    CHECK_STR(jstr(r.json, "q_b"), "");
    CHECK_STR(jstr(r.json, "q_host"), "h+x y");
    sb_test_response_free(&r);
    /* %2F is decoded before routing, so it cannot live inside a {param}. */
    sb_test_request(&t, "GET", "/api/test/echo/a%2Fb/x/c", NULL, &r);
    CHECK_ERROR(&r, 404, "API route not found");
    sb_test_response_free(&r);
    /* Form bodies (or bodies without a content type) feed parameters too. */
    static const char *const form_types[] = {"Content-Type: application/x-www-form-urlencoded\r\n", ""};
    for (size_t i = 0; i < 2; ++i) {
        char *form = sb_asprintf("POST /api/test/echo?host=q HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                                 "Authorization: Bearer %s\r\n%sContent-Length: 20\r\n\r\nhost=from+body&a=%%41",
                                 t.token, form_types[i]);
        char *resp = raw_exchange(t.port, form, strlen(form), 3000, NULL);
        CHECK_CONTAINS(resp, "\"q_host\":\"from body\"");
        CHECK_CONTAINS(resp, "\"q_a\":\"A\"");
        free(resp);
        free(form);
    }
    sb_test_request(&t, "POST", "/api/test/echo?host=q", "{\"host\":1}", &r); /* JSON body: query only */
    CHECK_STR(jstr(r.json, "q_host"), "q");
    sb_test_response_free(&r);
    /* Request headers: trimmed, first occurrence wins. */
    const char *custom[] = {"X-Custom: first  ", "X-Custom: second", NULL};
    sb_test_request_ex(&t, "GET", "/api/test/echo", NULL, NULL, custom, &r);
    CHECK_STR(jstr(r.json, "x_custom"), "first");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ---- static files and SPA ------------------------------------------------------------- */

TEST(static_assets_and_spa) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sb_test_response r;
    sb_test_request_ex(&t, "GET", "/assets/contract.js", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "window.sbEasyContract = true;\n");
    CHECK_STR(r.cache_control, "public, max-age=31536000, immutable");
    CHECK_STR(r.content_type, "text/javascript; charset=utf-8");
    sb_test_response_free(&r);
    static const char *const missing[] = {"/assets/missing.js", "/assets/", "/assets/../index.html",
                                          "/assets/%2e%2e/index.html", "/assets/contract.js%00.png",
                                          "/assets/sub/../../index.html"};
    for (size_t i = 0; i < sizeof missing / sizeof missing[0]; ++i) {
        char *resp = raw_request(&t, "GET", missing[i], NULL); /* raw: no client-side dot squashing */
        CHECK(sb_starts_with(resp, "HTTP/1.1 404 Not Found\r\n"));
        CHECK_STR(raw_body(resp), "{\"error\":\"Static resource not found\"}");
        free(resp);
    }
    static const char *const spa[] = {"/", "/devices/example", "/downloads", "/apix", "/x/../../etc/passwd",
                                      "/settings?tab=1"};
    for (size_t i = 0; i < sizeof spa / sizeof spa[0]; ++i) {
        sb_test_request_ex(&t, "GET", spa[i], NULL, "", NULL, &r);
        CHECK_EQ_INT(r.status, 200);
        CHECK_STR(r.body, "<!doctype html><title>sb-easy contract</title>");
        CHECK_STR(r.cache_control, "no-cache");
        CHECK_STR(r.content_type, "text/html; charset=utf-8");
        sb_test_response_free(&r);
    }
    /* /downloads/ is left to Drogon's static router (cwd-relative, fixed
     * file types): APKs are never served and nothing falls back to the SPA. */
    sb_test_request_ex(&t, "GET", "/downloads/sb-easy-android.apk", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 404);
    CHECK_CONTAINS(r.body, "<title>404 Not Found</title>");
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/downloads/missing.txt", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 404);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/downloads/README.md", NULL, "", NULL, &r); /* .md: not a static type */
    CHECK_EQ_INT(r.status, 404);
    sb_test_response_free(&r);
    /* Non-GET methods never reach the SPA fallback. */
    sb_test_request_ex(&t, "POST", "/devices/example", "{}", "", NULL, &r);
    CHECK_EQ_INT(r.status, 404);
    sb_test_response_free(&r);

    /* HEAD: headers of the GET response, no body. */
    char *head = raw_request(&t, "HEAD", "/assets/contract.js", NULL);
    CHECK(sb_starts_with(head, "HTTP/1.1 200 OK\r\n"));
    char *length = raw_header(head, "content-length");
    CHECK_STR(length, "30");
    char *cache = raw_header(head, "cache-control");
    CHECK_STR(cache, "public, max-age=31536000, immutable");
    CHECK_STR(raw_body(head), "");
    free(length);
    free(cache);
    free(head);
    head = raw_request(&t, "HEAD", "/some/page", NULL);
    CHECK(sb_starts_with(head, "HTTP/1.1 200 OK\r\n"));
    CHECK_STR(raw_body(head), "");
    free(head);
    sb_test_server_stop(&t);
}

static void no_index(sb_http_server_options *o, void *user) {
    sb_str_set(&o->static_directory, (const char *)user);
}

TEST(spa_without_index) {
    char tmpl[] = "/tmp/sb-easy-c-empty-XXXXXX";
    char *dir = mkdtemp(tmpl);
    REQUIRE(dir != NULL);
    sb_test_server t;
    REQUIRE(sb_test_server_start_ex(&t, NULL, no_index, dir) == 0);
    sb_test_response r;
    sb_test_request_ex(&t, "GET", "/", NULL, "", NULL, &r);
    CHECK_ERROR(&r, 404, "Static resource not found");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
    rmdir(dir);
}

/* ---- body limits / protocol ------------------------------------------------------------ */

TEST(body_limits_and_expect) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    /* Exactly 1 MiB is accepted. */
    size_t size = 1024u * 1024u;
    char *big = sb_xmalloc(size + 1);
    memset(big, 'x', size);
    big[size] = '\0';
    sb_test_response r;
    sb_test_request(&t, "POST", "/api/test/echo", big, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_get_int(r.json, "body_len", -1), (int64_t)size);
    sb_test_response_free(&r);
    free(big);
    /* One byte more: bare 413 before the body is read. */
    char *req = sb_asprintf("POST /api/test/echo HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\n\r\n", size + 1);
    int64_t started = sb_monotonic_ms();
    char *resp = raw_exchange(t.port, req, strlen(req), 5000, NULL);
    CHECK_STR(resp, "HTTP/1.1 413 Request Entity Too Large\r\nConnection: close\r\n\r\n");
    CHECK(sb_monotonic_ms() - started < 2000); /* closed without draining the body */
    free(resp);
    free(req);
    /* Chunked bodies are limited the same way. */
    sb_buf chunked = {0};
    sb_buf_puts(&chunked, "POST /api/test/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
    char block[65536];
    memset(block, 'y', sizeof block);
    for (int i = 0; i < 17; ++i) {
        sb_buf_printf(&chunked, "%zx\r\n", sizeof block);
        sb_buf_append(&chunked, block, sizeof block);
        sb_buf_puts(&chunked, "\r\n");
    }
    sb_buf_puts(&chunked, "0\r\n\r\n");
    resp = raw_exchange(t.port, chunked.p, chunked.len, 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 413 Request Entity Too Large\r\n"));
    free(resp);
    sb_buf_free(&chunked);
    /* A small chunked body is assembled for the handler. */
    char *small = sb_asprintf("POST /api/test/echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer %s\r\n"
                              "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
                              t.token);
    resp = raw_exchange(t.port, small, strlen(small), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 200 OK\r\n"));
    CHECK_CONTAINS(resp, "\"body\":\"abcde\"");
    free(resp);
    free(small);
    /* Expect: 100-continue gets an interim response; other expectations 417. */
    char *expect = sb_asprintf("POST /api/test/echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer %s\r\n"
                               "Expect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
                               t.token);
    resp = raw_exchange(t.port, expect, strlen(expect), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 100 Continue\r\ncontent-type: text/html; charset=utf-8\r\ndate: "));
    CHECK_CONTAINS(resp, " GMT\r\n\r\nHTTP/1.1 200 OK\r\n");
    free(resp);
    free(expect);
    const char *weird = "POST /api/test/echo HTTP/1.1\r\nHost: x\r\nExpect: tea\r\nContent-Length: 2\r\n\r\nhi";
    resp = raw_exchange(t.port, weird, strlen(weird), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\n\r\n"));
    free(resp);
    sb_test_server_stop(&t);
}

TEST(keep_alive_and_http10) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    /* Two pipelined keep-alive requests on one connection, then a close. */
    char *req = sb_asprintf("GET /api/test/echo HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n\r\n"
                            "HEAD /api/test/echo HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n\r\n"
                            "GET /api/test/text HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer %s\r\n\r\n",
                            t.token, t.token, t.token);
    char *resp = raw_exchange(t.port, req, strlen(req), 5000, NULL);
    const char *second = strstr(resp + 1, "HTTP/1.1 200 OK");
    const char *third = second ? strstr(second + 1, "HTTP/1.1 201 Created") : NULL;
    CHECK(sb_starts_with(resp, "HTTP/1.1 200 OK\r\n"));
    CHECK(second != NULL);
    CHECK(third != NULL);
    if (third) CHECK_CONTAINS(third, "connection: close\r\n");
    free(resp);
    free(req);
    /* HTTP/1.0: status line version follows the request; closes by default. */
    req = sb_asprintf("GET /api/test/echo HTTP/1.0\r\nAuthorization: Bearer %s\r\n\r\n", t.token);
    resp = raw_exchange(t.port, req, strlen(req), 5000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.0 200 OK\r\n"));
    CHECK_CONTAINS(resp, "connection: close\r\n");
    free(resp);
    free(req);
    sb_test_server_stop(&t);
}

/* ---- concurrency -------------------------------------------------------------------------- */

typedef struct {
    sb_test_server *t;
    long status;
} blocked_call;

static void *call_block(void *arg) {
    blocked_call *c = arg;
    sb_test_response r;
    sb_test_request(c->t, "GET", "/api/test/block", NULL, &r);
    c->status = r.status;
    sb_test_response_free(&r);
    return NULL;
}

TEST(handlers_block_concurrently) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    enum { BLOCKERS = 40 };
    pthread_t threads[BLOCKERS];
    blocked_call calls[BLOCKERS];
    g_block.entered = 0;
    g_block.released = false;
    for (int i = 0; i < BLOCKERS; ++i) {
        calls[i].t = &t;
        calls[i].status = 0;
        pthread_create(&threads[i], NULL, call_block, &calls[i]);
    }
    /* All blocking handlers run at once (more than 32 workers)... */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 10;
    pthread_mutex_lock(&g_block.mutex);
    while (g_block.entered < BLOCKERS &&
           pthread_cond_timedwait(&g_block.cond, &g_block.mutex, &deadline) != ETIMEDOUT) {
    }
    int entered = g_block.entered;
    pthread_mutex_unlock(&g_block.mutex);
    CHECK_EQ_INT(entered, BLOCKERS);
    /* ... and other requests are still served meanwhile. */
    int64_t started = sb_monotonic_ms();
    sb_test_response r;
    sb_test_request(&t, "GET", "/api/test/echo", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sb_monotonic_ms() - started < 2000);
    sb_test_response_free(&r);
    pthread_mutex_lock(&g_block.mutex);
    g_block.released = true;
    pthread_cond_broadcast(&g_block.cond);
    pthread_mutex_unlock(&g_block.mutex);
    for (int i = 0; i < BLOCKERS; ++i) {
        pthread_join(threads[i], NULL);
        CHECK_EQ_INT(calls[i].status, 200);
    }
    sb_test_server_stop(&t);
}

/* ---- WebSocket pass-through ------------------------------------------------------------------ */

TEST(websocket_upgrades) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    /* Upgrade on a bridge path goes to the clash_websocket.c handler, which
     * rejects a bad ?token= with the JSON 401 before upgrading. */
    const char *bad = "GET /api/sing-box/ws/traffic?token=bad HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n";
    char *resp = raw_exchange(t.port, bad, strlen(bad), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 401"));
    CHECK_CONTAINS(resp, "{\"error\":\"Invalid or expired token\"}");
    free(resp);
    /* A valid token upgrades (the unreachable upstream is reported in-band). */
    char *good = sb_asprintf("GET /api/sing-box/ws/memory?token=%s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                             "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                             "Sec-WebSocket-Version: 13\r\n\r\n",
                             t.token);
    resp = raw_exchange(t.port, good, strlen(good), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 101 Switching Protocols\r\n"));
    CHECK_CONTAINS(resp, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    free(resp);
    free(good);
    /* Upgrades elsewhere end like Drogon's WebSocket routing: 404 page. */
    char *other = sb_asprintf("GET /api/test/echo HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                              "Authorization: Bearer %s\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                              "Sec-WebSocket-Version: 13\r\n\r\n",
                              t.token);
    resp = raw_exchange(t.port, other, strlen(other), 3000, NULL);
    CHECK(sb_starts_with(resp, "HTTP/1.1 404 Not Found\r\n"));
    CHECK_CONTAINS(resp, "connection: close\r\n");
    CHECK_CONTAINS(resp, "<title>404 Not Found</title>");
    free(resp);
    free(other);
    sb_test_server_stop(&t);
}

/* ---- log ring ----------------------------------------------------------------------------------- */

TEST(server_log_ring) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    SB_WARN("core-test marker line");
    sbj *lines = sb_http_log_lines(t.server);
    bool found = false;
    const sbj *line;
    SBJ_ARR_FOREACH(lines, i, line) found = found || strstr(sbj_as_str(line, ""), "core-test marker line");
    CHECK(found);
    sbj_free(lines);
    for (int i = 0; i < 1200; ++i) SB_WARN("ring line %d", i);
    SB_WARN("multi\n\nline");
    lines = sb_http_log_lines(t.server);
    CHECK_EQ_INT(sbj_arr_len(lines), 1000);
    CHECK(sb_ends_with(sbj_as_str(sbj_arr_at(lines, 0), ""), "ring line 202"));
    CHECK(sb_ends_with(sbj_as_str(sbj_arr_at(lines, 997), ""), "ring line 1199"));
    CHECK_CONTAINS(sbj_as_str(sbj_arr_at(lines, 998), ""), "multi");
    CHECK_STR(sbj_as_str(sbj_arr_at(lines, 999), ""), "line");
    sbj_free(lines);
    sb_test_response r;
    sb_test_request(&t, "GET", "/api/system/logs", NULL, &r);
    if (r.status == 200) CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "lines")), 1000);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
    SB_WARN("after the server is gone"); /* the sink must be detached */
}

/* ---- options / lifecycle ------------------------------------------------------------------------- */

TEST(options_defaults_and_copy) {
    sb_http_server_options o;
    sb_http_server_options_init(&o);
    CHECK_STR(o.address, "127.0.0.1");
    CHECK_EQ_INT(o.port, 51821);
    CHECK_EQ_INT(o.threads, 1);
    CHECK_STR(o.admin_password, "admin");
    CHECK_STR(o.clash_api_url, "http://127.0.0.1:9090");
    CHECK_STR(o.singbox_binary, "sing-box");
    CHECK_EQ_INT(o.self_singbox_interval_seconds, 10);
    CHECK(o.singbox_validate_config);
    CHECK(!o.wireguard_enabled);
    CHECK_EQ_INT(o.wireguard_port, 51820);
    CHECK_STR(o.wireguard_address, "10.59.32.1/24");
    CHECK_EQ_INT(o.wireguard_mtu, 1420);
    CHECK_STR(o.static_directory, "frontend/dist");
    CHECK_STR(o.log_level, "info");
    sb_http_server_options copy;
    sb_str_set(&o.cors_origins, "https://x");
    sb_http_server_options_copy(&copy, &o);
    sb_http_server_options_free(&o);
    CHECK_STR(copy.cors_origins, "https://x");
    CHECK_STR(copy.wireguard_config_directory, "/etc/wireguard");
    sb_http_server_options_free(&copy);
}

typedef struct {
    const char *public_server;
    uint16_t port;
    const char *expected;
} enrollment_case;

TEST(enrollment_server_and_log_level) {
    sb_test_env env;
    sb_test_env_init(&env);
    sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err);
    REQUIRE(store != NULL);
    static const enrollment_case cases[] = {
        {"https://panel.example.com/", 51821, "https://panel.example.com"},
        {"  http://panel.example.com//  ", 51821, "http://panel.example.com"},
        {"panel.example.com", 8443, "http://panel.example.com:8443"},
        {"panel.example.com:9000", 8443, "http://panel.example.com:9000"},
        {"[::1]", 7000, "http://[::1]:7000"},
        {"[::1]:8000", 7000, "http://[::1]:8000"},
        {"", 51821, "http://:51821"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        sb_http_server_options o;
        sb_http_server_options_init(&o);
        sb_str_set(&o.public_server, cases[i].public_server);
        sb_str_set(&o.legacy_agent_token, "  legacy \n");
        sb_str_set(&o.log_level, "WARNING");
        o.port = cases[i].port;
        sb_http_server *srv = sb_http_server_new(store, &o, &err);
        REQUIRE(srv != NULL);
        CHECK_STR(srv->enrollment_server, cases[i].expected);
        CHECK_STR(srv->legacy_agent_token, "legacy");
        sb_http_server_free(srv);
        sb_http_server_options_free(&o);
    }
    sb_http_server_options o;
    sb_http_server_options_init(&o);
    sb_str_set(&o.log_level, "verbose");
    CHECK(sb_http_server_new(store, &o, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "LOG_LEVEL must be trace, debug, info, warn, error, or fatal");
    CHECK(sb_http_server_new(NULL, &o, &err) == NULL);
    CHECK_STR(err.msg, "HTTP store is required");
    sb_http_server_options_free(&o);
    sb_log_set_level(SB_LOG_WARN);
    sb_store_free(store);
    sb_test_env_free(&env);
}

TEST(ephemeral_port_and_restart) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    CHECK(t.port != 0);
    CHECK_EQ_INT(sb_http_server_port(t.server), t.port);
    sb_err err = {0};
    CHECK_EQ_INT(sb_http_server_start(t.server, &err), t.port); /* idempotent */
    sb_http_server_stop(t.server);
    sb_http_server_stop(t.server);
    sb_test_server_stop(&t);
    /* A port already in use is reported, not fatal. */
    sb_test_server first;
    REQUIRE(start(&first) == 0);
    sb_test_env env;
    sb_test_env_init(&env);
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err);
    REQUIRE(store != NULL);
    sb_http_server_options o;
    sb_http_server_options_init(&o);
    o.port = first.port;
    sb_str_set(&o.log_level, "warn");
    sb_http_server *second = sb_http_server_new(store, &o, &err);
    REQUIRE(second != NULL);
    CHECK_EQ_INT(sb_http_server_start(second, &err), -1);
    CHECK_CONTAINS(err.msg, "could not listen on 127.0.0.1:");
    sb_http_server_free(second);
    sb_http_server_options_free(&o);
    sb_store_free(store);
    sb_test_env_free(&env);
    sb_test_server_stop(&first);
}

/* ---- shared helpers ---------------------------------------------------------------------------------- */

TEST(string_helpers) {
    char *s = sb_http_trim(" \t a b \n");
    CHECK_STR(s, "a b");
    free(s);
    s = sb_http_trim("   ");
    CHECK_STR(s, "");
    free(s);
    s = sb_http_trim_trailing_slashes(" http://x/api/// ");
    CHECK_STR(s, "http://x/api");
    free(s);
    static const char *const urls[][2] = {{"http://127.0.0.1:9090/", "127.0.0.1:9090"},
                                          {"https://h:1", "h:1"},
                                          {"ws://h:2//", "h:2"},
                                          {"wss://h:3", "h:3"},
                                          {" 10.0.0.1:9090 ", "10.0.0.1:9090"},
                                          {"ftp://x", "ftp://x"}};
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; ++i) {
        s = sb_http_clash_controller_address(urls[i][0]);
        CHECK_STR(s, urls[i][1]);
        free(s);
    }
    s = sb_http_encode_component("A z-_.~/?&=%你");
    CHECK_STR(s, "A%20z-_.~%2F%3F%26%3D%25%E4%BD%A0");
    free(s);
    s = sb_http_secure_token(16);
    CHECK(s && strlen(s) == 32 && strspn(s, "0123456789abcdef") == 32);
    free(s);
    CHECK(sb_http_secure_token(0) == NULL);
    s = sb_http_utc_now();
    CHECK(s && strlen(s) == 20 && s[4] == '-' && s[10] == 'T' && s[19] == 'Z');
    free(s);
    s = sb_http_truncate_utf8("héllo", 2); /* 'h' + first byte of 'é' -> cut before 'é' */
    CHECK_STR(s, "h");
    free(s);
    s = sb_http_truncate_utf8("héllo", 3);
    CHECK_STR(s, "hé");
    free(s);
    s = sb_http_truncate_utf8("abc", 3);
    CHECK_STR(s, "abc");
    free(s);
}

TEST(json_helpers) {
    sbj *body = sbj_parse_cstr("{\"s\":\"x\",\"e\":\"\",\"n\":null,\"i\":5,\"u\":18446744073709551615,\"f\":1.5,"
                               "\"b\":true,\"o\":{},\"a\":[\"p\",\"q\"],\"m\":[1]}");
    sb_err err = {0};
    CHECK_STR(sb_json_required_string(body, "s", &err), "x");
    CHECK(sb_json_required_string(body, "e", &err) == NULL);
    CHECK_STR(err.msg, "e must be a non-empty string");
    CHECK(sb_json_required_object(body, "a", &err) == NULL);
    CHECK_STR(err.msg, "a must be a JSON object");
    CHECK(sb_json_required_object(body, "o", &err) != NULL);
    char *dest = sb_strdup("keep");
    CHECK_EQ_INT(sb_json_assign_string(body, "n", &dest, &err), 0);
    CHECK_EQ_INT(sb_json_assign_string(body, "missing", &dest, &err), 0);
    CHECK_STR(dest, "keep");
    CHECK_EQ_INT(sb_json_assign_string(body, "i", &dest, &err), -1);
    CHECK_STR(err.msg, "i must be a string");
    CHECK_EQ_INT(sb_json_assign_string(body, "s", &dest, &err), 0);
    CHECK_STR(dest, "x");
    free(dest);
    bool flag = false;
    CHECK_EQ_INT(sb_json_assign_bool(body, "s", &flag, &err), -1);
    CHECK_STR(err.msg, "s must be a boolean");
    CHECK_EQ_INT(sb_json_assign_bool(body, "b", &flag, &err), 0);
    CHECK(flag);
    sb_strvec values = {0};
    CHECK_EQ_INT(sb_json_required_string_array(body, "a", &values, &err), 0);
    CHECK_EQ_INT(values.len, 2);
    sb_strvec_free(&values);
    CHECK_EQ_INT(sb_json_required_string_array(body, "m", &values, &err), -1);
    CHECK_STR(err.msg, "m must contain only strings");
    CHECK_EQ_INT(sb_json_required_string_array(body, "o", &values, &err), -1);
    CHECK_STR(err.msg, "o must be an array");
    int64_t v = 7;
    CHECK_EQ_INT(sb_json_integer_field(body, "missing", &v, &err), 0);
    CHECK_EQ_INT(v, 0);
    CHECK_EQ_INT(sb_json_integer_field(body, "i", &v, &err), 0);
    CHECK_EQ_INT(v, 5);
    CHECK_EQ_INT(sb_json_integer_field(body, "u", &v, &err), 0);
    CHECK_EQ_INT(v, -1); /* nlohmann get<int64_t>() wraps */
    CHECK_EQ_INT(sb_json_integer_field(body, "f", &v, &err), -1);
    CHECK_STR(err.msg, "f must be an integer");
    CHECK_EQ_INT(sb_json_integer_field(body, "n", &v, &err), -1);
    sbj_free(body);

    sb_http_req req;
    memset(&req, 0, sizeof req);
    req.body = "[1]";
    req.body_len = 3;
    CHECK(sb_req_json_object(&req, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "Request body must be a JSON object");
    CHECK_EQ_INT(sb_require_admin(&req, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_AUTH);
    sb_auth_claims claims = {0};
    claims.role = "viewer";
    req.claims = &claims;
    CHECK_EQ_INT(sb_require_admin(&req, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_FORBIDDEN);
    CHECK_STR(err.msg, "Admin role required");
    claims.role = "admin";
    CHECK_EQ_INT(sb_require_admin(&req, &err), 0);
    CHECK(sb_req_claims(&req, &err) == &claims);
}

static sbj *telemetry(const char *text, sb_err *err) {
    sbj *body = sbj_parse_cstr(text);
    sbj *out = sb_http_normalize_telemetry(body, err);
    sbj_free(body);
    return out;
}

TEST(telemetry_normalization) {
    sb_err err = {0};
    sbj *t = telemetry("{}", &err);
    REQUIRE(t != NULL);
    char *dumped = sbj_dump(t, -1);
    CHECK_CONTAINS(dumped, "\"conn_count\":0,\"connections\":null,\"domain_stats\":[],\"down\":0,\"down_total\":0,"
                           "\"logs\":[],\"up\":0,\"up_total\":0}");
    CHECK_EQ_INT(strlen(jstr(t, "at")), 20);
    free(dumped);
    sbj_free(t);
    t = telemetry("{\"up\":1,\"down\":2,\"up_total\":3,\"down_total\":4,\"conn_count\":5,\"connections\":[{\"id\":1}],"
                  "\"domain_stats\":[{\"domain\":\"a.com\",\"chain\":[\"x\"],\"connection_count\":2,\"rule\":null}],"
                  "\"logs\":[\"l1\",\"l2\"]}",
                  &err);
    REQUIRE(t != NULL);
    CHECK_EQ_INT(sbj_get_int(t, "conn_count", -1), 5);
    dumped = sbj_dump(sbj_get(t, "domain_stats"), -1);
    CHECK_STR(dumped, "[{\"chain\":[\"x\"],\"connection_count\":2,\"domain\":\"a.com\",\"downlink_total\":0,"
                      "\"first_seen\":0,\"last_seen\":0,\"outbound\":\"\",\"outbound_type\":\"\",\"rule\":\"\","
                      "\"uplink_total\":0}]");
    free(dumped);
    sbj_free(t);
    static const char *const bad[][2] = {
        {"{\"up\":\"1\"}", "up must be an integer"},
        {"{\"conn_count\":-1}", "conn_count must not be negative"},
        {"{\"domain_stats\":{}}", "domain_stats must be an array"},
        {"{\"domain_stats\":[1]}", "domain_stats must contain only objects"},
        {"{\"domain_stats\":[{\"chain\":\"x\"}]}", "domain_stats chain must be an array of at most 16 entries"},
        {"{\"domain_stats\":[{\"chain\":[1]}]}", "domain_stats chain contains an invalid tag"},
        {"{\"domain_stats\":[{\"first_seen\":1.5}]}", "first_seen must be an integer"},
        {"{\"domain_stats\":[{\"uplink_total\":-1,\"domain\":5}]}", "domain_stats counters must not be negative"},
        {"{\"domain_stats\":[{}]}", "domain is required"},
        {"{\"domain_stats\":[{\"domain\":\"\"}]}", "domain has an invalid length"},
        {"{\"domain_stats\":[{\"domain\":\"a\",\"outbound\":1}]}", "outbound must be a string"},
        {"{\"logs\":\"x\"}", "logs must be an array"},
        {"{\"logs\":[1]}", "logs must contain only strings"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        sb_err_clear(&err);
        CHECK(telemetry(bad[i][0], &err) == NULL);
        CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
        CHECK_STR(err.msg, bad[i][1]);
    }
    /* Only the last 500 log lines are kept (and validated). */
    sb_buf b = {0};
    sb_buf_puts(&b, "{\"logs\":[1");
    for (int i = 0; i < 500; ++i) sb_buf_printf(&b, ",\"%d\"", i);
    sb_buf_puts(&b, "]}");
    t = telemetry(b.p, &err);
    REQUIRE(t != NULL);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(t, "logs")), 500);
    CHECK_STR(sbj_as_str(sbj_arr_at(sbj_get(t, "logs"), 0), NULL), "0");
    sbj_free(t);
    sb_buf_free(&b);
    t = sb_http_default_telemetry();
    CHECK_STR(jstr(t, "at"), "");
    sbj_free(t);
}

static sbj *diagnostic(const char *text, sb_err *err) {
    sbj *body = sbj_parse_cstr(text);
    sbj *out = sb_http_normalize_diagnostic_report(body, err);
    sbj_free(body);
    return out;
}

TEST(diagnostic_normalization) {
    sb_err err = {0};
    sbj *d = diagnostic("{}", &err);
    REQUIRE(d != NULL);
    char *dumped = sbj_dump(d, -1);
    CHECK_STR(dumped, "{\"app_version\":\"\",\"config\":{},\"connection_count\":0,\"core_version\":\"\",\"device\":{},"
                      "\"logs\":[],\"network\":{},\"reason\":\"manual\",\"runtime_log_count\":0,\"vpn\":{}}");
    free(dumped);
    sbj_free(d);
    sb_buf b = {0};
    sb_buf_puts(&b, "{\"reason\":\"");
    for (int i = 0; i < 100; ++i) sb_buf_puts(&b, "r");
    sb_buf_puts(&b, "\",\"device\":{\"k\":1},\"runtime_log_count\":3,\"logs\":[\"");
    for (int i = 0; i < 4010; ++i) sb_buf_puts(&b, "l");
    sb_buf_puts(&b, "\"]}");
    d = diagnostic(b.p, &err);
    REQUIRE(d != NULL);
    CHECK_EQ_INT(strlen(jstr(d, "reason")), 80);
    CHECK_EQ_INT(strlen(sbj_as_str(sbj_arr_at(sbj_get(d, "logs"), 0), "")), 4000);
    CHECK_EQ_INT(sbj_get_int(d, "runtime_log_count", -1), 3);
    sbj_free(d);
    sb_buf_free(&b);
    static const char *const bad[][2] = {
        {"{\"logs\":{}}", "logs must be an array"},
        {"{\"logs\":[null]}", "logs must contain only strings"},
        {"{\"reason\":1}", "reason must be a string"},
        {"{\"vpn\":[]}", "vpn must be a JSON object"},
        {"{\"connection_count\":\"1\"}", "connection_count must be an integer"},
        {"{\"connection_count\":-2}", "connection_count must not be negative"},
        {"{\"logs\":[1],\"reason\":1}", "logs must contain only strings"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        sb_err_clear(&err);
        CHECK(diagnostic(bad[i][0], &err) == NULL);
        CHECK_STR(err.msg, bad[i][1]);
    }
}

TEST(telemetry_store) {
    sb_test_server t;
    REQUIRE(start(&t) == 0);
    sbj *missing = sb_http_telemetry_get(t.server, "nope");
    CHECK_STR(jstr(missing, "at"), "");
    sbj_free(missing);
    sbj *value = sbj_object();
    sbj_set_int(value, "up", 9);
    sb_http_telemetry_put(t.server, "h1", value);
    sbj *got = sb_http_telemetry_get(t.server, "h1");
    CHECK_EQ_INT(sbj_get_int(got, "up", -1), 9);
    sbj_free(got);
    sb_test_server_stop(&t);
}
