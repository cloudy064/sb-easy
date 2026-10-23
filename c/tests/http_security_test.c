/* Real loopback HTTP and WebSocket regression tests for the security boundary. */
#include "test.h"
#include "http_test_support.h"
#include <poll.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <stdatomic.h>

static sb_test_response request_as(sb_test_server *t, const char *method, const char *path,
                                    const char *body, const char *token, const char *cookie, long status) {
    const char *headers[] = {cookie, NULL};
    sb_test_response response;
    sb_test_request_ex(t, method, path, body, token, cookie ? headers : NULL, &response);
    if (response.status != status) fprintf(stderr, "%s %s: expected %ld, got %ld: %s\n", method, path,
                                            status, response.status, response.body ? response.body : "");
    CHECK_EQ_INT(response.status, status); return response;
}
static void expect_status(sb_test_server *t, const char *method, const char *path,
                           const char *body, const char *token, long status) {
    sb_test_response response = request_as(t, method, path, body, token, NULL, status);
    sb_test_response_free(&response);
}
static char *flow_cookie(const sb_test_response *response) {
    char *set = sb_test_response_header(response, "Set-Cookie");
    if (!set) return NULL;
    CHECK_CONTAINS(set, "HttpOnly"); CHECK_CONTAINS(set, "SameSite=Lax"); CHECK_CONTAINS(set, "Secure");
    char *semicolon = strchr(set, ';'); if (semicolon) *semicolon = '\0';
    char *cookie = sb_asprintf("Cookie: %s", set); free(set); return cookie;
}
static char *body_code(const char *challenge, const char *code) {
    sbj *body = sbj_object(); sbj_set_str(body, "challenge", challenge); sbj_set_str(body, "code", code);
    char *text = sbj_dump(body, -1); sbj_free(body); return text;
}
static sb_user_account make_user(sb_test_server *t, const char *name, const char *role, char **token) {
    sb_user_account user; sb_user_account_init(&user); sb_err err = {0};
    char *hash = sb_hash_password("test-password", &err);
    if (sb_store_create_user(t->store, name, hash, role, &user, &err)) fprintf(stderr, "create user: %s\n", err.msg);
    free(hash);
    sb_auth_security *auth = sb_auth_security_new(sb_store_database(t->store), t->jwt_secret, false, &err);
    *token = sb_auth_security_issue(auth, user.id, "test", "HTTP security fixture", &err);
    sb_auth_security_free(auth); return user;
}

TEST(http_password_mfa_binding_one_use_totp_and_recovery) {
    sb_test_server t; REQUIRE(!sb_test_server_start(&t));
    const char *login = "{\"username\":\"admin\",\"password\":\"contract-admin-password\"}";
    sb_test_response r = request_as(&t, "POST", "/api/auth/login", login, "", NULL, 200);
    char *other = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(other); sb_test_response_free(&r);
    r = request_as(&t, "POST", "/api/auth/mfa/setup", "{\"password\":\"wrong\"}", NULL, NULL, 403); sb_test_response_free(&r);
    r = request_as(&t, "POST", "/api/auth/mfa/setup", "{\"password\":\"contract-admin-password\"}", NULL, NULL, 200);
    char *secret = sb_strdup(sbj_get_str(r.json, "secret", NULL)); REQUIRE(secret);
    CHECK_STR(r.cache_control, "no-store"); sb_test_response_free(&r);
    char code[9]; REQUIRE(!sb_auth_totp_code(secret, sb_unix_now(), 6, code, NULL));
    sbj *confirm = sbj_object(); sbj_set_str(confirm, "code", code); char *text = sbj_dump(confirm, -1); sbj_free(confirm);
    r = request_as(&t, "POST", "/api/auth/mfa/confirm", text, NULL, NULL, 200); free(text);
    sbj *codes = sbj_clone(sbj_get(r.json, "recovery_codes")); REQUIRE(sbj_arr_len(codes) == 10); sb_test_response_free(&r);
    expect_status(&t, "GET", "/api/auth/session", NULL, other, 401);
    expect_status(&t, "GET", "/api/auth/session", NULL, NULL, 200);
    r = request_as(&t, "GET", "/api/auth/mfa", NULL, NULL, NULL, 200);
    CHECK(sbj_get_bool(r.json, "enabled", false)); CHECK(!sbj_has(r.json, "secret")); sb_test_response_free(&r);
    r = request_as(&t, "POST", "/api/auth/login", login, "", NULL, 200);
    CHECK(sbj_get_bool(r.json, "mfa_required", false)); CHECK(!sbj_has(r.json, "token"));
    char *challenge = sb_strdup(sbj_get_str(r.json, "challenge", NULL)); REQUIRE(challenge);
    char *cookie = flow_cookie(&r); REQUIRE(cookie); sb_test_response_free(&r);
    /* The next accepted window avoids reusing the enrollment code. */
    REQUIRE(!sb_auth_totp_code(secret, sb_unix_now() + 30, 6, code, NULL));
    text = body_code(challenge, code);
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", NULL, 401); sb_test_response_free(&r);
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", "Cookie: sb_auth_flow=wrong", 401); sb_test_response_free(&r);
    char *duplicate = sb_asprintf("%s; sb_auth_flow=other", cookie);
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", duplicate, 401); sb_test_response_free(&r); free(duplicate);
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", cookie, 200);
    char *token = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(token); CHECK_STR(r.cache_control, "no-store"); sb_test_response_free(&r);
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", cookie, 401); sb_test_response_free(&r);
    free(text); free(challenge); free(cookie);
    expect_status(&t, "GET", "/api/auth/session", NULL, token, 200);
    r = request_as(&t, "POST", "/api/auth/login", login, "", NULL, 200);
    challenge = sb_strdup(sbj_get_str(r.json, "challenge", NULL)); cookie = flow_cookie(&r); REQUIRE(challenge && cookie); sb_test_response_free(&r);
    text = body_code(challenge, sbj_as_str(sbj_arr_at(codes, 0), ""));
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", cookie, 200);
    char *recovery_token = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(recovery_token); sb_test_response_free(&r);
    free(text); free(challenge); free(cookie);
    r = request_as(&t, "POST", "/api/auth/login", login, "", NULL, 200);
    challenge = sb_strdup(sbj_get_str(r.json, "challenge", NULL)); cookie = flow_cookie(&r); REQUIRE(challenge && cookie); sb_test_response_free(&r);
    text = body_code(challenge, sbj_as_str(sbj_arr_at(codes, 0), ""));
    r = request_as(&t, "POST", "/api/auth/login/mfa", text, "", cookie, 401); sb_test_response_free(&r);
    free(text); free(challenge); free(cookie);
    r = request_as(&t, "GET", "/api/auth/mfa", NULL, recovery_token, NULL, 200);
    CHECK_EQ_INT(sbj_get_int(r.json, "recovery_codes_remaining", -1), 9); sb_test_response_free(&r);
    /* A valid password alone cannot turn MFA off. */
    expect_status(&t, "POST", "/api/auth/mfa/disable", "{\"password\":\"contract-admin-password\"}", token, 400);
    free(secret); free(other); free(token); free(recovery_token); sbj_free(codes); sb_test_server_stop(&t);
}

TEST(http_registry_revocation_password_reset_and_last_admin) {
    sb_test_server t; REQUIRE(!sb_test_server_start(&t));
    char *legacy = sb_auth_create_token(t.jwt_secret, "pretend-admin", "admin", "admin");
    expect_status(&t, "GET", "/api/hosts", NULL, legacy, 401); free(legacy);
    char *token = NULL; sb_user_account user = make_user(&t, "reset-user", "viewer", &token); REQUIRE(token);
    expect_status(&t, "GET", "/api/auth/session", NULL, token, 200);
    char *path = sb_asprintf("/api/users/%s/password", user.id);
    expect_status(&t, "POST", path, "{\"password\":\"changed-password\"}", NULL, 200); free(path);
    expect_status(&t, "GET", "/api/auth/session", NULL, token, 401); free(token);
    sb_test_response r = request_as(&t, "POST", "/api/auth/login", "{\"username\":\"reset-user\",\"password\":\"changed-password\"}", "", NULL, 200);
    token = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(token); sb_test_response_free(&r);
    r = request_as(&t, "GET", "/api/auth/sessions", NULL, token, NULL, 200);
    char *session = NULL;
    for (size_t i = 0; i < sbj_arr_len(r.json); ++i)
        if (sbj_get_bool(sbj_arr_at(r.json, i), "current", false)) session = sb_strdup(sbj_get_str(sbj_arr_at(r.json, i), "id", ""));
    REQUIRE(session); sb_test_response_free(&r);
    path = sb_asprintf("/api/auth/sessions/%s", session);
    expect_status(&t, "DELETE", path, NULL, token, 200); free(path); free(session);
    expect_status(&t, "GET", "/api/auth/session", NULL, token, 401); free(token);
    r = request_as(&t, "POST", "/api/auth/login", "{\"username\":\"reset-user\",\"password\":\"changed-password\"}", "", NULL, 200);
    token = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(token); sb_test_response_free(&r);
    path = sb_asprintf("/api/users/%s/sessions", user.id);
    expect_status(&t, "DELETE", path, NULL, NULL, 200); free(path);
    expect_status(&t, "GET", "/api/auth/session", NULL, token, 401); free(token);
    sb_user_account admin; sb_user_account_init(&admin);
    REQUIRE(sb_store_find_user_by_username(t.store, "admin", &admin, NULL) == 1);
    path = sb_asprintf("/api/users/%s/role", admin.id);
    expect_status(&t, "PUT", path, "{\"role\":\"viewer\"}", NULL, 400); free(path);
    expect_status(&t, "GET", "/api/auth/session", NULL, NULL, 200);
    path = sb_asprintf("/api/users/%s/role", user.id);
    expect_status(&t, "PUT", path, "{\"role\":\"operator\"}", NULL, 200); free(path);
    expect_status(&t, "POST", "/api/auth/logout", "{}", NULL, 200);
    expect_status(&t, "GET", "/api/auth/session", NULL, NULL, 401);
    sb_user_account_free(&admin); sb_user_account_free(&user); sb_test_server_stop(&t);
}

typedef struct { sb_fixture upstream; char *remote_id, *other_id, *missing_id; } scoped_fixture;
static char *scoped_upstream(const sb_fixture_request *req, void *context) {
    (void)context;
    if (sb_starts_with(req->target, "/remote/")) {
        CHECK_CONTAINS(req->headers, "Authorization: Bearer remote-secret");
        return sb_fixture_response(200, "application/json", "{\"source\":\"remote\",\"proxies\":{}}");
    }
    return sb_fixture_response(200, "application/json", "{\"source\":\"self\"}");
}
static char *add_host(sb_store *store, const char *name, const char *url) {
    sb_host input, host; sb_host_init(&input); sb_host_init(&host);
    sb_str_set(&input.name, name); input.name_len = strlen(name);
    sbj_set_bool(input.capabilities, "runs_singbox", true); input.enabled = true;
    sb_str_set(&input.clash_api, url); input.clash_api_len = url ? strlen(url) : 0;
    sb_str_set(&input.clash_secret, "remote-secret"); input.clash_secret_len = strlen(input.clash_secret);
    sb_err err = {0};
    int rc = sb_store_create_host(store, &input, &host, &err);
    if (rc) fprintf(stderr, "create host: %s\n", err.msg);
    char *id = rc ? NULL : sb_strdup(host.id); sb_host_free(&input); sb_host_free(&host); return id;
}
static void prepare_scope(sb_store *store, void *context) {
    scoped_fixture *f = context; char *url = sb_asprintf("http://127.0.0.1:%u/remote", f->upstream.port);
    f->remote_id = add_host(store, "Allowed", url); f->other_id = add_host(store, "Hidden", url);
    f->missing_id = add_host(store, "No controller", NULL); free(url);
}
static void configure_scope(sb_http_server_options *options, void *context) {
    scoped_fixture *f = context; char *url = sb_asprintf("http://127.0.0.1:%u/self", f->upstream.port);
    sb_str_set(&options->clash_api_url, url); free(url);
}
static void set_group(sb_test_server *t, const char *id, const char *first, const char *second) {
    sbj *body = sbj_object(); sbj_set_str(body, "id", id); sbj_set_str(body, "name", id);
    sbj *ids = sbj_array(); if (first) sbj_arr_push(ids, sbj_str(first)); if (second) sbj_arr_push(ids, sbj_str(second));
    sbj_set(body, "host_ids", ids); char *text = sbj_dump(body, -1); sbj_free(body);
    expect_status(t, "PUT", "/api/device-groups", text, NULL, 200); free(text);
}
static void set_scope(sb_test_server *t, const char *user, const char *group, const char *permission) {
    sbj *body = sbj_object(); sbj_set_str(body, "scope", "groups"); sbj *grants = sbj_array();
    if (group) {
        sbj *grant = sbj_object(); sbj_set_str(grant, "group_id", group); sbj_set_str(grant, "permission", permission);
        sbj_arr_push(grants, grant);
    }
    sbj_set(body, "grants", grants); char *text = sbj_dump(body, -1); sbj_free(body);
    char *path = sb_asprintf("/api/users/%s/scope", user); expect_status(t, "PUT", path, text, NULL, 200);
    free(text); free(path);
}

TEST(http_scopes_filter_hosts_and_deny_global_secrets_and_controller_fallback) {
    scoped_fixture f = {0}; REQUIRE(!sb_fixture_start(&f.upstream, scoped_upstream, NULL));
    sb_test_server t; REQUIRE(!sb_test_server_start_ex(&t, prepare_scope, configure_scope, &f));
    REQUIRE(f.remote_id && f.other_id && f.missing_id);
    char *viewer = NULL, *operator_token = NULL;
    sb_user_account v = make_user(&t, "scoped-viewer", "viewer", &viewer);
    sb_user_account o = make_user(&t, "scoped-operator", "operator", &operator_token); REQUIRE(viewer && operator_token);
    sb_test_response r = request_as(&t, "GET", "/api/hosts", NULL, viewer, NULL, 200);
    CHECK_EQ_INT(sbj_arr_len(r.json), 0); sb_test_response_free(&r);
    set_group(&t, "one-group", f.remote_id, f.missing_id);
    set_scope(&t, v.id, "one-group", "operate"); set_scope(&t, o.id, "one-group", "view");
    r = request_as(&t, "GET", "/api/hosts", NULL, viewer, NULL, 200); CHECK_EQ_INT(sbj_arr_len(r.json), 2);
    CHECK(!strstr(r.body, f.other_id)); CHECK(!strstr(r.body, "remote-secret")); CHECK(!strstr(r.body, "agent_token"));
    for (size_t i = 0; i < sbj_arr_len(r.json); ++i) CHECK(!sbj_get_bool(sbj_get(sbj_arr_at(r.json, i), "access"), "operate", true));
    sb_test_response_free(&r);
    const char *blocked[] = {"/api/settings", "/api/proxies", "/api/subscriptions", "/api/users", "/api/device-groups", "/api/system/status", "/api/system/logs", "/api/config", "/api/profiles"};
    for (size_t i = 0; i < sizeof blocked / sizeof blocked[0]; ++i)
        expect_status(&t, "GET", blocked[i], NULL, viewer, 403);
    expect_status(&t, "GET", "/api/system/status", NULL, "", 401);
    char *path = sb_asprintf("/api/hosts/%s", f.other_id);
    expect_status(&t, "GET", path, NULL, viewer, 403); free(path);
    path = sb_asprintf("/api/hosts/%s/commands", f.remote_id);
    expect_status(&t, "POST", path, "{\"command\":\"restart\"}", viewer, 403);
    expect_status(&t, "POST", path, "{\"command\":\"restart\"}", operator_token, 403);
    set_scope(&t, o.id, "one-group", "operate");
    expect_status(&t, "POST", path, "{\"command\":\"restart\"}", operator_token, 200); free(path);
    expect_status(&t, "PUT", "/api/settings", "{}", operator_token, 403);
    expect_status(&t, "GET", "/api/sing-box/proxies", NULL, viewer, 403);
    expect_status(&t, "GET", "/api/sing-box/proxies?host=self", NULL, viewer, 403);
    path = sb_asprintf("/api/sing-box/proxies?host=%s", f.missing_id);
    expect_status(&t, "GET", path, NULL, viewer, 503); free(path);
    CHECK(!sb_fixture_saw(&f.upstream, "GET /self/proxies"));
    path = sb_asprintf("/api/sing-box/proxies?host=%s", f.remote_id);
    r = request_as(&t, "GET", path, NULL, viewer, NULL, 200); CHECK_STR(sbj_get_str(r.json, "source", ""), "remote");
    sb_test_response_free(&r); free(path);
    path = sb_asprintf("/api/sing-box/proxies/group?host=%s", f.remote_id);
    expect_status(&t, "PUT", path, "{\"name\":\"node\"}", viewer, 403);
    expect_status(&t, "PUT", path, "{\"name\":\"node\"}", operator_token, 200); free(path);
    set_scope(&t, o.id, NULL, NULL);
    path = sb_asprintf("/api/sing-box/proxies?host=%s", f.remote_id);
    expect_status(&t, "GET", path, NULL, operator_token, 403); free(path);
    sb_user_account_free(&v); sb_user_account_free(&o); free(viewer); free(operator_token);
    sb_test_server_stop(&t); sb_fixture_stop(&f.upstream); free(f.remote_id); free(f.other_id); free(f.missing_id);
}

static int send_bytes(int fd, const void *data, size_t size) {
    const char *cursor = data;
    while (size) {
        ssize_t sent = send(fd, cursor, size, MSG_NOSIGNAL);
        if (sent <= 0) return -1;
        cursor += (size_t)sent; size -= (size_t)sent;
    }
    return 0;
}
static char *read_headers(int fd, sb_buf *remaining) {
    sb_buf data = {0}; char chunk[4096];
    while (data.len < 65536) {
        ssize_t count = recv(fd, chunk, sizeof chunk, 0);
        if (count <= 0) break;
        sb_buf_append(&data, chunk, (size_t)count);
        char *end = strstr(data.p, "\r\n\r\n");
        if (end) {
            size_t length = (size_t)(end - data.p) + 4;
            char *headers = sb_strndup(data.p, length);
            if (remaining) sb_buf_append(remaining, data.p + length, data.len - length);
            sb_buf_free(&data); return headers;
        }
    }
    sb_buf_free(&data); return NULL;
}
typedef struct { int listener; uint16_t port; pthread_t thread; atomic_bool stop; char *host_id; } stream_fixture;
static void *stream_upstream(void *context) {
    stream_fixture *f = context;
    while (!atomic_load(&f->stop)) {
        struct pollfd waiting = {f->listener, POLLIN, 0};
        if (poll(&waiting, 1, 250) != 1) continue;
        int fd = accept(f->listener, NULL, NULL); if (fd < 0) continue;
        struct timeval timeout = {8, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        char *headers = read_headers(fd, NULL);
        if (headers) {
            sb_http_response response = {0}; response.headers = headers;
            char *key = sb_http_response_header(&response, "Sec-WebSocket-Key");
            if (key) {
                char *input = sb_asprintf("%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
                unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
                EVP_Digest(input, strlen(input), digest, &length, EVP_sha1(), NULL);
                char *accept = sb_base64_encode(digest, length);
                char *reply = sb_asprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
                send_bytes(fd, reply, strlen(reply)); const unsigned char frame[] = {0x81, 2, '{', '}'};
                send_bytes(fd, frame, sizeof frame); free(input); free(accept); free(reply); free(key);
                while (!atomic_load(&f->stop)) {
                    struct pollfd pending = {fd, POLLIN, 0};
                    if (poll(&pending, 1, 250) != 1) continue;
                    unsigned char bytes[512]; ssize_t received = recv(fd, bytes, sizeof bytes, 0);
                    if (received <= 0 || (bytes[0] & 15U) == 8) break;
                }
            }
            free(headers);
        }
        shutdown(fd, SHUT_RDWR); close(fd);
    }
    return NULL;
}
static int start_stream(stream_fixture *f) {
    memset(f, 0, sizeof *f); atomic_init(&f->stop, false);
    f->listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {0}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof address;
    if (f->listener < 0 || bind(f->listener, (struct sockaddr *)&address, sizeof address) ||
        listen(f->listener, 4) || getsockname(f->listener, (struct sockaddr *)&address, &size)) return -1;
    f->port = ntohs(address.sin_port); return pthread_create(&f->thread, NULL, stream_upstream, f);
}
static void stop_stream(stream_fixture *f) {
    atomic_store(&f->stop, true); shutdown(f->listener, SHUT_RDWR); pthread_join(f->thread, NULL);
    close(f->listener); free(f->host_id);
}
static void prepare_stream(sb_store *store, void *context) {
    stream_fixture *f = context; char *url = sb_asprintf("http://127.0.0.1:%u/stream", f->port);
    f->host_id = add_host(store, "Stream host", url); free(url);
}
typedef struct { int fd, status; sb_buf data; } browser_stream;
static int open_browser_stream(browser_stream *browser, uint16_t port, const char *target) {
    memset(browser, 0, sizeof *browser); browser->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {0}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    struct timeval timeout = {8, 0}; setsockopt(browser->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    if (connect(browser->fd, (struct sockaddr *)&address, sizeof address)) return -1;
    char *request = sb_asprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", target, port);
    int result = send_bytes(browser->fd, request, strlen(request)); free(request); if (result) return -1;
    char *headers = read_headers(browser->fd, &browser->data); if (!headers) return -1;
    browser->status = strlen(headers) > 12 ? atoi(headers + 9) : 0; free(headers); return 0;
}
static int browser_frame(browser_stream *browser, int *close_code) {
    for (;;) {
        unsigned char *bytes = (unsigned char *)browser->data.p;
        if (browser->data.len >= 2) {
            size_t length = bytes[1] & 127U, header = 2;
            if (length == 126 && browser->data.len >= 4) { length = ((size_t)bytes[2] << 8) | bytes[3]; header = 4; }
            if (length < 126 || header == 4) {
                if (browser->data.len >= header + length) {
                    int opcode = bytes[0] & 15U;
                    if (opcode == 8 && close_code && length >= 2) *close_code = ((int)bytes[header] << 8) | bytes[header + 1];
                    memmove(bytes, bytes + header + length, browser->data.len - header - length);
                    browser->data.len -= header + length; return opcode;
                }
            }
        }
        char chunk[4096]; ssize_t received = recv(browser->fd, chunk, sizeof chunk, 0);
        if (received <= 0 || browser->data.len > 65536) return -1;
        sb_buf_append(&browser->data, chunk, (size_t)received);
    }
}
static void close_browser_stream(browser_stream *browser) {
    shutdown(browser->fd, SHUT_RDWR); close(browser->fd); sb_buf_free(&browser->data);
}

TEST(websocket_closes_after_session_revocation_and_device_scope_removal) {
    stream_fixture f; REQUIRE(!start_stream(&f));
    sb_test_server t; REQUIRE(!sb_test_server_start_ex(&t, prepare_stream, NULL, &f)); REQUIRE(f.host_id);
    char *token = NULL; sb_user_account user = make_user(&t, "stream-user", "viewer", &token); REQUIRE(token);
    set_group(&t, "streams", f.host_id, NULL); set_scope(&t, user.id, "streams", "view");
    char *target = sb_asprintf("/api/sing-box/ws/traffic?token=%s", token); browser_stream browser;
    REQUIRE(!open_browser_stream(&browser, t.port, target)); CHECK_EQ_INT(browser.status, 403); close_browser_stream(&browser); free(target);
    target = sb_asprintf("/api/sing-box/ws/traffic?token=%s&host=%s", token, f.host_id);
    REQUIRE(!open_browser_stream(&browser, t.port, target)); CHECK_EQ_INT(browser.status, 101);
    CHECK_EQ_INT(browser_frame(&browser, NULL), 1);
    char *path = sb_asprintf("/api/users/%s/sessions", user.id);
    expect_status(&t, "DELETE", path, NULL, NULL, 200); free(path);
    int code = 0; CHECK_EQ_INT(browser_frame(&browser, &code), 8); CHECK_EQ_INT(code, 1008);
    close_browser_stream(&browser); free(target); free(token);
    sb_test_response r = request_as(&t, "POST", "/api/auth/login", "{\"username\":\"stream-user\",\"password\":\"test-password\"}", "", NULL, 200);
    token = sb_strdup(sbj_get_str(r.json, "token", NULL)); REQUIRE(token); sb_test_response_free(&r);
    target = sb_asprintf("/api/sing-box/ws/traffic?token=%s&host=%s", token, f.host_id);
    REQUIRE(!open_browser_stream(&browser, t.port, target)); CHECK_EQ_INT(browser.status, 101);
    CHECK_EQ_INT(browser_frame(&browser, NULL), 1);
    set_scope(&t, user.id, NULL, NULL);
    code = 0; CHECK_EQ_INT(browser_frame(&browser, &code), 8); CHECK_EQ_INT(code, 1008);
    close_browser_stream(&browser); free(target); free(token); sb_user_account_free(&user);
    sb_test_server_stop(&t); stop_stream(&f);
}
