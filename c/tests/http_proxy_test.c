/* Contract tests for the proxy, subscription and Clash control routes and the
 * Clash WebSocket bridge (port of the matching parts of
 * cpp/tests/http_server_test.cpp: SubscriptionFixture, ClashFixture and the
 * WebSocket cases), plus focused edge cases of the same handlers. */
#include "test.h"

#include "http_test_support.h"

#include <errno.h>
#include <poll.h>
#include <sys/time.h>

#include <openssl/evp.h>

/* ---- small JSON helpers ------------------------------------------------- */

static const char *jstr(const sbj *v, const char *key) {
    const sbj *f = sbj_get(v, key);
    return sbj_is_string(f) ? f->v.str.ptr : NULL;
}

static int64_t jint(const sbj *v, const char *key) { return sbj_get_int(v, key, -12345); }

static bool jnull(const sbj *v, const char *key) {
    const sbj *f = sbj_get(v, key);
    return f && f->type == SBJ_NULL;
}

static char *error_of(const sb_test_response *r) {
    return sb_strdup(r->json ? jstr(r->json, "error") : NULL);
}

#define CHECK_ERROR(resp, code, message)                                                           \
    do {                                                                                           \
        CHECK_EQ_INT((resp)->status, (code));                                                      \
        char *_e = error_of(resp);                                                                 \
        CHECK_STR(_e, (message));                                                                  \
        free(_e);                                                                                  \
    } while (0)

/* A port nothing listens on (bound, then released). */
static uint16_t unused_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(fd, (struct sockaddr *)&a, &len) != 0) abort();
    close(fd);
    return ntohs(a.sin_port);
}

static char *websocket_accept_for(const char *key) {
    char *input = sb_asprintf("%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    EVP_Digest(input, strlen(input), digest, &n, EVP_sha1(), NULL);
    free(input);
    return sb_base64_encode(digest, n);
}

/* Header value from a raw head (case-insensitive, trimmed); malloc'd/NULL. */
static char *head_value(const char *head, const char *name) {
    size_t n = strlen(name);
    for (const char *line = strstr(head, "\r\n"); line && line[2]; line = strstr(line + 2, "\r\n")) {
        if (strncasecmp(line + 2, name, n) == 0 && line[2 + n] == ':') {
            const char *v = line + 3 + n;
            const char *end = strstr(v, "\r\n");
            char *raw = sb_strndup(v, end ? (size_t)(end - v) : strlen(v));
            char *trimmed = sb_trim_dup(raw);
            free(raw);
            return trimmed;
        }
    }
    return NULL;
}

/* Server (unmasked) or client (masked) frame. */
static void append_frame(sb_buf *b, bool fin, int opcode, const void *payload, size_t len, bool masked) {
    unsigned char head[14];
    size_t h = 0;
    head[h++] = (unsigned char)((fin ? 0x80 : 0) | opcode);
    unsigned char mbit = masked ? 0x80 : 0;
    if (len < 126) {
        head[h++] = (unsigned char)(mbit | len);
    } else if (len <= 0xffff) {
        head[h++] = (unsigned char)(mbit | 126);
        head[h++] = (unsigned char)(len >> 8);
        head[h++] = (unsigned char)(len & 0xff);
    } else {
        head[h++] = (unsigned char)(mbit | 127);
        for (int i = 7; i >= 0; --i) head[h++] = (unsigned char)(((uint64_t)len >> (8 * i)) & 0xff);
    }
    const unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    if (masked) {
        memcpy(head + h, mask, 4);
        h += 4;
    }
    sb_buf_append(b, head, h);
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = ((const unsigned char *)payload)[i];
        sb_buf_putc(b, (char)(masked ? c ^ mask[i & 3] : c));
    }
}

/* Parses one frame at the start of `in` (unmasking); 1 ok, 0 incomplete. */
static int take_frame(sb_buf *in, int *opcode, bool *fin, char **payload, size_t *len) {
    unsigned char *p = (unsigned char *)in->p;
    if (in->len < 2) return 0;
    size_t head = 2;
    uint64_t n = p[1] & 0x7f;
    if (n == 126) {
        if (in->len < 4) return 0;
        n = ((uint64_t)p[2] << 8) | p[3];
        head = 4;
    } else if (n == 127) {
        if (in->len < 10) return 0;
        n = 0;
        for (int i = 2; i < 10; ++i) n = (n << 8) | p[i];
        head = 10;
    }
    bool masked = (p[1] & 0x80) != 0;
    if (masked) head += 4;
    if (in->len < head + n) return 0;
    *payload = sb_xmalloc(n + 1);
    for (uint64_t i = 0; i < n; ++i) (*payload)[i] = (char)(masked ? p[head + i] ^ p[head - 4 + (i & 3)] : p[head + i]);
    (*payload)[n] = '\0';
    *len = (size_t)n;
    *opcode = p[0] & 0x0f;
    *fin = (p[0] & 0x80) != 0;
    memmove(in->p, in->p + head + n, in->len - head - n);
    in->len -= head + n;
    return 1;
}

static void send_all_fd(int fd, const void *data, size_t len) {
    const char *p = data;
    while (len > 0) {
        ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
        if (w <= 0) return;
        p += w;
        len -= (size_t)w;
    }
}

/* ---- browser-side WebSocket client ---------------------------------------- */

typedef struct {
    int fd;
    int status;  /* handshake status */
    char *head;  /* response head */
    char *body;  /* body of a non-101 response */
    sb_buf in;   /* bytes received after the head */
} ws_client;

static void ws_client_close(ws_client *c) {
    if (c->fd >= 0) close(c->fd);
    free(c->head);
    free(c->body);
    sb_buf_free(&c->in);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

static int ws_client_open_ex(ws_client *c, uint16_t port, const char *target, const char *extra_headers) {
    memset(c, 0, sizeof *c);
    c->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(c->fd, (struct sockaddr *)&a, sizeof a) != 0) return -1;
    struct timeval tv = {5, 0};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char *request = sb_asprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nUpgrade: websocket\r\n"
                                "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n%s\r\n",
                                target, (unsigned)port, extra_headers ? extra_headers : "");
    send_all_fd(c->fd, request, strlen(request));
    free(request);
    sb_buf raw = {0};
    char chunk[4096];
    char *end = NULL;
    while (!(end = raw.p ? strstr(raw.p, "\r\n\r\n") : NULL)) {
        ssize_t n = recv(c->fd, chunk, sizeof chunk, 0);
        if (n <= 0) {
            sb_buf_free(&raw);
            return -1;
        }
        sb_buf_append(&raw, chunk, (size_t)n);
    }
    size_t head_len = (size_t)(end - raw.p) + 4;
    c->head = sb_strndup(raw.p, head_len);
    c->status = strlen(c->head) > 12 ? atoi(c->head + 9) : 0;
    sb_buf_append(&c->in, raw.p + head_len, raw.len - head_len);
    sb_buf_free(&raw);
    if (c->status != 101) {
        char *cl = head_value(c->head, "Content-Length");
        size_t want = cl ? strtoul(cl, NULL, 10) : 0;
        free(cl);
        while (c->in.len < want) {
            ssize_t n = recv(c->fd, chunk, sizeof chunk, 0);
            if (n <= 0) break;
            sb_buf_append(&c->in, chunk, (size_t)n);
        }
        c->body = sb_strndup(c->in.p ? c->in.p : "", c->in.len);
    }
    return 0;
}

static int ws_client_open(ws_client *c, uint16_t port, const char *target) {
    return ws_client_open_ex(c, port, target, NULL);
}

/* 1 frame, 0 EOF, -1 timeout/error. */
static int ws_client_frame(ws_client *c, int *opcode, char **payload, size_t *len) {
    for (;;) {
        bool fin;
        if (take_frame(&c->in, opcode, &fin, payload, len)) return 1;
        char chunk[8192];
        ssize_t n = recv(c->fd, chunk, sizeof chunk, 0);
        if (n == 0) return 0;
        if (n < 0) return -1;
        sb_buf_append(&c->in, chunk, (size_t)n);
    }
}

static void ws_client_send_close(ws_client *c, int code) {
    unsigned char payload[2] = {(unsigned char)(code >> 8), (unsigned char)(code & 0xff)};
    sb_buf b = {0};
    append_frame(&b, true, 0x8, payload, 2, true);
    send_all_fd(c->fd, b.p, b.len);
    sb_buf_free(&b);
}

static int close_code(const char *payload, size_t len) {
    return len >= 2 ? (((unsigned char)payload[0]) << 8) | (unsigned char)payload[1] : -1;
}

/* ---- scripted upstream WebSocket fixture ------------------------------------ */

typedef struct {
    int reject_status; /* answer the upgrade with this status instead of 101 */
    sb_buf script;     /* raw bytes sent right after the 101 */
    int hold_ms;       /* then read client frames for this long (0: close at once) */
    bool garbage;      /* answer whatever arrives with a non-TLS reply (TLS failure) */
    /* observed */
    char *target;
    int close_code;    /* close frame received from the relay, -1 none */
    char *pong;        /* payload of a pong received from the relay */
    int listener;
    uint16_t port;
    pthread_t thread;
} ws_upstream;

static void *ws_upstream_main(void *arg) {
    ws_upstream *u = arg;
    struct pollfd pl = {u->listener, POLLIN, 0};
    if (poll(&pl, 1, 10000) != 1) return NULL;
    int c = accept(u->listener, NULL, NULL);
    if (c < 0) return NULL;
    sb_buf in = {0};
    char chunk[4096];
    if (u->garbage) {
        ssize_t n = recv(c, chunk, sizeof chunk, 0);
        (void)n;
        const char *reply = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send_all_fd(c, reply, strlen(reply));
        shutdown(c, SHUT_RDWR);
        close(c);
        return NULL;
    }
    while (!(in.p && strstr(in.p, "\r\n\r\n"))) {
        ssize_t n = recv(c, chunk, sizeof chunk, 0);
        if (n <= 0) break;
        sb_buf_append(&in, chunk, (size_t)n);
    }
    if (in.p) {
        char *sp1 = strchr(in.p, ' ');
        char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        if (sp1 && sp2) u->target = sb_strndup(sp1 + 1, (size_t)(sp2 - sp1 - 1));
        char *end = strstr(in.p, "\r\n\r\n");
        char *head = sb_strndup(in.p, (size_t)(end - in.p) + 4);
        size_t consumed = (size_t)(end - in.p) + 4;
        memmove(in.p, in.p + consumed, in.len - consumed);
        in.len -= consumed;
        if (u->reject_status) {
            char *resp = sb_asprintf("HTTP/1.1 %d Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                     u->reject_status);
            send_all_fd(c, resp, strlen(resp));
            free(resp);
        } else {
            char *key = head_value(head, "Sec-WebSocket-Key");
            char *accept = websocket_accept_for(key ? key : "");
            char *resp = sb_asprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
                                     accept);
            send_all_fd(c, resp, strlen(resp));
            if (u->script.len) send_all_fd(c, u->script.p, u->script.len);
            free(resp);
            free(accept);
            free(key);
            int64_t deadline = sb_monotonic_ms() + u->hold_ms;
            while (u->hold_ms > 0 && sb_monotonic_ms() < deadline) {
                int opcode;
                bool fin;
                char *payload = NULL;
                size_t len = 0;
                if (take_frame(&in, &opcode, &fin, &payload, &len)) {
                    if (opcode == 0x8) {
                        u->close_code = close_code(payload, len);
                        free(payload);
                        break;
                    }
                    if (opcode == 0xA && !u->pong) u->pong = sb_strndup(payload, len);
                    free(payload);
                    continue;
                }
                struct pollfd p = {c, POLLIN, 0};
                int left = (int)(deadline - sb_monotonic_ms());
                if (left <= 0 || poll(&p, 1, left) != 1) break;
                ssize_t n = recv(c, chunk, sizeof chunk, 0);
                if (n <= 0) break;
                sb_buf_append(&in, chunk, (size_t)n);
            }
        }
        free(head);
    }
    sb_buf_free(&in);
    shutdown(c, SHUT_RDWR);
    close(c);
    return NULL;
}

static void ws_upstream_init(ws_upstream *u) {
    memset(u, 0, sizeof *u);
    u->close_code = -1;
}

static int ws_upstream_start(ws_upstream *u) {
    u->listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(u->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (bind(u->listener, (struct sockaddr *)&a, sizeof a) != 0 || listen(u->listener, 4) != 0) return -1;
    getsockname(u->listener, (struct sockaddr *)&a, &len);
    u->port = ntohs(a.sin_port);
    return pthread_create(&u->thread, NULL, ws_upstream_main, u);
}

static void ws_upstream_finish(ws_upstream *u) {
    pthread_join(u->thread, NULL);
    close(u->listener);
}

static void ws_upstream_free(ws_upstream *u) {
    sb_buf_free(&u->script);
    free(u->target);
    free(u->pong);
}

/* ---- Clash fixture (port of ClashFixture::send_response) -------------------- */

/* Request header from the fixture's raw head (C++ header_value()). */
static char *fixture_header(const sb_fixture_request *req, const char *name) {
    char *v = head_value(req->headers, name);
    return v ? v : sb_strdup("");
}

static char *clash_fixture_handler(const sb_fixture_request *req, void *user) {
    (void)user;
    char *upgrade = head_value(req->headers, "Upgrade");
    bool websocket = upgrade && strcasecmp(upgrade, "websocket") == 0;
    free(upgrade);
    if (websocket) {
        char *key = fixture_header(req, "Sec-WebSocket-Key");
        char *accept = websocket_accept_for(key);
        sbj *msg = sbj_object();
        sbj_set_str(msg, "stream", "fixture");
        sbj_set_str(msg, "target", req->target);
        char *text = sbj_dump(msg, -1);
        sbj_free(msg);
        sb_buf frame = {0};
        append_frame(&frame, true, 0x1, text, strlen(text), false);
        char *resp = sb_asprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                 "Sec-WebSocket-Accept: %s\r\n\r\n%s",
                                 accept, frame.p);
        sb_buf_free(&frame);
        free(text);
        free(accept);
        free(key);
        return resp;
    }
    char *authorization = fixture_header(req, "Authorization");
    sbj *body = sbj_object();
    sbj_set_str(body, "method", req->method);
    sbj_set_str(body, "target", req->target);
    sbj_set_str(body, "authorization", authorization);
    free(authorization);
    if (sb_ends_with(req->target, "/proxies")) {
        sbj *proxies = sbj_object();
        sbj *node = sbj_object();
        sbj_set_str(node, "type", "Shadowsocks");
        sbj_set(proxies, "Fixture Node", node);
        sbj *group = sbj_object();
        sbj_set_str(group, "type", "Selector");
        sbj *all = sbj_array();
        sbj_arr_push(all, sbj_str("Fixture Node"));
        sbj_set(group, "all", all);
        sbj_set(proxies, "Fixture Group", group);
        sbj_set(body, "proxies", proxies);
    }
    if (strstr(req->target, "/delay?")) sbj_set_int(body, "delay", 42);
    if (sb_ends_with(req->target, "/connections")) {
        sbj_set_int(body, "uploadTotal", 1024);
        sbj_set_int(body, "downloadTotal", 2048);
        sbj *connections = sbj_array();
        sbj *c = sbj_object();
        sbj_set_str(c, "id", "fixture-connection");
        sbj_arr_push(connections, c);
        sbj_set(body, "connections", connections);
    }
    char *text = sbj_dump(body, -1);
    sbj_free(body);
    char *resp = sb_fixture_response(200, "application/json", text);
    free(text);
    return resp;
}

/* ---- subscription fixture -------------------------------------------------- */

static const char clash_yaml[] = "proxies:\n"
                                 "  - name: YAML SS\n"
                                 "    type: ss\n"
                                 "    server: yaml-ss.example.com\n"
                                 "    port: 8388\n"
                                 "    cipher: aes-128-gcm\n"
                                 "    password: yaml-secret\n"
                                 "  - name: YAML Trojan\n"
                                 "    type: trojan\n"
                                 "    server: yaml-trojan.example.com\n"
                                 "    port: 443\n"
                                 "    password: yaml-trojan-secret\n";

static char *subscription_fixture_handler(const sb_fixture_request *req, void *user) {
    (void)user;
    const char *t = req->target;
    if (strcmp(t, "/fixture/subscription") == 0)
        return sb_fixture_response(200, "text/plain", "trojan://fixture-secret@fixture.example.com:443#Fixture\n");
    if (strcmp(t, "/fixture/base64") == 0) {
        const char *list = "trojan://b64-secret@b64-one.example.com:443#B64%20One\n"
                           "ss://YWVzLTI1Ni1nY206YjY0LXBhc3M=@b64-two.example.com:8388#B64%20Two\n";
        char *encoded = sb_base64_encode((const unsigned char *)list, strlen(list));
        char *resp = sb_fixture_response(200, "text/plain", encoded);
        free(encoded);
        return resp;
    }
    if (strcmp(t, "/fixture/clash.yaml") == 0) return sb_fixture_response(200, "application/yaml", clash_yaml);
    if (strcmp(t, "/fixture/redirect") == 0)
        return sb_strdup("HTTP/1.1 302 Found\r\nLocation: /fixture/subscription\r\nContent-Length: 0\r\n"
                         "Connection: close\r\n\r\n");
    if (strcmp(t, "/fixture/bad-vmess") == 0) {
        const char *json = "{\"add\":\"vmess.example.com\",\"port\":\"443\",\"id\":\"uuid\",\"aid\":\"x\",\"ps\":\"bad\"}";
        char *encoded = sb_base64_encode((const unsigned char *)json, strlen(json));
        char *line = sb_asprintf("vmess://%s\n", encoded);
        char *resp = sb_fixture_response(200, "text/plain", line);
        free(line);
        free(encoded);
        return resp;
    }
    return sb_fixture_response(404, "text/plain", "missing");
}

/* ---- server with Clash + subscription fixtures ------------------------------ */

typedef struct {
    sb_fixture clash;
    sb_fixture subscriptions;
    char *remote_id;         /* host whose clash_api points at the fixture */
    char *clash_url_override; /* local SINGBOX_API_URL override (NULL: fixture /local) */
} contract_ctx;

static void contract_prepare(sb_store *store, void *user) {
    contract_ctx *c = user;
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, "Remote Clash target");
    host.clash_api = sb_asprintf("http://127.0.0.1:%u/remote", (unsigned)c->clash.port);
    sb_str_set(&host.clash_secret, "remote-secret");
    sb_err err = {0};
    if (sb_store_create_host(store, &host, &created, &err) == 0) c->remote_id = sb_strdup(created.id);
    else fprintf(stderr, "create host failed: %s\n", err.msg);
    sb_host_free(&host);
    sb_host_free(&created);
}

static void contract_customize(sb_http_server_options *o, void *user) {
    contract_ctx *c = user;
    if (c->clash_url_override) {
        sb_str_set(&o->clash_api_url, c->clash_url_override);
    } else {
        char *url = sb_asprintf("http://127.0.0.1:%u/local", (unsigned)c->clash.port);
        sb_str_set(&o->clash_api_url, url);
        free(url);
    }
}

static int contract_start(contract_ctx *c, sb_test_server *t, const char *clash_url_override) {
    memset(c, 0, sizeof *c);
    c->clash_url_override = clash_url_override ? sb_strdup(clash_url_override) : NULL;
    if (sb_fixture_start(&c->clash, clash_fixture_handler, NULL) != 0) return -1;
    if (sb_fixture_start(&c->subscriptions, subscription_fixture_handler, NULL) != 0) return -1;
    return sb_test_server_start_ex(t, contract_prepare, contract_customize, c);
}

static void contract_stop(contract_ctx *c, sb_test_server *t) {
    sb_test_server_stop(t);
    sb_fixture_stop(&c->clash);
    sb_fixture_stop(&c->subscriptions);
    free(c->remote_id);
    free(c->clash_url_override);
}

/* Adds a host with the given clash_api directly in the store. */
static char *add_clash_host(sb_test_server *t, const char *name, const char *clash_api, const char *secret) {
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, name);
    host.clash_api = clash_api ? sb_strdup(clash_api) : NULL;
    sb_str_set(&host.clash_secret, secret ? secret : "");
    sb_err err = {0};
    char *id = sb_store_create_host(t->store, &host, &created, &err) == 0 ? sb_strdup(created.id) : NULL;
    sb_host_free(&host);
    sb_host_free(&created);
    return id;
}

static char *first_pending_command(sb_test_server *t, const char *host_id, size_t *count) {
    sb_host_command_vec v = {0};
    sb_err err = {0};
    char *command = NULL;
    if (sb_store_list_host_commands(t->store, host_id, true, &v, &err) == 0 && v.len > 0)
        command = sb_strdup(v.items[0].command);
    if (count) *count = v.len;
    sb_host_command_vec_free(&v);
    return command;
}

/* ---- the C++ contract (proxy / subscription / Clash / WebSocket parts) ------ */

TEST(contract) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    REQUIRE(c.remote_id != NULL);
    sb_test_response r;

    /* Clash WebSocket routes must return 401 for invalid query JWTs. */
    sb_test_request(&t, "GET", "/api/sing-box/ws/traffic?token=invalid-token", NULL, &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);

    /* Handshakes with invalid JWTs are rejected before the upgrade. */
    ws_client ws;
    REQUIRE(ws_client_open(&ws, t.port, "/api/sing-box/ws/traffic?token=invalid-token") == 0);
    CHECK_EQ_INT(ws.status, 401);
    CHECK_STR(ws.body, "{\"error\":\"Invalid or expired token\"}");
    ws_client_close(&ws);

    /* Local Clash WebSockets bridge JWT-authenticated log streams. */
    char *target = sb_asprintf("/api/sing-box/ws/logs?token=%s&level=debug", t.token);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 101);
    int opcode = 0;
    char *payload = NULL;
    size_t len = 0;
    if (ws_client_frame(&ws, &opcode, &payload, &len) == 1) {
        CHECK_EQ_INT(opcode, 1);
        sbj *stream = sbj_parse(payload, len, NULL, 0);
        CHECK_STR(jstr(stream, "target"), "/local/logs?level=debug&token=local-secret");
        sbj_free(stream);
        free(payload);
    } else {
        CHECK(!"local Clash WebSocket returned no payload");
    }
    ws_client_close(&ws);

    /* Remote Clash WebSockets select the host target and secret. */
    target = sb_asprintf("/api/sing-box/ws/traffic?token=%s&host=%s", t.token, c.remote_id);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 101);
    if (ws_client_frame(&ws, &opcode, &payload, &len) == 1) {
        sbj *stream = sbj_parse(payload, len, NULL, 0);
        CHECK_STR(jstr(stream, "target"), "/remote/traffic?token=remote-secret");
        sbj_free(stream);
        free(payload);
    } else {
        CHECK(!"remote Clash WebSocket returned no payload");
    }
    ws_client_close(&ws);

    /* Viewers keep read access but are blocked before mutations. */
    char *viewer = sb_test_token(&t, "viewer-id", "contract-viewer", "viewer");
    sb_test_request_ex(&t, "GET", "/api/proxy/nodes", NULL, viewer, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/proxy/nodes", "{}", viewer, NULL, &r);
    CHECK_EQ_INT(r.status, 403);
    sb_test_response_free(&r);
    free(viewer);

    /* Clash proxy list uses the local target and bearer secret. */
    sb_test_request(&t, "GET", "/api/sing-box/proxies", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "method"), "GET");
    CHECK_STR(jstr(r.json, "target"), "/local/proxies");
    CHECK_STR(jstr(r.json, "authorization"), "Bearer local-secret");
    CHECK(sbj_is_object(sbj_get(sbj_get(r.json, "proxies"), "Fixture Group")));
    sb_test_response_free(&r);

    /* Clash path parameters are encoded exactly once. */
    sb_test_request(&t, "GET", "/api/sing-box/proxies/Group%20A", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "target"), "/local/proxies/Group%20A");
    sb_test_response_free(&r);

    /* Clash selector updates forward successful PUT requests. */
    sb_test_request(&t, "PUT", "/api/sing-box/proxies/Group%20A", "{\"name\":\"Node A\"}", &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "success", false));
    sb_test_response_free(&r);
    CHECK(sb_fixture_saw(&c.clash, "PUT /local/proxies/Group%20A"));

    /* Clash delay parameters are normalized and encoded. */
    sb_test_request(&t, "GET", "/api/sing-box/group/Auto/delay?url=https%3A%2F%2Fexample.com%2F204&timeout=3000",
                    NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "target"), "/local/group/Auto/delay?url=https%3A%2F%2Fexample.com%2F204&timeout=3000");
    sb_test_response_free(&r);

    /* Remote hosts select their own Clash target and secret. */
    char *path = sb_asprintf("/api/sing-box/version?host=%s", c.remote_id);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "target"), "/remote/version");
    CHECK_STR(jstr(r.json, "authorization"), "Bearer remote-secret");
    sb_test_response_free(&r);

    /* Connection close forwards DELETE with an encoded id. */
    sb_test_request(&t, "DELETE", "/api/sing-box/connections/connection%201", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "method"), "DELETE");
    CHECK_STR(jstr(r.json, "target"), "/local/connections/connection%201");
    sb_test_response_free(&r);

    /* Proxy creation preserves the Rust response contract. */
    sb_test_request(&t, "POST", "/api/proxy/nodes",
                    "{\"tag\":\"HTTP SS\",\"node_type\":\"shadowsocks\",\"server\":\"http-proxy.example.com\","
                    "\"server_port\":8388,\"protocol_config\":{\"method\":\"aes-256-gcm\",\"password\":\"http-secret\"}}",
                    &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "node_type"), "shadowsocks");
    CHECK(sbj_is_string(sbj_get(r.json, "protocol_config")));
    char *node_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(node_id != NULL);

    /* Proxy partial updates preserve omitted fields. */
    path = sb_asprintf("/api/proxy/nodes/%s", node_id);
    sb_test_request(&t, "PUT", path, "{\"tag\":\"HTTP SS renamed\",\"enabled\":false}", &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "tag"), "HTTP SS renamed");
    CHECK(!sbj_get_bool(r.json, "enabled", true));
    CHECK_STR(jstr(r.json, "server"), "http-proxy.example.com");
    sb_test_response_free(&r);

    /* Single-node latency tests persist a Clash delay result. */
    path = sb_asprintf("/api/proxy/nodes/%s/test-latency", node_id);
    sb_test_request(&t, "POST", path, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "node_id"), node_id);
    CHECK(sbj_get_double(r.json, "latency", -1) == 42.0);
    CHECK_CONTAINS(r.body, "\"latency\":42.0");
    CHECK(jstr(r.json, "tested_at") != NULL);
    sb_test_response_free(&r);
    CHECK(sb_fixture_saw(&c.clash,
                         "GET /local/proxies/HTTP%20SS%20renamed/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
                         "&timeout=5000"));
    free(path);

    /* Remote latency tests enqueue a targeted agent command. */
    path = sb_asprintf("/api/proxy/nodes/%s/test-latency?host=%s", node_id, c.remote_id);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "queued", false));
    CHECK_STR(jstr(r.json, "host"), c.remote_id);
    sb_test_response_free(&r);
    char *command = first_pending_command(&t, c.remote_id, NULL);
    CHECK_STR(command, "test-proxies [\"HTTP SS renamed\"]");
    free(command);

    /* sing-box outbound import adds structured nodes. */
    sb_test_request(&t, "POST", "/api/proxy/nodes/import",
                    "{\"config\":\"{\\\"outbounds\\\":[{\\\"type\\\":\\\"vless\\\",\\\"tag\\\":\\\"Imported VLESS\\\","
                    "\\\"server\\\":\\\"vless.example.com\\\",\\\"server_port\\\":443,\\\"uuid\\\":\\\"uuid-import\\\","
                    "\\\"flow\\\":\\\"\\\",\\\"packet_encoding\\\":\\\"xudp\\\"}]}\"}",
                    &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "found"), 1);
    CHECK_EQ_INT(jint(r.json, "added"), 1);
    sb_test_response_free(&r);

    /* Blank subscription names derive from the URL host. */
    char *body = sb_asprintf("{\"name\":\"\",\"url\":\"http://127.0.0.1:%u/fixture/subscription\","
                             "\"refresh_interval\":900}",
                             (unsigned)c.subscriptions.port);
    sb_test_request(&t, "POST", "/api/subscriptions", body, &r);
    free(body);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "name"), "127.0.0.1");
    CHECK_EQ_INT(jint(r.json, "refresh_interval"), 900);
    char *sub_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(sub_id != NULL);

    /* Subscription fetch pulls, parses, and persists nodes. */
    path = sb_asprintf("/api/subscriptions/%s/fetch", sub_id);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "found"), 1);
    CHECK_EQ_INT(jint(r.json, "added"), 1);
    CHECK_EQ_INT(jint(r.json, "skipped"), 0);
    sb_test_response_free(&r);

    /* Subscription fetch persists result metadata. */
    path = sb_asprintf("/api/subscriptions/%s", sub_id);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK(!jnull(r.json, "last_fetched_at") && sbj_get(r.json, "last_fetched_at"));
    CHECK(!jnull(r.json, "last_fetch_result") && sbj_get(r.json, "last_fetch_result"));
    sb_test_response_free(&r);

    /* The proxy list includes manual, imported, and subscribed nodes. */
    sb_test_request(&t, "GET", "/api/proxy/nodes", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_arr_len(r.json), 3);
    sb_test_response_free(&r);

    /* Bulk latency tests measure every enabled node. */
    sb_test_request(&t, "POST", "/api/proxy/nodes/test-all", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "tested"), 2);
    CHECK_EQ_INT(sbj_obj_len(sbj_get(r.json, "results")), 2);
    CHECK(sbj_get_double(sbj_get(r.json, "results"), "Imported VLESS", -1) == 42.0);
    sb_test_response_free(&r);

    /* Remote bulk latency tests enqueue an agent command. */
    path = sb_asprintf("/api/proxy/nodes/test-all?host=%s", c.remote_id);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "queued", false));
    sb_test_response_free(&r);
    size_t pending = 0;
    command = first_pending_command(&t, c.remote_id, &pending);
    CHECK_EQ_INT(pending, 2);
    free(command);

    free(sub_id);
    free(node_id);
    contract_stop(&c, &t);
}

/* ---- Clash HTTP control edge cases ------------------------------------------ */

static char *reject_handler_401(const sb_fixture_request *req, void *user) {
    (void)req;
    (void)user;
    return sb_fixture_response(401, "application/json", "{\"message\":\"Unauthorized\"}");
}

static char *reject_handler_404(const sb_fixture_request *req, void *user) {
    (void)req;
    (void)user;
    return sb_fixture_response(404, "application/json", "{\"message\":\"resource not found\"}");
}

static char *empty_body_handler(const sb_fixture_request *req, void *user) {
    (void)req;
    (void)user;
    return sb_strdup("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
}

TEST(clash_control_errors) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    sb_test_response r;

    /* Non-401 upstream statuses are passed through as 200 with the body. */
    sb_fixture missing;
    REQUIRE(sb_fixture_start(&missing, reject_handler_404, NULL) == 0);
    char *url = sb_asprintf("http://127.0.0.1:%u/", (unsigned)missing.port);
    char *missing_host = add_clash_host(&t, "404 host", url, "");
    free(url);
    char *path = sb_asprintf("/api/sing-box/rules?host=%s", missing_host);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "message"), "resource not found");
    sb_test_response_free(&r);
    CHECK(sb_fixture_saw(&missing, "GET /rules"));

    /* A failed selector switch surfaces the upstream status as 400. */
    path = sb_asprintf("/api/sing-box/proxies/Auto?host=%s", missing_host);
    sb_test_request(&t, "PUT", path, "{\"name\":\"x\"}", &r);
    CHECK_ERROR(&r, 400, "sing-box returned HTTP 404");
    sb_test_response_free(&r);
    sb_test_request(&t, "PUT", path, "[1]", &r);
    CHECK_ERROR(&r, 400, "Request body must be a JSON object");
    sb_test_response_free(&r);
    free(path);

    /* A 401 from the controller is a 503 naming the target. */
    sb_fixture unauthorized;
    REQUIRE(sb_fixture_start(&unauthorized, reject_handler_401, NULL) == 0);
    url = sb_asprintf("http://127.0.0.1:%u/api//", (unsigned)unauthorized.port);
    char *auth_host = add_clash_host(&t, "401 host", url, "wrong");
    free(url);
    path = sb_asprintf("/api/sing-box/connections?host=%s", auth_host);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    url = sb_asprintf("sing-box Clash API authentication failed for http://127.0.0.1:%u/api; check the configured secret",
                      (unsigned)unauthorized.port);
    CHECK_ERROR(&r, 503, url);
    free(url);
    sb_test_response_free(&r);

    /* Unreachable controllers are 503 with the transport reason. */
    uint16_t dead = unused_port();
    url = sb_asprintf("http://127.0.0.1:%u", (unsigned)dead);
    char *dead_host = add_clash_host(&t, "dead host", url, "");
    path = sb_asprintf("/api/sing-box/proxies?host=%s", dead_host);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    char *expected = sb_asprintf("Could not reach sing-box Clash API (%s): Clash API request failed: Network failure", url);
    CHECK_ERROR(&r, 503, expected);
    free(expected);
    sb_test_response_free(&r);
    free(url);

    /* A non-HTTP controller URL fails in the client (503). */
    char *ftp_host = add_clash_host(&t, "ftp host", "ftp://controller.example", "");
    path = sb_asprintf("/api/sing-box/version?host=%s", ftp_host);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK_ERROR(&r, 503,
                "Could not reach sing-box Clash API (ftp://controller.example): Clash API URL must include http:// or "
                "https://");
    sb_test_response_free(&r);

    /* self, unknown hosts and hosts without (usable) controllers use the local API. */
    char *blank_host = add_clash_host(&t, "blank host", "  /// ", "ignored");
    char *no_api_host = add_clash_host(&t, "no api host", NULL, "ignored");
    const char *locals[] = {"self", "%20self%20", "missing-host", blank_host, no_api_host, ""};
    for (size_t i = 0; i < sizeof locals / sizeof locals[0]; ++i) {
        path = sb_asprintf("/api/sing-box/version?host=%s", locals[i]);
        sb_test_request(&t, "GET", path, NULL, &r);
        free(path);
        CHECK_EQ_INT(r.status, 200);
        CHECK_STR(jstr(r.json, "target"), "/local/version");
        CHECK_STR(jstr(r.json, "authorization"), "Bearer local-secret");
        sb_test_response_free(&r);
    }

    /* Delay defaults, the other passthrough routes and an empty body ({}). */
    sb_test_request(&t, "GET", "/api/sing-box/proxies/Node%20%231/delay", NULL, &r);
    CHECK_STR(jstr(r.json, "target"),
              "/local/proxies/Node%20%231/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000");
    CHECK_EQ_INT(jint(r.json, "delay"), 42);
    sb_test_response_free(&r);
    /* Drogon decodes the path before routing: an encoded '/' splits the name. */
    sb_test_request(&t, "GET", "/api/sing-box/proxies/Node%20%2F1/delay", NULL, &r);
    CHECK_ERROR(&r, 404, "API route not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/sing-box/proxies/A/delay?url=&timeout=", NULL, &r);
    CHECK_STR(jstr(r.json, "target"),
              "/local/proxies/A/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/sing-box/group/G/delay?url=http://x/y%3Fz&timeout=a%20b", NULL, &r);
    CHECK_STR(jstr(r.json, "target"), "/local/group/G/delay?url=http%3A%2F%2Fx%2Fy%3Fz&timeout=a%20b");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/sing-box/rules", NULL, &r);
    CHECK_STR(jstr(r.json, "target"), "/local/rules");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/sing-box/connections", NULL, &r);
    CHECK_STR(jstr(r.json, "target"), "/local/connections");
    CHECK_EQ_INT(jint(r.json, "uploadTotal"), 1024);
    sb_test_response_free(&r);
    sb_test_request(&t, "DELETE", "/api/sing-box/connections", NULL, &r);
    CHECK_STR(jstr(r.json, "method"), "DELETE");
    CHECK_STR(jstr(r.json, "target"), "/local/connections");
    sb_test_response_free(&r);

    sb_fixture empty;
    REQUIRE(sb_fixture_start(&empty, empty_body_handler, NULL) == 0);
    url = sb_asprintf("http://127.0.0.1:%u", (unsigned)empty.port);
    char *empty_host = add_clash_host(&t, "empty host", url, "");
    free(url);
    path = sb_asprintf("/api/sing-box/connections/abc?host=%s", empty_host);
    sb_test_request(&t, "DELETE", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "{}");
    sb_test_response_free(&r);

    free(missing_host);
    free(auth_host);
    free(dead_host);
    free(ftp_host);
    free(blank_host);
    free(no_api_host);
    free(empty_host);
    sb_fixture_stop(&empty);
    sb_fixture_stop(&missing);
    sb_fixture_stop(&unauthorized);
    contract_stop(&c, &t);
}

TEST(clash_without_url) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, " /// ") == 0);
    sb_test_response r;
    sb_test_request(&t, "GET", "/api/sing-box/proxies", NULL, &r);
    CHECK_ERROR(&r, 503, "No sing-box Clash API URL is configured");
    sb_test_response_free(&r);
    /* The URL check precedes the body check for selector updates. */
    sb_test_request(&t, "PUT", "/api/sing-box/proxies/A", "not json", &r);
    CHECK_ERROR(&r, 503, "No sing-box Clash API URL is configured");
    sb_test_response_free(&r);

    /* Without a controller latency tests record null. */
    sb_test_request(&t, "POST", "/api/proxy/nodes",
                    "{\"tag\":\"T\",\"node_type\":\"trojan\",\"server\":\"t.example.com\",\"server_port\":443,"
                    "\"protocol_config\":{\"password\":\"p\"}}",
                    &r);
    char *id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    char *path = sb_asprintf("/api/proxy/nodes/%s/test-latency", id);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK(jnull(r.json, "latency"));
    sb_test_response_free(&r);
    path = sb_asprintf("/api/proxy/nodes/%s", id);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK(jnull(r.json, "latency"));
    CHECK(jstr(r.json, "last_latency_test") != NULL);
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/test-all?host=self", NULL, &r);
    CHECK_EQ_INT(jint(r.json, "tested"), 1);
    CHECK(jnull(sbj_get(r.json, "results"), "T"));
    sb_test_response_free(&r);
    free(id);
    contract_stop(&c, &t);
}

/* ---- proxy nodes ------------------------------------------------------------ */

TEST(proxy_node_validation) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    sb_test_response r;
    static const struct {
        const char *body;
        int status;
        const char *error;
    } cases[] = {
        {"[]", 400, "Request body must be a JSON object"},
        {"{}", 400, "tag must be a non-empty string"},
        {"{\"tag\":\"\"}", 400, "tag must be a non-empty string"},
        {"{\"tag\":\"a\",\"node_type\":5}", 400, "node_type must be a non-empty string"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"enabled\":\"yes\"}", 400,
         "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is string"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"enabled\":null}", 400,
         "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is null"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"\"}", 400, "server must be a non-empty string"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\"}", 400, "server_port must be an integer"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":443.0}", 400,
         "server_port must be an integer"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":0}", 400,
         "server_port must be between 1 and 65535"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":65536}", 400,
         "server_port must be between 1 and 65535"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":18446744073709551615}", 400,
         "server_port must be between 1 and 65535"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":443}", 400,
         "protocol_config must be a JSON object"},
        {"{\"tag\":\"a\",\"node_type\":\"trojan\",\"server\":\"s\",\"server_port\":443,\"protocol_config\":[]}", 400,
         "protocol_config must be a JSON object"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        sb_test_request(&t, "POST", "/api/proxy/nodes", cases[i].body, &r);
        CHECK_ERROR(&r, cases[i].status, cases[i].error);
        sb_test_response_free(&r);
    }

    const char *node = "{\"tag\":\"Node\",\"node_type\":\"trojan\",\"server\":\"s.example.com\",\"server_port\":443,"
                       "\"enabled\":false,\"protocol_config\":{\"password\":\"p\"}}";
    sb_test_request(&t, "POST", "/api/proxy/nodes", node, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(!sbj_get_bool(r.json, "enabled", true));
    CHECK(jnull(r.json, "subscription_id"));
    CHECK(jnull(r.json, "latency"));
    CHECK_STR(jstr(r.json, "protocol_config"), "{\"password\":\"p\"}");
    char *id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes", node, &r);
    CHECK_ERROR(&r, 400, "A proxy with the same tag or fingerprint already exists");
    sb_test_response_free(&r);

    char *path = sb_asprintf("/api/proxy/nodes/%s", id);
    static const struct {
        const char *body;
        const char *error;
    } updates[] = {
        {"{\"tag\":\"\"}", "tag must be a non-empty string"},
        {"{\"server\":1}", "server must be a non-empty string"},
        {"{\"server_port\":\"443\"}", "server_port must be an integer"},
        {"{\"server_port\":-1}", "server_port must be between 1 and 65535"},
        {"{\"protocol_config\":\"x\"}", "protocol_config must be a JSON object"},
        {"{\"enabled\":1}", "enabled must be a boolean"},
        {"\"x\"", "Request body must be a JSON object"},
    };
    for (size_t i = 0; i < sizeof updates / sizeof updates[0]; ++i) {
        sb_test_request(&t, "PUT", path, updates[i].body, &r);
        CHECK_ERROR(&r, 400, updates[i].error);
        sb_test_response_free(&r);
    }
    /* Null fields and node_type are ignored; others replace. */
    sb_test_request(&t, "PUT", path,
                    "{\"tag\":null,\"server\":null,\"server_port\":8443,\"node_type\":\"vmess\",\"enabled\":true,"
                    "\"protocol_config\":{\"password\":\"q\"}}",
                    &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "tag"), "Node");
    CHECK_STR(jstr(r.json, "node_type"), "trojan");
    CHECK_EQ_INT(jint(r.json, "server_port"), 8443);
    CHECK(sbj_get_bool(r.json, "enabled", false));
    CHECK_STR(jstr(r.json, "protocol_config"), "{\"password\":\"q\"}");
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", path, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "id"), id);
    sb_test_response_free(&r);
    sb_test_request(&t, "DELETE", path, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "success", false));
    sb_test_response_free(&r);

    /* Missing nodes: 404 before the body is looked at. */
    sb_test_request(&t, "GET", path, NULL, &r);
    CHECK_ERROR(&r, 404, "Node not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "PUT", path, "not json", &r);
    CHECK_ERROR(&r, 404, "Node not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "DELETE", path, NULL, &r);
    CHECK_ERROR(&r, 404, "Node not found");
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/proxy/nodes/%s/test-latency?host=missing-host", id);
    sb_test_request(&t, "POST", path, NULL, &r);
    CHECK_ERROR(&r, 404, "Node not found");
    sb_test_response_free(&r);
    free(path);
    sb_test_request(&t, "POST", "/api/proxy/nodes/test-all?host=missing-host", NULL, &r);
    CHECK_ERROR(&r, 404, "Host not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/test-all", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "tested"), 0);
    sb_test_response_free(&r);
    free(id);
    contract_stop(&c, &t);
}

TEST(proxy_import) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    sb_test_response r;
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{}", &r);
    CHECK_ERROR(&r, 400, "Provide either profile_id or config");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"profile_id\":\"\",\"config\":5}", &r);
    CHECK_ERROR(&r, 400, "Provide either profile_id or config");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"config\":\"{nope\"}", &r);
    CHECK_ERROR(&r, 400, "Pasted config is not valid JSON");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"profile_id\":\"missing\",\"config\":\"[]\"}", &r);
    CHECK_ERROR(&r, 404, "Profile not found");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"config\":\"[{\\\"type\\\":5}]\"}", &r);
    CHECK_ERROR(&r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");
    sb_test_response_free(&r);
    /* Scalars and objects without outbounds import nothing. */
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"config\":\"42\"}", &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "{\"added\":0,\"errors\":[],\"found\":0,\"skipped\":[],\"updated\":0}");
    sb_test_response_free(&r);
    /* Bare arrays, skipped outbounds and updates of existing nodes. */
    const char *config = "{\"config\":\"[{\\\"type\\\":\\\"selector\\\",\\\"tag\\\":\\\"Proxy\\\"},"
                         "{\\\"type\\\":\\\"trojan\\\",\\\"tag\\\":\\\"T1\\\",\\\"server\\\":\\\"t1.example.com\\\","
                         "\\\"server_port\\\":443,\\\"password\\\":\\\"p\\\"},"
                         "{\\\"type\\\":\\\"vmess\\\",\\\"tag\\\":\\\"Broken\\\",\\\"server\\\":\\\"\\\","
                         "\\\"server_port\\\":1}]\"}";
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", config, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "found"), 1);
    CHECK_EQ_INT(jint(r.json, "added"), 1);
    CHECK_EQ_INT(jint(r.json, "updated"), 0);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "skipped")), 1);
    CHECK_STR(sbj_as_str(sbj_arr_at(sbj_get(r.json, "skipped"), 0), NULL), "Broken (vmess)");
    sb_test_response_free(&r);
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", config, &r);
    CHECK_EQ_INT(jint(r.json, "added"), 0);
    CHECK_EQ_INT(jint(r.json, "updated"), 1);
    sb_test_response_free(&r);
    /* profile_id wins over config; the seeded default profile has no proxy outbounds. */
    sb_test_request(&t, "POST", "/api/proxy/nodes/import", "{\"profile_id\":\"default\",\"config\":\"{nope\"}", &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "found"), 0);
    sb_test_response_free(&r);
    contract_stop(&c, &t);
}

/* ---- subscriptions ---------------------------------------------------------- */

static char *create_subscription(sb_test_server *t, const char *body_json, sb_test_response *r) {
    sb_test_request(t, "POST", "/api/subscriptions", body_json, r);
    return r->status == 200 ? sb_strdup(jstr(r->json, "id")) : NULL;
}

TEST(subscription_validation_and_names) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    sb_test_response r;
    static const struct {
        const char *body;
        const char *error;
    } bad[] = {
        {"[]", "Request body must be a JSON object"},
        {"{\"name\":\"x\"}", "url must be a non-empty string"},
        {"{\"url\":\"http://a/b\"}", "name must be a string"},
        {"{\"url\":\"http://a/b\",\"name\":null}", "name must be a string"},
        {"{\"url\":\"http://a/b\",\"name\":\"n\",\"refresh_interval\":\"60\"}", "refresh_interval must be an integer"},
        {"{\"url\":\"http://a/b\",\"name\":\"n\",\"refresh_interval\":0}", "refresh_interval must be positive"},
        {"{\"url\":\"http://a/b\",\"name\":\"n\",\"refresh_interval\":9223372036854775808}",
         "refresh_interval must be positive"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        sb_test_request(&t, "POST", "/api/subscriptions", bad[i].body, &r);
        CHECK_ERROR(&r, 400, bad[i].error);
        sb_test_response_free(&r);
    }
    static const struct {
        const char *url;
        const char *name;
    } names[] = {
        {"https://user:pw@Example.com:8443/path?q=1", "Example.com"},
        {"http://[2001:db8::1]:8080/x", "2001:db8::1"},
        {"http://[::1", "[::1"},
        {"plain-host:99/list", "plain-host"},
        {"https://", "Subscription"},
        {"http://host?token=a:b", "host?token=a"},
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i) {
        char *body = sb_asprintf("{\"name\":\" \\t\",\"url\":\"%s\",\"refresh_interval\":null}", names[i].url);
        char *id = create_subscription(&t, body, &r);
        free(body);
        CHECK_EQ_INT(r.status, 200);
        CHECK_STR(jstr(r.json, "name"), names[i].name);
        CHECK_EQ_INT(jint(r.json, "refresh_interval"), 3600);
        CHECK(sbj_get_bool(r.json, "enabled", false));
        CHECK(jnull(r.json, "last_fetched_at"));
        sb_test_response_free(&r);
        free(id);
    }
    char *id = create_subscription(&t, "{\"name\":\"  Named  \",\"url\":\"http://a/b\",\"enabled\":false}", &r);
    CHECK_STR(jstr(r.json, "name"), "Named");
    CHECK(sbj_get_bool(r.json, "enabled", false)); /* create always enables */
    sb_test_response_free(&r);

    char *path = sb_asprintf("/api/subscriptions/%s", id);
    static const struct {
        const char *body;
        const char *error;
    } bad_updates[] = {
        {"{\"name\":\"\"}", "name must be a non-empty string"},
        {"{\"url\":5}", "url must be a non-empty string"},
        {"{\"enabled\":\"no\"}", "enabled must be a boolean"},
        {"{\"refresh_interval\":-5}", "refresh_interval must be positive"},
        {"{\"name\":\"   \"}", "Subscription id, name, URL, and positive refresh interval are required"},
        {"1", "Request body must be a JSON object"},
    };
    for (size_t i = 0; i < sizeof bad_updates / sizeof bad_updates[0]; ++i) {
        sb_test_request(&t, "PUT", path, bad_updates[i].body, &r);
        CHECK_ERROR(&r, 400, bad_updates[i].error);
        sb_test_response_free(&r);
    }
    sb_test_request(&t, "PUT", path, "{\"name\":\" Renamed \",\"url\":null,\"enabled\":false,\"refresh_interval\":60}",
                    &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "name"), "Renamed");
    CHECK_STR(jstr(r.json, "url"), "http://a/b");
    CHECK(!sbj_get_bool(r.json, "enabled", true));
    CHECK_EQ_INT(jint(r.json, "refresh_interval"), 60);
    sb_test_response_free(&r);
    sb_test_request(&t, "GET", "/api/subscriptions", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_arr_len(r.json), 7);
    sb_test_response_free(&r);
    sb_test_request(&t, "DELETE", path, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "success", false));
    sb_test_response_free(&r);
    const char *methods[] = {"GET", "PUT", "DELETE"};
    for (size_t i = 0; i < 3; ++i) {
        sb_test_request(&t, methods[i], path, i == 1 ? "{}" : NULL, &r);
        CHECK_ERROR(&r, 404, "Subscription not found");
        sb_test_response_free(&r);
    }
    free(path);
    path = sb_asprintf("/api/subscriptions/%s/fetch", id);
    sb_test_request(&t, "POST", path, NULL, &r);
    CHECK_ERROR(&r, 404, "Subscription not found");
    sb_test_response_free(&r);
    free(path);
    free(id);
    contract_stop(&c, &t);
}

TEST(subscription_fetching) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    sb_test_response r;
    unsigned port = c.subscriptions.port;
    char *body = sb_asprintf("{\"name\":\"B64\",\"url\":\"http://127.0.0.1:%u/fixture/base64\"}", port);
    char *b64 = create_subscription(&t, body, &r);
    free(body);
    sb_test_response_free(&r);
    body = sb_asprintf("{\"name\":\"Clash\",\"url\":\"http://127.0.0.1:%u/fixture/clash.yaml\"}", port);
    char *yaml = create_subscription(&t, body, &r);
    free(body);
    sb_test_response_free(&r);
    body = sb_asprintf("{\"name\":\"Missing\",\"url\":\"http://127.0.0.1:%u/fixture/missing\"}", port);
    char *missing = create_subscription(&t, body, &r);
    free(body);
    sb_test_response_free(&r);
    body = sb_asprintf("{\"name\":\"Redirect\",\"url\":\"http://127.0.0.1:%u/fixture/redirect\"}", port);
    char *redirect = create_subscription(&t, body, &r);
    free(body);
    sb_test_response_free(&r);
    body = sb_asprintf("{\"name\":\"Vmess\",\"url\":\"http://127.0.0.1:%u/fixture/bad-vmess\"}", port);
    char *vmess = create_subscription(&t, body, &r);
    free(body);
    sb_test_response_free(&r);
    char *disabled = create_subscription(&t, "{\"name\":\"Zz disabled\",\"url\":\"ftp://nowhere/x\"}", &r);
    sb_test_response_free(&r);
    REQUIRE(b64 && yaml && missing && redirect && vmess && disabled);
    char *path = sb_asprintf("/api/subscriptions/%s", disabled);
    sb_test_request(&t, "PUT", path, "{\"enabled\":false}", &r);
    free(path);
    sb_test_response_free(&r);

    path = sb_asprintf("/api/subscriptions/%s/fetch", b64);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "{\"added\":2,\"errors\":[],\"found\":2,\"skipped\":0,\"updated\":0}");
    sb_test_response_free(&r);
    path = sb_asprintf("/api/subscriptions/%s/fetch", yaml);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(jint(r.json, "found"), 2);
    CHECK_EQ_INT(jint(r.json, "added"), 2);
    sb_test_response_free(&r);
    path = sb_asprintf("/api/subscriptions/%s", yaml);
    sb_test_request(&t, "GET", path, NULL, &r);
    free(path);
    CHECK_STR(jstr(r.json, "last_fetch_result"), "{\"added\":2,\"errors\":[],\"skipped\":0,\"total\":2,\"updated\":0}");
    sb_test_response_free(&r);
    path = sb_asprintf("/api/subscriptions/%s/fetch", missing);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_ERROR(&r, 400, "Failed to fetch subscription: subscription returned HTTP 404");
    sb_test_response_free(&r);
    path = sb_asprintf("/api/subscriptions/%s/fetch", vmess);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 400);
    CHECK_CONTAINS(r.json ? jstr(r.json, "error") : NULL, "Invalid JSON request: [json.exception.type_error.302]");
    sb_test_response_free(&r);
    path = sb_asprintf("/api/subscriptions/%s/fetch", redirect);
    sb_test_request(&t, "POST", path, NULL, &r);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "added"), 1);
    sb_test_response_free(&r);

    /* fetch-all: enabled subscriptions in name order, errors per entry. */
    sb_test_request(&t, "POST", "/api/subscriptions/fetch-all", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    REQUIRE(sbj_arr_len(r.json) == 5);
    const char *order[] = {"B64", "Clash", "Missing", "Redirect", "Vmess"};
    for (size_t i = 0; i < 5; ++i) CHECK_STR(jstr(sbj_arr_at(r.json, i), "name"), order[i]);
    const sbj *first = sbj_arr_at(r.json, 0);
    CHECK_EQ_INT(jint(first, "updated"), 2);
    CHECK_EQ_INT(jint(first, "added"), 0);
    CHECK(!sbj_has(first, "skipped"));
    CHECK_STR(jstr(sbj_arr_at(r.json, 2), "error"), "Failed to fetch subscription: subscription returned HTTP 404");
    CHECK_STR(jstr(sbj_arr_at(r.json, 2), "id"), missing);
    CHECK_CONTAINS(jstr(sbj_arr_at(r.json, 4), "error"), "[json.exception.type_error.302]");
    sb_test_response_free(&r);

    /* Subscribed nodes carry their subscription id. */
    sb_test_request(&t, "GET", "/api/proxy/nodes", NULL, &r);
    CHECK_EQ_INT(sbj_arr_len(r.json), 5);
    const sbj *item;
    size_t owned = 0;
    SBJ_ARR_FOREACH(r.json, i, item) if (sb_streq(jstr(item, "subscription_id"), yaml)) ++owned;
    CHECK_EQ_INT(owned, 2);
    sb_test_response_free(&r);

    free(b64);
    free(yaml);
    free(missing);
    free(redirect);
    free(vmess);
    free(disabled);
    contract_stop(&c, &t);
}

/* ---- WebSocket bridge ------------------------------------------------------- */

/* Opens /api/sing-box/ws/<kind> for `host` (NULL: local) with the admin token. */
static int open_stream(sb_test_server *t, ws_client *ws, const char *kind, const char *host, const char *extra_query) {
    char *target = sb_asprintf("/api/sing-box/ws/%s?token=%s%s%s%s", kind, t->token, host ? "&host=" : "",
                               host ? host : "", extra_query ? extra_query : "");
    int rc = ws_client_open(ws, t->port, target);
    free(target);
    return rc;
}

/* Expects {"error": message} followed by Close 1011 "upstream unavailable". */
static void expect_stream_error(ws_client *ws, const char *message) {
    int opcode = 0;
    char *payload = NULL;
    size_t len = 0;
    CHECK_EQ_INT(ws->status, 101);
    if (ws_client_frame(ws, &opcode, &payload, &len) != 1) {
        CHECK(!"no error frame");
        return;
    }
    CHECK_EQ_INT(opcode, 1);
    sbj *body = sbj_parse(payload, len, NULL, 0);
    CHECK_STR(jstr(body, "error"), message);
    CHECK_EQ_INT(sbj_obj_len(body), 1);
    sbj_free(body);
    free(payload);
    if (ws_client_frame(ws, &opcode, &payload, &len) != 1) {
        CHECK(!"no close frame");
        return;
    }
    CHECK_EQ_INT(opcode, 8);
    CHECK_EQ_INT(close_code(payload, len), 1011);
    CHECK(len >= 2 && strcmp(payload + 2, "upstream unavailable") == 0);
    free(payload);
}

static void expect_close(ws_client *ws, int code, const char *reason) {
    int opcode = 0;
    char *payload = NULL;
    size_t len = 0;
    if (ws_client_frame(ws, &opcode, &payload, &len) != 1) {
        CHECK(!"no close frame");
        return;
    }
    CHECK_EQ_INT(opcode, 8);
    CHECK_EQ_INT(close_code(payload, len), code);
    CHECK(len >= 2 && strcmp(payload + 2, reason) == 0);
    free(payload);
}

TEST(websocket_authentication) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    ws_client ws;
    const char *rejected[] = {"/api/sing-box/ws/memory", "/api/sing-box/ws/memory?token=", "/api/sing-box/ws/memory?token=%20",
                              "/api/sing-box/ws/connections?token=a.b.c"};
    for (size_t i = 0; i < sizeof rejected / sizeof rejected[0]; ++i) {
        REQUIRE(ws_client_open(&ws, t.port, rejected[i]) == 0);
        CHECK_EQ_INT(ws.status, 401);
        CHECK_STR(ws.body, "{\"error\":\"Invalid or expired token\"}");
        char *type = head_value(ws.head, "Content-Type");
        CHECK_STR(type, "application/json; charset=utf-8");
        free(type);
        ws_client_close(&ws);
    }
    /* CORS headers are applied to the pre-upgrade rejection. */
    REQUIRE(ws_client_open_ex(&ws, t.port, "/api/sing-box/ws/traffic", "Origin: https://allowed.example\r\n") == 0);
    CHECK_EQ_INT(ws.status, 401);
    char *origin = head_value(ws.head, "Access-Control-Allow-Origin");
    CHECK_STR(origin, "https://allowed.example");
    free(origin);
    ws_client_close(&ws);
    /* The token is trimmed; the last duplicate parameter wins (Drogon). */
    char *target = sb_asprintf("/api/sing-box/ws/memory?token=bad&token=%%20%s%%20", t.token);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 101);
    ws_client_close(&ws);
    /* Drogon routes on the decoded path: an encoded kind still streams, while
     * case variants are not Clash stream paths (the core answers those). */
    target = sb_asprintf("/api/sing-box/ws/%%74raffic?token=%s", t.token);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 101);
    {
        int op = 0;
        char *msg = NULL;
        size_t n = 0;
        if (ws_client_frame(&ws, &op, &msg, &n) == 1) {
            CHECK_CONTAINS(msg, "\"target\":\"/local/traffic?token=local-secret\"");
            free(msg);
        } else {
            CHECK(!"encoded kind returned no payload");
        }
    }
    ws_client_close(&ws);
    target = sb_asprintf("/API/sing-box/ws/traffic?token=%s", t.token);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 404);
    ws_client_close(&ws);
    target = sb_asprintf("/api/sing-box/ws/TRAFFIC?token=%s", t.token);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 401);
    ws_client_close(&ws);
    /* Viewers may stream (only a valid token is required). */
    char *viewer = sb_test_token(&t, "viewer-id", "viewer", "viewer");
    target = sb_asprintf("/api/sing-box/ws/connections?token=%s", viewer);
    REQUIRE(ws_client_open(&ws, t.port, target) == 0);
    free(target);
    CHECK_EQ_INT(ws.status, 101);
    int opcode = 0;
    char *payload = NULL;
    size_t len = 0;
    if (ws_client_frame(&ws, &opcode, &payload, &len) == 1) {
        CHECK_CONTAINS(payload, "\"target\":\"/local/connections?token=local-secret\"");
        free(payload);
    }
    ws_client_close(&ws);
    free(viewer);
    contract_stop(&c, &t);
}

TEST(websocket_upstream_failures) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    ws_client ws;

    char *ftp = add_clash_host(&t, "ftp", "ftp://controller.example", "");
    REQUIRE(open_stream(&t, &ws, "traffic", ftp, NULL) == 0);
    expect_stream_error(&ws, "Clash API URL must use http, https, ws, or wss");
    ws_client_close(&ws);

    char *dead_url = sb_asprintf("http://127.0.0.1:%u", (unsigned)unused_port());
    char *dead = add_clash_host(&t, "dead", dead_url, "");
    free(dead_url);
    REQUIRE(open_stream(&t, &ws, "memory", dead, NULL) == 0);
    expect_stream_error(&ws, "Could not connect to sing-box Clash WebSocket: Network failure");
    ws_client_close(&ws);

    const char *bad_ports[] = {"ws://127.0.0.1:0/x", "http://127.0.0.1:65536", "https://[::1]:abc", "ws://:9090"};
    for (size_t i = 0; i < sizeof bad_ports / sizeof bad_ports[0]; ++i) {
        char *id = add_clash_host(&t, bad_ports[i], bad_ports[i], "");
        REQUIRE(open_stream(&t, &ws, "logs", id, NULL) == 0);
        expect_stream_error(&ws, "Could not connect to sing-box Clash WebSocket: Bad server address");
        ws_client_close(&ws);
        free(id);
    }

    ws_upstream reject;
    ws_upstream_init(&reject);
    reject.reject_status = 401;
    REQUIRE(ws_upstream_start(&reject) == 0);
    char *url = sb_asprintf("http://127.0.0.1:%u", (unsigned)reject.port);
    char *rejecting = add_clash_host(&t, "rejecting", url, "");
    free(url);
    REQUIRE(open_stream(&t, &ws, "connections", rejecting, NULL) == 0);
    expect_stream_error(&ws, "Could not connect to sing-box Clash WebSocket: Bad response from server");
    ws_client_close(&ws);
    ws_upstream_finish(&reject);
    ws_upstream_free(&reject);

    /* A failed TLS handshake drops the upstream: "upstream closed". */
    ws_upstream garbage;
    ws_upstream_init(&garbage);
    garbage.garbage = true;
    REQUIRE(ws_upstream_start(&garbage) == 0);
    url = sb_asprintf("https://127.0.0.1:%u", (unsigned)garbage.port);
    char *tls = add_clash_host(&t, "tls", url, "");
    free(url);
    REQUIRE(open_stream(&t, &ws, "traffic", tls, NULL) == 0);
    CHECK_EQ_INT(ws.status, 101);
    expect_close(&ws, 1001, "upstream closed");
    ws_client_close(&ws);
    ws_upstream_finish(&garbage);
    ws_upstream_free(&garbage);

    free(ftp);
    free(dead);
    free(rejecting);
    free(tls);
    contract_stop(&c, &t);

    /* No local controller at all. */
    REQUIRE(contract_start(&c, &t, "") == 0);
    REQUIRE(open_stream(&t, &ws, "logs", NULL, NULL) == 0);
    expect_stream_error(&ws, "No sing-box Clash API URL is configured");
    ws_client_close(&ws);
    contract_stop(&c, &t);
}

TEST(websocket_relay_and_teardown) {
    contract_ctx c;
    sb_test_server t;
    REQUIRE(contract_start(&c, &t, NULL) == 0);
    ws_client ws;
    int opcode = 0;
    char *payload = NULL;
    size_t len = 0;

    /* Fragmented text, binary, a large message and a ping are relayed; the
     * ping is answered upstream; the browser closing sends Close 1000 up. */
    ws_upstream up;
    ws_upstream_init(&up);
    append_frame(&up.script, false, 0x1, "hel", 3, false);
    append_frame(&up.script, true, 0x0, "lo", 2, false);
    const unsigned char binary[3] = {0, 1, 2};
    append_frame(&up.script, true, 0x2, binary, 3, false);
    char *large = sb_xmalloc(70001);
    for (size_t i = 0; i < 70000; ++i) large[i] = (char)('a' + i % 26);
    large[70000] = '\0';
    append_frame(&up.script, true, 0x1, large, 70000, false);
    append_frame(&up.script, true, 0x9, "p1", 2, false);
    up.hold_ms = 3000;
    REQUIRE(ws_upstream_start(&up) == 0);
    char *url = sb_asprintf("http://127.0.0.1:%u/base/", (unsigned)up.port);
    char *host = add_clash_host(&t, "relay", url, "s p/+");
    free(url);
    REQUIRE(open_stream(&t, &ws, "logs", host, "&level=%20info%20") == 0);
    CHECK_EQ_INT(ws.status, 101);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_EQ_INT(opcode, 1);
    CHECK_STR(payload, "hello");
    free(payload);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_EQ_INT(opcode, 2);
    CHECK(len == 3 && memcmp(payload, binary, 3) == 0);
    free(payload);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_EQ_INT(opcode, 1);
    CHECK(len == 70000 && memcmp(payload, large, 70000) == 0);
    free(payload);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_EQ_INT(opcode, 9);
    CHECK_STR(payload, "p1");
    free(payload);
    ws_client_send_close(&ws, 1000);
    ws_upstream_finish(&up);
    CHECK_STR(up.target, "/base/logs?level=info&token=s+p%2F%2B");
    CHECK_STR(up.pong, "p1");
    CHECK_EQ_INT(up.close_code, 1000);
    ws_client_close(&ws);
    ws_upstream_free(&up);
    free(host);
    free(large);

    /* The upstream's own Close frame is forwarded to the browser. */
    ws_upstream closing;
    ws_upstream_init(&closing);
    append_frame(&closing.script, true, 0x1, "{\"up\":1}", 8, false);
    unsigned char bye[5] = {0x03, 0xe8, 'b', 'y', 'e'};
    append_frame(&closing.script, true, 0x8, bye, sizeof bye, false);
    closing.hold_ms = 1000;
    REQUIRE(ws_upstream_start(&closing) == 0);
    url = sb_asprintf("ws://127.0.0.1:%u", (unsigned)closing.port);
    host = add_clash_host(&t, "closing", url, "");
    free(url);
    REQUIRE(open_stream(&t, &ws, "traffic", host, "&level=debug") == 0);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_STR(payload, "{\"up\":1}");
    free(payload);
    expect_close(&ws, 1000, "bye");
    ws_client_send_close(&ws, 1000);
    ws_upstream_finish(&closing);
    CHECK_STR(closing.target, "/traffic");
    ws_client_close(&ws);
    ws_upstream_free(&closing);
    free(host);

    /* An upstream that just goes away: 1001 "upstream closed". */
    ws_upstream gone;
    ws_upstream_init(&gone);
    append_frame(&gone.script, true, 0x1, "last", 4, false);
    REQUIRE(ws_upstream_start(&gone) == 0);
    url = sb_asprintf("http://127.0.0.1:%u", (unsigned)gone.port);
    host = add_clash_host(&t, "gone", url, "secret");
    free(url);
    REQUIRE(open_stream(&t, &ws, "memory", host, NULL) == 0);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    CHECK_STR(payload, "last");
    free(payload);
    expect_close(&ws, 1001, "upstream closed");
    ws_client_send_close(&ws, 1000);
    ws_upstream_finish(&gone);
    CHECK_STR(gone.target, "/memory?token=secret");
    ws_client_close(&ws);
    ws_upstream_free(&gone);
    free(host);

    /* Browser disconnecting abruptly mid-stream still tears the upstream down. */
    ws_upstream held;
    ws_upstream_init(&held);
    append_frame(&held.script, true, 0x1, "x", 1, false);
    held.hold_ms = 3000;
    REQUIRE(ws_upstream_start(&held) == 0);
    url = sb_asprintf("http://127.0.0.1:%u", (unsigned)held.port);
    host = add_clash_host(&t, "held", url, "");
    free(url);
    REQUIRE(open_stream(&t, &ws, "connections", host, NULL) == 0);
    REQUIRE(ws_client_frame(&ws, &opcode, &payload, &len) == 1);
    free(payload);
    ws_client_close(&ws);
    ws_upstream_finish(&held);
    CHECK_EQ_INT(held.close_code, 1000);
    ws_upstream_free(&held);
    free(host);

    contract_stop(&c, &t);
}
