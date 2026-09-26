/* Authenticated Clash WebSocket bridge for /api/sing-box/ws/{traffic,logs,
 * connections,memory}. Port of cpp/src/clash_websocket.cpp.
 *
 * Browser side: civetweb WebSocket handlers. The ?token= JWT is checked in
 * the connect handler, i.e. before the upgrade, answering the same 401 JSON
 * as the C++ pre-routing advice. After the handshake a relay thread resolves
 * the Clash target (?host=), opens the upstream WebSocket and forwards every
 * upstream message to the browser; browser messages are ignored (the streams
 * are downstream-only). Upstream side: a small RFC 6455 client over plain
 * sockets or OpenSSL (wss), replacing Drogon's WebSocketClient.
 *
 * Teardown: when the browser goes away civetweb calls the close handler,
 * which marks the browser closed, wakes the relay thread through a pipe and
 * joins it (the relay then sends a Close frame upstream). When the upstream
 * ends, the relay sends the browser a Close frame (1001 "upstream closed", or
 * the upstream's own Close payload) and exits; the browser's reply ends
 * civetweb's read loop. */
#include "http_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "civetweb.h"
#include "sb/auth.h"

static const char websocket_prefix[] = "/api/sing-box/ws/";
static const char *const stream_kinds[] = {"traffic", "logs", "connections", "memory"};

/* stream_kind(): the exact kind after the prefix, or NULL. */
static const char *stream_kind(const char *path) {
    size_t n = sizeof websocket_prefix - 1;
    if (!path || strncmp(path, websocket_prefix, n) != 0) return NULL;
    for (size_t i = 0; i < sizeof stream_kinds / sizeof stream_kinds[0]; ++i)
        if (strcmp(path + n, stream_kinds[i]) == 0) return stream_kinds[i];
    return NULL;
}

/* The request path as Drogon routes it: civetweb runs with decode_url=no, so
 * local_uri is still percent-encoded; Drogon's urlDecode also maps '+'. */
static const char *request_stream_kind(const struct mg_connection *conn) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    const char *raw = ri && ri->local_uri ? ri->local_uri : "";
    char *path = sb_xmalloc(strlen(raw) + 1);
    size_t o = 0;
    for (size_t i = 0; raw[i]; ++i) {
        if (raw[i] == '+') {
            path[o++] = ' ';
        } else if (raw[i] == '%' && isxdigit((unsigned char)raw[i + 1]) && isxdigit((unsigned char)raw[i + 2])) {
            char hex[3] = {raw[i + 1], raw[i + 2], 0};
            path[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            path[o++] = raw[i];
        }
    }
    path[o] = '\0';
    const char *kind = strlen(path) == o ? stream_kind(path) : NULL; /* no embedded NUL */
    free(path);
    return kind;
}

/* A request view over a civetweb connection so the shared request helpers
 * (query decoding, headers) apply exactly as for the HTTP routes. */
static void request_view(sb_http_server *srv, const struct mg_connection *conn, sb_http_req *req) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    memset(req, 0, sizeof *req);
    req->server = srv;
    req->conn = (struct mg_connection *)conn;
    req->method = ri && ri->request_method ? ri->request_method : "GET";
    req->path = ri && ri->local_uri ? ri->local_uri : "";
    req->query = ri ? ri->query_string : NULL;
    req->body = "";
    req->remote_addr = ri ? ri->remote_addr : "";
}

/* getParameter(name); malloc'd, "" when absent. */
static char *param_or_empty(const sb_http_req *req, const char *name) {
    char *value = sb_req_query_param(req, name);
    return value ? value : sb_strdup("");
}

/* ---- Drogon URL encoding (upstream upgrade request) ---------------------- */

static void put_hex(sb_buf *b, unsigned char c) {
    static const char hex[] = "0123456789ABCDEF";
    char enc[3] = {'%', hex[c >> 4], hex[c & 0x0f]};
    sb_buf_append(b, enc, 3);
}

/* drogon::utils::urlEncode(): applied to the request path. */
static void drogon_url_encode(sb_buf *b, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == ' ') sb_buf_putc(b, '+');
        else if (isalnum(*p) || strchr("-_.!~*'()&=/\\?", *p)) sb_buf_putc(b, (char)*p);
        else put_hex(b, *p);
    }
}

/* drogon::utils::urlEncodeComponent(): applied to query parameters. */
static void drogon_url_encode_component(sb_buf *b, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == ' ') sb_buf_putc(b, '+');
        else if (isalnum(*p) || strchr("-_.!~*()", *p)) sb_buf_putc(b, (char)*p);
        else put_hex(b, *p);
    }
}

/* ---- targets ---------------------------------------------------------- */

typedef struct {
    char *base_url;
    char *secret;
} clash_target;

static void clash_target_free(clash_target *t) {
    free(t->base_url);
    free(t->secret);
    t->base_url = t->secret = NULL;
}

/* resolve_target(): same rules as the HTTP routes' resolve_clash_target(). */
static int resolve_target(sb_http_server *srv, const char *host_param, clash_target *out, sb_err *err) {
    out->base_url = out->secret = NULL;
    char *host_id = sb_http_trim(host_param);
    if (*host_id && strcmp(host_id, "self") != 0) {
        sb_host host;
        sb_host_init(&host);
        int found = sb_store_find_host(srv->store, host_id, &host, err);
        if (found < 0) {
            sb_host_free(&host);
            free(host_id);
            return -1;
        }
        if (found == 1 && host.clash_api) {
            char *url = sb_http_trim_trailing_slashes(host.clash_api);
            if (*url) {
                out->base_url = url;
                out->secret = sb_strdup(host.clash_secret ? host.clash_secret : "");
                sb_host_free(&host);
                free(host_id);
                return 0;
            }
            free(url);
        }
        sb_host_free(&host);
    }
    free(host_id);
    out->base_url = sb_http_trim_trailing_slashes(srv->opts.clash_api_url ? srv->opts.clash_api_url : "");
    out->secret = sb_strdup(srv->opts.clash_api_secret ? srv->opts.clash_api_secret : "");
    return 0;
}

/* The upstream endpoint as Drogon's WebSocketClient would dial it. */
typedef struct {
    bool tls;
    char *host;     /* lowercased domain (IPv6 without brackets) */
    int port;       /* 0 when the authority has an unusable port */
    char *target;   /* request target: encoded path + query */
    char *host_header;
} upstream_endpoint;

static void upstream_endpoint_free(upstream_endpoint *e) {
    free(e->host);
    free(e->target);
    free(e->host_header);
    memset(e, 0, sizeof *e);
}

/* upstream_target() + WebSocketClient::newWebSocketClient(origin) +
 * HttpRequest rendering. Fails with the C++ std::invalid_argument message. */
static int upstream_endpoint_init(upstream_endpoint *e, const clash_target *target, const char *kind,
                                  const char *level, sb_err *err) {
    memset(e, 0, sizeof *e);
    const char *base = target->base_url;
    char *url;
    if (sb_starts_with(base, "http://")) url = sb_asprintf("ws://%s", base + 7);
    else if (sb_starts_with(base, "https://")) url = sb_asprintf("wss://%s", base + 8);
    else if (sb_starts_with(base, "ws://") || sb_starts_with(base, "wss://")) url = sb_strdup(base);
    else return sb_fail(err, SB_ERR_VALIDATION, "Clash API URL must use http, https, ws, or wss");

    char *authority_start = strstr(url, "://") + 3;
    char *path_start = strchr(authority_start, '/');
    char *raw_path = path_start ? sb_http_trim_trailing_slashes(path_start) : sb_strdup("");
    if (path_start) *path_start = '\0';
    char *path = sb_asprintf("%s/%s", raw_path, kind);
    free(raw_path);

    /* Drogon lowercases the origin and parses host[:port]. */
    e->tls = sb_starts_with(url, "wss://");
    char *authority = sb_lower_dup(authority_start);
    int default_port = e->tls ? 443 : 80;
    char *close = authority[0] == '[' ? strchr(authority, ']') : NULL;
    if (close) {
        e->host = sb_strndup(authority + 1, (size_t)(close - authority - 1));
        if (close[1] == ':') {
            int port = atoi(close + 2);
            e->port = port > 0 && port < 65536 ? port : 0;
        } else {
            e->port = default_port;
        }
    } else {
        char *colon = strchr(authority, ':');
        if (colon) {
            e->host = sb_strndup(authority, (size_t)(colon - authority));
            int port = atoi(colon + 1);
            e->port = port > 0 && port < 65536 ? port : 0;
        } else {
            e->host = sb_strdup(authority);
            e->port = default_port;
        }
    }
    free(authority);
    bool ipv6 = strchr(e->host, ':') != NULL;
    if (e->port == default_port) e->host_header = ipv6 ? sb_asprintf("[%s]", e->host) : sb_strdup(e->host);
    else e->host_header = ipv6 ? sb_asprintf("[%s]:%d", e->host, e->port) : sb_asprintf("%s:%d", e->host, e->port);

    /* Parameters render in libstdc++ unordered_map order: the later insert
     * ("level") before the earlier one ("token"). */
    sb_buf t = {0};
    drogon_url_encode(&t, path);
    free(path);
    sb_buf params = {0};
    if (level && *level) {
        sb_buf_puts(&params, "level=");
        drogon_url_encode_component(&params, level);
    }
    if (!sb_str_empty(target->secret)) {
        if (params.len) sb_buf_putc(&params, '&');
        sb_buf_puts(&params, "token=");
        drogon_url_encode_component(&params, target->secret);
    }
    if (params.len) {
        const char *question = strchr(t.p, '?');
        if (!question) sb_buf_putc(&t, '?');
        else if (question[1] != '\0') sb_buf_putc(&t, '&');
        sb_buf_append(&t, params.p, params.len);
    }
    sb_buf_free(&params);
    e->target = sb_buf_detach(&t);
    free(url);
    return 0;
}

/* ---- pre-upgrade authentication ------------------------------------------ */

/* CorsPolicy::apply() for the 401 written before any upgrade. */
static void append_cors_headers(sb_http_server *srv, const struct mg_connection *conn, sb_buf *out) {
    char *origin = sb_http_trim(mg_get_header(conn, "Origin"));
    const char *allowed = NULL;
    if (*origin) {
        if (srv->cors_wildcard) allowed = "*";
        else if (sb_strvec_contains(&srv->cors_origins, origin)) allowed = origin;
    }
    if (allowed) {
        char *requested = sb_http_trim(mg_get_header(conn, "Access-Control-Request-Headers"));
        sb_buf_printf(out, "Access-Control-Allow-Origin: %s\r\n", allowed);
        sb_buf_puts(out, "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS\r\n");
        sb_buf_printf(out, "Access-Control-Allow-Headers: %s\r\n", *requested ? requested : "Authorization, Content-Type");
        sb_buf_puts(out, "Access-Control-Expose-Headers: ETag, Content-Disposition, X-SB-Easy-Rule-Source, "
                         "X-SB-Easy-Profile-Id, X-SB-Easy-Profile-Name\r\n");
        sb_buf_puts(out, "Access-Control-Max-Age: 600\r\n");
        if (!srv->cors_wildcard) sb_buf_puts(out, "Vary: Origin\r\n");
        free(requested);
    }
    free(origin);
}

static void reject_unauthorized(sb_http_server *srv, const struct mg_connection *conn) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", "Invalid or expired token");
    char *text = sbj_dump(body, -1);
    sbj_free(body);
    sb_buf headers = {0};
    append_cors_headers(srv, conn, &headers);
    mg_printf((struct mg_connection *)conn,
              "HTTP/1.1 401 Unauthorized\r\n"
              "Content-Type: application/json; charset=utf-8\r\n"
              "Content-Length: %zu\r\n"
              "%s"
              "Connection: close\r\n\r\n%s",
              strlen(text), headers.p ? headers.p : "", text);
    sb_buf_free(&headers);
    free(text);
}

/* Connect handler (before the handshake): the C++ pre-routing advice for
 * clash_websocket_path() — trim(?token=) must verify, else 401 JSON. */
static int ws_connect(const struct mg_connection *conn, void *cbdata) {
    sb_http_server *srv = cbdata;
    sb_http_req req;
    request_view(srv, conn, &req);
    bool authorized = false;
    if (request_stream_kind(conn)) {
        char *raw = sb_req_query_param(&req, "token");
        char *token = sb_http_trim(raw ? raw : "");
        free(raw);
        sb_auth_claims claims = {0};
        if (*token && sb_auth_verify_token(srv->opts.jwt_secret ? srv->opts.jwt_secret : "", token, &claims)) {
            authorized = true;
            sb_auth_claims_free(&claims);
        }
        free(token);
    }
    /* The core only lets upgrades of exact Clash stream paths reach civetweb's
     * WebSocket dispatch, so the kind check is a safety net. */
    if (authorized) return 0;
    reject_unauthorized(srv, conn);
    return 1;
}

/* ---- upstream WebSocket client -------------------------------------------- */

enum { IO_WOKEN = -2, IO_TIMEOUT = -3 };

#define PING_INTERVAL_MS 30000
#define MAX_MESSAGE_BYTES (64u * 1024u * 1024u)
#define MAX_HANDSHAKE_BYTES (64u * 1024u)

typedef struct {
    int fd;
    int wake_fd; /* readable once the browser side is gone */
    SSL_CTX *ctx;
    SSL *ssl;
} upstream_io;

static void upstream_io_close(upstream_io *io) {
    if (io->ssl) SSL_free(io->ssl);
    if (io->ctx) SSL_CTX_free(io->ctx);
    if (io->fd >= 0) close(io->fd);
    io->ssl = NULL;
    io->ctx = NULL;
    io->fd = -1;
}

/* 1 ready, IO_WOKEN (browser gone), IO_TIMEOUT, -1 error. timeout < 0 waits
 * forever. With ignore_wake only the socket is watched. */
static int io_wait(upstream_io *io, short events, int timeout_ms, bool ignore_wake) {
    struct pollfd fds[2] = {{io->fd, events, 0}, {io->wake_fd, POLLIN, 0}};
    nfds_t count = ignore_wake || io->wake_fd < 0 ? 1 : 2;
    for (;;) {
        int r = poll(fds, count, timeout_ms);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return IO_TIMEOUT;
        if (count == 2 && fds[1].revents) return IO_WOKEN;
        return 1;
    }
}

/* >0 bytes read, 0 end of stream, -1 error, IO_WOKEN, IO_TIMEOUT. */
static ssize_t io_read(upstream_io *io, void *buf, size_t n, int timeout_ms) {
    for (;;) {
        int want;
        if (io->ssl) {
            ERR_clear_error();
            int r = SSL_read(io->ssl, buf, n > INT32_MAX ? INT32_MAX : (int)n);
            if (r > 0) return r;
            int e = SSL_get_error(io->ssl, r);
            if (e == SSL_ERROR_ZERO_RETURN) return 0;
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
            want = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        } else {
            ssize_t r = recv(io->fd, buf, n, 0);
            if (r >= 0) return r;
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            want = POLLIN;
        }
        int w = io_wait(io, (short)want, timeout_ms, false);
        if (w != 1) return w;
    }
}

/* 0 all written, -1 error, IO_WOKEN. `final` writes (the Close sent after the
 * browser left) ignore the wake pipe and give up after a second. */
static int io_write_all(upstream_io *io, const void *data, size_t n, bool final) {
    const char *p = data;
    while (n > 0) {
        int want;
        if (io->ssl) {
            ERR_clear_error();
            int r = SSL_write(io->ssl, p, n > INT32_MAX ? INT32_MAX : (int)n);
            if (r > 0) {
                p += r;
                n -= (size_t)r;
                continue;
            }
            int e = SSL_get_error(io->ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
            want = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        } else {
            ssize_t r = send(io->fd, p, n, MSG_NOSIGNAL);
            if (r > 0) {
                p += r;
                n -= (size_t)r;
                continue;
            }
            if (r < 0 && errno == EINTR) continue;
            if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
            want = POLLOUT;
        }
        int w = io_wait(io, (short)want, final ? 1000 : -1, final);
        if (w == IO_WOKEN) return IO_WOKEN;
        if (w != 1) return -1;
    }
    return 0;
}

/* Masked client frame (only control frames are ever sent upstream). */
static int upstream_send(upstream_io *io, int opcode, const void *data, size_t len, bool final) {
    if (len > 125) len = 125;
    unsigned char frame[2 + 4 + 125];
    unsigned char mask[4];
    if (sb_random_bytes(mask, sizeof mask) != 0) memset(mask, 0x5a, sizeof mask);
    frame[0] = (unsigned char)(0x80 | (opcode & 0x0f));
    frame[1] = (unsigned char)(0x80 | len);
    memcpy(frame + 2, mask, 4);
    for (size_t i = 0; i < len; ++i) frame[6 + i] = (unsigned char)(((const unsigned char *)data)[i] ^ mask[i & 3]);
    return io_write_all(io, frame, 6 + len, final);
}

typedef enum { UP_OK, UP_WOKEN, UP_BAD_ADDRESS, UP_NETWORK, UP_BAD_RESPONSE, UP_CLOSED } upstream_result;

/* drogon::to_string_view(ReqResult) for the connect failures. */
static const char *upstream_reason(upstream_result r) {
    switch (r) {
    case UP_BAD_ADDRESS: return "Bad server address";
    case UP_BAD_RESPONSE: return "Bad response from server";
    default: return "Network failure";
    }
}

static upstream_result io_connect(upstream_io *io, const upstream_endpoint *e) {
    if (e->port <= 0 || !*e->host) return UP_BAD_ADDRESS;
    char port[16];
    snprintf(port, sizeof port, "%d", e->port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(e->host, port, &hints, &res) != 0 || !res) return UP_BAD_ADDRESS;
    upstream_result result = UP_NETWORK;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        io->fd = fd;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            result = UP_OK;
            break;
        }
        if (errno == EINPROGRESS) {
            int w = io_wait(io, POLLOUT, -1, false);
            if (w == IO_WOKEN) {
                result = UP_WOKEN;
                break;
            }
            int so_error = 0;
            socklen_t len = sizeof so_error;
            if (w == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0) {
                result = UP_OK;
                break;
            }
        }
        close(fd);
        io->fd = -1;
    }
    freeaddrinfo(res);
    return result;
}

/* TLS for wss:// with certificate and host verification (Drogon's client is
 * created with validateCert = true). A failed TLS handshake closes the TCP
 * connection, which Drogon reports as "upstream closed". */
static upstream_result io_tls(upstream_io *io, const upstream_endpoint *e) {
    io->ctx = SSL_CTX_new(TLS_client_method());
    if (!io->ctx) return UP_CLOSED;
    SSL_CTX_set_min_proto_version(io->ctx, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(io->ctx);
    SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(io->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    io->ssl = SSL_new(io->ctx);
    if (!io->ssl || SSL_set_fd(io->ssl, io->fd) != 1) return UP_CLOSED;
    unsigned char addr[16];
    if (inet_pton(AF_INET, e->host, addr) == 1 || inet_pton(AF_INET6, e->host, addr) == 1) {
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(io->ssl), e->host);
    } else {
        SSL_set_tlsext_host_name(io->ssl, e->host);
        SSL_set1_host(io->ssl, e->host);
    }
    for (;;) {
        ERR_clear_error();
        int r = SSL_connect(io->ssl);
        if (r == 1) return UP_OK;
        int err = SSL_get_error(io->ssl, r);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return UP_CLOSED;
        int w = io_wait(io, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, -1, false);
        if (w == IO_WOKEN) return UP_WOKEN;
        if (w != 1) return UP_CLOSED;
    }
}

static char *websocket_accept(const char *key) {
    char *input = sb_asprintf("%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char *accept = NULL;
    if (EVP_Digest(input, strlen(input), digest, &digest_len, EVP_sha1(), NULL) == 1)
        accept = sb_base64_encode(digest, digest_len);
    free(input);
    return accept;
}

/* Sends the upgrade request and validates the 101 + Sec-WebSocket-Accept.
 * Bytes after the response head stay in `in` (the first frames). */
static upstream_result upstream_handshake(upstream_io *io, const upstream_endpoint *e, sb_buf *in) {
    unsigned char nonce[16];
    if (sb_random_bytes(nonce, sizeof nonce) != 0) return UP_NETWORK;
    char *key = sb_base64_encode(nonce, sizeof nonce);
    char *request = sb_asprintf("GET %s HTTP/1.1\r\n"
                                "Host: %s\r\n"
                                "Connection: Upgrade\r\n"
                                "Upgrade: websocket\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "Sec-WebSocket-Key: %s\r\n\r\n",
                                e->target, e->host_header, key);
    upstream_result result = UP_OK;
    int w = io_write_all(io, request, strlen(request), false);
    free(request);
    if (w != 0) result = w == IO_WOKEN ? UP_WOKEN : UP_CLOSED;
    char *head_end = NULL;
    while (result == UP_OK) {
        head_end = in->p ? memmem(in->p, in->len, "\r\n\r\n", 4) : NULL;
        if (head_end) break;
        if (in->len > MAX_HANDSHAKE_BYTES) {
            result = UP_BAD_RESPONSE;
            break;
        }
        char chunk[4096];
        ssize_t n = io_read(io, chunk, sizeof chunk, -1);
        if (n == IO_WOKEN) result = UP_WOKEN;
        else if (n <= 0) result = UP_CLOSED;
        else sb_buf_append(in, chunk, (size_t)n);
    }
    if (result == UP_OK) {
        size_t head_len = (size_t)(head_end - in->p) + 4;
        char *head = sb_strndup(in->p, head_len - 2);
        int status = 0;
        if (sb_starts_with(head, "HTTP/1.") && strlen(head) > 12 && head[8] == ' ') status = atoi(head + 9);
        char *accept = NULL;
        for (char *line = strstr(head, "\r\n"); line && line[2]; line = strstr(line + 2, "\r\n")) {
            char *name = line + 2;
            if (strncasecmp(name, "Sec-WebSocket-Accept:", 21) == 0) {
                char *end = strstr(name, "\r\n");
                char *value = sb_strndup(name + 21, end ? (size_t)(end - name - 21) : strlen(name + 21));
                free(accept);
                accept = sb_http_trim(value);
                free(value);
            }
        }
        char *expected = websocket_accept(key);
        if (status != 101 || !accept || !expected || strcmp(accept, expected) != 0) result = UP_BAD_RESPONSE;
        free(expected);
        free(accept);
        free(head);
        memmove(in->p, in->p + head_len, in->len - head_len);
        in->len -= head_len;
        in->p[in->len] = '\0';
    }
    free(key);
    return result;
}

/* ---- bridge ------------------------------------------------------------ */

typedef struct ws_bridge {
    struct ws_bridge *next;
    const struct mg_connection *key;
    struct mg_connection *browser;
    sb_http_server *srv;
    pthread_mutex_t mutex; /* serialises browser writes against teardown */
    bool browser_open;     /* false once civetweb's close handler ran */
    bool browser_closing;  /* a Close frame was sent to the browser */
    int wake[2];
    pthread_t thread;
    bool thread_started;
    char kind[16];
    char *host;  /* raw ?host= */
    char *level; /* trimmed ?level= */
} ws_bridge;

/* Live bridges keyed by browser connection (the connection user-data slot is
 * left to the core). */
static pthread_mutex_t bridges_mutex = PTHREAD_MUTEX_INITIALIZER;
static ws_bridge *bridges;

static void bridge_register(ws_bridge *b) {
    pthread_mutex_lock(&bridges_mutex);
    b->next = bridges;
    bridges = b;
    pthread_mutex_unlock(&bridges_mutex);
}

static ws_bridge *bridge_take(const struct mg_connection *conn) {
    pthread_mutex_lock(&bridges_mutex);
    ws_bridge *found = NULL;
    for (ws_bridge **p = &bridges; *p; p = &(*p)->next) {
        if ((*p)->key == conn) {
            found = *p;
            *p = found->next;
            break;
        }
    }
    pthread_mutex_unlock(&bridges_mutex);
    return found;
}

static void bridge_free(ws_bridge *b) {
    if (b->wake[0] >= 0) close(b->wake[0]);
    if (b->wake[1] >= 0) close(b->wake[1]);
    pthread_mutex_destroy(&b->mutex);
    free(b->host);
    free(b->level);
    free(b);
}

static bool bridge_browser_open(ws_bridge *b) {
    pthread_mutex_lock(&b->mutex);
    bool open = b->browser_open && !b->browser_closing;
    pthread_mutex_unlock(&b->mutex);
    return open;
}

/* connection->send(message, type) while the browser is connected. */
static void browser_send(ws_bridge *b, int opcode, const void *data, size_t len) {
    pthread_mutex_lock(&b->mutex);
    if (b->browser_open && !b->browser_closing) {
        mg_websocket_write(b->browser, opcode, data, len);
        if (opcode == MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE) b->browser_closing = true;
    }
    pthread_mutex_unlock(&b->mutex);
}

static void close_payload(unsigned char *out, size_t *len, int code, const char *reason) {
    size_t n = strlen(reason);
    if (n > 123) n = 123;
    out[0] = (unsigned char)((code >> 8) & 0xff);
    out[1] = (unsigned char)(code & 0xff);
    memcpy(out + 2, reason, n);
    *len = 2 + n;
}

/* connection->shutdown(code, reason). */
static void browser_close(ws_bridge *b, int code, const char *reason) {
    unsigned char payload[125];
    size_t len = 0;
    close_payload(payload, &len, code, reason);
    browser_send(b, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, payload, len);
}

/* close_with_error(): {"error": message} then Close 1011 "upstream unavailable". */
static void close_with_error(ws_bridge *b, const char *message) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", message);
    char *text = sbj_dump(body, -1);
    sbj_free(body);
    unsigned char payload[125];
    size_t len = 0;
    close_payload(payload, &len, 1011, "upstream unavailable");
    pthread_mutex_lock(&b->mutex);
    if (b->browser_open && !b->browser_closing) {
        mg_websocket_write(b->browser, MG_WEBSOCKET_OPCODE_TEXT, text, strlen(text));
        mg_websocket_write(b->browser, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, (const char *)payload, len);
        b->browser_closing = true;
    }
    pthread_mutex_unlock(&b->mutex);
    free(text);
}

/* One frame from `in` at *offset: 1 parsed (masked payloads are unmasked in
 * place), 0 incomplete, -1 oversized. */
static int next_frame(sb_buf *in, size_t *offset, int *opcode, bool *fin, const char **payload, size_t *len) {
    unsigned char *p = (unsigned char *)in->p + *offset;
    size_t avail = in->len - *offset;
    if (avail < 2) return 0;
    size_t head = 2;
    uint64_t n = p[1] & 0x7f;
    if (n == 126) {
        if (avail < 4) return 0;
        n = ((uint64_t)p[2] << 8) | p[3];
        head = 4;
    } else if (n == 127) {
        if (avail < 10) return 0;
        n = 0;
        for (int i = 2; i < 10; ++i) n = (n << 8) | p[i];
        head = 10;
    }
    bool masked = (p[1] & 0x80) != 0;
    if (masked) head += 4;
    if (n > MAX_MESSAGE_BYTES) return -1;
    if (avail < head || avail - head < n) return 0;
    if (masked)
        for (uint64_t i = 0; i < n; ++i) p[head + i] ^= p[head - 4 + (i & 3)];
    *fin = (p[0] & 0x80) != 0;
    *opcode = p[0] & 0x0f;
    *payload = (const char *)p + head;
    *len = (size_t)n;
    *offset += head + (size_t)n;
    return 1;
}

typedef enum { PUMP_UPSTREAM_CLOSED, PUMP_UPSTREAM_CLOSE_FRAME, PUMP_BROWSER_GONE } pump_end;

/* Relays upstream messages until either side ends. Drogon forwards every
 * reassembled message with its type (text, binary, ping, pong, close) and
 * answers upstream pings itself; both sides are pinged every 30 s. */
static pump_end relay_pump(ws_bridge *b, upstream_io *io, sb_buf *in) {
    sb_buf message = {0};
    int message_opcode = 0;
    int64_t next_ping = sb_monotonic_ms() + PING_INTERVAL_MS;
    pump_end end = PUMP_UPSTREAM_CLOSED;
    for (;;) {
        size_t offset = 0;
        int opcode = 0;
        bool fin = false;
        const char *payload = NULL;
        size_t len = 0;
        int parsed;
        while ((parsed = next_frame(in, &offset, &opcode, &fin, &payload, &len)) == 1) {
            switch (opcode) {
            case MG_WEBSOCKET_OPCODE_TEXT:
            case MG_WEBSOCKET_OPCODE_BINARY:
                if (fin) {
                    browser_send(b, opcode, payload, len);
                } else {
                    sb_buf_reset(&message);
                    sb_buf_append(&message, payload, len);
                    message_opcode = opcode;
                }
                break;
            case MG_WEBSOCKET_OPCODE_CONTINUATION:
                if (!message_opcode || message.len + len > MAX_MESSAGE_BYTES) goto out;
                sb_buf_append(&message, payload, len);
                if (fin) {
                    browser_send(b, message_opcode, message.p, message.len);
                    sb_buf_reset(&message);
                    message_opcode = 0;
                }
                break;
            case MG_WEBSOCKET_OPCODE_PING: {
                int w = upstream_send(io, MG_WEBSOCKET_OPCODE_PONG, payload, len, false);
                if (w != 0) {
                    end = w == IO_WOKEN ? PUMP_BROWSER_GONE : PUMP_UPSTREAM_CLOSED;
                    goto out;
                }
                browser_send(b, MG_WEBSOCKET_OPCODE_PING, payload, len > 125 ? 125 : len);
                break;
            }
            case MG_WEBSOCKET_OPCODE_PONG:
                browser_send(b, MG_WEBSOCKET_OPCODE_PONG, payload, len > 125 ? 125 : len);
                break;
            case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
                browser_send(b, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, payload, len > 125 ? 125 : len);
                end = PUMP_UPSTREAM_CLOSE_FRAME;
                goto out;
            default:
                goto out; /* protocol error: the upstream connection is dropped */
            }
        }
        if (parsed < 0) goto out;
        if (offset > 0) {
            memmove(in->p, in->p + offset, in->len - offset);
            in->len -= offset;
            in->p[in->len] = '\0';
        }
        if (!bridge_browser_open(b)) {
            end = PUMP_BROWSER_GONE;
            goto out;
        }
        int64_t now = sb_monotonic_ms();
        if (now >= next_ping) {
            browser_send(b, MG_WEBSOCKET_OPCODE_PING, "", 0);
            int w = upstream_send(io, MG_WEBSOCKET_OPCODE_PING, "", 0, false);
            if (w != 0) {
                end = w == IO_WOKEN ? PUMP_BROWSER_GONE : PUMP_UPSTREAM_CLOSED;
                goto out;
            }
            next_ping = now + PING_INTERVAL_MS;
        }
        char chunk[16384];
        ssize_t n = io_read(io, chunk, sizeof chunk, (int)(next_ping - now));
        if (n == IO_TIMEOUT) continue;
        if (n == IO_WOKEN) {
            end = PUMP_BROWSER_GONE;
            goto out;
        }
        if (n <= 0) goto out;
        sb_buf_append(in, chunk, (size_t)n);
    }
out:
    sb_buf_free(&message);
    return end;
}

static void *relay_main(void *arg) {
    ws_bridge *b = arg;
    sigset_t pipe_signal;
    sigemptyset(&pipe_signal);
    sigaddset(&pipe_signal, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &pipe_signal, NULL); /* TLS writes use write(2) */

    clash_target target = {0};
    upstream_endpoint endpoint = {0};
    upstream_io io = {.fd = -1, .wake_fd = b->wake[0], .ctx = NULL, .ssl = NULL};
    sb_buf in = {0};
    sb_err err = {0};
    if (resolve_target(b->srv, b->host, &target, &err) != 0) {
        close_with_error(b, err.msg);
        goto done;
    }
    if (sb_str_empty(target.base_url)) {
        close_with_error(b, "No sing-box Clash API URL is configured");
        goto done;
    }
    if (upstream_endpoint_init(&endpoint, &target, b->kind, strcmp(b->kind, "logs") == 0 ? b->level : NULL,
                               &err) != 0) {
        close_with_error(b, err.msg);
        goto done;
    }
    upstream_result r = io_connect(&io, &endpoint);
    if (r == UP_OK && endpoint.tls) r = io_tls(&io, &endpoint);
    if (r == UP_OK) r = upstream_handshake(&io, &endpoint, &in);
    if (r == UP_OK) {
        switch (relay_pump(b, &io, &in)) {
        case PUMP_BROWSER_GONE: {
            /* upstream->stop(): Close 1000 to the controller, then drop it. */
            unsigned char payload[2] = {0x03, 0xe8};
            upstream_send(&io, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, payload, sizeof payload, true);
            if (io.ssl) SSL_shutdown(io.ssl);
            break;
        }
        case PUMP_UPSTREAM_CLOSED:
            browser_close(b, 1001, "upstream closed");
            break;
        case PUMP_UPSTREAM_CLOSE_FRAME:
            break;
        }
    } else if (r == UP_CLOSED) {
        browser_close(b, 1001, "upstream closed");
    } else if (r != UP_WOKEN) {
        char *message = sb_asprintf("Could not connect to sing-box Clash WebSocket: %s", upstream_reason(r));
        close_with_error(b, message);
        free(message);
    }
done:
    upstream_io_close(&io);
    upstream_endpoint_free(&endpoint);
    clash_target_free(&target);
    sb_buf_free(&in);
    return NULL;
}

/* ---- browser side --------------------------------------------------------- */

/* Ready handler (after the 101): starts the relay for this stream. */
static void ws_ready(struct mg_connection *conn, void *cbdata) {
    sb_http_server *srv = cbdata;
    sb_http_req req;
    request_view(srv, conn, &req);
    const char *kind = request_stream_kind(conn);
    ws_bridge *b = sb_xcalloc(1, sizeof *b);
    b->key = conn;
    b->browser = conn;
    b->srv = srv;
    b->browser_open = true;
    b->wake[0] = b->wake[1] = -1;
    pthread_mutex_init(&b->mutex, NULL);
    snprintf(b->kind, sizeof b->kind, "%s", kind ? kind : "");
    b->host = param_or_empty(&req, "host");
    char *level = param_or_empty(&req, "level");
    b->level = sb_http_trim(level);
    free(level);
    bridge_register(b);
    if (!kind) {
        browser_close(b, 1008, "unsupported stream");
        return;
    }
    if (pipe2(b->wake, O_CLOEXEC | O_NONBLOCK) != 0) {
        b->wake[0] = b->wake[1] = -1;
        close_with_error(b, "Could not start the Clash WebSocket relay");
        return;
    }
    if (pthread_create(&b->thread, NULL, relay_main, b) == 0) b->thread_started = true;
    else close_with_error(b, "Could not start the Clash WebSocket relay");
}

static int ws_data(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata) {
    (void)cbdata;
    int opcode = bits & 0x0f;
    if (opcode == MG_WEBSOCKET_OPCODE_PING) {
        mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_PONG, data, len);
        return 1;
    }
    /* Clash telemetry streams are downstream-only; a Close ends the loop. */
    return opcode == MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE ? 0 : 1;
}

/* Close handler: handleConnectionClosed() — stop the upstream and wait for
 * the relay so nothing touches this connection after civetweb reuses it. */
static void ws_close(const struct mg_connection *conn, void *cbdata) {
    (void)cbdata;
    ws_bridge *b = bridge_take(conn);
    if (!b) return;
    pthread_mutex_lock(&b->mutex);
    b->browser_open = false;
    pthread_mutex_unlock(&b->mutex);
    if (b->wake[1] >= 0) {
        char byte = 1;
        ssize_t ignored = write(b->wake[1], &byte, 1);
        (void)ignored;
    }
    if (b->thread_started) pthread_join(b->thread, NULL);
    bridge_free(b);
}

/* The core's begin_request answers every request itself except WebSocket
 * upgrades of the exact (decoded, case-sensitive) Clash stream paths, which it
 * leaves to civetweb's WebSocket dispatch. civetweb matches handlers against
 * the still-encoded URI, so the handler covers every URI ("**") and derives
 * the stream kind from the decoded path. */
void sb_http_register_clash_websocket(sb_http_server *srv) {
    if (!srv || !srv->mg) return;
    mg_set_websocket_handler(srv->mg, "**", ws_connect, ws_ready, ws_data, ws_close, srv);
}
