/* Port of cpp/tests/proxy_parser_test.cpp plus C-specific cases for the
 * yaml-cpp compatible Clash loader and the subscription fetcher. */
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sb/config_renderer.h"
#include "sb/json.h"
#include "sb/proxy_parser.h"
#include "sb/subscription_fetcher.h"
#include "sb/types.h"
#include "sb/util.h"

/* Follows a dotted path of object keys ("tls.utls.fingerprint"). */
static const sbj *at(const sbj *v, const char *path) {
    char *copy = sb_strdup(path);
    char *save = NULL;
    for (char *k = strtok_r(copy, ".", &save); k && v; k = strtok_r(NULL, ".", &save)) v = sbj_get(v, k);
    free(copy);
    return v;
}
static const char *at_str(const sbj *v, const char *path) { return sbj_as_str(at(v, path), NULL); }

static sb_parsed_node_vec parse_body(const char *body) {
    return sb_parse_subscription_body(body, strlen(body));
}

/* ---- ported from proxy_parser_test.cpp ------------------------------- */

TEST(proxy_uri_parser_covers_credentials_and_transports) {
    sb_parsed_node n;
    REQUIRE(sb_parse_proxy_uri("ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@server.example.com:443"
                               "#Test%20Node",
                               &n) == 1);
    CHECK_STR(n.node_type, "shadowsocks");
    CHECK_STR(n.tag, "Test Node");
    CHECK_STR(at_str(n.protocol_config, "password"), "testpassword");
    sb_parsed_node_free(&n);

    REQUIRE(sb_parse_proxy_uri("trojan://password123@trojan.example.com:443?"
                               "sni=sni.example.com&fp=chrome#Trojan01",
                               &n) == 1);
    CHECK_STR(at_str(n.protocol_config, "tls.server_name"), "sni.example.com");
    CHECK_STR(at_str(n.protocol_config, "tls.utls.fingerprint"), "chrome");
    sb_parsed_node_free(&n);

    REQUIRE(sb_parse_proxy_uri("vless://abc123@vless.example.com:443?"
                               "security=tls&type=ws&path=%2Fws&host=cdn.example.com#VLESS-WS",
                               &n) == 1);
    CHECK_STR(at_str(n.protocol_config, "transport.type"), "ws");
    CHECK_STR(at_str(n.protocol_config, "transport.path"), "/ws");
    CHECK_STR(at_str(n.protocol_config, "transport.headers.Host"), "cdn.example.com");
    sb_parsed_node_free(&n);

    REQUIRE(sb_parse_proxy_uri("tuic://uuid-1:secret@tuic.example.com:443?"
                               "sni=tuic.example.com&congestion=bbr#TUIC",
                               &n) == 1);
    CHECK_STR(at_str(n.protocol_config, "uuid"), "uuid-1");
    CHECK_STR(at_str(n.protocol_config, "password"), "secret");
    sb_parsed_node_free(&n);

    /* nodes without required credentials must be rejected */
    CHECK_EQ_INT(sb_parse_proxy_uri("vmess://eyJhZGQiOiJlLmV4YW1wbGUiLCJwb3J0Ijo0NDN9", &n), 0);
    sb_parsed_node_free(&n);
}

static const char *const CLASH_YAML =
    "\nport: 7890\n"
    "proxies:\n"
    "  - {name: \"HK 01\", server: hk.example, port: 19274, type: ss, cipher: aes-256-gcm, "
    "password: secret-pw}\n"
    "  - {name: \"JP WS\", server: jp.example, port: 443, type: vmess, uuid: uuid-123, alterId: 1, "
    "cipher: auto, network: ws, ws-opts: {path: /vm, headers: {Host: cdn.example}}, tls: true, "
    "servername: cdn.example}\n"
    "  - {name: bad, server: bad.example, port: 443, type: vmess}\n"
    "  - {name: \"Tokyo HTTP\", server: tokyo.example, port: 8443, type: http, username: user-1, "
    "password: http-secret, tls: true, sni: edge.example}\n"
    "proxy-groups:\n"
    "  - {name: Proxy, type: select, proxies: [\"HK 01\"]}\n";

TEST(subscription_parser_supports_base64_lists_and_clash_yaml) {
    sb_parsed_node_vec encoded = parse_body("c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2ZEdWemRIQmhjM04zYjNKa0BzZXJ2ZXIu"
                                            "ZXhhbXBsZS5jb206NDQzI0VuY29kZWQ=");
    CHECK_EQ_INT(encoded.len, 1);
    if (encoded.len == 1) CHECK_STR(encoded.items[0].tag, "Encoded");
    sb_parsed_node_vec_free(&encoded);

    sb_parsed_node_vec nodes = parse_body(CLASH_YAML);
    REQUIRE(nodes.len == 3); /* only valid supported nodes */
    const sbj *vm = nodes.items[1].protocol_config;
    CHECK(sbj_is_integer(at(vm, "alter_id")) && sbj_as_int(at(vm, "alter_id"), -1) == 1);
    CHECK_STR(at_str(vm, "transport.path"), "/vm");
    CHECK_STR(at_str(vm, "tls.server_name"), "cdn.example");

    sb_parsed_node *http = &nodes.items[2];
    CHECK_STR(http->node_type, "http");
    CHECK_STR(at_str(http->protocol_config, "username"), "user-1");
    CHECK_STR(at_str(http->protocol_config, "password"), "http-secret");
    CHECK(sbj_as_bool(at(http->protocol_config, "tls.enabled"), false) == true);
    CHECK_STR(at_str(http->protocol_config, "tls.server_name"), "edge.example");

    char *fp0 = sb_parsed_node_fingerprint(&nodes.items[0]);
    CHECK_EQ_INT(strlen(fp0), 64); /* SHA-256 hex */
    free(fp0);
    char *before = sb_parsed_node_fingerprint(http);
    sbj_set_str(http->protocol_config, "password", "rotated-secret");
    char *after = sb_parsed_node_fingerprint(http);
    CHECK(strcmp(before, after) != 0); /* HTTP fingerprints include credentials */
    free(before);
    free(after);
    sb_parsed_node_vec_free(&nodes);
}

/* Renders the parsed node with the config renderer and compares it with the
 * original outbound. */
static bool round_trips(const sb_parsed_node *parsed, const sbj *original) {
    sb_proxy_node node;
    sb_proxy_node_init(&node);
    sb_str_set(&node.id, "imported");
    sb_str_set(&node.tag, parsed->tag);
    sb_str_set(&node.type, parsed->node_type);
    node.enabled = true;
    sb_str_set(&node.server, parsed->server);
    node.server_port = parsed->server_port;
    sbj_free(node.protocol_config);
    node.protocol_config = sbj_clone(parsed->protocol_config);
    sb_err err = {0};
    sbj *rendered = sb_config_generate_outbound(&node, &err);
    bool same = rendered && sbj_equal(rendered, original);
    if (!same) {
        char *a = rendered ? sbj_dump(rendered, -1) : sb_strdup(err.msg);
        char *b = sbj_dump(original, -1);
        fprintf(stderr, "    rendered: %s\n    original: %s\n", a, b);
        free(a);
        free(b);
    }
    sbj_free(rendered);
    sb_proxy_node_free(&node);
    return same;
}

TEST(singbox_outbound_import_preserves_renderer_fields) {
    sbj *original = sbj_parse_cstr(
        "{\"type\":\"vless\",\"tag\":\"VLESS\",\"server\":\"vless.example.com\",\"server_port\":443,"
        "\"uuid\":\"uuid-1\",\"flow\":\"xtls-rprx-vision\",\"packet_encoding\":\"xudp\","
        "\"tls\":{\"enabled\":true,\"server_name\":\"vless.example.com\","
        "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},"
        "\"transport\":{\"type\":\"ws\",\"path\":\"/ray\",\"headers\":{\"Host\":\"cdn.example.com\"}}}");
    REQUIRE(original);
    sbj *config = sbj_object();
    sbj *outbounds = sbj_get_or_array(config, "outbounds");
    sbj_arr_push(outbounds, sbj_clone(original));
    sbj_arr_push(outbounds, sbj_parse_cstr("{\"type\":\"selector\",\"tag\":\"Proxy\"}"));
    sb_proxy_import imp;
    sb_err err = {0};
    REQUIRE(sb_parse_outbound_config(config, &imp, &err) == 0);
    CHECK_EQ_INT(imp.nodes.len, 1); /* groups are ignored */
    CHECK_EQ_INT(imp.skipped.len, 0);
    if (imp.nodes.len == 1) CHECK(round_trips(&imp.nodes.items[0], original));
    sb_proxy_import_free(&imp);
    sbj_free(config);
    sbj_free(original);
}

TEST(http_outbound_import_preserves_optional_auth_and_tls) {
    sbj *original = sbj_parse_cstr(
        "{\"type\":\"http\",\"tag\":\"Tokyo HTTP\",\"server\":\"tokyo.example.com\",\"server_port\":8443,"
        "\"username\":\"http-user\",\"password\":\"http-password\","
        "\"tls\":{\"enabled\":true,\"server_name\":\"edge.example.com\"}}");
    REQUIRE(original);
    sbj *config = sbj_object();
    sbj_arr_push(sbj_get_or_array(config, "outbounds"), sbj_clone(original));
    sb_proxy_import imp;
    REQUIRE(sb_parse_outbound_config(config, &imp, NULL) == 0);
    CHECK_EQ_INT(imp.nodes.len, 1);
    CHECK_EQ_INT(imp.skipped.len, 0);
    if (imp.nodes.len == 1) CHECK(round_trips(&imp.nodes.items[0], original));
    sb_proxy_import_free(&imp);
    sbj_free(config);

    sbj *unauthenticated = sbj_clone(original);
    sbj_del(unauthenticated, "username");
    sbj_del(unauthenticated, "password");
    config = sbj_object();
    sbj_arr_push(sbj_get_or_array(config, "outbounds"), unauthenticated);
    REQUIRE(sb_parse_outbound_config(config, &imp, NULL) == 0);
    CHECK_EQ_INT(imp.nodes.len, 1); /* HTTP proxy authentication stays optional */
    sb_proxy_import_free(&imp);
    sbj_free(config);
    sbj_free(original);
}

/* ---- C port specifics ------------------------------------------------- */

static char *dump_node(const sb_parsed_node *n) {
    sbj *o = sbj_object();
    sbj_set_str(o, "type", n->node_type);
    sbj_set_str(o, "tag", n->tag);
    sbj_set_str(o, "server", n->server);
    sbj_set_int(o, "port", n->server_port);
    sbj_set(o, "config", sbj_clone(n->protocol_config));
    char *d = sbj_dump(o, -1);
    sbj_free(o);
    return d;
}

TEST(uri_protocol_config_matches_cpp_output) {
    /* Expected strings were produced by the C++ parser (parity harness). */
    static const struct {
        const char *uri, *expected;
    } cases[] = {
        {"hy2://pw@h:443?sni=s&obfs=salamander&obfs-password=op&insecure=1#H",
         "{\"config\":{\"obfs\":{\"password\":\"op\",\"type\":\"salamander\"},\"password\":\"pw\","
         "\"tls\":{\"enabled\":true,\"insecure\":true,\"server_name\":\"s\"}},\"port\":443,"
         "\"server\":\"h\",\"tag\":\"H\",\"type\":\"hysteria2\"}"},
        {"tuic://u:p@[2001:db8::1]:8443?congestion_control=cubic&alpn=h3,%20h2#T",
         "{\"config\":{\"congestion_control\":\"cubic\",\"heartbeat\":\"10s\",\"password\":\"p\","
         "\"tls\":{\"alpn\":[\"h3\",\"h2\"],\"enabled\":true},\"udp_relay_mode\":\"native\",\"uuid\":\"u\"},"
         "\"port\":8443,\"server\":\"2001:db8::1\",\"tag\":\"T\",\"type\":\"tuic\"}"},
        {"vless://id@v.example?type=grpc&security=reality&fp=chrome&flow=xtls-rprx-vision",
         "{\"config\":{\"flow\":\"xtls-rprx-vision\",\"packet_encoding\":\"xudp\",\"tls\":{\"enabled\":true,"
         "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},\"transport\":{\"type\":\"grpc\"},"
         "\"uuid\":\"id\"},\"port\":443,\"server\":\"v.example\",\"tag\":\"vless\",\"type\":\"vless\"}"},
        /* legacy base64(method:password@host:port) Shadowsocks without a fragment */
        {"ss://YWVzLTEyOC1nY206cHdAaG9zdC5leGFtcGxlOjEyMzQ=",
         "{\"config\":{\"method\":\"aes-128-gcm\",\"password\":\"pw\"},\"port\":1234,"
         "\"server\":\"host.example\",\"tag\":\"host.example:1234\",\"type\":\"shadowsocks\"}"},
        /* vmess JSON: numeric port, alter_id stays a number, tls + transport */
        {"vmess://eyJhZGQiOiJ2bS5leGFtcGxlIiwicG9ydCI6NDQzLCJpZCI6InUiLCJhaWQiOiIxIn0=", NULL},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        sb_parsed_node n;
        int r = sb_parse_proxy_uri(cases[i].uri, &n);
        if (!cases[i].expected) {
            CHECK_EQ_INT(r, 0); /* "aid":"1" is a type error in C++: nullopt here */
        } else {
            REQUIRE(r == 1);
            char *d = dump_node(&n);
            CHECK_STR(d, cases[i].expected);
            free(d);
        }
        sb_parsed_node_free(&n);
    }
}

TEST(vmess_type_errors_are_reported_like_nlohmann) {
    /* {"add":"a","port":1,"id":"u","aid":"1"} */
    const char *uri = "vmess://eyJhZGQiOiJhIiwicG9ydCI6MSwiaWQiOiJ1IiwiYWlkIjoiMSJ9";
    sb_parsed_node n;
    sb_err err = {0};
    CHECK_EQ_INT(sb_parse_proxy_uri_ex(uri, strlen(uri), &n, &err), -1);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be number, but is string");
    sb_parsed_node_free(&n);
    /* ... and abort the whole URI-list subscription parse */
    sb_parsed_node_vec v;
    char *body = sb_asprintf("trojan://pw@t.example:443#ok\n%s\n", uri);
    CHECK_EQ_INT(sb_parse_subscription_body_ex(body, strlen(body), &v, &err), -1);
    CHECK_EQ_INT(v.len, 0);
    sb_parsed_node_vec_free(&v);
    v = sb_parse_subscription_body(body, strlen(body));
    CHECK_EQ_INT(v.len, 0);
    sb_parsed_node_vec_free(&v);
    free(body);
}

TEST(outbound_import_mirrors_cpp_quirks) {
    /* json{nullptr}/json{0} defaults are one-element arrays in nlohmann; a
     * missing credential therefore imports as [null]. */
    sbj *config = sbj_parse_cstr("[{\"type\":\"shadowsocks\",\"server\":\"s\",\"server_port\":\"8388\"},"
                                 "{\"type\":\"vless\",\"server\":\"\",\"server_port\":1,\"tag\":\"empty\"},"
                                 "{\"type\":\"direct\",\"tag\":\"direct\"}, 5]");
    sb_proxy_import imp;
    sb_err err = {0};
    REQUIRE(sb_parse_outbound_config(config, &imp, &err) == 0);
    REQUIRE(imp.nodes.len == 1);
    char *d = sbj_dump(imp.nodes.items[0].protocol_config, -1);
    CHECK_STR(d, "{\"method\":[null],\"password\":[null]}");
    free(d);
    CHECK_STR(imp.nodes.items[0].tag, "s");
    CHECK_EQ_INT(imp.nodes.items[0].server_port, 8388);
    REQUIRE(imp.skipped.len == 1);
    CHECK_STR(imp.skipped.items[0], "empty (vless)");
    sb_proxy_import_free(&imp);
    sbj_free(config);

    config = sbj_parse_cstr("{\"outbounds\":[{\"type\":\"trojan\",\"server\":\"t\",\"server_port\":1,\"tag\":7}]}");
    CHECK_EQ_INT(sb_parse_outbound_config(config, &imp, &err), -1);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be string, but is number");
    CHECK_EQ_INT(imp.nodes.len, 0);
    sb_proxy_import_free(&imp);
    sbj_free(config);

    config = sbj_parse_cstr("{\"outbounds\":{}}");
    CHECK_EQ_INT(sb_parse_outbound_config(config, &imp, &err), 0);
    CHECK_EQ_INT(imp.nodes.len + imp.skipped.len, 0);
    sb_proxy_import_free(&imp);
    sbj_free(config);
}

/* Parses body and returns "tag,tag,..." of the nodes found. */
static char *tags_of(const char *body, size_t len) {
    sb_parsed_node_vec v = sb_parse_subscription_body(body, len);
    sb_buf b = {0};
    for (size_t i = 0; i < v.len; ++i) {
        if (i) sb_buf_putc(&b, ',');
        sb_buf_puts(&b, v.items[i].tag);
    }
    sb_parsed_node_vec_free(&v);
    return sb_buf_detach(&b);
}

static void check_tags(const char *body, const char *expected, int line) {
    char *got = tags_of(body, strlen(body));
    if (strcmp(got, expected) != 0) {
        fprintf(stderr, "  line %d: tags \"%s\", expected \"%s\"\n", line, got, expected);
        sb_test_current_failed = 1;
    }
    free(got);
}
#define CHECK_TAGS(body, expected) check_tags(body, expected, __LINE__)

#define P(name) "  - {name: " name ", type: trojan, server: t.example, port: 443, password: pw}\n"

TEST(clash_yaml_follows_yaml_cpp_semantics) {
    /* scalars stay strings; nulls; merge keys are ordinary keys (no merge) */
    CHECK_TAGS("common: &c {type: trojan, password: pw}\nproxies:\n"
               "  - {name: merged, server: s, port: 1, <<: *c}\n" P("plain"),
               "plain");
    /* aliases resolve, including anchor names libyaml does not allow */
    CHECK_TAGS("p: &香港 {name: cjk, type: trojan, server: s, port: 1, password: pw}\n"
               "proxies: [*香港, *香港]\n",
               "cjk,cjk");
    /* ':'-leading plain scalars in flow context (IPv6) */
    CHECK_TAGS("proxies:\n  - {name: v6, type: trojan, server: ::1, port: 443, password: pw}\n", "v6");
    /* yaml-cpp fails on '?' inside a flow plain scalar -> URI-list fallback */
    CHECK_TAGS("proxies:\n  - {name: q, type: trojan, server: s, port: 1, password: pw, "
               "ws-opts: {path: /ws?ed=2048}}\n",
               "");
    /* ... but not in block context */
    CHECK_TAGS("proxies:\n  - name: q\n    type: trojan\n    server: s\n    port: 1\n    password: pw\n"
               "    ws-opts:\n      path: /ws?ed=2048\n",
               "q");
    /* the \' escape, tab-only lines, CRLF, BOM */
    CHECK_TAGS("\xEF\xBB\xBFproxies:\r\n\t\r\n" P("\"it\\'s\"") "  \t# tabbed comment\r\n", "it's");
    /* a truncated download: colon-less last key line / open quote */
    CHECK_TAGS("proxies:\n" P("a") "  - name: b\n    type: trojan\n    server: s\n    port: 2\n"
               "    password: pw\n    skip-cert",
               "a,b");
    CHECK_TAGS("proxies:\n" P("a") "  - name: b\n    type: trojan\n    server: s\n    port: 2\n"
               "    password: \"pw",
               ""); /* yaml-cpp rejects EOF after nonempty quoted content */
    CHECK_TAGS("proxies:\n" P("a") "  - name: b\n    password: \"pw x", ""); /* yaml-cpp: EOF in scalar */
    /* empty flow entries and keys are null nodes */
    CHECK_TAGS("proxies:\n  - {name: e, , type: trojan, : x, server: s, port: 1, password: pw}\n", "e");
    /* the token after the document is scanned: a stray ']' fails the load */
    CHECK_TAGS("proxies:\n" P("a") "]\n", "");
    /* only the first document counts */
    CHECK_TAGS("proxies:\n" P("first") "---\nproxies:\n" P("second"), "first");
    /* nesting limit (yaml-cpp DepthGuard<500>) */
    {
        sb_buf b = {0};
        sb_buf_puts(&b, "proxies:\n" P("deep") "x: ");
        for (int i = 0; i < 498; ++i) sb_buf_putc(&b, '[');
        for (int i = 0; i < 498; ++i) sb_buf_putc(&b, ']');
        sb_buf_putc(&b, '\n');
        CHECK_TAGS(b.p, "deep"); /* depth 499 */
        sb_buf_reset(&b);
        sb_buf_puts(&b, "proxies:\n" P("deep") "x: ");
        for (int i = 0; i < 499; ++i) sb_buf_putc(&b, '[');
        for (int i = 0; i < 499; ++i) sb_buf_putc(&b, ']');
        CHECK_TAGS(b.p, ""); /* depth 500 */
        sb_buf_free(&b);
    }
    /* recursive aliases do not recurse forever (C++ overflowed the stack) */
    CHECK_TAGS("proxies: &p\n  - *p\n" P("r"), "r");
}

TEST(clash_yaml_utf16_and_raw_bytes) {
    /* UTF-16LE with BOM, as yaml-cpp detects it */
    const char *utf8 = "proxies:\n  - {name: \"\xE9\xA6\x99\", type: trojan, server: s, port: 1, password: pw}\n";
    sb_buf b = {0};
    sb_buf_append(&b, "\xFF\xFE", 2);
    for (const unsigned char *p = (const unsigned char *)utf8; *p;) {
        unsigned cp = *p++;
        if (cp >= 0xE0) {
            cp = (cp & 0x0F) << 12;
            cp |= (unsigned)(*p++ & 0x3F) << 6;
            cp |= (unsigned)(*p++ & 0x3F);
        }
        char u[2] = {(char)(cp & 0xFF), (char)(cp >> 8)};
        sb_buf_append(&b, u, 2);
    }
    char *got = tags_of(b.p, b.len);
    CHECK_STR(got, "\xE9\xA6\x99");
    free(got);
    sb_buf_free(&b);
    /* invalid UTF-8 and control bytes pass through into scalars */
    const char raw_body[] = "proxies:\n  - {name: \"x\xFF\x01y\", type: trojan, server: s, port: 1, password: pw}\n";
    got = tags_of(raw_body, sizeof raw_body - 1);
    CHECK_STR(got, "x\xFF\x01y");
    free(got);
    /* a raw NUL inside a quoted scalar is kept (it truncates the C tag) */
    const char nul_body[] = "proxies:\n  - {name: \"a\0b\", type: trojan, server: s, port: 1, password: pw}\n";
    got = tags_of(nul_body, sizeof nul_body - 1);
    CHECK_STR(got, "a");
    free(got);
}

TEST(uri_list_fallback_skips_comments_and_invalid_lines) {
    CHECK_TAGS("# comment\n// other\n\n  trojan://pw@t.example:443#one  \r\nnot-a-uri\n"
               "hy2://pw@h.example#two\nvmess://!!!\n",
               "one,two");
    /* base64 detection needs > 20 characters without spaces or newlines */
    CHECK_TAGS("dHJvamFuOi8vcHdAdDo0NDMjYjY0", "b64");
    CHECK_TAGS("  dHJvamFuOi8vcHdAdDo0NDMjYjY0\n", "b64");
}

/* ---- subscription fetcher -------------------------------------------- */

/* A one-thread HTTP/1.1 server on 127.0.0.1:<ephemeral> answering requests
 * by path. Handles `expected` connections, then exits. */
typedef struct {
    int listen_fd;
    int port;
    int expected;
    int handled;
    char last_request[4096];
    pthread_t thread;
} test_server;

static void respond(int fd, const char *status, const char *extra_headers, const char *body,
                    size_t body_len) {
    char head[512];
    int n = snprintf(head, sizeof head, "HTTP/1.1 %s\r\nContent-Length: %zu\r\nConnection: close\r\n%s\r\n",
                     status, body_len, extra_headers ? extra_headers : "");
    if (send(fd, head, (size_t)n, MSG_NOSIGNAL) < 0) return;
    size_t off = 0;
    while (off < body_len) {
        ssize_t w = send(fd, body + off, body_len - off, MSG_NOSIGNAL);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void *server_main(void *arg) {
    test_server *s = arg;
    for (int i = 0; i < s->expected; ++i) {
        /* A broken redirect must fail the test, not leave pthread_join
         * waiting forever for a request the client never sends. */
        struct pollfd ready = {s->listen_fd, POLLIN, 0};
        if (poll(&ready, 1, 3000) <= 0) break;
        int fd = accept(s->listen_fd, NULL, NULL);
        if (fd < 0) break;
        ++s->handled;
        struct timeval receive_timeout = {3, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof receive_timeout);
        char req[4096] = {0};
        size_t len = 0;
        while (len < sizeof req - 1 && !strstr(req, "\r\n\r\n")) {
            ssize_t r = read(fd, req + len, sizeof req - 1 - len);
            if (r <= 0) break;
            len += (size_t)r;
            req[len] = '\0';
        }
        req[len] = '\0';
        memcpy(s->last_request, req, len + 1);
        char path[1024] = "";
        sscanf(req, "GET %1023s", path);
        if (!strcmp(path, "/sub")) {
            respond(fd, "200 OK", "Content-Type: text/plain\r\n", "trojan://pw@t.example:443#fetched\n", 34);
        } else if (!strcmp(path, "/missing")) {
            respond(fd, "404 Not Found", NULL, "nope", 4);
        } else if (!strcmp(path, "/redirect-rel")) {
            respond(fd, "302 Found", "Location: sub\r\n", "", 0);
        } else if (!strcmp(path, "/redirect-abs")) {
            respond(fd, "301 Moved Permanently", "Location: /sub\r\n", "", 0);
        } else if (!strcmp(path, "/redirect-none")) {
            respond(fd, "307 Temporary Redirect", NULL, "", 0);
        } else if (!strcmp(path, "/loop")) {
            respond(fd, "302 Found", "Location: /loop\r\n", "", 0);
        } else if (!strcmp(path, "/big")) {
            static char big[4096];
            memset(big, 'x', sizeof big);
            respond(fd, "200 OK", NULL, big, sizeof big);
        } else if (!strcmp(path, "/slow")) {
            sb_sleep_ms(1500);
            respond(fd, "200 OK", NULL, "late", 4);
        } else if (!strcmp(path, "/garbage")) {
            if (send(fd, "not http at all\r\n\r\n", 19, MSG_NOSIGNAL) < 0) {
            }
        } else {
            respond(fd, "200 OK", NULL, path, strlen(path)); /* echo the request target */
        }
        close(fd);
    }
    return NULL;
}

static void server_start(test_server *s, int expected) {
    memset(s, 0, sizeof *s);
    s->expected = expected;
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0; /* ephemeral */
    int one = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s->listen_fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->listen_fd, 8) != 0) abort();
    socklen_t alen = sizeof a;
    getsockname(s->listen_fd, (struct sockaddr *)&a, &alen);
    s->port = ntohs(a.sin_port);
    pthread_create(&s->thread, NULL, server_main, s);
}

static void server_stop(test_server *s) {
    pthread_join(s->thread, NULL);
    close(s->listen_fd);
    CHECK_EQ_INT(s->handled, s->expected);
}

static char *fetch(sb_subscription_fetcher *f, const char *url, sb_err *err) {
    sb_err_clear(err);
    return sb_subscription_fetcher_fetch(f, url, NULL, err);
}

TEST(subscription_fetcher_validates_options_and_urls) {
    sb_err err = {0};
    sb_subscription_fetcher_options o;
    sb_subscription_fetcher_options_init(&o);
    CHECK_EQ_INT(o.timeout_ms, 30000);
    CHECK_EQ_INT(o.maximum_body_bytes, 8u * 1024u * 1024u);
    CHECK_EQ_INT(o.maximum_redirects, 5);
    o.maximum_body_bytes = 0;
    CHECK(sb_subscription_fetcher_new(&o, &err) == NULL);
    CHECK_STR(err.msg, "subscription timeout and body limit must be positive");
    CHECK(err.code == SB_ERR_VALIDATION);

    sb_subscription_fetcher *f = sb_subscription_fetcher_new(NULL, &err);
    REQUIRE(f);
    static const struct {
        const char *url, *msg;
    } bad[] = {
        {"example.com/sub", "subscription URL must include http:// or https://"},
        {"ftp://example.com/sub", "subscription URL must use HTTP or HTTPS"},
        {"https://example.com/sub#frag", "subscription URL must not contain a fragment"},
        {"https://user:pw@example.com/sub", "subscription URL authority is empty or contains credentials"},
        {"http:///sub", "subscription URL authority is empty or contains credentials"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        CHECK(fetch(f, bad[i].url, &err) == NULL);
        CHECK_STR(err.msg, bad[i].msg);
        CHECK(err.code == SB_ERR_VALIDATION);
    }
    sb_subscription_fetcher_free(f);
}

TEST(subscription_fetcher_against_local_server) {
    test_server s;
    server_start(&s, 12);
    sb_subscription_fetcher_options o;
    sb_subscription_fetcher_options_init(&o);
    o.maximum_body_bytes = 1024;
    o.timeout_ms = 700;
    o.maximum_redirects = 3;
    sb_err err = {0};
    sb_subscription_fetcher *f = sb_subscription_fetcher_new(&o, &err);
    REQUIRE(f);
    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    char url[256];

#define URL(path) (snprintf(url, sizeof url, "%s%s", base, path), url)
    size_t len = 0;
    char *body = sb_subscription_fetcher_fetch(f, URL("/sub"), &len, &err); /* 1 */
    CHECK_STR(body, "trojan://pw@t.example:443#fetched\n");
    CHECK_EQ_INT(len, 34);
    CHECK_CONTAINS(s.last_request, "User-Agent: sb-easy-cpp/");
    CHECK_CONTAINS(s.last_request, "Accept: text/plain, application/yaml, application/json");
    free(body);

    body = fetch(f, URL("/redirect-rel"), &err); /* 2, 3 */
    CHECK_STR(body, "trojan://pw@t.example:443#fetched\n");
    free(body);
    body = fetch(f, URL("/redirect-abs"), &err); /* 4, 5 */
    CHECK_STR(body, "trojan://pw@t.example:443#fetched\n");
    free(body);

    CHECK(fetch(f, URL("/missing"), &err) == NULL); /* 6 */
    CHECK_STR(err.msg, "subscription returned HTTP 404");
    CHECK(err.code == SB_ERR_UPSTREAM);
    CHECK(fetch(f, URL("/redirect-none"), &err) == NULL); /* 7 */
    CHECK_STR(err.msg, "subscription redirect is missing Location");
    CHECK(fetch(f, URL("/loop"), &err) == NULL); /* 8-11: the first plus 3 redirects */
    CHECK_STR(err.msg, "subscription exceeded the redirect limit");
    CHECK(fetch(f, URL("/big"), &err) == NULL); /* 12 */
    CHECK_STR(err.msg, "subscription response exceeds the configured size limit");
    server_stop(&s);

    /* the request target is sent encoded the way Drogon's setPath did */
    server_start(&s, 1);
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    body = fetch(f, URL("/a b/%41?x=1&y=é"), &err);
    CHECK_STR(body, "/a+b/%2541?x=1&y=%C3%A9");
    free(body);
    server_stop(&s);

    server_start(&s, 2);
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    CHECK(fetch(f, URL("/garbage"), &err) == NULL);
    CHECK_STR(err.msg, "subscription HTTP request failed: Bad response from server");
    CHECK(fetch(f, URL("/slow"), &err) == NULL); /* last: the server is single-threaded */
    CHECK_STR(err.msg, "subscription HTTP request failed: Timeout");
    server_stop(&s);
#undef URL

    /* nothing listens on a port we just released */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t alen = sizeof a;
    REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
    getsockname(fd, (struct sockaddr *)&a, &alen);
    close(fd);
    snprintf(url, sizeof url, "http://127.0.0.1:%d/sub", ntohs(a.sin_port));
    CHECK(fetch(f, url, &err) == NULL);
    CHECK_STR(err.msg, "subscription HTTP request failed: Bad server address");
    CHECK(err.code == SB_ERR_UPSTREAM);
    sb_subscription_fetcher_free(f);
}
