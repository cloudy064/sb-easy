/* Port of cpp/tests/agent_client_test.cpp. The C++ test drives the real
 * Drogon control plane + Store; the C port uses a raw-socket fake control
 * plane that asserts the same paths, headers and JSON bodies, plus the same
 * raw-socket Clash fixture for sb_clash_client. */
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sb/agent_client.h"
#include "sb/agent_config.h"
#include "sb/clash_client.h"

/* ---- tiny HTTP fixture ------------------------------------------------ */

typedef struct {
    char method[16];
    char target[512];
    char *headers; /* raw header block */
    char *body;
} fixture_request;

typedef void (*fixture_handler)(const fixture_request *req, sb_buf *response);

typedef struct {
    int listener;
    int port;
    pthread_t thread;
    fixture_handler handler;
    pthread_mutex_t mutex;
    fixture_request last; /* guarded */
    int requests;
} fixture;

static char *header_value(const char *headers, const char *name) {
    size_t n = strlen(name);
    for (const char *p = headers; p && *p;) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) > n && strncasecmp(p, name, n) == 0 && p[n] == ':') {
            const char *v = p + n + 1;
            while (*v == ' ') ++v;
            return sb_strndup(v, (size_t)(eol - v));
        }
        p = eol + 2;
    }
    return NULL;
}

static void *fixture_serve(void *arg) {
    fixture *f = arg;
    for (;;) {
        int client = accept4(f->listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) return NULL;
        sb_buf request = {0};
        char buffer[4096];
        char *end = NULL;
        while (!(end = request.p ? strstr(request.p, "\r\n\r\n") : NULL)) {
            ssize_t count = recv(client, buffer, sizeof buffer, 0);
            if (count <= 0) break;
            sb_buf_append(&request, buffer, (size_t)count);
        }
        if (!end) {
            close(client);
            sb_buf_free(&request);
            continue;
        }
        size_t header_len = (size_t)(end - request.p) + 4;
        char *headers = sb_strndup(request.p, header_len);
        char *length_text = header_value(headers, "Content-Length");
        size_t content_length = length_text ? (size_t)strtoul(length_text, NULL, 10) : 0;
        free(length_text);
        while (request.len < header_len + content_length) {
            ssize_t count = recv(client, buffer, sizeof buffer, 0);
            if (count <= 0) break;
            sb_buf_append(&request, buffer, (size_t)count);
        }
        fixture_request req = {0};
        sscanf(request.p, "%15s %511s", req.method, req.target);
        req.headers = headers;
        req.body = sb_strndup(request.p + header_len, content_length);
        sb_buf response = {0};
        f->handler(&req, &response);
        pthread_mutex_lock(&f->mutex);
        free(f->last.headers);
        free(f->last.body);
        f->last = req;
        ++f->requests;
        pthread_mutex_unlock(&f->mutex);
        size_t sent = 0;
        while (sent < response.len) {
            ssize_t count = send(client, response.p + sent, response.len - sent, MSG_NOSIGNAL);
            if (count <= 0) break;
            sent += (size_t)count;
        }
        sb_buf_free(&response);
        sb_buf_free(&request);
        close(client);
    }
}

static void fixture_start(fixture *f, fixture_handler handler) {
    memset(f, 0, sizeof *f);
    pthread_mutex_init(&f->mutex, NULL);
    f->handler = handler;
    f->listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int reuse = 1;
    setsockopt(f->listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(f->listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(f->listener, 8) != 0)
        abort();
    socklen_t size = sizeof address;
    getsockname(f->listener, (struct sockaddr *)&address, &size);
    f->port = ntohs(address.sin_port);
    pthread_create(&f->thread, NULL, fixture_serve, f);
}

static void fixture_stop(fixture *f) {
    shutdown(f->listener, SHUT_RDWR);
    close(f->listener);
    pthread_join(f->thread, NULL);
    free(f->last.headers);
    free(f->last.body);
    pthread_mutex_destroy(&f->mutex);
}

/* Copies of the last request's pieces (the fixture thread is idle after a
 * blocking client call returns). */
static char *last_header(fixture *f, const char *name) {
    pthread_mutex_lock(&f->mutex);
    char *value = header_value(f->last.headers, name);
    pthread_mutex_unlock(&f->mutex);
    return value;
}

static void respond(sb_buf *out, const char *status, const char *extra_headers,
                    const char *body) {
    sb_buf_printf(out,
                  "HTTP/1.1 %s\r\nContent-Type: application/json\r\n%sContent-Length: %zu\r\n"
                  "Connection: close\r\n\r\n%s",
                  status, extra_headers ? extra_headers : "", strlen(body), body);
}

/* ---- config transform contract ---------------------------------------- */

static const char *transform_input =
    "{\"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"management-dns\",\"server\":\"223.5.5.5\","
    "\"detour\":\"wg-internal\"}],\"rules\":[]},"
    "\"outbounds\":[{\"type\":\"selector\",\"tag\":\"Proxy\",\"outbounds\":[\"node-a\",\"node-b\"],"
    "\"default\":\"node-b\"},"
    "{\"type\":\"shadowsocks\",\"tag\":\"node-a\",\"server\":\"old.example\",\"server_port\":443,"
    "\"detour\":\"wg-internal\"},"
    "{\"type\":\"shadowsocks\",\"tag\":\"node-b\",\"server\":\"remote.example\",\"server_port\":443}],"
    "\"route\":{\"final\":\"Proxy\",\"rules\":[{\"domain_suffix\":\"example.com\",\"outbound\":\"node-b\"}]}}";

static void contract_options(sb_agent_config_options *options) {
    sb_agent_config_options_init(options);
    options->local_proxy_egress = true;
    sbj_set_str(options->outbound_server_overrides, "node-a", "local.example");
    sbj_set(options->outbound_overrides, "node-b",
            sbj_parse_cstr("{\"type\":\"socks\",\"tag\":\"local-node-b\",\"server\":\"127.0.0.1\","
                           "\"server_port\":10080}"));
    options->default_proxy_outbound = sb_strdup("node-a");
}

static sbj *at_path(sbj *v, const char *a, long i, const char *b) {
    v = sbj_get(v, a);
    if (i >= 0) v = sbj_arr_at(v, (size_t)i);
    return b ? sbj_get(v, b) : v;
}

TEST(config_transform_contract) {
    sbj *input_json = sbj_parse_cstr(transform_input);
    char *input = sbj_dump(input_json, -1);
    sbj_free(input_json);
    sb_agent_config_options options;
    contract_options(&options);
    sb_err err = {0};
    char *text = sb_prepare_agent_config(input, strlen(input), &options, &err);
    REQUIRE(text);
    sbj *t = sbj_parse_cstr(text);
    free(text);
    CHECK_STR(sbj_as_str(at_path(t, "outbounds", 0, "default"), NULL), "node-a");
    CHECK_STR(sbj_as_str(at_path(t, "outbounds", 1, "server"), NULL), "local.example");
    CHECK(!sbj_has(at_path(t, "outbounds", 1, NULL), "detour"));
    CHECK_STR(sbj_as_str(at_path(t, "outbounds", 2, "tag"), NULL), "local-node-b");
    CHECK_STR(sbj_as_str(at_path(t, "outbounds", 2, "type"), NULL), "socks");
    CHECK_STR(sbj_as_str(sbj_get(sbj_arr_at(at_path(t, "route", -1, "rules"), 0), "outbound"), NULL),
              "local-node-b");
    sbj *servers = at_path(t, "dns", -1, "servers");
    CHECK(!sbj_has(sbj_arr_at(servers, 0), "detour"));
    CHECK_STR(sbj_get_str(sbj_arr_at(servers, 1), "tag", NULL), "proxy-dns");
    CHECK_STR(sbj_get_str(sbj_arr_at(servers, 1), "detour", NULL), "Proxy");
    CHECK_STR(sbj_get_str(sbj_arr_at(at_path(t, "dns", -1, "rules"), 0), "server", NULL),
              "proxy-dns");
    sbj_free(t);

    /* node-local route rules are prepended */
    sb_agent_config_options local;
    sb_agent_config_options_copy(&local, &options);
    sbj_arr_push(local.local_route_rules,
                 sbj_parse_cstr("{\"domain_suffix\":[\"google.com\",\"googleapis.com\"],"
                                "\"outbound\":\"\xf0\x9f\x87\xad\xf0\x9f\x87\xb0 \xe8\x87\xaa\xe5\x8a\xa8\"}"));
    text = sb_prepare_agent_config(input, strlen(input), &local, &err);
    REQUIRE(text);
    t = sbj_parse_cstr(text);
    free(text);
    sbj *rules = at_path(t, "route", -1, "rules");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 0), "outbound", NULL),
              "\xf0\x9f\x87\xad\xf0\x9f\x87\xb0 \xe8\x87\xaa\xe5\x8a\xa8");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 1), "outbound", NULL), "local-node-b");
    sbj_free(t);
    sb_agent_config_options_free(&local);

    /* disabled local egress preserves the panel response byte-for-byte */
    options.local_proxy_egress = false;
    text = sb_prepare_agent_config(input, strlen(input), &options, &err);
    CHECK_STR(text, input);
    free(text);
    options.local_proxy_egress = true;

    /* default outside the selector is rejected */
    sb_str_set(&options.default_proxy_outbound, "missing-node");
    CHECK(sb_prepare_agent_config(input, strlen(input), &options, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "default proxy outbound missing-node is not in selector Proxy");
    sb_str_set(&options.default_proxy_outbound, "node-a");

    /* atomic persistence roundtrip */
    char dir[] = "/tmp/sb-easy-agent-client-XXXXXX";
    REQUIRE(mkdtemp(dir));
    char *settings_path = sb_asprintf("%s/agent-settings.json", dir);
    REQUIRE(sb_agent_config_options_save(settings_path, &options, &err) == 0);
    sb_agent_config_options loaded;
    REQUIRE(sb_agent_config_options_load(settings_path, NULL, &loaded, &err) == 0);
    sbj *a = sb_agent_config_options_to_json(&loaded);
    sbj *b = sb_agent_config_options_to_json(&options);
    CHECK(sbj_equal(a, b));
    sbj_free(a);
    sbj_free(b);

    /* partial settings preserve omitted values */
    sbj *partial_json = sbj_parse_cstr("{\"default_proxy_outbound\":null}");
    sb_agent_config_options partial;
    REQUIRE(sb_agent_config_options_from_json(partial_json, &loaded, &partial, &err) == 0);
    CHECK(partial.default_proxy_outbound == NULL);
    CHECK(sbj_equal(partial.outbound_server_overrides, options.outbound_server_overrides));
    sb_agent_config_options_free(&partial);
    sbj_free(partial_json);

    sbj *invalid = sbj_parse_cstr("{\"outbound_server_overrides\":{\"node-a\":42}}");
    sb_agent_config_options rejected;
    CHECK(sb_agent_config_options_from_json(invalid, NULL, &rejected, &err) != 0);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "outbound_server_overrides values must be non-empty strings");
    sbj_free(invalid);

    sb_agent_config_options_free(&loaded);
    unlink(settings_path);
    rmdir(dir);
    free(settings_path);
    sb_agent_config_options_free(&options);
    free(input);
}

/* ---- control plane contract ------------------------------------------- */

#define ENROLL_CODE "0123456789abcdef0123456789abcdef"
#define AGENT_TOKEN "agent-token-123"
#define CONFIG_ETAG "\"etag-1\""
#define CONFIG_BODY "{\"outbounds\":[],\"route\":{\"final\":\"direct\"}}"

static void control_plane(const fixture_request *req, sb_buf *out) {
    char *auth = header_value(req->headers, "Authorization");
    char *content_type = header_value(req->headers, "Content-Type");
    char *agent = header_value(req->headers, "User-Agent");
    bool authorised = sb_streq(auth, "Bearer " AGENT_TOKEN);
    bool json_body = sb_streq(content_type, "application/json; charset=utf-8");
    bool ua_ok = sb_streq(agent, "sb-easy-cpp-agent/" SB_EASY_VERSION);
    if (!ua_ok) {
        respond(out, "400 Bad Request", NULL, "{\"error\":\"user agent\"}");
    } else if (!strcmp(req->method, "POST") && !strcmp(req->target, "/prefix/api/devices/enroll")) {
        sbj *body = sbj_parse_cstr(req->body);
        bool ok = json_body && !auth &&
                  sb_streq(sbj_get_str(body, "code", NULL), ENROLL_CODE) &&
                  sb_streq(sbj_get_str(sbj_get(body, "device"), "platform", NULL), "linux");
        sbj_free(body);
        if (ok)
            respond(out, "200 OK", NULL,
                    "{\"host_id\":\"host-1\",\"host_name\":\"C agent\",\"agent_token\":\"" AGENT_TOKEN
                    "\",\"profile\":{\"id\":\"p1\",\"name\":\"Default\"}}");
        else
            respond(out, "400 Bad Request", NULL, "{\"error\":\"bad enrollment\"}");
    } else if (!authorised) {
        respond(out, "401 Unauthorized", NULL, "{\"error\":\"unauthorized\"}");
    } else if (!strcmp(req->method, "GET") && !strcmp(req->target, "/prefix/api/agent/config")) {
        char *inm = header_value(req->headers, "If-None-Match");
        if (sb_streq(inm, CONFIG_ETAG))
            sb_buf_puts(out, "HTTP/1.1 304 Not Modified\r\nETag: " CONFIG_ETAG
                             "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        else
            respond(out, "200 OK", "ETag: " CONFIG_ETAG "\r\n", CONFIG_BODY);
        free(inm);
    } else if (!strcmp(req->method, "GET") && !strcmp(req->target, "/prefix/api/agent/commands")) {
        respond(out, "200 OK", NULL, "[{\"id\":\"cmd-1\",\"command\":\"restart\",\"extra\":1}]");
    } else if (!strcmp(req->method, "POST") &&
               !strcmp(req->target, "/prefix/api/agent/commands/cmd-1/ack")) {
        bool ok = json_body && sb_streq(req->body, "{\"result\":\"restarted\",\"status\":\"done\"}");
        respond(out, ok ? "200 OK" : "400 Bad Request", NULL, "{\"ok\":true}");
    } else if (!strcmp(req->method, "POST") && !strcmp(req->target, "/prefix/api/agent/status")) {
        bool ok = json_body && sb_streq(req->body, "{\"config_etag\":\"\\\"etag-1\\\"\","
                                                   "\"singbox_running\":true,"
                                                   "\"singbox_version\":\"sb-easy-cpp-agent/test\"}");
        respond(out, ok ? "200 OK" : "400 Bad Request", NULL, "{\"ok\":true}");
    } else if (!strcmp(req->method, "POST") && !strcmp(req->target, "/prefix/api/agent/telemetry")) {
        bool ok = json_body && sb_streq(req->body, "{\"down\":2,\"up\":1}");
        respond(out, ok ? "200 OK" : "400 Bad Request", NULL, "{\"ok\":true}");
    } else if (!strcmp(req->method, "POST") &&
               !strcmp(req->target, "/prefix/api/agent/proxy-latency")) {
        bool ok = json_body && sb_streq(req->body, "{\"results\":{\"client-node\":8.5}}");
        respond(out, ok ? "200 OK" : "400 Bad Request", NULL, "{\"updated\":1}");
    } else {
        respond(out, "404 Not Found", NULL, "{\"error\":\"not found\"}");
    }
    free(auth);
    free(content_type);
    free(agent);
}

TEST(agent_client_contract) {
    sb_err err = {0};
    sb_agent_client_options bad = {"ftp://127.0.0.1", "token", 15000};
    CHECK(sb_agent_client_new(&bad, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "agent server must include http:// or https://");
    sb_agent_client_options query = {"http://x/?a", "token", 15000};
    CHECK(sb_agent_client_new(&query, &err) == NULL);
    CHECK_STR(err.msg, "agent server must not contain a query or fragment");
    sb_agent_client_options no_token = {"http://x", "", 15000};
    CHECK(sb_agent_client_new(&no_token, &err) == NULL);
    CHECK_STR(err.msg, "agent token is required");

    fixture f;
    fixture_start(&f, control_plane);
    char *server = sb_asprintf("http://127.0.0.1:%d/prefix/", f.port);

    sbj *device = sbj_parse_cstr("{\"platform\":\"linux\",\"agent_version\":\"sb-easy-cpp-agent/test\","
                                 "\"hostname\":\"agent-client-contract\",\"architecture\":\"x86_64\"}");
    sb_device_enrollment_options short_code = {server, "short", device, 2000};
    sb_device_credential credential;
    CHECK(sb_enroll_device(&short_code, &credential, &err) != 0);
    CHECK_STR(err.msg, "device enrollment code is required");
    sb_device_enrollment_options enroll = {server, ENROLL_CODE, device, 2000};
    REQUIRE(sb_enroll_device(&enroll, &credential, &err) == 0);
    CHECK_STR(credential.host_id, "host-1");
    CHECK_STR(credential.token, AGENT_TOKEN);
    CHECK_STR(credential.server, server); /* falls back to the requested server */
    CHECK_STR(credential.profile_name, "Default");
    sb_device_credential_free(&credential);
    sbj_free(device);

    sb_agent_client_options options = {server, AGENT_TOKEN, 2000};
    sb_agent_client *client = sb_agent_client_new(&options, &err);
    REQUIRE(client);
    sb_agent_config_response config;
    REQUIRE(sb_agent_client_poll_config(client, NULL, &config, &err) == 0);
    CHECK(config.modified);
    CHECK_STR(config.etag, CONFIG_ETAG);
    CHECK_STR(config.body, CONFIG_BODY);
    CHECK_STR(config.rule_source, "profile");

    sb_agent_config_response unchanged;
    REQUIRE(sb_agent_client_poll_config(client, config.etag, &unchanged, &err) == 0);
    CHECK(!unchanged.modified);
    CHECK_STR(unchanged.etag, config.etag);
    CHECK_STR(unchanged.rule_source, "profile");
    char *inm = last_header(&f, "If-None-Match");
    CHECK_STR(inm, CONFIG_ETAG);
    free(inm);
    sb_agent_config_response_free(&unchanged);

    sb_agent_command_vec pending;
    REQUIRE(sb_agent_client_pending_commands(client, &pending, &err) == 0);
    CHECK_EQ_INT(pending.len, 1);
    CHECK_STR(pending.items[0].id, "cmd-1");
    CHECK_STR(pending.items[0].command, "restart");
    sb_agent_command_vec_free(&pending);

    CHECK(sb_agent_client_acknowledge_command(client, "cmd-1", true, "restarted", &err) == 0);
    bool running = true;
    CHECK(sb_agent_client_report_status(client, "sb-easy-cpp-agent/test", &running, config.etag,
                                        &err) == 0);
    sbj *telemetry = sbj_parse_cstr("{\"up\":1,\"down\":2}");
    CHECK(sb_agent_client_report_telemetry(client, telemetry, &err) == 0);
    sbj_free(telemetry);
    sbj *not_object = sbj_array();
    CHECK(sb_agent_client_report_telemetry(client, not_object, &err) != 0);
    CHECK_STR(err.msg, "agent telemetry must be a JSON object");
    sbj_free(not_object);
    sbj *latencies = sbj_parse_cstr("{\"client-node\":8.5}");
    size_t updated = 0;
    CHECK(sb_agent_client_report_proxy_latencies(client, latencies, &updated, &err) == 0);
    CHECK_EQ_INT(updated, 1);
    sbj_free(latencies);
    CHECK(sb_agent_client_acknowledge_command(client, "unknown", false, NULL, &err) != 0);
    CHECK_STR(err.msg, "agent endpoint returned HTTP 404");
    sb_agent_config_response_free(&config);
    sb_agent_client_free(client);

    sb_agent_client_options invalid_options = {server, "invalid", 2000};
    sb_agent_client *invalid = sb_agent_client_new(&invalid_options, &err);
    REQUIRE(invalid);
    sb_agent_config_response rejected;
    CHECK(sb_agent_client_poll_config(invalid, NULL, &rejected, &err) != 0);
    CHECK_STR(err.msg, "agent config endpoint returned HTTP 401");
    sb_agent_client_free(invalid);

    fixture_stop(&f);

    /* nothing is listening any more */
    sb_agent_client *offline = sb_agent_client_new(&options, &err);
    REQUIRE(offline);
    CHECK(sb_agent_client_poll_config(offline, NULL, &rejected, &err) != 0);
    CHECK_STR(err.msg, "agent HTTP request failed: Network failure");
    sb_agent_client_free(offline);
    free(server);
}

/* ---- Clash client ----------------------------------------------------- */

static void clash_api(const fixture_request *req, sb_buf *out) {
    char *auth = header_value(req->headers, "Authorization");
    char *accept = header_value(req->headers, "Accept");
    if (!sb_streq(accept, "application/json")) {
        respond(out, "400 Bad Request", NULL, "{}");
    } else if (!strcmp(req->target, "/api/proxies")) {
        if (sb_streq(auth, "Bearer fixture-secret"))
            respond(out, "200 OK", NULL,
                    "{\"proxies\":{\"Agent / Group\":{\"type\":\"Selector\",\"now\":\"Agent Node\"}}}");
        else
            respond(out, "401 Unauthorized", NULL, "{\"message\":\"Unauthorized\"}");
    } else if (!strcmp(req->method, "PUT") && !strcmp(req->target, "/api/proxies/Agent%20%2F%20Group")) {
        if (sb_streq(req->body, "{\"name\":\"Agent Node\"}"))
            sb_buf_puts(out, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        else
            respond(out, "400 Bad Request", NULL, "{}");
    } else if (!strcmp(req->method, "DELETE") && !strcmp(req->target, "/api/connections")) {
        respond(out, "200 OK", NULL, "not json");
    } else if (!strcmp(req->target, "/api/big")) {
        char big[300];
        memset(big, 'x', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        char *body = sb_asprintf("\"%s\"", big);
        respond(out, "200 OK", NULL, body);
        free(body);
    } else {
        respond(out, "404 Not Found", NULL, "{\"message\":\"not found\"}");
    }
    free(auth);
    free(accept);
}

TEST(clash_client_contract) {
    sb_err err = {0};
    sb_clash_client_options bad_options = {0, 1};
    CHECK(sb_clash_client_new(&bad_options, &err) == NULL);
    CHECK_STR(err.msg, "Clash timeout and response limit must be positive");

    fixture f;
    fixture_start(&f, clash_api);
    sb_clash_client_options options;
    sb_clash_client_options_init(&options);
    options.maximum_body_bytes = 256;
    options.timeout_ms = 2000;
    sb_clash_client *client = sb_clash_client_new(&options, &err);
    REQUIRE(client);
    char *base = sb_asprintf("http://127.0.0.1:%d/api/", f.port);
    sb_clash_target target = {base, "fixture-secret"};
    sb_clash_response resp = {0};

    REQUIRE(sb_clash_get(client, &target, "/proxies", &resp, &err) == 0);
    CHECK_EQ_INT(resp.status, 200);
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(resp.body, "proxies"), "Agent / Group"), "now", NULL),
              "Agent Node");
    sb_clash_response_free(&resp);

    sb_clash_target no_secret = {base, ""};
    REQUIRE(sb_clash_get(client, &no_secret, "/proxies", &resp, &err) == 0);
    CHECK_EQ_INT(resp.status, 401);
    char *auth = last_header(&f, "Authorization");
    CHECK(auth == NULL);
    free(auth);
    sb_clash_response_free(&resp);

    sbj *select = sbj_parse_cstr("{\"name\":\"Agent Node\"}");
    REQUIRE(sb_clash_put(client, &target, "/proxies/Agent%20%2F%20Group", select, &resp, &err) == 0);
    CHECK_EQ_INT(resp.status, 204);
    CHECK(sbj_is_object(resp.body) && sbj_obj_len(resp.body) == 0);
    sb_clash_response_free(&resp);
    sbj_free(select);

    REQUIRE(sb_clash_remove(client, &target, "/connections", &resp, &err) == 0);
    CHECK_EQ_INT(resp.status, 200);
    CHECK(sbj_is_object(resp.body) && sbj_obj_len(resp.body) == 0); /* invalid JSON -> {} */
    sb_clash_response_free(&resp);

    CHECK(sb_clash_get(client, &target, "/big", &resp, &err) != 0);
    CHECK_EQ_INT(err.code, SB_ERR_UPSTREAM);
    CHECK_STR(err.msg, "Clash API response exceeds the configured size limit");

    sb_clash_target ftp = {"ftp://x", NULL};
    CHECK(sb_clash_get(client, &ftp, "/", &resp, &err) != 0);
    CHECK_STR(err.msg, "Clash API URL must include http:// or https://");
    sb_clash_target query = {"http://x/?q", NULL};
    CHECK(sb_clash_get(client, &query, "/", &resp, &err) != 0);
    CHECK_STR(err.msg, "Clash API base URL must not contain a query or fragment");
    sb_clash_target empty = {"http:///x", NULL};
    CHECK(sb_clash_get(client, &empty, "/", &resp, &err) != 0);
    CHECK_STR(err.msg, "Clash API URL has an empty authority");

    fixture_stop(&f);
    CHECK(sb_clash_get(client, &target, "/proxies", &resp, &err) != 0);
    CHECK_STR(err.msg, "Clash API request failed: Network failure");
    sb_clash_client_free(client);
    free(base);
}
