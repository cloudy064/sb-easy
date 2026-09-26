/* AgentClashService contract (port of the Clash parts of
 * cpp/tests/agent_client_test.cpp) with a raw-socket fake Clash API, plus a
 * fake mixed inbound for the CONNECT route test. */
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sb/agent_clash.h"
#include "sb/json.h"
#include "sb/util.h"

/* ---- listener helpers --------------------------------------------------- */

static int listen_loopback(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t size = sizeof address;
    getsockname(fd, (struct sockaddr *)&address, &size);
    *port = ntohs(address.sin_port);
    return fd;
}

static void send_text(int fd, const char *text) {
    size_t len = strlen(text), sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, text + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += (size_t)n;
    }
}

/* Reads one request (headers + Content-Length body). */
static char *read_request(int fd, size_t *header_len) {
    sb_buf in = {0};
    char chunk[4096];
    size_t header_end = 0, content_length = 0;
    for (;;) {
        ssize_t n = recv(fd, chunk, sizeof chunk, 0);
        if (n <= 0) break;
        sb_buf_append(&in, chunk, (size_t)n);
        if (!header_end) {
            char *end = strstr(in.p, "\r\n\r\n");
            if (end) {
                header_end = (size_t)(end - in.p) + 4;
                char *lower = sb_lower_dup(in.p);
                char *found = strstr(lower, "\r\ncontent-length:");
                if (found && (size_t)(found - lower) < header_end)
                    content_length = strtoul(found + 17, NULL, 10);
                free(lower);
            }
        }
        if (header_end && in.len >= header_end + content_length) break;
    }
    *header_len = header_end;
    return sb_buf_detach(&in);
}

/* ---- fake Clash API ------------------------------------------------------ */

typedef struct {
    int listener;
    uint16_t port;
    pthread_t thread;
    pthread_mutex_t mutex;
    sb_strvec seen;           /* "METHOD target" */
    sb_strvec authorizations; /* Authorization header per request ("" if none) */
    char *last_put_body;
    /* scripted state */
    int proxies_status;       /* HTTP status for GET /proxies */
    char *connections_body;   /* NULL -> the C++ fixture body */
    uint16_t route_port;      /* source port reported for the route test */
} clash_fixture;

static const char *default_connections =
    "{\"uploadTotal\":4096,\"downloadTotal\":8192,\"connections\":[{\"id\":\"agent-connection\","
    "\"metadata\":{\"host\":\"Example.COM\",\"destinationIP\":\"203.0.113.1\"},"
    "\"upload\":512,\"download\":2048,\"chains\":[\"Proxy\",\"Agent Node\"],"
    "\"rule\":\"DomainSuffix\",\"rulePayload\":\"example.com\"}]}";

static char *header_value(const char *request, size_t header_len, const char *name) {
    char *head = sb_strndup(request, header_len);
    char *lower = sb_lower_dup(head);
    char *needle = sb_asprintf("\r\n%s:", name);
    char *found = strstr(lower, needle);
    char *value = NULL;
    if (found) {
        const char *start = head + (found - lower) + strlen(needle);
        while (*start == ' ') ++start;
        value = sb_strndup(start, strcspn(start, "\r\n"));
    }
    free(needle);
    free(lower);
    free(head);
    return value;
}

static char *clash_respond(clash_fixture *f, const char *method, const char *target,
                           const char *body) {
    int status = 200;
    char *payload = NULL;
    pthread_mutex_lock(&f->mutex);
    if (strcmp(method, "GET") == 0 && strcmp(target, "/proxies") == 0) {
        status = f->proxies_status;
        payload = status == 200
                      ? sb_strdup("{\"proxies\":{\"Agent Node\":{\"type\":\"Shadowsocks\"},"
                                  "\"Agent / Group\":{\"type\":\"Selector\",\"now\":\"Agent Node\","
                                  "\"all\":[\"Agent Node\"]},\"direct\":{\"type\":\"Direct\"}}}")
                      : sb_strdup("{\"message\":\"controller exploded\"}");
    } else if (strcmp(method, "PUT") == 0 && strcmp(target, "/proxies/Agent%20%2F%20Group") == 0) {
        free(f->last_put_body);
        f->last_put_body = sb_strdup(body);
        payload = sb_strdup("{\"selected\":true}");
    } else if (strstr(target, "/delay?")) {
        payload = sb_strdup("{\"delay\":33}");
    } else if (strcmp(target, "/connections") == 0) {
        if (f->route_port) {
            payload = sb_asprintf(
                "{\"uploadTotal\":1,\"downloadTotal\":2,\"connections\":["
                "{\"id\":\"other\",\"metadata\":{\"sourcePort\":\"1\"},\"chains\":[\"x\"]},"
                "{\"id\":\"route\",\"metadata\":{\"sourcePort\":%u,\"host\":\"example.com\"},"
                "\"chains\":[\"node-a\",\"Proxy\"],\"rule\":\"domain_suffix=example.com\","
                "\"rulePayload\":\"\"}]}",
                (unsigned)f->route_port);
        } else {
            payload = sb_strdup(f->connections_body ? f->connections_body : default_connections);
        }
    } else {
        status = 404;
        payload = sb_strdup("{}");
    }
    pthread_mutex_unlock(&f->mutex);
    char *response = sb_asprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                                 "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                                 status, status == 200 ? "OK" : "Error", strlen(payload), payload);
    free(payload);
    return response;
}

static void *clash_main(void *arg) {
    clash_fixture *f = arg;
    for (;;) {
        int client = accept4(f->listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) return NULL;
        size_t header_len = 0;
        char *request = read_request(client, &header_len);
        if (header_len) {
            char method[16] = {0}, target[1024] = {0};
            sscanf(request, "%15s %1023s", method, target);
            char *authorization = header_value(request, header_len, "authorization");
            pthread_mutex_lock(&f->mutex);
            sb_strvec_push_take(&f->seen, sb_asprintf("%s %s", method, target));
            sb_strvec_push(&f->authorizations, authorization ? authorization : "");
            pthread_mutex_unlock(&f->mutex);
            free(authorization);
            char *response = clash_respond(f, method, target, request + header_len);
            send_text(client, response);
            free(response);
        }
        free(request);
        close(client);
    }
}

static int clash_fixture_start(clash_fixture *f) {
    memset(f, 0, sizeof *f);
    pthread_mutex_init(&f->mutex, NULL);
    f->proxies_status = 200;
    f->listener = listen_loopback(&f->port);
    if (f->listener < 0) return -1;
    return pthread_create(&f->thread, NULL, clash_main, f) == 0 ? 0 : -1;
}

static void clash_fixture_stop(clash_fixture *f) {
    shutdown(f->listener, SHUT_RDWR);
    close(f->listener);
    pthread_join(f->thread, NULL);
    sb_strvec_free(&f->seen);
    sb_strvec_free(&f->authorizations);
    free(f->last_put_body);
    free(f->connections_body);
    pthread_mutex_destroy(&f->mutex);
}

static bool fixture_saw(clash_fixture *f, const char *line) {
    bool found = false;
    pthread_mutex_lock(&f->mutex);
    for (size_t i = 0; i < f->seen.len && !found; ++i) found = strcmp(f->seen.items[i], line) == 0;
    pthread_mutex_unlock(&f->mutex);
    return found;
}

static void fixture_set_connections(clash_fixture *f, const char *body) {
    pthread_mutex_lock(&f->mutex);
    sb_str_set(&f->connections_body, body);
    pthread_mutex_unlock(&f->mutex);
}

/* ---- fake mixed inbound (CONNECT) --------------------------------------- */

typedef struct {
    int listener;
    uint16_t port;
    pthread_t thread;
    clash_fixture *clash;
    char *request; /* the CONNECT request that arrived */
} proxy_fixture;

static void *proxy_main(void *arg) {
    proxy_fixture *p = arg;
    for (;;) {
        struct sockaddr_in peer;
        socklen_t size = sizeof peer;
        int client = accept4(p->listener, (struct sockaddr *)&peer, &size, SOCK_CLOEXEC);
        if (client < 0) return NULL;
        size_t header_len = 0;
        char *request = read_request(client, &header_len);
        pthread_mutex_lock(&p->clash->mutex);
        free(p->request);
        p->request = request;
        p->clash->route_port = ntohs(peer.sin_port);
        pthread_mutex_unlock(&p->clash->mutex);
        close(client);
    }
}

static int proxy_fixture_start(proxy_fixture *p, clash_fixture *clash) {
    memset(p, 0, sizeof *p);
    p->clash = clash;
    p->listener = listen_loopback(&p->port);
    if (p->listener < 0) return -1;
    return pthread_create(&p->thread, NULL, proxy_main, p) == 0 ? 0 : -1;
}

static void proxy_fixture_stop(proxy_fixture *p) {
    shutdown(p->listener, SHUT_RDWR);
    close(p->listener);
    pthread_join(p->thread, NULL);
    free(p->request);
}

/* ---- config files -------------------------------------------------------- */

static char *temp_dir(void) {
    char tmpl[] = "/tmp/sb-easy-agent-clash-XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) abort();
    return sb_strdup(dir);
}

static void remove_dir(const char *dir) {
    char *command = sb_asprintf("rm -rf '%s'", dir);
    if (system(command) != 0) {
    }
    free(command);
}

static char *write_config(const char *dir, const char *name, const char *text) {
    char *path = sb_path_join(dir, name);
    sb_write_file(path, text, strlen(text));
    return path;
}

static char *clash_config(const char *dir, uint16_t clash_port, uint16_t inbound_port) {
    char *text = sb_asprintf(
        "{\"experimental\":{\"clash_api\":{\"external_controller\":\"0.0.0.0:%u\","
        "\"secret\":\"fixture-secret\"}},\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\"},"
        "{\"type\":\"mixed\",\"tag\":\"mixed-in\",\"listen\":\"0.0.0.0\",\"listen_port\":%u}]}",
        (unsigned)clash_port, (unsigned)inbound_port);
    char *path = write_config(dir, "clash.json", text);
    free(text);
    return path;
}

/* ---- latency reporter ---------------------------------------------------- */

typedef struct {
    sbj *reports; /* array */
    int fail_after;
} reporter_state;

static int collect_latency(const sbj *latency, void *user, sb_err *err) {
    reporter_state *state = user;
    if (state->fail_after >= 0 && (int)sbj_arr_len(state->reports) >= state->fail_after)
        return sb_fail(err, SB_ERR_UPSTREAM, "agent endpoint returned HTTP 500");
    sbj_arr_push(state->reports, sbj_clone(latency));
    return 0;
}

/* ---- tests ----------------------------------------------------------------- */

TEST(agent_clash_contract) {
    clash_fixture fixture;
    REQUIRE(clash_fixture_start(&fixture) == 0);
    char *dir = temp_dir();
    char *config = clash_config(dir, fixture.port, 7);
    sb_agent_clash *clash = sb_agent_clash_new(config);
    sb_err err = {0};

    /* agent Clash integration should return live selector state */
    sbj *live = sb_agent_clash_proxies(clash, &err);
    REQUIRE(live != NULL);
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(live, "proxies"), "Agent / Group"), "now", NULL),
              "Agent Node");
    sbj_free(live);
    CHECK(fixture_saw(&fixture, "GET /proxies"));
    CHECK_STR(fixture.authorizations.items[0], "Bearer fixture-secret");

    /* agent Clash integration should encode special selector names */
    sbj *selected = sb_agent_clash_select_proxy(clash, "Agent / Group", "Agent Node", &err);
    REQUIRE(selected != NULL);
    CHECK(sbj_get_bool(selected, "success", false));
    CHECK_STR(sbj_get_str(selected, "group", NULL), "Agent / Group");
    CHECK_STR(sbj_get_str(selected, "name", NULL), "Agent Node");
    sbj_free(selected);
    CHECK(fixture_saw(&fixture, "PUT /proxies/Agent%20%2F%20Group"));
    CHECK_STR(fixture.last_put_body, "{\"name\":\"Agent Node\"}");

    /* agent Clash tests should skip groups/built-ins and report each delay */
    reporter_state reports = {.reports = sbj_array(), .fail_after = -1};
    size_t tested = 99;
    REQUIRE(sb_agent_clash_test_proxies(clash, NULL, collect_latency, &reports, &tested, &err) == 0);
    CHECK_EQ_INT(tested, 1);
    REQUIRE(sbj_arr_len(reports.reports) == 1);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(reports.reports, 0), "Agent Node", -1), 33);
    CHECK(fixture_saw(&fixture, "GET /proxies/Agent%20Node/delay?url=https%3A%2F%2Fwww.gstatic.com"
                                "%2Fgenerate_204&timeout=5000"));
    sbj_free(reports.reports);

    /* agent Clash telemetry should expose totals and an initial zero rate */
    sbj *telemetry = NULL;
    REQUIRE(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    REQUIRE(telemetry != NULL);
    CHECK_EQ_INT(sbj_get_int(telemetry, "up_total", -1), 4096);
    CHECK_EQ_INT(sbj_get_int(telemetry, "down_total", -1), 8192);
    CHECK_EQ_INT(sbj_get_int(telemetry, "conn_count", -1), 1);
    CHECK_EQ_INT(sbj_get_int(telemetry, "up", -1), 0);
    CHECK_EQ_INT(sbj_get_int(telemetry, "down", -1), 0);
    const sbj *stat = sbj_arr_at(sbj_get(telemetry, "domain_stats"), 0);
    CHECK_STR(sbj_get_str(stat, "domain", NULL), "example.com");
    CHECK_STR(sbj_get_str(stat, "outbound", NULL), "Agent Node");
    CHECK_STR(sbj_get_str(stat, "outbound_type", NULL), "proxy");
    CHECK_STR(sbj_get_str(stat, "rule", NULL), "DomainSuffix: example.com");
    CHECK_EQ_INT(sbj_get_int(stat, "connection_count", -1), 1);
    CHECK_EQ_INT(sbj_get_int(stat, "uplink_total", -1), 512);
    CHECK_EQ_INT(sbj_get_int(stat, "downlink_total", -1), 2048);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(stat, "chain")), 2);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(telemetry, "connections")), 1);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(telemetry, "logs")), 0);
    sbj_free(telemetry);

    sb_agent_clash_free(clash);
    free(config);
    remove_dir(dir);
    free(dir);
    clash_fixture_stop(&fixture);
}

TEST(agent_clash_test_proxies_filters_and_errors) {
    clash_fixture fixture;
    REQUIRE(clash_fixture_start(&fixture) == 0);
    char *dir = temp_dir();
    char *config = clash_config(dir, fixture.port, 7);
    sb_agent_clash *clash = sb_agent_clash_new(config);
    sb_err err = {0};
    size_t tested = 99;

    /* A reporter is required. */
    CHECK(sb_agent_clash_test_proxies(clash, NULL, NULL, NULL, &tested, &err) == -1);
    CHECK_STR(err.msg, "proxy latency reporter is required");
    CHECK(err.code == SB_ERR_VALIDATION);

    /* Only the requested tags are tested; an empty list tests nothing. */
    reporter_state reports = {.reports = sbj_array(), .fail_after = -1};
    sb_strvec tags = {0};
    sb_strvec_push(&tags, "missing");
    CHECK(sb_agent_clash_test_proxies(clash, &tags, collect_latency, &reports, &tested, &err) == 0);
    CHECK_EQ_INT(tested, 0);
    sb_strvec_push(&tags, "Agent Node");
    sb_strvec_push(&tags, "Agent / Group"); /* groups are never tested */
    CHECK(sb_agent_clash_test_proxies(clash, &tags, collect_latency, &reports, &tested, &err) == 0);
    CHECK_EQ_INT(tested, 1);
    sb_strvec_free(&tags);
    sb_strvec empty = {0};
    CHECK(sb_agent_clash_test_proxies(clash, &empty, collect_latency, &reports, &tested, &err) == 0);
    CHECK_EQ_INT(tested, 0);

    /* Reporter failures abort the run (C++ exception propagation). */
    reports.fail_after = 0;
    CHECK(sb_agent_clash_test_proxies(clash, NULL, collect_latency, &reports, &tested, &err) == -1);
    CHECK_STR(err.msg, "agent endpoint returned HTTP 500");
    sbj_free(reports.reports);

    /* Clash errors surface with the C++ messages. */
    pthread_mutex_lock(&fixture.mutex);
    fixture.proxies_status = 500;
    pthread_mutex_unlock(&fixture.mutex);
    reporter_state more = {.reports = sbj_array(), .fail_after = -1};
    CHECK(sb_agent_clash_test_proxies(clash, NULL, collect_latency, &more, &tested, &err) == -1);
    CHECK_STR(err.msg, "Clash proxy list returned HTTP 500");
    sbj_free(more.reports);
    CHECK(sb_agent_clash_proxies(clash, &err) == NULL);
    CHECK_STR(err.msg, "读取本地代理组失败：controller exploded");

    /* select_proxy validates its arguments first. */
    CHECK(sb_agent_clash_select_proxy(clash, "", "x", &err) == NULL);
    CHECK_STR(err.msg, "策略组和节点名称不能为空");
    CHECK(err.code == SB_ERR_VALIDATION);

    sb_agent_clash_free(clash);
    free(config);
    remove_dir(dir);
    free(dir);
    clash_fixture_stop(&fixture);
}

TEST(agent_clash_config_errors) {
    char *dir = temp_dir();
    sb_err err = {0};
    char *missing = sb_path_join(dir, "missing.json");
    sb_agent_clash *clash = sb_agent_clash_new(missing);
    sbj *telemetry = NULL;
    CHECK(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == -1);
    char *expected = sb_asprintf("cannot read sing-box config: %s", missing);
    CHECK_STR(err.msg, expected);
    free(expected);
    sb_agent_clash_free(clash);

    char *array = write_config(dir, "array.json", "[1,2]");
    clash = sb_agent_clash_new(array);
    CHECK(sb_agent_clash_proxies(clash, &err) == NULL);
    expected = sb_asprintf("sing-box config is not a JSON object: %s", array);
    CHECK_STR(err.msg, expected);
    free(expected);
    sb_agent_clash_free(clash);

    /* Without a controller there is no telemetry (not an error). */
    char *plain = write_config(dir, "plain.json", "{\"outbounds\":[]}");
    clash = sb_agent_clash_new(plain);
    telemetry = (sbj *)1;
    CHECK(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    CHECK(telemetry == NULL);
    sb_agent_clash_free(clash);
    char *empty_controller = write_config(
        dir, "empty.json", "{\"experimental\":{\"clash_api\":{\"external_controller\":\"\"}}}");
    clash = sb_agent_clash_new(empty_controller);
    telemetry = (sbj *)1;
    CHECK(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    CHECK(telemetry == NULL);
    sb_agent_clash_free(clash);

    free(missing);
    free(array);
    free(plain);
    free(empty_controller);
    remove_dir(dir);
    free(dir);
}

TEST(agent_clash_domain_stats_accumulate) {
    clash_fixture fixture;
    REQUIRE(clash_fixture_start(&fixture) == 0);
    char *dir = temp_dir();
    char *config = clash_config(dir, fixture.port, 7);
    sb_agent_clash *clash = sb_agent_clash_new(config);
    sb_err err = {0};
    sbj *telemetry = NULL;

    fixture_set_connections(
        &fixture,
        "{\"uploadTotal\":1000,\"downloadTotal\":1000,\"connections\":["
        "{\"id\":\"a\",\"metadata\":{\"host\":\"a.example.\"},\"upload\":10,\"download\":20,"
        "\"chains\":[\"DIRECT\"],\"rule\":\"final\"},"
        "{\"id\":\"b\",\"metadata\":{\"destinationIP\":\"198.51.100.7\"},\"upload\":5,"
        "\"download\":5,\"chains\":[\"Proxy\",\"node\"]},"
        "{\"id\":\"\",\"metadata\":{\"host\":\"ignored\"}},"
        "{\"id\":\"c\",\"metadata\":{\"host\":\"b.example\"},\"upload\":-5,\"download\":1,"
        "\"chains\":[]}]}");
    REQUIRE(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    const sbj *stats = sbj_get(telemetry, "domain_stats");
    REQUIRE(sbj_arr_len(stats) == 3);
    /* Ties on connection_count sort by total traffic, descending. */
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 0), "domain", NULL), "a.example");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 0), "outbound_type", NULL), "direct");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 0), "rule", NULL), "final");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 1), "domain", NULL), "198.51.100.7");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 1), "outbound", NULL), "node");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 2), "domain", NULL), "b.example");
    CHECK_STR(sbj_get_str(sbj_arr_at(stats, 2), "outbound_type", NULL), "");
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(stats, 2), "uplink_total", -1), 0);
    CHECK_EQ_INT(sbj_get_int(telemetry, "conn_count", -1), 4);
    int64_t first_seen = sbj_get_int(sbj_arr_at(stats, 0), "first_seen", 0);
    CHECK(first_seen > 1700000000000LL);
    sbj_free(telemetry);

    /* Growth is added as a delta, a new connection on the same route counts,
     * a vanished connection keeps its accumulated totals. */
    sb_sleep_ms(20);
    fixture_set_connections(
        &fixture,
        "{\"uploadTotal\":3000,\"downloadTotal\":5000,\"connections\":["
        "{\"id\":\"a\",\"metadata\":{\"host\":\"a.example\"},\"upload\":30,\"download\":20,"
        "\"chains\":[\"DIRECT\"],\"rule\":\"final\"},"
        "{\"id\":\"d\",\"metadata\":{\"host\":\"A.EXAMPLE\"},\"upload\":1,\"download\":1,"
        "\"chains\":[\"DIRECT\"],\"rule\":\"final\"}]}");
    REQUIRE(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    stats = sbj_get(telemetry, "domain_stats");
    REQUIRE(sbj_arr_len(stats) == 3);
    const sbj *a = sbj_arr_at(stats, 0);
    CHECK_STR(sbj_get_str(a, "domain", NULL), "a.example");
    CHECK_EQ_INT(sbj_get_int(a, "connection_count", -1), 2);
    CHECK_EQ_INT(sbj_get_int(a, "uplink_total", -1), 31);
    CHECK_EQ_INT(sbj_get_int(a, "downlink_total", -1), 21);
    CHECK_EQ_INT(sbj_get_int(a, "first_seen", -1), first_seen);
    CHECK(sbj_get_int(a, "last_seen", 0) >= first_seen);
    CHECK(sbj_get_int(telemetry, "up", 0) > 0);
    CHECK(sbj_get_int(telemetry, "down", 0) > sbj_get_int(telemetry, "up", 0));
    sbj_free(telemetry);

    /* A connection whose route changes moves between buckets; an emptied
     * bucket disappears. */
    fixture_set_connections(
        &fixture,
        "{\"uploadTotal\":3000,\"downloadTotal\":5000,\"connections\":["
        "{\"id\":\"d\",\"metadata\":{\"host\":\"a.example\"},\"upload\":1,\"download\":1,"
        "\"chains\":[\"Proxy\",\"node\"],\"rule\":\"final\"}]}");
    REQUIRE(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    stats = sbj_get(telemetry, "domain_stats");
    bool found_moved = false;
    const sbj *item;
    SBJ_ARR_FOREACH(stats, i, item) {
        if (strcmp(sbj_get_str(item, "outbound", ""), "node") == 0 &&
            strcmp(sbj_get_str(item, "domain", ""), "a.example") == 0) {
            found_moved = true;
            CHECK_EQ_INT(sbj_get_int(item, "connection_count", -1), 1);
        }
        if (strcmp(sbj_get_str(item, "outbound", ""), "DIRECT") == 0) {
            CHECK_EQ_INT(sbj_get_int(item, "connection_count", -1), 1);
            CHECK_EQ_INT(sbj_get_int(item, "uplink_total", -1), 30);
        }
    }
    CHECK(found_moved);
    CHECK_EQ_INT(sbj_get_int(telemetry, "up", -1), 0);
    sbj_free(telemetry);

    /* A non-array connections member resets the observed set. */
    fixture_set_connections(&fixture, "{\"connections\":null}");
    REQUIRE(sb_agent_clash_sample_telemetry(clash, &telemetry, &err) == 0);
    CHECK(sbj_is_null(sbj_get(telemetry, "connections")));
    CHECK_EQ_INT(sbj_get_int(telemetry, "conn_count", -1), 0);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(telemetry, "domain_stats")), 0);
    sbj_free(telemetry);

    sb_agent_clash_free(clash);
    free(config);
    remove_dir(dir);
    free(dir);
    clash_fixture_stop(&fixture);
}

TEST(agent_clash_route_test) {
    clash_fixture fixture;
    REQUIRE(clash_fixture_start(&fixture) == 0);
    proxy_fixture inbound;
    REQUIRE(proxy_fixture_start(&inbound, &fixture) == 0);
    char *dir = temp_dir();
    char *config = clash_config(dir, fixture.port, inbound.port);
    sb_agent_clash *clash = sb_agent_clash_new(config);
    sb_err err = {0};

    sbj *result = sb_agent_clash_test_route(clash, "  example.com/path  ", &err);
    if (!result) fprintf(stderr, "test_route: %s\n", err.msg);
    REQUIRE(result != NULL);
    CHECK(sbj_get_bool(result, "success", false));
    CHECK_STR(sbj_get_str(result, "url", NULL), "https://example.com/path");
    CHECK_STR(sbj_get_str(result, "host", NULL), "example.com");
    CHECK_EQ_INT(sbj_get_int(result, "port", -1), 443);
    CHECK_STR(sbj_get_str(result, "kind", NULL), "proxy");
    CHECK_STR(sbj_get_str(result, "outbound", NULL), "node-a");
    CHECK_STR(sbj_get_str(result, "rule", NULL), "domain_suffix=example.com");
    CHECK_STR(sbj_get_str(result, "rule_payload", NULL), "");
    CHECK_EQ_INT(sbj_arr_len(sbj_get(result, "chains")), 2);
    sbj_free(result);
    pthread_mutex_lock(&fixture.mutex);
    CHECK_STR(inbound.request, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                               "User-Agent: sb-easy-route-test/1.0\r\n"
                               "Proxy-Connection: keep-alive\r\n\r\n");
    fixture.route_port = 0;
    pthread_mutex_unlock(&fixture.mutex);

    result = sb_agent_clash_test_route(clash, "http://[2001:db8::1]:8080/x", &err);
    REQUIRE(result != NULL);
    CHECK_STR(sbj_get_str(result, "host", NULL), "2001:db8::1");
    CHECK_EQ_INT(sbj_get_int(result, "port", -1), 8080);
    sbj_free(result);
    pthread_mutex_lock(&fixture.mutex);
    CHECK_CONTAINS(inbound.request, "CONNECT [2001:db8::1]:8080 HTTP/1.1\r\n");
    pthread_mutex_unlock(&fixture.mutex);

    /* URL validation (std::invalid_argument -> SB_ERR_VALIDATION). */
    static const struct {
        const char *url;
        const char *message;
    } invalid[] = {
        {"   ", "请输入要测试的 URL"},
        {"ftp://example.com", "只支持 http:// 或 https:// URL"},
        {"https://user@example.com", "URL 主机名无效"},
        {"https://exa mple.com", "URL 主机名无效"},
        {"https://:443", "URL 主机名无效"},
        {"https://example.com:0", "URL 端口无效"},
        {"https://example.com:65536", "URL 端口无效"},
        {"https://example.com:x", "URL 端口无效"},
        {"https://[::1", "URL IPv6 主机名无效"},
        {"https://[::1]x", "URL 主机名无效"},
        {"https:///path", "URL 主机名无效"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        sb_err e = {0};
        CHECK(sb_agent_clash_test_route(clash, invalid[i].url, &e) == NULL);
        CHECK_STR(e.msg, invalid[i].message);
        CHECK(e.code == SB_ERR_VALIDATION);
    }
    sb_agent_clash_free(clash);

    /* A config without mixed/http inbounds cannot run a route test. */
    char *no_inbound = write_config(dir, "no-inbound.json", "{\"inbounds\":[{\"type\":\"tun\"}]}");
    clash = sb_agent_clash_new(no_inbound);
    CHECK(sb_agent_clash_test_route(clash, "https://example.com", &err) == NULL);
    CHECK_STR(err.msg, "当前配置需要 mixed 或 http 入站才能执行真实路由测试");
    sb_agent_clash_free(clash);
    char *no_inbounds = write_config(dir, "no-inbounds.json", "{}");
    clash = sb_agent_clash_new(no_inbounds);
    CHECK(sb_agent_clash_test_route(clash, "https://example.com", &err) == NULL);
    CHECK_STR(err.msg, "当前配置没有可用于测试的 HTTP/mixed 入站");
    sb_agent_clash_free(clash);

    free(no_inbound);
    free(no_inbounds);
    free(config);
    remove_dir(dir);
    free(dir);
    proxy_fixture_stop(&inbound);
    clash_fixture_stop(&fixture);
}
