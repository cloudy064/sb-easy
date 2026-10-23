#include "test.h"
#include "http_test_support.h"
#include "sb/agent_client.h"
#include "sb/proxy_runtime.h"
#include "sb/proxy_users.h"
#include <stdatomic.h>

typedef struct {
    const char *reports;
    char *begun, *applied, *acknowledged;
    atomic_int begins, applies, acknowledgments, stops, stats_calls;
    bool fail_apply, fail_acknowledge;
} engine;
static int begin_request(void *context, const char *value, sb_err *err) {
    (void)err; engine *e = context; sb_str_set(&e->begun, value); ++e->begins; return 0;
}
static int apply_policy(void *context, const char *value, sb_err *err) {
    engine *e = context; sb_str_set(&e->applied, value); ++e->applies;
    return e->fail_apply ? sb_fail(err, SB_ERR_GENERIC, "fixture credential MUST_NOT_LEAK") : 0;
}
static int read_stats(void *context, char **value, size_t *length, sb_err *err) {
    (void)err; engine *e = context; *value = sb_strdup(e->reports ? e->reports : "[]");
    *length = strlen(*value); ++e->stats_calls; return 0;
}
static int acknowledge(void *context, const char *value, sb_err *err) {
    engine *e = context; sb_str_set(&e->acknowledged, value); ++e->acknowledgments;
    return e->fail_acknowledge ? sb_fail(err, SB_ERR_GENERIC, "fixture credential MUST_NOT_LEAK") : 0;
}
static void stop_engine(void *context) { engine *e = context; ++e->stops; }
static sb_proxy_bridge bridge(engine *e) {
    return (sb_proxy_bridge){e, begin_request, apply_policy, read_stats, acknowledge, stop_engine};
}
static void engine_free(engine *e) { free(e->begun); free(e->applied); free(e->acknowledged); }
static sbj *policy(const char *raw, const char *host, int ttl) {
    sbj *request = sbj_parse_cstr(raw), *out = sbj_object();
    sbj_set_int(out, "version", 1); sbj_set_str(out, "host_id", host);
    sbj_set(out, "boot_id", sbj_clone(sbj_get(request, "boot_id")));
    sbj_set(out, "request_seq", sbj_clone(sbj_get(request, "request_seq")));
    int64_t now = sb_unix_now(); sbj_set_int(out, "generated_at", now); sbj_set_int(out, "expires_at", now + ttl);
    sbj_set(out, "node", sbj_null()); sbj_set(out, "users", sbj_array()); sbj_free(request); return out;
}
typedef struct {
    sb_agent_client *client;
    sb_strvec requests;
    atomic_int mode, delay_ms;
    atomic_int received;
} remote;
enum { GOOD, DROP_FIRST, WRONG_HOST, WRONG_SEQUENCE, WRONG_TYPE, DUPLICATE_KEY, UNKNOWN_FIELD, BAD_USER, REDIRECT,
    FULL_POLICY, NONCANONICAL_KEY, ZERO_GRANT, MISSING_DEVICE_EXPIRY, DUPLICATE_DEVICE_KEY, SCOPED_ADDRESS, FLOAT_EPOCH, OVERSIZED };
static char *serve_policy(const sb_fixture_request *request, void *context) {
    remote *r = context;
    if (strcmp(request->method, "POST") || strcmp(request->target, "/prefix/api/agent/proxy-leases") ||
        !strstr(request->headers, "Authorization: Bearer runtime-fixture-token")) abort();
    sb_strvec_push(&r->requests, request->body); ++r->received;
    if (r->mode == DROP_FIRST && r->requests.len == 1) return NULL;
    if (r->delay_ms) usleep((useconds_t)r->delay_ms * 1000);
    if (r->mode == REDIRECT) return sb_strdup("HTTP/1.1 302 Found\r\nLocation: /credential-leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if (r->mode == OVERSIZED) {
        char *large = sb_xmalloc(SB_PROXY_POLICY_LIMIT + 2); memset(large, ' ', SB_PROXY_POLICY_LIMIT + 1); large[SB_PROXY_POLICY_LIMIT + 1] = 0;
        char *response = sb_fixture_response(200, "application/json", large); free(large); return response;
    }
    sbj *out = policy(request->body, r->mode == WRONG_HOST ? "another-host" : "node-one", r->mode == DROP_FIRST ? 2 : 60);
    if (r->mode == WRONG_SEQUENCE) sbj_set_int(out, "request_seq", 99);
    if (r->mode == WRONG_TYPE) sbj_set_str(out, "request_seq", "1");
    if (r->mode == UNKNOWN_FIELD) sbj_set_str(out, "unexpected", "MUST_NOT_LEAK");
    if (r->mode == BAD_USER) sbj_arr_push(sbj_get(out, "users"), sbj_object());
    if (r->mode >= FULL_POLICY) {
        sbj *node = sbj_parse_cstr("{\"listen\":\"127.0.0.1\",\"listen_port\":8388,\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"AAECAwQFBgcICQoLDA0ODw==\"}");
        sbj *user = sbj_parse_cstr("{\"id\":\"user-one\",\"epoch\":1,\"lease\":{\"id\":\"lease-one\",\"grant_bytes\":100,\"used_bytes\":0},\"devices\":[{\"id\":\"device-one\",\"password\":\"EBESExQVFhcYGRobHB0eHw==\",\"expires_at\":0}]}");
        sbj *lease = sbj_get(user, "lease"), *device = sbj_arr_at(sbj_get(user, "devices"), 0);
        sbj_set_int(lease, "expires_at", sbj_get_int(out, "expires_at", 0));
        if (r->mode == NONCANONICAL_KEY) sbj_set_str(device, "password", "EBESExQVFhcYGRobHB0eHx==");
        if (r->mode == ZERO_GRANT) sbj_set_int(lease, "grant_bytes", 0);
        if (r->mode == MISSING_DEVICE_EXPIRY) sbj_del(device, "expires_at");
        if (r->mode == DUPLICATE_DEVICE_KEY) { sbj *duplicate = sbj_clone(device); sbj_set_str(duplicate, "id", "device-two"); sbj_arr_push(sbj_get(user, "devices"), duplicate); }
        if (r->mode == SCOPED_ADDRESS) sbj_set_str(node, "listen", "fe80::1%eth0");
        if (r->mode == FLOAT_EPOCH) sbj_set(user, "epoch", sbj_float(1.5));
        sbj_set(out, "node", node); sbj_arr_push(sbj_get(out, "users"), user);
    }
    char *body = sbj_dump(out, -1); sbj_free(out);
    if (r->mode == DUPLICATE_KEY) { char *duplicate = sb_asprintf("{\"version\":1,%s", body + 1); free(body); body = duplicate; }
    char *response = sb_fixture_response(200, "application/json", body); free(body); return response;
}
static int exchange_http(void *context, const char *request, size_t length, char **response, size_t *size, sb_err *err) {
    remote *r = context; return sb_agent_client_proxy_exchange(r->client, request, length, response, size, err);
}
static bool remote_start(remote *r, sb_fixture *fixture) {
    if (sb_fixture_start(fixture, serve_policy, r)) return false;
    char *url = sb_asprintf("http://127.0.0.1:%u/prefix", fixture->port);
    sb_agent_client_options options = {url, "runtime-fixture-token", 3000};
    r->client = sb_agent_client_new(&options, NULL); free(url); return r->client != NULL;
}
static void remote_free(remote *r, sb_fixture *fixture) {
    sb_fixture_stop(fixture); sb_agent_client_free(r->client); sb_strvec_free(&r->requests);
}
TEST(real_http_lost_reply_keeps_exact_reports_and_expired_retry_advances) {
    engine e = {.reports = "[{\"lease_id\":\"lease-one\",\"used_bytes\":7}]"}; sb_proxy_bridge b = bridge(&e);
    remote r = {.mode = DROP_FIRST}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture)); sb_err err = {0};
    sb_proxy_runtime *runtime = sb_proxy_runtime_new("node-one", &b, exchange_http, &r, &err); REQUIRE(runtime);
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(e.begins, 1); CHECK_EQ_INT(e.acknowledgments, 0);
    e.reports = "[{\"lease_id\":\"lease-one\",\"used_bytes\":19}]";
    usleep(1100000);
    CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 1);
    CHECK_EQ_INT(r.requests.len, 2); CHECK_STR(r.requests.items[0], r.requests.items[1]);
    CHECK_EQ_INT(e.begins, 1); CHECK_EQ_INT(e.stats_calls, 1); CHECK_EQ_INT(e.acknowledgments, 1);
    sbj *ack = sbj_parse_cstr(e.acknowledged); CHECK_EQ_INT(sbj_get_int(sbj_arr_at(ack, 0), "used_bytes", -1), 7); sbj_free(ack);
    r.mode = GOOD; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0);
    sbj *first = sbj_parse_cstr(r.requests.items[0]), *next = sbj_parse_cstr(r.requests.items[2]);
    CHECK_EQ_INT(sbj_get_int(next, "request_seq", 0), 2); CHECK(sbj_equal(sbj_get(first, "boot_id"), sbj_get(next, "boot_id")));
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(sbj_get(next, "reports"), 0), "used_bytes", 0), 19);
    sbj_free(first); sbj_free(next); sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(real_http_wrong_identity_or_schema_never_acknowledges_or_changes_pending) {
    engine e = {0}; sb_proxy_bridge b = bridge(&e); remote r = {0}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_err err = {0}; sb_proxy_runtime *runtime = sb_proxy_runtime_new("node-one", &b, exchange_http, &r, &err); REQUIRE(runtime);
    const int invalid[] = {WRONG_HOST, WRONG_SEQUENCE, WRONG_TYPE, DUPLICATE_KEY, UNKNOWN_FIELD, BAD_USER, REDIRECT};
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        r.mode = invalid[i]; CHECK(sb_proxy_runtime_step(runtime, &err) < 0);
        CHECK(!strstr(err.msg, "MUST_NOT_LEAK")); CHECK_EQ_INT(e.acknowledgments, 0); CHECK_EQ_INT(e.applies, 0);
        CHECK_EQ_INT(e.begins, 1); CHECK_STR(r.requests.items[0], r.requests.items[r.requests.len - 1]);
    }
    CHECK_EQ_INT(r.requests.len, sizeof invalid / sizeof *invalid);
    r.mode = GOOD; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0); CHECK_EQ_INT(e.acknowledgments, 1);
    sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(local_apply_or_ack_failure_consumes_the_accepted_sequence) {
    engine e = {.fail_apply = true}; sb_proxy_bridge b = bridge(&e); remote r = {0}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_err err = {0}; sb_proxy_runtime *runtime = sb_proxy_runtime_new("", &b, exchange_http, &r, &err); REQUIRE(runtime);
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK(!strstr(err.msg, "MUST_NOT_LEAK")); CHECK_EQ_INT(e.acknowledgments, 1);
    e.fail_apply = false; e.fail_acknowledge = true;
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK(!strstr(err.msg, "MUST_NOT_LEAK"));
    sbj *second = sbj_parse_cstr(r.requests.items[1]); CHECK_EQ_INT(sbj_get_int(second, "request_seq", 0), 2); sbj_free(second);
    e.fail_acknowledge = false; r.mode = WRONG_HOST;
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(e.acknowledgments, 2);
    r.mode = GOOD; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0);
    CHECK_STR(r.requests.items[2], r.requests.items[3]); sbj *third = sbj_parse_cstr(r.requests.items[3]);
    CHECK_EQ_INT(sbj_get_int(third, "request_seq", 0), 3); sbj_free(third);
    sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(real_http_policy_fields_match_the_engine_before_sequence_or_report_acceptance) {
    engine e = {0}; sb_proxy_bridge b = bridge(&e); remote r = {0}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_err err = {0}; sb_proxy_runtime *runtime = sb_proxy_runtime_new("node-one", &b, exchange_http, &r, &err); REQUIRE(runtime);
    const int modes[] = {NONCANONICAL_KEY, ZERO_GRANT, MISSING_DEVICE_EXPIRY, DUPLICATE_DEVICE_KEY, SCOPED_ADDRESS, FLOAT_EPOCH, OVERSIZED};
    for (size_t i = 0; i < sizeof modes / sizeof *modes; ++i) {
        r.mode = modes[i]; CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(e.applies, 0); CHECK_EQ_INT(e.acknowledgments, 0);
    }
    r.mode = FULL_POLICY; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0); CHECK_EQ_INT(e.applies, 1); CHECK_EQ_INT(e.begins, 1);
    sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(invalid_engine_statistics_never_send_or_drop_reports) {
    engine e = {.reports = "[{\"lease_id\":\"duplicate\",\"used_bytes\":0},{\"lease_id\":\"duplicate\",\"used_bytes\":1}]"};
    sb_proxy_bridge b = bridge(&e); remote r = {0}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_err err = {0}; sb_proxy_runtime *runtime = sb_proxy_runtime_new("node-one", &b, exchange_http, &r, &err); REQUIRE(runtime);
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(e.begins, 0); CHECK_EQ_INT(r.received, 0);
    CHECK_EQ_INT(e.acknowledgments, 0); CHECK_EQ_INT(e.stops, 1);
    e.reports = "[{\"lease_id\":\"lease\",\"used_bytes\":9007199254740992}]";
    CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(r.received, 0);
    e.reports = "[]"; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0);
    sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(worker_serializes_requests_and_stops_before_applying_a_late_response) {
    engine e = {0}; sb_proxy_bridge b = bridge(&e); remote r = {.delay_ms = 250}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_err err = {0}; sb_proxy_runtime *runtime = sb_proxy_runtime_new("node-one", &b, exchange_http, &r, &err); REQUIRE(runtime);
    REQUIRE(!sb_proxy_runtime_start(runtime, &err));
    int64_t limit = sb_monotonic_ms() + 3000;
    while (!r.received && sb_monotonic_ms() < limit) usleep(1000);
    REQUIRE(r.received); CHECK(sb_proxy_runtime_step(runtime, &err) < 0); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    int64_t began = sb_monotonic_ms(); sb_proxy_runtime_stop(runtime);
    CHECK(sb_monotonic_ms() - began < 2000); CHECK_EQ_INT(e.applies, 0); CHECK_EQ_INT(e.acknowledgments, 0);
    r.delay_ms = 0; REQUIRE(!sb_proxy_runtime_start(runtime, &err)); limit = sb_monotonic_ms() + 3000;
    while (!e.acknowledgments && sb_monotonic_ms() < limit) usleep(1000);
    sb_proxy_runtime_stop(runtime); CHECK_EQ_INT(e.acknowledgments, 1); CHECK_EQ_INT(e.begins, 1);
    CHECK_EQ_INT(r.requests.len, 2); CHECK_STR(r.requests.items[0], r.requests.items[1]);
    sb_proxy_runtime_free(runtime); remote_free(&r, &fixture); engine_free(&e);
}
TEST(self_worker_uses_real_database_leases_reports_and_clears_capability_on_stop) {
    sb_test_server t; REQUIRE(!sb_test_server_start(&t)); sb_database *db = sb_store_database(t.store);
    engine e = {0}; sb_proxy_bridge b = bridge(&e); sb_err err = {0};
    sb_proxy_runtime *runtime = sb_proxy_runtime_new_self(db, &b, &err); REQUIRE(runtime);
    CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0);
    sbj *body = sbj_parse_cstr("{\"enabled\":true,\"server\":\"node.example\",\"listen\":\"127.0.0.1\",\"listen_port\":8388}");
    sbj *node = sb_proxy_ingress_save(db, "self", body, sb_unix_now(), &err); sbj_free(body); REQUIRE(node); sbj_free(node);
    body = sbj_parse_cstr("{\"name\":\"runtime fixture\",\"enabled\":true,\"quota_bytes\":100,\"expires_at\":0,\"max_devices\":1,\"host_ids\":[\"self\"]}");
    sbj *user = sb_proxy_user_save(db, NULL, body, sb_unix_now(), &err); sbj_free(body); REQUIRE(user);
    char *id = sb_strdup(sbj_get_str(user, "id", "")); sbj_free(user); body = sbj_parse_cstr("{\"name\":\"device\",\"expires_at\":0}");
    sbj *device = sb_proxy_device_create(db, id, body, sb_unix_now(), &err); sbj_free(body); REQUIRE(device); sbj_free(device);
    CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0); sbj *applied = sbj_parse_cstr(e.applied);
    const sbj *lease = sbj_get(sbj_arr_at(sbj_get(applied, "users"), 0), "lease"); REQUIRE(lease);
    char *reports = sb_asprintf("[{\"lease_id\":\"%s\",\"used_bytes\":40}]", sbj_get_str(lease, "id", "")); sbj_free(applied);
    e.reports = reports; CHECK_EQ_INT(sb_proxy_runtime_step(runtime, &err), 0);
    user = sb_proxy_user_get(db, id, &err); REQUIRE(user); CHECK_EQ_INT(sbj_get_int(user, "reported_bytes", -1), 40); sbj_free(user);
    sb_proxy_runtime_stop(runtime); sbj *nodes = sb_proxy_ingress_list(db, &err); REQUIRE(nodes);
    CHECK(!sbj_get_bool(sbj_arr_at(nodes, 0), "runtime_supported", true)); sbj_free(nodes);
    int previous = e.acknowledgments; REQUIRE(!sb_proxy_runtime_start(runtime, &err)); int64_t deadline = sb_monotonic_ms() + 3000;
    while (e.acknowledgments == previous && sb_monotonic_ms() < deadline) usleep(1000);
    CHECK(e.acknowledgments > previous); sb_proxy_runtime_stop(runtime);
    nodes = sb_proxy_ingress_list(db, &err); REQUIRE(nodes); CHECK(!sbj_get_bool(sbj_arr_at(nodes, 0), "runtime_supported", true)); sbj_free(nodes);
    sb_proxy_runtime_free(runtime); free(reports); free(id); engine_free(&e); sb_test_server_stop(&t);
}
TEST(each_runtime_boot_is_fresh_and_external_builds_report_no_gate) {
    engine a = {0}, b = {0}; sb_proxy_bridge ab = bridge(&a), bb = bridge(&b); remote r = {0}; sb_fixture fixture; REQUIRE(remote_start(&r, &fixture));
    sb_proxy_runtime *first = sb_proxy_runtime_new("node-one", &ab, exchange_http, &r, NULL);
    sb_proxy_runtime *second = sb_proxy_runtime_new("node-one", &bb, exchange_http, &r, NULL); REQUIRE(first && second);
    CHECK_EQ_INT(sb_proxy_runtime_step(first, NULL), 0); CHECK_EQ_INT(sb_proxy_runtime_step(second, NULL), 0);
    sbj *one = sbj_parse_cstr(a.begun), *two = sbj_parse_cstr(b.begun);
    CHECK(!sbj_equal(sbj_get(one, "boot_id"), sbj_get(two, "boot_id"))); CHECK_EQ_INT(strlen(sbj_get_str(one, "boot_id", "")), 36);
    sbj_free(one); sbj_free(two); sbj *caps = sb_proxy_runtime_capabilities();
    CHECK_EQ_INT(sbj_arr_len(caps), sb_proxy_runtime_available() ? 1 : 0); sbj_free(caps);
    if (!sb_proxy_runtime_available()) CHECK(!sb_proxy_runtime_new("node-one", NULL, exchange_http, &r, NULL));
    sb_proxy_runtime_free(first); sb_proxy_runtime_free(second); remote_free(&r, &fixture); engine_free(&a); engine_free(&b);
}
