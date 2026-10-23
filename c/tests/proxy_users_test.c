#include "test.h"
#include "http_test_support.h"
#include "sb/proxy_users.h"
#include <stdatomic.h>
#include <spawn.h>
#include <sys/wait.h>

static int64_t test_monotonic(void *context) { return atomic_load((_Atomic int64_t *)context); }

static sbj *object(const char *text) {
    sbj *out = sbj_parse_cstr(text);
    if (!out)
        abort();
    return out;
}
static char *add_host(sb_test_server *t, const char *name) {
    sb_host host, result;
    sb_host_init(&host);
    sb_host_init(&result);
    sb_str_set(&host.name, name);
    host.name_len = strlen(name);
    sb_err err = {0};
    if (sb_store_create_host(t->store, &host, &result, &err)) {
        fprintf(stderr, "host: %s\n", err.msg);
        abort();
    }
    char *id = sb_strdup(result.id);
    sb_host_free(&result);
    sb_host_free(&host);
    return id;
}
static void node(sb_database *db, const char *host) {
    sbj *body = object(
        "{\"enabled\":true,\"server\":\"node.example\",\"listen\":\"127.0.0.1\",\"listen_port\":8388}");
    sb_err err = {0};
    sbj *capabilities = object("[\"proxy_users_v1\"]");
    if (sb_proxy_runtime_report(db, host, capabilities, 1000, &err))
        abort();
    sbj_free(capabilities);
    sbj *out = sb_proxy_ingress_save(db, host, body, 1000, &err);
    if (!out) {
        fprintf(stderr, "ingress: %s\n", err.msg);
        abort();
    }
    sbj_free(out);
    sbj_free(body);
}
static char *create_user(sb_database *db, const char *other, int64_t quota, int limit) {
    sbj *body = object("{\"name\":\"用户\",\"enabled\":true,\"quota_bytes\":0,\"expires_at\":0,\"max_"
                       "devices\":1,\"host_ids\":[\"self\"]}");
    sbj_set_int(body, "quota_bytes", quota);
    sbj_set_int(body, "max_devices", limit);
    if (other)
        sbj_arr_push(sbj_get(body, "host_ids"), sbj_str(other));
    sb_err err = {0};
    sbj *out = sb_proxy_user_save(db, NULL, body, 1000, &err);
    if (!out) {
        fprintf(stderr, "user: %s\n", err.msg);
        abort();
    }
    char *id = sb_strdup(sbj_get_str(out, "id", ""));
    sbj_free(out);
    sbj_free(body);
    return id;
}
static sbj *device(sb_database *db, const char *id) {
    sbj *body = object("{\"name\":\"phone\"}");
    sb_err err = {0};
    sbj *out = sb_proxy_device_create(db, id, body, 1000, &err);
    sbj_free(body);
    if (!out) {
        fprintf(stderr, "device: %s\n", err.msg);
        abort();
    }
    return out;
}
static sbj *request(const char *boot, int64_t seq, const char *lease, int64_t used) {
    sbj *out = sbj_object();
    sbj_set_int(out, "version", 1);
    sbj_set_str(out, "boot_id", boot);
    sbj_set_int(out, "request_seq", seq);
    sbj *reports = sbj_array();
    sbj_set(out, "reports", reports);
    if (lease) {
        sbj *r = sbj_object();
        sbj_set_str(r, "lease_id", lease);
        sbj_set_int(r, "used_bytes", used);
        sbj_arr_push(reports, r);
    }
    return out;
}
typedef struct {
    sb_database *db;
    const char *host;
    sbj *request;
    sbj *response;
    pthread_barrier_t *barrier;
    sb_err error;
} exchange_task;
static void *exchange_thread(void *arg) {
    exchange_task *t = arg;
    pthread_barrier_wait(t->barrier);
    t->response = sb_proxy_lease_exchange(t->db, t->host, t->request, 1000, &t->error);
    return NULL;
}
TEST(multinode_atomic_budget_retry_restart_and_reset) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store);
    _Atomic int64_t monotonic = 0;
    sb_err clock_error = {0};
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &clock_error) == 0);
    char *other = add_host(&t, "second");
    node(db, "self");
    node(db, other);
    char *id = create_user(db, other, 100, 3);
    sbj *d = device(db, id);
    sbj_free(d);
    sb_err err = {0};
    sb_database *second = sb_database_open(t.env.db_path, &err);
    REQUIRE(second);
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, 2);
    exchange_task a = {db, "self", request("boot-a", 1, NULL, 0), NULL, &barrier, {0}},
                  b = {second, other, request("boot-b", 1, NULL, 0), NULL, &barrier, {0}};
    pthread_t ta, tb;
    REQUIRE(pthread_create(&ta, NULL, exchange_thread, &a) == 0);
    REQUIRE(pthread_create(&tb, NULL, exchange_thread, &b) == 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    pthread_barrier_destroy(&barrier);
    REQUIRE(a.response);
    REQUIRE(b.response);
    const sbj *la = sbj_get(sbj_arr_at(sbj_get(a.response, "users"), 0), "lease"),
              *lb = sbj_get(sbj_arr_at(sbj_get(b.response, "users"), 0), "lease");
    REQUIRE(la);
    REQUIRE(lb);
    int64_t ga = sbj_get_int(la, "grant_bytes", 0), gb = sbj_get_int(lb, "grant_bytes", 0);
    CHECK(ga > 0 && gb > 0 && ga + gb <= 100);
    char *lease = sb_strdup(sbj_get_str(la, "id", ""));
    sbj *replay = sb_proxy_lease_exchange(db, "self", a.request, 1005, &err);
    REQUIRE(replay);
    CHECK(sbj_equal(replay, a.response));
    CHECK_EQ_INT(sbj_get_int(replay, "expires_at", 0), 1060);
    sbj_free(replay);
    sbj *r = request("boot-a", 1, lease, 1);
    CHECK(sb_proxy_lease_exchange(db, "self", r, 1005, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(r);
    r = request("boot-a", 2, lease, 0);
    sbj *out = sb_proxy_lease_exchange(db, "self", r, 1010, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(sbj_get(sbj_arr_at(sbj_get(out, "users"), 0), "lease"), "grant_bytes", 0), ga);
    sbj_free(out);
    sbj_free(r);
    r = request("boot-a", 3, lease, ga);
    out = sb_proxy_lease_exchange(db, "self", r, 1020, &err);
    REQUIRE(out);
    sbj_free(out);
    sbj_free(r);
    r = request("boot-a", 4, lease, ga - 1);
    CHECK(sb_proxy_lease_exchange(db, "self", r, 1021, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(r);
    r = request("boot-b", 2, lease, ga);
    CHECK(sb_proxy_lease_exchange(second, other, r, 1021, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(r);
    r = request("boot-restarted", 1, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, 1025, &err);
    REQUIRE(out);
    sbj_free(out);
    sbj_free(r);
    out = sb_proxy_user_get(db, id, &err);
    REQUIRE(out);
    CHECK(sbj_get_int(out, "allocated_bytes", 0) <= 100);
    CHECK_EQ_INT(sbj_get_int(out, "reported_bytes", 0), ga);
    sbj_free(out);
    atomic_store(&monotonic, 30000);
    out = sb_proxy_user_reset(db, id, 1030, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "epoch", 0), 2);
    int64_t ready = sbj_get_int(out, "not_before", 0);
    CHECK(ready >= 1080);
    sbj_free(out);
    atomic_store(&monotonic, 89999);
    r = request("boot-reset", 1, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, ready - 1, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0);
    sbj_free(out);
    sbj_free(r);
    atomic_store(&monotonic, 90000);
    r = request("boot-reset", 2, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, ready, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(sbj_get(out, "users"), 0), "epoch", 0), 2);
    sbj_free(out);
    sbj_free(r);
    sbj_free(a.request);
    sbj_free(b.request);
    sbj_free(a.response);
    sbj_free(b.response);
    free(lease);
    sb_database_free(second);
    free(id);
    free(other);
    sb_test_server_stop(&t);
}
TEST(credentials_limits_revocation_expiry_and_private_inventory) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store);
    node(db, "self");
    char *id = create_user(db, NULL, 1000, 1);
    sbj *d = device(db, id);
    sb_err err = {0};
    char *token = sb_strdup(sbj_get_str(d, "subscription_token", "")),
         *did = sb_strdup(sbj_get_str(d, "id", ""));
    sbj_free(d);
    sbj *body = object("{\"name\":\"duplicate\"}");
    CHECK(sb_proxy_device_create(db, id, body, 1000, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(body);
    sbj *out = sb_proxy_subscription(db, token, 1000, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "outbounds")), 1);
    const sbj *outbound = sbj_arr_at(sbj_get(out, "outbounds"), 0);
    CHECK_STR(sbj_get_str(outbound, "method", ""), "2022-blake3-aes-128-gcm");
    CHECK(strchr(sbj_get_str(outbound, "password", ""), ':'));
    sbj_free(out);
    out = sb_proxy_user_get(db, id, &err);
    REQUIRE(out);
    char *public_json = sbj_dump(out, -1);
    CHECK(strstr(public_json, "password") == NULL);
    CHECK(strstr(public_json, "token") == NULL);
    free(public_json);
    sbj_free(out);
    out = sb_proxy_claim_rotate(db, id, 1000, &err);
    REQUIRE(out);
    char *claim = sb_strdup(sbj_get_str(out, "claim_token", ""));
    sbj_free(out);
    char *resolved = sb_proxy_claim_resolve(db, claim, 1000, &err);
    REQUIRE(resolved);
    CHECK_STR(resolved, id);
    free(resolved);
    out = sb_proxy_claim_rotate(db, id, 1001, &err);
    REQUIRE(out);
    CHECK(sb_proxy_claim_resolve(db, claim, 1001, &err) == NULL);
    sbj_free(out);
    free(claim);
    CHECK_EQ_INT(sb_proxy_device_revoke(db, "another-user", did, 1001, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_NOT_FOUND);
    CHECK_EQ_INT(sb_proxy_device_revoke(db, id, did, 1001, &err), 0);
    CHECK(sb_proxy_subscription(db, token, 1001, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_AUTH);
    d = device(db, id);
    sbj_free(d);
    sbj *r = request("boot", 1, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, 1002, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(sbj_arr_at(sbj_get(out, "users"), 0), "devices")), 1);
    sbj_free(out);
    sbj_free(r);
    body = object("{\"name\":\"expires\",\"enabled\":true,\"quota_bytes\":1000,\"expires_at\":1010,\"max_"
                  "devices\":1,\"host_ids\":[\"self\"]}");
    out = sb_proxy_user_save(db, id, body, 1003, &err);
    REQUIRE(out);
    sbj_free(out);
    sbj_free(body);
    r = request("boot", 2, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, 1005, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(sbj_get(sbj_arr_at(sbj_get(out, "users"), 0), "lease"), "expires_at", 0), 1010);
    sbj_free(out);
    sbj_free(r);
    r = request("boot", 3, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", r, 1010, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0);
    sbj_free(out);
    sbj_free(r);
    free(id);
    free(token);
    free(did);
    sb_test_server_stop(&t);
}
TEST(http_auth_scope_strict_json_and_self_service) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store);
    node(db, "self");
    char *id = create_user(db, NULL, 0, 2);
    sb_err err = {0};
    sbj *out = sb_proxy_claim_rotate(db, id, 1000, &err);
    REQUIRE(out);
    char *claim = sb_strdup(sbj_get_str(out, "claim_token", ""));
    sbj_free(out);
    char *viewer = sb_test_token(&t, "ignored", "proxy-viewer", "viewer");
    sb_test_response r = {0};
    sb_test_request_ex(&t, "POST", "/api/agent/status", "{\"capabilities\":[\"proxy_users_v1\"]}",
                       "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/proxy-users", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/proxy-users", NULL, viewer, NULL, &r);
    CHECK_EQ_INT(r.status, 403);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/proxy-self/status", "{}", claim, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(sbj_get_str(r.json, "id", ""), id);
    CHECK_STR(r.cache_control, "no-store");
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/proxy-self/devices", "{\"name\":\"one\",\"name\":\"two\"}", claim,
                       NULL, &r);
    CHECK_EQ_INT(r.status, 400);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/proxy-self/devices", "{\"name\":\"mobile\"}", claim, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    char *sub =
        sb_asprintf("/api/proxy-self/subscription?token=%s", sbj_get_str(r.json, "subscription_token", ""));
    char *device_id = sb_strdup(sbj_get_str(r.json, "id", ""));
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", sub, NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.cache_control, "no-store");
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/agent/proxy-leases",
                       "{\"version\":1,\"boot_id\":\"http-boot\",\"request_seq\":1,\"reports\":[]}", claim,
                       NULL, &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/agent/proxy-leases",
                       "{\"version\":1,\"boot_id\":\"http-boot\",\"request_seq\":1,\"reports\":[]}",
                       "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(sbj_get_str(r.json, "host_id", ""), "self");
    sb_test_response_free(&r);
    char *path = sb_asprintf("/api/proxy-self/devices/%s", device_id);
    sb_test_request_ex(&t, "DELETE", path, NULL, claim, NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", sub, NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);
    free(path);
    free(sub);
    free(device_id);
    free(id);
    free(claim);
    free(viewer);
    sb_test_server_stop(&t);
}
TEST(runtime_capability_requires_authenticated_fresh_report) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store);
    sb_err err = {0};
    int64_t now = sb_unix_now();
    CHECK_EQ_INT(
        sb_database_execute(
            db,
            "UPDATE hosts SET capabilities='{\"runs_singbox\":true,\"proxy_users_v1\":true}' WHERE id='self'",
            &err),
        0);
    sbj *body = object(
        "{\"enabled\":true,\"server\":\"node.example\",\"listen\":\"127.0.0.1\",\"listen_port\":8388}");
    CHECK(sb_proxy_ingress_save(db, "self", body, now, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sb_test_response r = {0};
    sb_test_request_ex(&t, "POST", "/api/agent/status", "{\"capabilities\":[\"proxy_users_v1\"]}", NULL, NULL,
                       &r);
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "POST", "/api/agent/status", "{\"capabilities\":[\"proxy_users_v1\"]}",
                       "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    now = sb_unix_now();
    sbj *out = sb_proxy_ingress_save(db, "self", body, now, &err);
    REQUIRE(out);
    CHECK(sbj_get_bool(out, "runtime_supported", false));
    sbj_free(out);
    char *id = create_user(db, NULL, 1000, 2);
    sbj *d = device(db, id);
    char *token = sb_strdup(sbj_get_str(d, "subscription_token", ""));
    sbj_free(d);
    out = sb_proxy_subscription(db, token, now, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "outbounds")), 1);
    sbj_free(out);
    out = sb_proxy_subscription(db, token, now + 181, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "outbounds")), 0);
    sbj_free(out);
    sbj *req = request("stale-runtime", 1, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", req, now + 181, &err);
    REQUIRE(out);
    CHECK(sbj_is_null(sbj_get(out, "node")));
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0);
    sbj_free(out);
    sbj_free(req);
    sb_test_request_ex(&t, "POST", "/api/agent/status", "{}", "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    CHECK(sb_proxy_ingress_save(db, "self", body, sb_unix_now(), &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(body);
    free(token);
    free(id);
    sb_test_server_stop(&t);
}

typedef struct {
    sb_database *database;
    const char *user;
    pthread_barrier_t *barrier;
    sbj *result;
    sb_err error;
} device_task;
static void *device_thread(void *argument) {
    device_task *task = argument;
    sbj *body = object("{\"name\":\"concurrent\"}");
    pthread_barrier_wait(task->barrier);
    task->result = sb_proxy_device_create(task->database, task->user, body, 1010, &task->error);
    sbj_free(body);
    return NULL;
}
TEST(independent_device_expiry_and_atomic_credential_limit) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store);
    node(db, "self");
    char *id = create_user(db, NULL, 1000, 1);
    sb_err err = {0};
    sbj *body = object("{\"name\":\"temporary\",\"expires_at\":1010}");
    sbj *d = sb_proxy_device_create(db, id, body, 1000, &err);
    REQUIRE(d);
    char *token = sb_strdup(sbj_get_str(d, "subscription_token", ""));
    sbj_free(d);
    CHECK(sb_proxy_device_create(db, id, body, 1001, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj *req = request("device-expiry", 1, NULL, 0),
        *out = sb_proxy_lease_exchange(db, "self", req, 1005, &err);
    REQUIRE(out);
    const sbj *u = sbj_arr_at(sbj_get(out, "users"), 0);
    REQUIRE(u);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(sbj_get(u, "devices"), 0), "expires_at", 0), 1010);
    CHECK_EQ_INT(sbj_get_int(sbj_get(u, "lease"), "expires_at", 0), 1065);
    sbj_free(out);
    sbj_free(req);
    CHECK(sb_proxy_subscription(db, token, 1010, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_AUTH);
    req = request("device-expiry", 2, NULL, 0);
    out = sb_proxy_lease_exchange(db, "self", req, 1010, &err);
    REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0);
    sbj_free(out);
    sbj_free(req);
    CHECK(sb_proxy_device_create(db, id, body, 1010, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    sbj_free(body);
    sb_database *other = sb_database_open(t.env.db_path, &err);
    REQUIRE(other);
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, 2);
    device_task a = {db, id, &barrier, NULL, {0}}, b = {other, id, &barrier, NULL, {0}};
    pthread_t ta, tb;
    REQUIRE(pthread_create(&ta, NULL, device_thread, &a) == 0);
    REQUIRE(pthread_create(&tb, NULL, device_thread, &b) == 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    pthread_barrier_destroy(&barrier);
    CHECK((a.result != NULL) != (b.result != NULL));
    CHECK_EQ_INT(a.result ? b.error.code : a.error.code, SB_ERR_CONFLICT);
    sbj_free(a.result);
    sbj_free(b.result);
    sb_database_free(other);
    free(token);
    free(id);
    sb_test_server_stop(&t);
}


static void refresh_capability(sb_database *db, int64_t now) {
    sb_err error = {0}; sbj *caps = object("[\"proxy_users_v1\"]");
    if (sb_proxy_runtime_report(db, "self", caps, now, &error)) abort();
    sbj_free(caps);
}
static sbj *clock_exchange(sb_database *db, const char *boot, int64_t sequence, int64_t wall) {
    refresh_capability(db, wall);
    sb_err error = {0}; sbj *req = request(boot, sequence, NULL, 0);
    sbj *out = sb_proxy_lease_exchange(db, "self", req, wall, &error); sbj_free(req);
    if (!out) fprintf(stderr, "clock lease exchange: %s\n", error.msg);
    return out;
}
TEST(clock_forward_jump_does_not_bypass_reset_and_connections_share_fence) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store); sb_err error = {0}; _Atomic int64_t monotonic = 10000;
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &error) == 0);
    node(db, "self"); char *id = create_user(db, NULL, 1000, 1); sbj_free(device(db, id));
    sbj *out = clock_exchange(db, "clock-forward", 1, 1000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1); sbj_free(out);
    sb_database *second = sb_database_open(t.env.db_path, &error); REQUIRE(second);
    CHECK(sb_database_proxy_clock(db) == sb_database_proxy_clock(second));
    out = sb_proxy_user_reset(db, id, 1000000, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 60); sbj_free(out);
    CHECK(sb_proxy_clock_set_source(second, test_monotonic, &monotonic, &error) != 0);
    out = clock_exchange(second, "clock-second", 1, 2000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    out = sb_proxy_user_get(second, id, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 60); sbj_free(out);
    atomic_store(&monotonic, 69999);
    out = clock_exchange(db, "clock-forward", 2, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    atomic_store(&monotonic, 70000);
    out = clock_exchange(second, "clock-second", 2, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(sbj_get(out, "users"), 0), "epoch", 0), 2); sbj_free(out);
    sb_database_free(second); free(id); sb_test_server_stop(&t);
}

TEST(clock_failure_and_backward_monotonic_values_keep_grants_closed) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store); sb_err error = {0}; _Atomic int64_t monotonic = 1000;
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &error) == 0);
    node(db, "self"); char *id = create_user(db, NULL, 1000, 1); sbj_free(device(db, id));
    sbj *out = clock_exchange(db, "clock-failure", 1, 1000); REQUIRE(out); sbj_free(out);
    atomic_store(&monotonic, -1);
    out = sb_proxy_user_reset(db, id, 1000000, &error); REQUIRE(out); sbj_free(out);
    out = clock_exchange(db, "clock-failure", 2, 2000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    /* A reset made while the clock failed starts its full wait when a valid
     * source returns. A later backward reading cannot open the grant gate. */
    atomic_store(&monotonic, 1000);
    out = clock_exchange(db, "clock-failure", 3, 2000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    atomic_store(&monotonic, 50000);
    out = sb_proxy_user_get(db, id, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 11); sbj_free(out);
    atomic_store(&monotonic, 49999);
    out = clock_exchange(db, "clock-failure", 4, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    out = sb_proxy_user_get(db, id, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 60); sbj_free(out);
    atomic_store(&monotonic, 61000);
    out = clock_exchange(db, "clock-failure", 5, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1); sbj_free(out);
    free(id); sb_test_server_stop(&t);
}

/* Spawned by the parent regression with a separate process clock/registry. */
TEST(clock_external_reset_child) {
    const char *path = getenv("SB_PROXY_CLOCK_CHILD_DB"), *id = getenv("SB_PROXY_CLOCK_CHILD_USER");
    if (!path || !id) return;
    sb_err error = {0}; sb_database *db = sb_database_open(path, &error); REQUIRE(db);
    sbj *out = sb_proxy_user_reset(db, id, 1000000, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "epoch", 0), 2); sbj_free(out); sb_database_free(db);
}
static int reset_in_another_process(const char *path, const char *user) {
    extern char **environ;
    size_t count = 0; while (environ[count]) ++count;
    char **environment = sb_xcalloc(count + 3, sizeof(*environment));
    for (size_t i = 0; i < count; ++i) environment[i] = environ[i];
    environment[count] = sb_asprintf("SB_PROXY_CLOCK_CHILD_DB=%s", path);
    environment[count + 1] = sb_asprintf("SB_PROXY_CLOCK_CHILD_USER=%s", user);
    char *arguments[] = {"proxy_users_test", "clock_external_reset_child", NULL};
    pid_t process; int rc = posix_spawn(&process, "/proc/self/exe", NULL, NULL, arguments, environment);
    if (!rc) { int status = 0; rc = waitpid(process, &status, 0) == process && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1; }
    free(environment[count]); free(environment[count + 1]); free(environment); return rc;
}
TEST(clock_other_process_epoch_observation_and_backward_generation_are_fenced) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store); sb_err error = {0}; _Atomic int64_t monotonic = 0;
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &error) == 0);
    node(db, "self"); char *id = create_user(db, NULL, 1000, 1); sbj_free(device(db, id));
    sbj *out = clock_exchange(db, "clock-observer", 1, 1000); REQUIRE(out); sbj_free(out);
    REQUIRE(reset_in_another_process(t.env.db_path, id) == 0);
    atomic_store(&monotonic, 500000);
    out = clock_exchange(db, "clock-observer", 2, 2000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    atomic_store(&monotonic, 559999);
    out = clock_exchange(db, "clock-observer", 3, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    atomic_store(&monotonic, 560000);
    out = clock_exchange(db, "clock-observer", 4, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1); sbj_free(out);
    /* A persisted generation rollback is a new observation, not permission to
     * reuse an earlier process deadline. No real production database is used. */
    char *sql = sb_asprintf("UPDATE proxy_users SET epoch=1,not_before=0 WHERE id='%s'", id);
    REQUIRE(sb_database_execute(db, sql, &error) == 0); free(sql);
    out = clock_exchange(db, "clock-observer", 5, 4000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    out = sb_proxy_user_get(db, id, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 60); sbj_free(out);
    free(id); sb_test_server_stop(&t);
}
TEST(clock_database_reopen_fences_persisted_leases_and_memory_connections_are_distinct) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sb_database *db = sb_store_database(t.store); sb_err error = {0}; _Atomic int64_t monotonic = 0;
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &error) == 0);
    node(db, "self"); char *id = create_user(db, NULL, 1000, 1); sbj_free(device(db, id));
    sbj *out = clock_exchange(db, "clock-before-restart", 1, 1000); REQUIRE(out); sbj_free(out);
    sb_http_server_stop(t.server); sb_http_server_free(t.server); t.server = NULL;
    sb_store_free(t.store); t.store = NULL; /* Last reference releases the process clock state. */
    atomic_store(&monotonic, 10000000);
    db = sb_database_open(t.env.db_path, &error); REQUIRE(db);
    REQUIRE(sb_proxy_clock_set_source(db, test_monotonic, &monotonic, &error) == 0);
    out = clock_exchange(db, "clock-after-restart", 1, 2000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    out = sb_proxy_user_get(db, id, &error); REQUIRE(out);
    CHECK_EQ_INT(sbj_get_int(out, "lease_wait_seconds", 0), 60); sbj_free(out);
    atomic_store(&monotonic, 10059999);
    out = clock_exchange(db, "clock-after-restart", 2, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 0); sbj_free(out);
    atomic_store(&monotonic, 10060000);
    /* Existing grants are still conservatively reserved, so reuse the earlier
     * boot to verify renewal resumes after the startup fence. */
    out = clock_exchange(db, "clock-before-restart", 2, 3000000); REQUIRE(out);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(out, "users")), 1); sbj_free(out);
    sb_database_free(db);
    sb_database *memory_a = sb_database_open(":memory:", &error), *memory_b = sb_database_open(":memory:", &error);
    REQUIRE(memory_a && memory_b); CHECK(sb_database_proxy_clock(memory_a) != sb_database_proxy_clock(memory_b));
    REQUIRE(sb_proxy_clock_set_source(memory_a, test_monotonic, &monotonic, &error) == 0);
    REQUIRE(sb_proxy_clock_set_source(memory_b, test_monotonic, &monotonic, &error) == 0);
    sb_database_free(memory_a); sb_database_free(memory_b);
    free(id); sb_test_server_stop(&t);
}
