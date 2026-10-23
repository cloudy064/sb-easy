#include "test.h"
#include "http_test_support.h"
#include "sb/observability.h"
#include "../src/http_internal.h"
#include <sqlite3.h>

static sb_host new_host(sb_test_server *t, const char *name) {
    sb_host input, host; sb_host_init(&input); sb_host_init(&host);
    sb_str_set(&input.name, name); input.name_len = strlen(name);
    CHECK_EQ_INT(sb_store_create_host(t->store, &input, &host, NULL), 0); sb_host_free(&input); return host;
}
static sbj *sample(int64_t up, int64_t down) {
    sbj *out = sbj_object(); sbj_set_int(out, "up", 10); sbj_set_int(out, "down", 20);
    sbj_set_int(out, "up_total", up); sbj_set_int(out, "down_total", down); sbj_set_int(out, "conn_count", 3); return out;
}
static const sbj *find_host_row(const sbj *list, const char *id) {
    for (size_t i = 0; i < sbj_arr_len(list); ++i) if (sb_streq(sbj_get_str(sbj_arr_at(list, i), "host_id", ""), id)) return sbj_arr_at(list, i);
    return NULL;
}
static int count_kind(const sbj *list, const char *kind) {
    int count = 0;
    for (size_t i = 0; i < sbj_arr_len(list); ++i) if (sb_streq(sbj_get_str(sbj_arr_at(list, i), "kind", ""), kind)) ++count;
    return count;
}
TEST(sample_baseline_counter_resets_gaps_and_retention) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_database *db = sb_store_database(t.store);
    sb_observability_stop(t.server->observability);
    sb_host host = new_host(&t, "History"); int64_t now = sb_unix_now() / 60 * 60; sb_err err = {0};
    sbj *v = sample(1000, 2000); REQUIRE(sb_observability_sample(db, host.id, v, now, &err) == 0); sbj_free(v);
    v = sample(1100, 2200); REQUIRE(sb_observability_sample(db, host.id, v, now + 10, &err) == 0); sbj_free(v);
    v = sample(10, 20); REQUIRE(sb_observability_sample(db, host.id, v, now + 120, &err) == 0); sbj_free(v);
    v = sample(9999, 9999); REQUIRE(sb_observability_sample(db, host.id, v, now + 100, &err) == 0); sbj_free(v);
    v = sample(-1, 20); CHECK(sb_observability_sample(db, host.id, v, now + 130, &err) != 0); sbj_free(v);
    sbj *rows = sb_observability_history(db, host.id, now, now + 180, 60, &err); REQUIRE(rows);
    CHECK_EQ_INT(sbj_arr_len(rows), 2); /* No invented zero-traffic row for the missing minute. */
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(rows, 0), "samples", 0), 2);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(rows, 0), "up_bytes", 0), 100);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(rows, 1), "up_bytes", 0), 10);
    CHECK_EQ_INT(sbj_get_int(sbj_arr_at(rows, 1), "counter_resets", 0), 1); sbj_free(rows);
    rows = sb_observability_hosts(db, now + 121, &err); REQUIRE(rows); const sbj *found = find_host_row(rows, host.id); REQUIRE(found);
    CHECK_EQ_INT(sbj_get_int(found, "observed_up", 0), 110); CHECK_EQ_INT(sbj_get_int(found, "observed_down", 0), 220); sbj_free(rows);
    CHECK(sb_observability_history(db, host.id, now - 86400 * 31, now, 60, &err) == NULL);
    REQUIRE(sb_observability_evaluate(db, now + 31LL * 86400, &err) == 0);
    rows = sb_observability_history(db, host.id, now, now + 180, 60, &err); REQUIRE(rows); CHECK_EQ_INT(sbj_arr_len(rows), 0); sbj_free(rows);
    sb_host_free(&host); sb_test_server_stop(&t);
}
TEST(alert_transitions_config_success_acknowledgement_and_recurrence) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_database *db = sb_store_database(t.store);
    sb_observability_stop(t.server->observability);
    sb_host host = new_host(&t, "Status"); int64_t now = sb_unix_now(); sb_err err = {0};
    sbj *state = sbj_parse_cstr("{\"running\":true,\"etag\":\"old\",\"last_error\":\"\",\"app_version\":\"1.2.3\",\"version\":\"1.14.3\"}");
    REQUIRE(sb_store_update_agent_status(t.store, host.id, state, &err) == 0);
    REQUIRE(sb_observability_status(db, host.id, state, now, &err) == 0);
    REQUIRE(sb_observability_target(db, host.id, "new", now, &err) == 0);
    REQUIRE(sb_observability_target(db, host.id, "new", now + 200, &err) == 0); /* polling must not reset drift age */
    REQUIRE(sb_observability_evaluate(db, now + 301, &err) == 0);
    sbj *alerts = sb_observability_alerts(db, host.id, true, &err); REQUIRE(alerts);
    CHECK_EQ_INT(count_kind(alerts, "device_offline"), 1); CHECK_EQ_INT(count_kind(alerts, "config_drift"), 1);
    int64_t id = sbj_get_int(sbj_arr_at(alerts, 0), "id", 0); sbj_free(alerts);
    sb_user_account admin; sb_user_account_init(&admin); REQUIRE(sb_store_find_user_by_username(t.store, "admin", &admin, &err) == 1);
    REQUIRE(sb_observability_ack(db, id, admin.id, &err) == 0); sb_user_account_free(&admin);
    REQUIRE(sb_observability_evaluate(db, now + 302, &err) == 0);
    alerts = sb_observability_alerts(db, host.id, true, &err); REQUIRE(alerts); CHECK_EQ_INT(sbj_arr_len(alerts), 2); sbj_free(alerts);
    sbj_set_str(state, "etag", "new"); REQUIRE(sb_store_update_agent_status(t.store, host.id, state, &err) == 0);
    REQUIRE(sb_observability_status(db, host.id, state, now + 303, &err) == 0);
    REQUIRE(sb_observability_evaluate(db, now + 304, &err) == 0);
    alerts = sb_observability_alerts(db, host.id, true, &err); REQUIRE(alerts); CHECK_EQ_INT(sbj_arr_len(alerts), 0); sbj_free(alerts);
    sbj_set_str(state, "last_error", "config failed"); sbj_set_str(state, "etag", "bad");
    REQUIRE(sb_store_update_agent_status(t.store, host.id, state, &err) == 0);
    REQUIRE(sb_observability_status(db, host.id, state, now + 305, &err) == 0);
    REQUIRE(sb_observability_evaluate(db, now + 306, &err) == 0);
    sbj *rows = sb_observability_hosts(db, now + 306, &err); REQUIRE(rows);
    CHECK_STR(sbj_get_str(find_host_row(rows, host.id), "applied_etag", ""), "new"); sbj_free(rows);
    alerts = sb_observability_alerts(db, host.id, true, &err); REQUIRE(alerts); CHECK_EQ_INT(count_kind(alerts, "config_failure"), 1); sbj_free(alerts);
    REQUIRE(sb_observability_evaluate(db, now + 600, &err) == 0);
    alerts = sb_observability_alerts(db, host.id, false, &err); REQUIRE(alerts); CHECK_EQ_INT(count_kind(alerts, "device_offline"), 2); sbj_free(alerts);
    sbj_free(state); sb_host_free(&host); sb_test_server_stop(&t);
}
TEST(http_scoped_history_and_revocable_read_only_metrics) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_database *db = sb_store_database(t.store);
    sb_host host = new_host(&t, "HTTP history"); sbj *v = sample(20, 30);
    REQUIRE(sb_observability_sample(db, host.id, v, sb_unix_now(), NULL) == 0); sbj_free(v);
    sb_test_response r = {0}; sb_test_request_ex(&t, "POST", "/api/observability/token", "{}", NULL, NULL, &r);
    CHECK_EQ_INT(r.status, 200); char *token = sb_strdup(sbj_get_str(r.json, "token", "")); REQUIRE(*token); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/metrics", NULL, "", NULL, &r); CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/metrics", NULL, token, NULL, &r); CHECK_EQ_INT(r.status, 200);
    CHECK_CONTAINS(r.body, "# TYPE sb_easy_traffic_observed_bytes_total counter"); CHECK_CONTAINS(r.body, host.id);
    CHECK(!strstr(r.body, host.agent_token)); CHECK_STR(r.cache_control, "no-store"); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/hosts", NULL, token, NULL, &r); CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    char *viewer = sb_test_token(&t, "ignored", "history-viewer", "viewer"); REQUIRE(viewer);
    char *path = sb_asprintf("/api/hosts/%s/history", host.id);
    sb_test_request_ex(&t, "GET", path, NULL, viewer, NULL, &r); CHECK_EQ_INT(r.status, 200); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/observability", NULL, viewer, NULL, &r); CHECK_EQ_INT(r.status, 403); sb_test_response_free(&r);
    sb_user_account user; sb_user_account_init(&user); REQUIRE(sb_store_find_user_by_username(t.store, "history-viewer", &user, NULL) == 1);
    sb_auth_security *security = sb_auth_security_new(db, t.jwt_secret, false, NULL); sbj *scope = sbj_parse_cstr("{\"scope\":\"groups\",\"grants\":[]}");
    REQUIRE(sb_auth_user_scope_set(security, user.id, scope, NULL) == 0); sbj_free(scope); sb_auth_security_free(security); sb_user_account_free(&user);
    sb_test_request_ex(&t, "GET", path, NULL, viewer, NULL, &r); CHECK_EQ_INT(r.status, 403); sb_test_response_free(&r);
    sb_test_request_ex(&t, "DELETE", "/api/observability/token", NULL, NULL, NULL, &r); CHECK_EQ_INT(r.status, 200); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/metrics", NULL, token, NULL, &r); CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    free(path); free(viewer); free(token); sb_host_free(&host); sb_test_server_stop(&t);
}
TEST(background_evaluation_node_failure_staleness_and_restart_persistence) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_observability_stop(t.server->observability);
    sb_database *db = sb_store_database(t.store); sb_err err = {0}; int64_t now = sb_unix_now();
    sb_host host = new_host(&t, "Lost reporter");
    sbj *state = sbj_parse_cstr("{\"running\":true,\"etag\":\"good\"}");
    REQUIRE(sb_observability_status(db, host.id, state, now - 400, &err) == 0); sbj_free(state);
    sb_proxy_record input, node; sb_proxy_record_init(&input); sb_proxy_record_init(&node);
    sb_str_set(&input.tag, "Probe node"); input.tag_len = strlen(input.tag);
    sb_str_set(&input.node_type, "trojan"); input.node_type_len = 6;
    sb_str_set(&input.server, "node.example"); input.server_len = strlen(input.server); input.server_port = 443;
    sbj_set_str(input.protocol_config, "password", "private-node-password");
    REQUIRE(sb_store_create_proxy_node(t.store, &input, &node, &err) == 0); sb_proxy_record_free(&input);
    sbj *latencies = sbj_object(); sbj_set_null(latencies, node.tag); size_t updated = 0;
    REQUIRE(sb_store_update_proxy_latencies(t.store, latencies, &updated, &err) == 0); sbj_free(latencies);
    sb_observability *worker = sb_observability_new(db); REQUIRE(sb_observability_start(worker, &err) == 0);
    bool seen = false;
    for (int i = 0; i < 100 && !seen; ++i) {
        sbj *events = sb_observability_alerts(db, NULL, true, &err);
        seen = count_kind(events, "device_offline") == 1 && count_kind(events, "node_unreachable") == 1;
        sbj_free(events); if (!seen) usleep(10000);
    }
    CHECK(seen); sb_observability_free(worker);
    REQUIRE(sb_observability_evaluate(db, now + 3700, &err) == 0);
    sbj *events = sb_observability_alerts(db, NULL, true, &err); REQUIRE(events);
    CHECK_EQ_INT(count_kind(events, "node_unreachable"), 0); CHECK_EQ_INT(count_kind(events, "node_probe_stale"), 1); sbj_free(events);
    sb_database *reopened = sb_database_open(t.env.db_path, &err); REQUIRE(reopened);
    events = sb_observability_alerts(reopened, NULL, false, &err); REQUIRE(events);
    CHECK_EQ_INT(count_kind(events, "node_unreachable"), 1); CHECK_EQ_INT(count_kind(events, "node_probe_stale"), 1);
    sbj_free(events); sb_database_free(reopened); sb_proxy_record_free(&node); sb_host_free(&host); sb_test_server_stop(&t);
}
