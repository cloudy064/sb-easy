#include "test.h"
#include "http_test_support.h"
#include "sb/subscription_service.h"
#include "sb/proxy_parser.h"
#include <stdatomic.h>

static char *source_response(const sb_fixture_request *request, void *user) {
    atomic_int *mode = user;
    if (strcmp(request->target, "/redirect") == 0)
        return sb_strdup("HTTP/1.1 302 Found\r\nLocation: /source\r\nSubscription-Userinfo: total=999999\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if (atomic_load(mode) == 2) return sb_fixture_response(503, "text/plain", "private provider error");
    const char *body = atomic_load(mode) == 1 ? "trojan://secret@rotated.example:443#Shared\n"
                         : "trojan://secret@first.example:443#Shared\nunsupported://secret-token\n";
    return sb_asprintf("HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nSubscription-Userinfo: upload=10; download=20; total=100; expire=1900000000\r\nConnection: close\r\n\r\n%s", strlen(body), body);
}

static int make_source(sb_store *store, const char *name, const char *url, sb_subscription *out) {
    sb_subscription input;
    sb_subscription_init(&input);
    sb_str_set(&input.name, name); input.name_len = strlen(name);
    sb_str_set(&input.url, url); input.url_len = strlen(url);
    input.refresh_interval = 120;
    sb_err err = {0};
    int rc = sb_store_create_subscription(store, &input, out, &err);
    sb_subscription_free(&input);
    return rc;
}

TEST(usage_header_validation_and_import_diagnostics_do_not_expose_credentials) {
    sbj *usage = sb_subscription_parse_usage("upload=10;download=-1;total=999999999999999999999;expire=42;upload=11");
    CHECK(!sbj_has(usage, "upload")); CHECK(!sbj_has(usage, "download")); CHECK(!sbj_has(usage, "total"));
    CHECK_EQ_INT(sbj_get_int(usage, "expire", -1), 42); sbj_free(usage);
    const char *json = "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"},{\"type\":\"trojan\",\"tag\":\"node\",\"server\":\"example.com\",\"server_port\":443,\"password\":\"secret\"},{\"type\":\"unsupported\",\"password\":\"sensitive\"}]}";
    sb_proxy_import parsed; sb_err err = {0};
    REQUIRE(sb_parse_subscription_report(json, strlen(json), &parsed, &err) == 0);
    CHECK_EQ_INT(parsed.nodes.len, 1); CHECK_EQ_INT(parsed.skipped.len, 1);
    CHECK(strstr(parsed.skipped.items[0], "sensitive") == NULL);
    sb_proxy_import_free(&parsed);
    const char *yaml = "proxies:\n - {type: trojan, name: valid, server: host.example, port: 443, password: secret}\n - {type: unsupported, password: token}\n";
    REQUIRE(sb_parse_subscription_report(yaml, strlen(yaml), &parsed, &err) == 0);
    CHECK_EQ_INT(parsed.nodes.len, 1); CHECK_EQ_INT(parsed.skipped.len, 1);
    sb_proxy_import_free(&parsed);
    const char *basic = "socks5://user:pass@proxy.example:1080#SOCKS\nhttps://proxy.example:443#HTTP\n";
    REQUIRE(sb_parse_subscription_report(basic, strlen(basic), &parsed, &err) == 0);
    REQUIRE(parsed.nodes.len == 2); CHECK_STR(parsed.nodes.items[0].node_type, "socks");
    CHECK_STR(sbj_get_str(parsed.nodes.items[0].protocol_config, "username", NULL), "user");
    CHECK(sbj_get_bool(sbj_get(parsed.nodes.items[1].protocol_config, "tls"), "enabled", false));
    sb_proxy_import_free(&parsed);
    const char *socks_yaml = "proxies:\n - {type: socks5, name: local, server: host.example, port: 1080}\n";
    REQUIRE(sb_parse_subscription_report(socks_yaml, strlen(socks_yaml), &parsed, &err) == 0);
    CHECK_EQ_INT(parsed.nodes.len, 1); CHECK_STR(parsed.nodes.items[0].node_type, "socks");
    sb_proxy_import_free(&parsed);
    const char *unsafe_json = "[{\"type\":\"trojan\",\"server\":\"proxy.example\",\"server_port\":443,\"password\":\"secret\",\"tls\":{\"enabled\":true,\"client_key_path\":\"/private/secret\"}}]";
    CHECK_EQ_INT(sb_parse_subscription_report(unsafe_json, strlen(unsafe_json), &parsed, &err), -1);
    CHECK_EQ_INT(parsed.nodes.len, 0); CHECK_EQ_INT(parsed.skipped.len, 1);
    sb_proxy_import_free(&parsed);
    const char *vmess_json = "[{\"type\":\"vmess\",\"server\":\"proxy.example\",\"server_port\":443,\"uuid\":\"00000000-0000-0000-0000-000000000001\"}]";
    REQUIRE(sb_parse_subscription_report(vmess_json, strlen(vmess_json), &parsed, &err) == 0);
    CHECK_EQ_INT(sbj_get_int(parsed.nodes.items[0].protocol_config, "alter_id", -1), 0);
    CHECK_STR(sbj_get_str(parsed.nodes.items[0].protocol_config, "security", NULL), "auto");
    sb_proxy_import_free(&parsed);
    const char *plugins = "ss://YWVzLTEyOC1nY206c2VjcmV0@proxy.example:8388/?plugin=secret-plugin#Unsupported\ntrojan://secret@valid.example:443#Valid";
    REQUIRE(sb_parse_subscription_report(plugins, strlen(plugins), &parsed, &err) == 0);
    CHECK_EQ_INT(parsed.nodes.len, 1); CHECK_EQ_INT(parsed.skipped.len, 1);
    CHECK_CONTAINS(parsed.skipped.items[0], "unsupported Shadowsocks plugin");
    sb_proxy_import_free(&parsed);
}

TEST(refresh_is_scheduled_isolated_preserves_edits_and_recovers_without_data_loss) {
    sb_test_env env; sb_test_env_init(&env); sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err); REQUIRE(store);
    atomic_int mode = 0; sb_fixture fixture;
    REQUIRE(sb_fixture_start(&fixture, source_response, &mode) == 0);
    char *url = sb_asprintf("http://127.0.0.1:%u/redirect", fixture.port);
    sb_subscription a, b, current;
    sb_subscription_init(&a); sb_subscription_init(&b); sb_subscription_init(&current);
    REQUIRE(make_source(store, "A", url, &a) == 0); REQUIRE(make_source(store, "B", url, &b) == 0);
    sb_subscription_fetcher *fetcher = sb_subscription_fetcher_new(NULL, &err); REQUIRE(fetcher);
    sb_subscription_service *service = sb_subscription_service_new(store, fetcher);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1000, &err), 2);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1100, &err), 0);
    REQUIRE(sb_store_find_subscription(store, a.id, &current, &err) == 1);
    CHECK_EQ_INT(current.next_refresh_at, 1120); CHECK_EQ_INT(current.failure_count, 0);
    CHECK_EQ_INT(sbj_get_int(current.usage, "total", -1), 100);
    CHECK_CONTAINS(current.last_fetch_result, "\"skipped\":1");
    sb_proxy_record_vec nodes = {0}; REQUIRE(sb_store_list_proxy_nodes(store, &nodes, &err) == 0);
    REQUIRE(nodes.len == 2); CHECK(strcmp(nodes.items[0].id, nodes.items[1].id) != 0);
    CHECK(strcmp(nodes.items[0].tag, nodes.items[1].tag) != 0);
    sb_proxy_record *selected = strcmp(nodes.items[0].subscription_id, a.id) == 0 ? &nodes.items[0] : &nodes.items[1];
    char *selected_id = sb_strdup(selected->id);
    sb_str_set(&selected->tag, "My preferred exit"); selected->tag_len = strlen(selected->tag); selected->enabled = false;
    sb_proxy_record saved; sb_proxy_record_init(&saved);
    REQUIRE(sb_store_update_proxy_node(store, selected, &saved, &err) == 0);
    sb_proxy_record_vec_free(&nodes);
    atomic_store(&mode, 1);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1120, &err), 2);
    REQUIRE(sb_store_find_proxy_node(store, selected_id, &saved, &err) == 1);
    CHECK_STR(saved.tag, "My preferred exit"); CHECK(!saved.enabled); CHECK_STR(saved.server, "rotated.example");
    CHECK_STR(saved.source_tag, "Shared");
    atomic_store(&mode, 2);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1240, &err), 2);
    REQUIRE(sb_store_find_subscription(store, a.id, &current, &err) == 1);
    CHECK_EQ_INT(current.failure_count, 1); CHECK_EQ_INT(current.next_refresh_at, 1300);
    CHECK(current.last_error != NULL); CHECK_EQ_INT(sbj_get_int(current.usage, "total", -1), 100);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1299, &err), 0);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1300, &err), 2);
    REQUIRE(sb_store_find_subscription(store, a.id, &current, &err) == 1);
    CHECK_EQ_INT(current.failure_count, 2); CHECK_EQ_INT(current.next_refresh_at, 1420);
    current.enabled = false;
    REQUIRE(sb_store_update_subscription(store, &current, &a, &err) == 0);
    atomic_store(&mode, 1);
    CHECK_EQ_INT(sb_subscription_service_refresh_due(service, 1420, &err), 1);
    REQUIRE(sb_store_find_subscription(store, b.id, &current, &err) == 1);
    CHECK_EQ_INT(current.failure_count, 0); CHECK(current.last_error == NULL);
    sbj *backup = sb_store_export_backup(store, &err); REQUIRE(backup);
    sbj *restored = sb_store_restore_backup(store, backup, &err); REQUIRE(restored);
    sbj_free(restored); sbj_free(backup);
    REQUIRE(sb_store_find_proxy_node(store, selected_id, &saved, &err) == 1);
    CHECK_STR(saved.source_tag, "Shared"); CHECK_STR(saved.tag, "My preferred exit");
    REQUIRE(sb_store_find_subscription(store, b.id, &current, &err) == 1);
    CHECK_EQ_INT(sbj_get_int(current.usage, "total", -1), 100); CHECK_EQ_INT(current.next_refresh_at, 1540);
    sb_proxy_record_free(&saved); free(selected_id);
    sb_subscription_service_free(service); sb_subscription_fetcher_free(fetcher);
    sb_subscription_free(&a); sb_subscription_free(&b); sb_subscription_free(&current);
    sb_fixture_stop(&fixture); free(url); sb_store_free(store); sb_test_env_free(&env);
}

TEST(stale_sources_and_invalid_batches_cannot_modify_previous_nodes) {
    sb_test_env env; sb_test_env_init(&env); sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err); REQUIRE(store);
    sb_subscription original, changed; sb_subscription_init(&original); sb_subscription_init(&changed);
    REQUIRE(make_source(store, "Source", "https://source.example/old", &original) == 0);
    sb_subscription_copy(&changed, &original);
    sb_str_set(&changed.url, "https://source.example/new"); changed.url_len = strlen(changed.url);
    sb_subscription saved; sb_subscription_init(&saved);
    REQUIRE(sb_store_update_subscription(store, &changed, &saved, &err) == 0);
    const char *body = "trojan://secret@a.example:443#A\ntrojan://secret@b.example:443#B";
    sb_proxy_import parsed; REQUIRE(sb_parse_subscription_report(body, strlen(body), &parsed, &err) == 0);
    sb_subscription_fetch_result result; sb_subscription_fetch_result_init(&result); result.usage = sbj_object();
    CHECK_EQ_INT(sb_store_apply_subscription_fetch(store, &original, parsed.nodes.items, parsed.nodes.len, &result, 1000, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    parsed.nodes.items[1].server_port = 0;
    CHECK_EQ_INT(sb_store_apply_subscription_fetch(store, &saved, parsed.nodes.items, parsed.nodes.len, &result, 1000, &err), -1);
    sb_proxy_record_vec nodes = {0}; REQUIRE(sb_store_list_proxy_nodes(store, &nodes, &err) == 0);
    CHECK_EQ_INT(nodes.len, 0); sb_proxy_record_vec_free(&nodes);
    sb_proxy_import_free(&parsed); sb_subscription_fetch_result_free(&result);
    sb_subscription_free(&original); sb_subscription_free(&changed); sb_subscription_free(&saved);
    sb_store_free(store); sb_test_env_free(&env);
}

TEST(background_worker_refreshes_without_a_manual_http_request) {
    sb_test_env env; sb_test_env_init(&env); sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err); REQUIRE(store);
    atomic_int mode = 0; sb_fixture fixture; REQUIRE(sb_fixture_start(&fixture, source_response, &mode) == 0);
    char *url = sb_asprintf("http://127.0.0.1:%u/source", fixture.port);
    sb_subscription source; sb_subscription_init(&source); REQUIRE(make_source(store, "Auto", url, &source) == 0);
    sb_http_server_options options; sb_http_server_options_init(&options); options.port = 0;
    sb_str_set(&options.jwt_secret, "isolated-subscription-worker-test");
    sb_http_server *server = sb_http_server_new(store, &options, &err); REQUIRE(server);
    REQUIRE(sb_http_server_start(server, &err) > 0);
    char *id = sb_strdup(source.id);
    for (int i = 0; i < 200; ++i) {
        REQUIRE(sb_store_find_subscription(store, id, &source, &err) == 1);
        if (source.last_fetched_at) break;
        struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
    }
    CHECK(source.last_fetched_at != NULL);
    sb_http_server_free(server); sb_http_server_options_free(&options);
    free(id); free(url); sb_subscription_free(&source); sb_fixture_stop(&fixture);
    sb_store_free(store); sb_test_env_free(&env);
}
