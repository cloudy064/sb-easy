#include "test.h"
#include "http_test_support.h"
#include "sb/wg_migration.h"
#include "sb/wireguard.h"

static sbj *source_fixture(void) {
    sb_err err = {0};
    sb_wireguard_keypair server = {0}, first = {0}, second = {0};
    if (sb_wireguard_generate_keypair(&server, &err) != 0 ||
        sb_wireguard_generate_keypair(&first, &err) != 0 ||
        sb_wireguard_generate_keypair(&second, &err) != 0) abort();
    sbj *source = sbj_object(), *s = sbj_object(), *clients = sbj_object();
    sbj_set_str(s, "privateKey", server.private_key); sbj_set_str(s, "publicKey", server.public_key);
    sbj_set_str(s, "address", "10.77.42.1"); sbj_set(source, "server", s);
    sbj *a = sbj_object(); sbj_set_str(a, "name", "First client"); sbj_set_str(a, "address", "10.77.42.2");
    sbj_set_str(a, "privateKey", first.private_key); sbj_set_str(a, "publicKey", first.public_key);
    char *psk = sb_wireguard_generate_preshared_key(&err); sbj_set(a, "preSharedKey", sbj_str_take(psk));
    sbj_set_bool(a, "enabled", true); sbj_set(clients, "first-id", a);
    sbj *b = sbj_object(); sbj_set_str(b, "name", "Public only"); sbj_set_str(b, "address", "10.77.42.3");
    sbj_set_str(b, "publicKey", second.public_key); sbj_set(b, "preSharedKey", sbj_null());
    sbj_set_bool(b, "enabled", false); sbj_set(clients, "second-id", b);
    sbj_set(source, "clients", clients);
    sb_wireguard_keypair_free(&server); sb_wireguard_keypair_free(&first); sb_wireguard_keypair_free(&second);
    return source;
}

static sbj *client_first(sbj *source) { return (sbj *)sbj_get(sbj_get(source, "clients"), "first-id"); }
static sbj *client_second(sbj *source) { return (sbj *)sbj_get(sbj_get(source, "clients"), "second-id"); }

TEST(v14_validation_checks_identity_keys_addresses_and_options) {
    sbj *source = source_fixture(); sb_err err = {0};
    sbj *batch = sb_wg_easy_v14_normalize(source, NULL, "1.1.1.1", &err); REQUIRE(batch);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(batch, "wireguard_peers")), 2); sbj_free(batch);
    const char *addresses[] = {"10.77.43.2", "10.77.42.1", "10.77.42.255", "invalid"};
    for (size_t i = 0; i < sizeof addresses / sizeof *addresses; ++i) {
        sbj *bad = sbj_clone(source); sbj_set_str(client_first(bad), "address", addresses[i]);
        batch = sb_wg_easy_v14_normalize(bad, NULL, NULL, &err); CHECK(!batch); sbj_free(batch); sbj_free(bad);
    }
    sbj *bad = sbj_clone(source); sbj_set_str(client_second(bad), "address", "10.77.42.2");
    batch = sb_wg_easy_v14_normalize(bad, NULL, NULL, &err); CHECK(!batch); sbj_free(batch); sbj_free(bad);
    bad = sbj_clone(source);
    sbj_set_str(client_first(bad), "publicKey", sbj_get_str(client_second(bad), "publicKey", ""));
    batch = sb_wg_easy_v14_normalize(bad, NULL, NULL, &err); CHECK(!batch); sbj_free(batch); sbj_free(bad);
    bad = sbj_clone(source); sbj_set_str(client_first(bad), "privateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    batch = sb_wg_easy_v14_normalize(bad, NULL, NULL, &err); CHECK(!batch); sbj_free(batch); sbj_free(bad);
    sbj *options = sbj_object();
    const char nul_dns[] = "1.1.1.1\0unseen"; sbj_set(options, "dns", sbj_strn(nul_dns, sizeof nul_dns - 1));
    batch = sb_wg_easy_v14_normalize(source, options, NULL, &err); CHECK(!batch); sbj_free(batch);
    sbj_set_str(options, "dns", "1.1.1.1, 2606:4700:4700::1111"); sbj_set_str(options, "allowed_ips", "10.0.0.0/33");
    batch = sb_wg_easy_v14_normalize(source, options, NULL, &err); CHECK(!batch); sbj_free(batch);
    sbj_set_str(options, "allowed_ips", "0.0.0.0/0, ::/0"); sbj_set_int(options, "persistent_keepalive", 65536);
    batch = sb_wg_easy_v14_normalize(source, options, NULL, &err); CHECK(!batch); sbj_free(batch);
    sbj_set_int(options, "persistent_keepalive", 0);
    batch = sb_wg_easy_v14_normalize(source, options, NULL, &err); REQUIRE(batch);
    CHECK_EQ_INT(sbj_get_int(sbj_get(batch, "client_defaults"), "persistent_keepalive", -1), 0);
    sbj_free(batch); sbj_free(options); sbj_free(source);
}

TEST(preview_apply_export_and_exact_rollback_preserve_identity_without_exposing_secrets) {
    sb_test_env env; sb_test_env_init(&env); sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err); REQUIRE(store);
    sbj *source = source_fixture(), *batch = sb_wg_easy_v14_normalize(source, NULL, "9.9.9.9", &err); REQUIRE(batch);
    sbj *before = sb_store_export_backup(store, &err), *preview = NULL, *applied = NULL, *rolled = NULL;
    REQUIRE(sb_store_wg_import(store, batch, false, NULL, "admin", 5, &preview, &err) == 0);
    CHECK(sbj_get_bool(preview, "can_import", false)); CHECK_EQ_INT(sbj_get_int(preview, "added", -1), 2);
    char *safe = sbj_dump(preview, -1);
    CHECK(!strstr(safe, sbj_get_str(sbj_get(source, "server"), "privateKey", "")));
    CHECK(!strstr(safe, sbj_get_str(client_first(source), "privateKey", ""))); free(safe);
    sbj *unchanged = sb_store_export_backup(store, &err); CHECK(sbj_equal(before, unchanged)); sbj_free(unchanged);
    REQUIRE(sb_store_wg_import(store, batch, true, sbj_get_str(preview, "preview_digest", NULL), "admin", 5, &applied, &err) == 0);
    sbj *history = sb_store_list_wg_imports(store, &err); REQUIRE(history); CHECK_EQ_INT(sbj_arr_len(history), 1);
    safe = sbj_dump(history, -1); CHECK(!strstr(safe, "private")); CHECK(!strstr(safe, "snapshot")); free(safe); sbj_free(history);
    sb_wireguard_options options; sb_wireguard_options_init(&options); sb_str_set(&options.external_hostname, "vpn.example.test");
    sb_wireguard *wg = sb_wireguard_new(store, &options); sb_wireguard_options_free(&options); REQUIRE(wg);
    sb_wireguard_options runtime; REQUIRE(sb_wireguard_runtime_options(wg, &runtime, &err) == 0);
    CHECK_STR(runtime.address, "10.77.42.1/24"); sb_wireguard_options_free(&runtime);
    sb_wireguard_peer peer; sb_wireguard_peer_init(&peer);
    REQUIRE(sb_store_find_wireguard_peer(store, "wg-easy-first-id", &peer, &err) == 1);
    char *config = sb_wireguard_client_config(wg, &peer, &err); REQUIRE(config);
    CHECK_CONTAINS(config, sbj_get_str(client_first(source), "privateKey", ""));
    CHECK_CONTAINS(config, sbj_get_str(sbj_get(source, "server"), "publicKey", ""));
    CHECK_CONTAINS(config, "Address = 10.77.42.2/24");
    CHECK_CONTAINS(config, "DNS = 9.9.9.9"); free(config); sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_init(&peer); REQUIRE(sb_store_find_wireguard_peer(store, "wg-easy-second-id", &peer, &err) == 1);
    CHECK(!peer.enabled); config = sb_wireguard_client_config(wg, &peer, &err); CHECK(!config); free(config);
    sb_wireguard_peer_free(&peer); sb_wireguard_free(wg);
    sbj *again = NULL;
    REQUIRE(sb_store_wg_import(store, batch, false, NULL, "admin", 5, &again, &err) == 0);
    CHECK_EQ_INT(sbj_get_int(again, "skipped", -1), 2); CHECK_EQ_INT(sbj_get_int(again, "added", -1), 0); sbj_free(again);
    const char *id = sbj_get_str(applied, "migration_id", NULL);
    REQUIRE(sb_store_wg_import_rollback(store, id, "admin", 5, &rolled, &err) == 0); sbj_free(rolled); rolled = NULL;
    sbj *after = sb_store_export_backup(store, &err); CHECK(sbj_equal(before, after)); sbj_free(after);
    CHECK_EQ_INT(sb_store_wg_import_rollback(store, id, "admin", 5, &rolled, &err), -1); sbj_free(rolled);
    sbj_free(before); sbj_free(preview); sbj_free(applied); sbj_free(batch); sbj_free(source);
    sb_store_free(store); sb_test_env_free(&env);
}

TEST(stale_preview_and_post_import_edits_cannot_be_overwritten) {
    sb_test_env env; sb_test_env_init(&env); sb_err err = {0};
    sb_store *store = sb_store_open(env.db_path, sb_test_migrations_dir(), &err); REQUIRE(store);
    sbj *source = source_fixture(), *batch = sb_wg_easy_v14_normalize(source, NULL, NULL, &err); REQUIRE(batch);
    sbj *preview = NULL, *result = NULL;
    REQUIRE(sb_store_wg_import(store, batch, false, NULL, "admin", 5, &preview, &err) == 0);
    sbj *setting = sbj_object(); sbj_set_str(setting, "address", "10.99.0.1/24");
    REQUIRE(sb_store_set_app_setting(store, "wireguard_interface", setting, &err) == 0); sbj_free(setting);
    CHECK_EQ_INT(sb_store_wg_import(store, batch, true, sbj_get_str(preview, "preview_digest", NULL), "admin", 5, &result, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT); sbj_free(preview); preview = NULL;
    REQUIRE(sb_store_wg_import(store, batch, false, NULL, "admin", 5, &preview, &err) == 0);
    REQUIRE(sb_store_wg_import(store, batch, true, sbj_get_str(preview, "preview_digest", NULL), "admin", 5, &result, &err) == 0);
    char *id = sb_strdup(sbj_get_str(result, "migration_id", "")); sbj_free(result); result = NULL;
    REQUIRE(sb_store_set_wireguard_peer_enabled(store, "wg-easy-first-id", false, &err) == 0);
    CHECK_EQ_INT(sb_store_wg_import_rollback(store, id, "admin", 5, &result, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT); sbj_free(result);
    sb_wireguard_peer peer; sb_wireguard_peer_init(&peer); REQUIRE(sb_store_find_wireguard_peer(store, "wg-easy-first-id", &peer, &err) == 1);
    CHECK(!peer.enabled); sb_wireguard_peer_free(&peer);
    sbj *other = source_fixture(), *other_batch = sb_wg_easy_v14_normalize(other, NULL, NULL, &err), *conflict = NULL;
    REQUIRE(sb_store_wg_import(store, other_batch, false, NULL, "admin", 5, &conflict, &err) == 0);
    CHECK(!sbj_get_bool(conflict, "can_import", true)); CHECK(sbj_arr_len(sbj_get(conflict, "conflicts")) > 0);
    result = NULL; CHECK_EQ_INT(sb_store_wg_import(store, other_batch, true, sbj_get_str(conflict, "preview_digest", NULL), "admin", 5, &result, &err), -1);
    sbj_free(result); sbj_free(conflict); sbj_free(other_batch); sbj_free(other); free(id);
    sbj_free(preview); sbj_free(batch); sbj_free(source); sb_store_free(store); sb_test_env_free(&env);
}

static void set_running(sb_http_server_options *options, void *user) { (void)user; options->wireguard_enabled = true; }

TEST(http_migration_is_admin_only_redacted_and_requires_offline_activation) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_test_response response;
    sbj *source = source_fixture(), *request = sbj_object();
    sbj_set_str(request, "format", "wg-easy-v14"); sbj_set(request, "configuration", sbj_clone(source));
    char *body = sbj_dump(request, -1);
    char *viewer = sb_test_token(&t, "viewer-id", "viewer", "viewer");
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", body, viewer, NULL, &response);
    CHECK_EQ_INT(response.status, 403); sb_test_response_free(&response);
    sb_test_request_ex(&t, "GET", "/api/system/migrate/wg-easy", NULL, viewer, NULL, &response);
    CHECK_EQ_INT(response.status, 403); sb_test_response_free(&response); free(viewer);
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", body, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 200);
    CHECK(!strstr(response.body, sbj_get_str(sbj_get(source, "server"), "privateKey", "")));
    sbj_set_str(request, "preview_digest", sbj_get_str(response.json, "preview_digest", ""));
    sbj_set_str(request, "action", "apply"); sb_test_response_free(&response); free(body); body = sbj_dump(request, -1);
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", body, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 200); CHECK(sbj_get_bool(response.json, "restart_required", false));
    char *migration_id = sb_strdup(sbj_get_str(response.json, "migration_id", "")); sb_test_response_free(&response);
    sb_test_request_ex(&t, "GET", "/api/system/migrate/wg-easy", NULL, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 200); CHECK_EQ_INT(sbj_arr_len(response.json), 1);
    CHECK(!strstr(response.body, "snapshot")); sb_test_response_free(&response);
    sbj *rollback = sbj_object(); sbj_set_str(rollback, "action", "rollback"); sbj_set_str(rollback, "migration_id", migration_id);
    char *rollback_body = sbj_dump(rollback, -1); sbj_free(rollback); free(migration_id);
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", rollback_body, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 200); sb_test_response_free(&response); free(rollback_body);
    sb_test_server_stop(&t);
    /* Starting this HTTP fixture does not initialize a kernel interface. The
     * apply guard is checked before any WireGuard operation can run. */
    REQUIRE(sb_test_server_start_ex(&t, NULL, set_running, NULL) == 0);
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", body, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 409); CHECK_CONTAINS(response.body, "WG_ENABLED=false"); sb_test_response_free(&response);
    sbj_set_str(request, "action", "preview"); free(body); body = sbj_dump(request, -1);
    sb_test_request_ex(&t, "POST", "/api/system/migrate/wg-easy", body, NULL, NULL, &response);
    CHECK_EQ_INT(response.status, 200); CHECK(sbj_get_bool(response.json, "wireguard_running", false)); sb_test_response_free(&response);
    sb_test_server_stop(&t); free(body); sbj_free(request); sbj_free(source);
}
