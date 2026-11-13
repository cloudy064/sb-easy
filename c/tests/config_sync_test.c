#include "test.h"
#include "http_test_support.h"
#include "sb/config_sync.h"
#include "sb/tailscale.h"

TEST(merge_patch_add_delete_arrays_and_inheritance) {
    sbj *base = sbj_parse_cstr("{\"dns\":{\"final\":\"a\",\"cache\":true},\"rules\":[1,2],\"remove\":1}");
    sbj *patch = sbj_parse_cstr("{\"dns\":{\"final\":\"b\"},\"rules\":[3],\"remove\":null,\"added\":{\"enabled\":false}}");
    sbj *effective = sb_config_merge_patch(base, patch);
    sbj *expected = sbj_parse_cstr("{\"dns\":{\"final\":\"b\",\"cache\":true},\"rules\":[3],\"added\":{\"enabled\":false}}");
    CHECK(sbj_equal(effective, expected));
    sbj *diff = sb_config_merge_diff(base, effective), *again = sb_config_merge_patch(base, diff);
    CHECK(sbj_equal(again, effective));
    sbj_set_bool(sbj_get(base, "dns"), "new_default", true);
    sbj_free(again); again = sb_config_merge_patch(base, patch);
    CHECK(sbj_get_bool(sbj_get(again, "dns"), "new_default", false));
    CHECK(!sbj_has(again, "remove"));
    sbj_free(base); sbj_free(patch); sbj_free(effective); sbj_free(expected); sbj_free(diff); sbj_free(again);
}

static sbj *request_body(const sbj *state, const char *patch) {
    sbj *out = sbj_object();
    sbj_set_int(out, "base_version", sbj_get_int(state, "base_version", 0));
    sbj_set_int(out, "patch_version", sbj_get_int(state, "patch_version", 0));
    sbj_set(out, "patch", sbj_parse_cstr(patch)); sbj_set(out, "agent_settings", sbj_object());
    return out;
}

TEST(http_sync_cas_fanout_reset_and_legacy_download) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_STR(r.cache_control, "no-store");
    CHECK_EQ_INT(sbj_get_int(r.json, "patch_version", -1), 0);
    CHECK(!sbj_get_bool(r.json, "agent_settings_initialized", true));
    sbj *write = request_body(r.json, "{\"log\":{\"level\":\"debug\"},\"route\":{\"auto_detect_interface\":null}}");
    sbj *settings = sbj_object(); sbj_set(settings, "android_routing", sbj_parse_cstr("{\"version\":1}"));
    sbj_set(write, "agent_settings", settings);
    char *body = sbj_dump(write, -1); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/agent/config-state", body, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200);
    int64_t patch_version = sbj_get_int(r.json, "patch_version", 0); CHECK(patch_version > 0);
    CHECK(sbj_get_bool(r.json, "agent_settings_initialized", false));
    CHECK_STR(sbj_get_str(sbj_get(r.json, "config"), "missing", "fallback"), "fallback");
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(r.json, "config"), "log"), "level", ""), "debug");
    CHECK(!sbj_has(sbj_get(sbj_get(r.json, "config"), "route"), "auto_detect_interface"));
    CHECK(sbj_equal(sbj_get(r.json, "agent_settings"), sbj_get(write, "agent_settings")));
    char *etag = sb_strdup(sbj_get_str(r.json, "etag", ""));
    sbj *effective = sbj_clone(sbj_get(r.json, "config")); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/agent/config-state", body, "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 409); sb_test_response_free(&r); free(body); sbj_free(write);
    sb_test_request_ex(&t, "GET", "/api/agent/config", NULL, "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 200); CHECK(sbj_equal(r.json, effective)); CHECK_STR(r.etag, etag);
    sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/config/sing-box/full", NULL, NULL, NULL, &r);
    CHECK_EQ_INT(r.status, 200); CHECK(sbj_equal(r.json, effective));
    sb_test_response_free(&r); free(etag); sbj_free(effective);
    sb_err err = {0}; sb_config_profile p, saved; sb_config_profile_init(&p); sb_config_profile_init(&saved);
    REQUIRE(sb_store_find_profile(t.store, "default", &p, &err) == 1);
    sbj_set_bool(sbj_get_or_object(p.profile, "log"), "disabled", true);
    REQUIRE(sb_store_update_profile(t.store, &p, &saved, &err) == 0);
    sb_config_profile_free(&p); sb_config_profile_free(&saved);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_EQ_INT(sbj_get_int(r.json, "patch_version", 0), patch_version);
    CHECK(sbj_get_bool(sbj_get(sbj_get(r.json, "config"), "log"), "disabled", false));
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(r.json, "config"), "log"), "level", ""), "debug");
    write = request_body(r.json, "{}"); body = sbj_dump(write, -1); sbj_free(write); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/hosts/self/config-state", body, NULL, NULL, &r);
    REQUIRE(r.status == 200); CHECK(sbj_equal(sbj_get(r.json, "base"), sbj_get(r.json, "config")));
    CHECK(sbj_get_int(r.json, "patch_version", 0) > patch_version);
    CHECK(sbj_get_bool(r.json, "agent_settings_initialized", false));
    sb_test_response_free(&r); free(body); sb_test_server_stop(&t);
}

TEST(http_auth_scope_and_bad_payloads) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "", NULL, &r);
    CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "wrong", NULL, &r);
    CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    char *viewer = sb_test_token(&t, "ignored", "sync-viewer", "viewer"); REQUIRE(viewer);
    sb_test_request_ex(&t, "GET", "/api/hosts/self/config-state", NULL, viewer, NULL, &r);
    CHECK_EQ_INT(r.status, 403); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/agent/config-state", "{}", "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 400); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); sbj *write = request_body(r.json, "[]");
    char *body = sbj_dump(write, -1); sbj_free(write); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/agent/config-state", body, "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 400); sb_test_response_free(&r); free(body); free(viewer); sb_test_server_stop(&t);
}

typedef struct { sb_database *db; const sbj *base; int64_t version; pthread_barrier_t *barrier; bool saved; } sync_race;
static void *race_save(void *arg) {
    sync_race *p = arg; sb_err err = {0}; sbj *patch = sbj_parse_cstr("{\"log\":{\"level\":\"debug\"}}"), *settings = sbj_object();
    pthread_barrier_wait(p->barrier);
    sbj *saved = sb_config_sync_put(p->db, "self", p->base, p->version, p->version, 0, patch, settings, &err);
    p->saved = saved != NULL; sbj_free(saved); sbj_free(patch); sbj_free(settings); return NULL;
}
TEST(concurrent_writes_and_changed_base_do_not_overwrite) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_database *db = sb_store_database(t.store); sb_err err = {0};
    int64_t version = sb_config_sync_source_version(db, &err); sbj *base = sbj_parse_cstr("{\"log\":{\"level\":\"info\"}}");
    sbj *state = sb_config_sync_get(db, "self", base, NULL, version, &err); REQUIRE(state); sbj_free(state);
    pthread_barrier_t barrier; pthread_barrier_init(&barrier, NULL, 2);
    sync_race left = {db, base, version, &barrier, false}, right = left; pthread_t a,b;
    REQUIRE(pthread_create(&a, NULL, race_save, &left) == 0); REQUIRE(pthread_create(&b, NULL, race_save, &right) == 0);
    pthread_join(a, NULL); pthread_join(b, NULL); pthread_barrier_destroy(&barrier); CHECK(left.saved != right.saved);
    REQUIRE(sb_database_execute(db, "UPDATE config_profiles SET name='Changed' WHERE id='default'", &err) == 0);
    CHECK(sb_config_sync_source_version(db, &err) > version);
    CHECK(sb_config_sync_get(db, "self", base, NULL, version, &err) == NULL); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(base); sb_test_server_stop(&t);
}

TEST(default_config_timestamp_cas_and_status_noop) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/config/default", NULL, NULL, NULL, &r);
    REQUIRE(r.status == 200); int64_t before = sbj_get_int(r.json, "base_version", 0); CHECK(before > 0);
    sbj *write = sbj_clone(r.json); sbj *profile = sbj_get(write, "profile");
    sbj *template = sbj_parse_cstr(sbj_get_str(profile, "template", "{}"));
    sbj_set(profile, "template", template);
    sbj_set_bool(sbj_get_or_object(sbj_get(profile, "template"), "log"), "disabled", true);
    char *body = sbj_dump(write, -1); sbj_free(write); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/config/default", body, NULL, NULL, &r);
    if (r.status != 200) fprintf(stderr, "default PUT status=%ld error=%s\n", r.status, sbj_get_str(r.json, "error", ""));
    REQUIRE(r.status == 200); CHECK(sbj_get_int(r.json, "base_version", 0) > before); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/config/default", body, NULL, NULL, &r);
    CHECK_EQ_INT(r.status, 409); sb_test_response_free(&r); free(body);
    sb_err err = {0}; sb_database *db = sb_store_database(t.store);
    int64_t current = sb_config_sync_source_version(db, &err);
    CHECK_EQ_INT(sb_store_touch_host(t.store, "self", &err), 0);
    CHECK_EQ_INT(sb_database_execute(db, "UPDATE hosts SET name=name,profile_id=profile_id,capabilities=capabilities WHERE id='self'", &err), 0);
    CHECK_EQ_INT(sb_database_execute(db, "UPDATE config_profiles SET name=name,template=template WHERE id='default'", &err), 0);
    CHECK_EQ_INT(sb_config_sync_source_version(db, &err), current);
    sb_test_server_stop(&t);
}

TEST(legacy_profile_migrates_without_losing_personalization) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_err err = {0};
    sb_config_profile profile, saved; sb_config_profile_init(&profile); sb_config_profile_init(&saved);
    REQUIRE(sb_store_find_profile(t.store, "default", &profile, &err) == 1);
    sb_str_set(&profile.id, "custom"); sb_str_set(&profile.name, "Custom"); profile.name_len = 6;
    sbj_set_str(sbj_get_or_object(profile.profile, "log"), "level", "debug");
    REQUIRE(sb_store_create_profile(t.store, &profile, &saved, &err) == 0);
    CHECK_EQ_INT(sb_database_execute(sb_store_database(t.store), "UPDATE hosts SET profile_id='custom' WHERE id='self'", &err), 0);
    sb_config_profile_free(&profile); sb_config_profile_free(&saved);
    sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/config/sing-box/full", NULL, NULL, NULL, &r);
    REQUIRE(r.status == 200); sbj *legacy = sbj_clone(r.json); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK(sbj_equal(legacy, sbj_get(r.json, "config")));
    CHECK(sbj_get_int(r.json, "patch_version", 0) > 0);
    CHECK(!sbj_get_bool(r.json, "agent_settings_initialized", true));
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(r.json, "patch"), "log"), "level", ""), "debug");
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(r.json, "base"), "log"), "level", ""), "info");
    sbj_free(legacy); sb_test_response_free(&r); sb_test_server_stop(&t);
}

TEST(rendered_runtime_change_gets_a_new_timestamp_without_sql_change) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_err err = {0};
    sb_database *db = sb_store_database(t.store); int64_t version = sb_config_sync_source_version(db, &err);
    sbj *base = sbj_parse_cstr("{\"log\":{\"level\":\"info\"}}");
    sbj *state = sb_config_sync_get(db, "self", base, NULL, version, &err); REQUIRE(state);
    CHECK_EQ_INT(sbj_get_int(state, "base_version", 0), version); sbj_free(state);
    REQUIRE(sb_database_execute(db, "INSERT INTO hosts(id,name) VALUES('second','Second')", &err) == 0);
    sbj *second_base = sbj_parse_cstr("{\"log\":{\"level\":\"warn\"}}");
    state = sb_config_sync_get(db, "second", second_base, NULL, version, &err); REQUIRE(state);
    CHECK_EQ_INT(sbj_get_int(state, "base_version", 0), version); sbj_free(state);
    sbj_set_str(sbj_get(base, "log"), "level", "debug");
    state = sb_config_sync_get(db, "self", base, NULL, version, &err); REQUIRE(state);
    int64_t changed = sbj_get_int(state, "base_version", 0); CHECK(changed > version); sbj_free(state);
    state = sb_config_sync_get(db, "second", second_base, NULL, changed, &err); REQUIRE(state);
    CHECK_EQ_INT(sbj_get_int(state, "base_version", 0), changed); sbj_free(state); sbj_free(second_base);
    state = sb_config_sync_get(db, "self", base, NULL, changed, &err); REQUIRE(state);
    CHECK_EQ_INT(sbj_get_int(state, "base_version", 0), changed); sbj_free(state);
    sbj *empty = sbj_object();
    CHECK(sb_config_sync_put(db, "self", base, changed, version, 0, empty, empty, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_free(empty); sbj_free(base); sb_test_server_stop(&t);
}

TEST(full_shared_profile_does_not_bypass_assigned_node_scope) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_err err = {0};
    sb_config_profile p, saved; sb_config_profile_init(&p); sb_config_profile_init(&saved);
    REQUIRE(sb_store_find_profile(t.store, "default", &p, &err) == 1); p.mode = SB_PROFILE_FULL;
    REQUIRE(sb_store_update_profile(t.store, &p, &saved, &err) == 0);
    sb_config_profile_free(&p); sb_config_profile_free(&saved);
    sb_database *db = sb_store_database(t.store);
    REQUIRE(sb_database_execute(db, "INSERT INTO host_outbounds(host_id,node_id) VALUES('self','restricted-node')", &err) == 0);
    sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    CHECK_EQ_INT(r.status, 400); CHECK(!sbj_has(r.json, "base"));
    CHECK_EQ_INT(sb_config_sync_exists(db, "self", &err), 0);
    sb_test_response_free(&r); sb_test_server_stop(&t);
}

static const sbj *tailscale_endpoint(const sbj *config) {
    const sbj *endpoint;
    SBJ_ARR_FOREACH(sbj_get(config, "endpoints"), i, endpoint)
        if (sbj_string_is(sbj_get(endpoint, "type"), "tailscale")) return endpoint;
    return NULL;
}

TEST(empty_patch_tracks_tailscale_changes_and_rejects_stale_snapshots) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_err err = {0};
    sb_database *db = sb_store_database(t.store); sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200);
    int64_t before = sbj_get_int(r.json, "base_version", 0);
    sbj *old_base = sbj_clone(sbj_get(r.json, "base"));
    char *old_etag = sb_strdup(sbj_get_str(r.json, "etag", ""));
    CHECK(tailscale_endpoint(sbj_get(r.json, "config")) == NULL); sb_test_response_free(&r);

    sb_host host, saved; sb_host_init(&host); sb_host_init(&saved);
    REQUIRE(sb_store_find_host(t.store, "self", &host, &err) == 1);
    sbj_set_bool(host.tailscale, "enabled", true);
    sbj_set_str(host.tailscale, "auth_key", "tskey-auth-sync-first");
    REQUIRE(sb_store_update_host(t.store, &host, &saved, &err) == 0);
    int64_t enabled_version = sb_config_sync_source_version(db, &err);
    CHECK(enabled_version > before); /* Must advance before any render/GET. */
    sbj *empty = sbj_object();
    CHECK(sb_config_sync_put(db, "self", old_base, before, before, 0, empty, empty, &err) == NULL);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT); sbj_free(old_base); sbj_free(empty);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_EQ_INT(sbj_get_int(r.json, "base_version", 0), enabled_version);
    CHECK_EQ_INT(sbj_get_int(r.json, "patch_version", -1), 0); CHECK_EQ_INT(sbj_obj_len(sbj_get(r.json, "patch")), 0);
    CHECK(sbj_equal(sbj_get(r.json, "base"), sbj_get(r.json, "config")));
    CHECK_STR(sbj_get_str(tailscale_endpoint(sbj_get(r.json, "config")), "auth_key", ""), "tskey-auth-sync-first");
    CHECK(strcmp(old_etag, sbj_get_str(r.json, "etag", "")) != 0); free(old_etag);
    old_etag = sb_strdup(sbj_get_str(r.json, "etag", "")); sb_test_response_free(&r);

    REQUIRE(sb_store_update_host(t.store, &host, &saved, &err) == 0);
    CHECK_EQ_INT(sb_config_sync_source_version(db, &err), enabled_version);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_EQ_INT(sbj_get_int(r.json, "base_version", 0), enabled_version);
    CHECK_STR(sbj_get_str(r.json, "etag", ""), old_etag); sb_test_response_free(&r);

    sbj_set_str(host.tailscale, "auth_key", "tskey-auth-sync-rotated");
    sbj_set(host.tailscale, "route_cidrs", sbj_parse_cstr("[\"192.168.87.0/24\"]"));
    REQUIRE(sb_store_update_host(t.store, &host, &saved, &err) == 0);
    int64_t rotated_version = sb_config_sync_source_version(db, &err); CHECK(rotated_version > enabled_version);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_EQ_INT(sbj_get_int(r.json, "base_version", 0), rotated_version);
    CHECK_STR(sbj_get_str(tailscale_endpoint(sbj_get(r.json, "config")), "auth_key", ""), "tskey-auth-sync-rotated");
    CHECK(strcmp(old_etag, sbj_get_str(r.json, "etag", "")) != 0); free(old_etag);
    CHECK_EQ_INT(sbj_get_int(r.json, "patch_version", -1), 0); sb_test_response_free(&r);

    sbj_set_bool(host.tailscale, "enabled", false);
    REQUIRE(sb_store_update_host(t.store, &host, &saved, &err) == 0);
    int64_t disabled_version = sb_config_sync_source_version(db, &err); CHECK(disabled_version > rotated_version);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK_EQ_INT(sbj_get_int(r.json, "base_version", 0), disabled_version);
    CHECK(tailscale_endpoint(sbj_get(r.json, "config")) == NULL);
    sb_test_response_free(&r); sb_host_free(&host); sb_host_free(&saved); sb_test_server_stop(&t);
}

TEST(shared_default_keeps_tailscale_identity_per_device_without_wireguard_provision) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0); sb_err err = {0};
    sb_host host, created; sb_host_init(&host); sb_host_init(&created);
    sb_str_set(&host.name, "Mobile"); host.name_len = 6;
    sbj_set_str(host.capabilities, "platform", "android");
    sbj_set_bool(host.capabilities, "runs_singbox", true);
    sbj_set_bool(host.tailscale, "enabled", true);
    sbj_set_str(host.tailscale, "auth_key", "tskey-auth-mobile-only");
    REQUIRE(sb_store_create_host(t.store, &host, &created, &err) == 0);
    sb_test_response r = {0};
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, created.agent_token, NULL, &r);
    REQUIRE(r.status == 200);
    CHECK_STR(sbj_get_str(tailscale_endpoint(sbj_get(r.json, "base")), "auth_key", ""), "tskey-auth-mobile-only");
    CHECK(sbj_equal(sbj_get(r.json, "base"), sbj_get(r.json, "config")));
    sb_test_response_free(&r); sb_host_free(&host); sb_host_init(&host);
    REQUIRE(sb_store_find_host(t.store, created.id, &host, &err) == 1); CHECK(host.wg_address == NULL);
    sb_test_request_ex(&t, "GET", "/api/agent/config-state", NULL, "legacy-self-token", NULL, &r);
    REQUIRE(r.status == 200); CHECK(tailscale_endpoint(sbj_get(r.json, "base")) == NULL);
    sb_test_response_free(&r); sb_host_free(&host); sb_host_free(&created); sb_test_server_stop(&t);
}
