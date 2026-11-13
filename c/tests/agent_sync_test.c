#include "test.h"
#include "sb/agent_sync.h"
#include <sys/stat.h>
#include <unistd.h>

static char *new_path(void) {
    char path[] = "/tmp/sb-easy-config-sync-XXXXXX";
    int fd = mkstemp(path); if (fd < 0) abort(); close(fd); unlink(path);
    return sb_strdup(path);
}
static sbj *state(int64_t base, int64_t patch, const char *content, const char *settings) {
    sbj *result = sbj_object();
    sbj_set_int(result, "base_version", base); sbj_set_int(result, "patch_version", patch);
    sbj_set(result, "base", sbj_parse_cstr("{\"dns\":{\"strategy\":\"prefer_ipv4\"}}"));
    sbj_set(result, "config", sbj_parse_cstr("{\"dns\":{\"strategy\":\"prefer_ipv4\"}}"));
    sbj_set(result, "patch", sbj_parse_cstr(content)); sbj_set(result, "agent_settings", sbj_parse_cstr(settings));
    return result;
}
static sbj *edit(sb_agent_sync *sync, const char *patch) {
    sbj *result = sb_agent_sync_snapshot(sync);
    sbj_set(result, "patch", sbj_parse_cstr(patch));
    return result;
}

TEST(agent_outbox_survives_restart_and_rejects_stale_edits) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device-a", NULL, &err); REQUIRE(sync);
    sbj *server = state(100, 0, "{}", "{}");
    REQUIRE(sb_agent_sync_observe(sync, server, &err) == 0);
    sbj *change = edit(sync, "{\"dns\":null,\"route\":{\"final\":\"direct\"}}");
    REQUIRE(sb_agent_sync_queue(sync, change, &err) == 0);
    CHECK(sb_agent_sync_queue(sync, change, &err) != 0); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sb_agent_sync_free(sync);
    sync = sb_agent_sync_new(path, "device-a", NULL, &err); REQUIRE(sync);
    sbj *request = sb_agent_sync_request(sync); REQUIRE(request);
    CHECK(sbj_is_null(sbj_get(sbj_get(request, "patch"), "dns")));
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(request, "patch"), "route"), "final", ""), "direct");
    CHECK(sb_agent_sync_new(path, "device-b", NULL, &err) == NULL);
    struct stat info; REQUIRE(stat(path, &info) == 0); CHECK_EQ_INT(info.st_mode & 0777, 0600);
    sbj_free(request); sbj_free(change); sbj_free(server); sb_agent_sync_free(sync); unlink(path); free(path);
}

TEST(agent_sync_conflicts_keep_pending_and_require_reviewed_resolution) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *first = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, first, &err) == 0);
    sbj *change = edit(sync, "{\"dns\":null}"); REQUIRE(sb_agent_sync_queue(sync, change, &err) == 0);
    sbj *other = state(101, 102, "{\"route\":{\"final\":\"Proxy\"}}", "{}");
    REQUIRE(sb_agent_sync_observe(sync, other, &err) == 0);
    sbj *snapshot = sb_agent_sync_snapshot(sync);
    CHECK(sbj_get_bool(snapshot, "conflict", false)); CHECK(sbj_get_bool(snapshot, "pending", false));
    CHECK(sbj_is_null(sbj_get(sbj_get(snapshot, "patch"), "dns")));
    CHECK(sbj_has(sbj_get(snapshot, "server_patch"), "route"));
    CHECK(sb_agent_sync_request(sync) == NULL);
    CHECK(sb_agent_sync_queue(sync, snapshot, &err) != 0); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj_set_str(snapshot, "resolve", "retry_local");
    REQUIRE(sb_agent_sync_queue(sync, snapshot, &err) == 0);
    sbj *request = sb_agent_sync_request(sync); REQUIRE(request);
    CHECK_EQ_INT(sbj_get_int(request, "base_version", 0), 101);
    CHECK_EQ_INT(sbj_get_int(request, "patch_version", 0), 102);
    sbj *remote_again = state(103, 104, "{\"route\":{\"final\":\"Proxy\"}}", "{}");
    REQUIRE(sb_agent_sync_observe(sync, remote_again, &err) == 0);
    sbj_free(remote_again);
    sbj_free(snapshot); snapshot = sb_agent_sync_snapshot(sync);
    sbj_set_str(snapshot, "resolve", "use_server"); REQUIRE(sb_agent_sync_queue(sync, snapshot, &err) == 0);
    sbj_free(snapshot); snapshot = sb_agent_sync_snapshot(sync);
    CHECK(!sbj_get_bool(snapshot, "pending", true)); CHECK(!sbj_get_bool(snapshot, "conflict", true));
    CHECK(sbj_equal(sbj_get(snapshot, "patch"), sbj_get(other, "patch")));
    sbj_free(snapshot); sbj_free(request); sbj_free(other); sbj_free(change); sbj_free(first);
    sb_agent_sync_free(sync); unlink(path); free(path);
}

TEST(agent_sync_lost_ack_and_inflight_successor_do_not_lose_edits) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *first = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, first, &err) == 0);
    sbj *change = edit(sync, "{\"dns\":null}"); REQUIRE(sb_agent_sync_queue(sync, change, &err) == 0);
    sbj *sent = sb_agent_sync_request(sync); REQUIRE(sent);
    sbj *newer = edit(sync, "{\"dns\":null,\"route\":{\"final\":\"direct\"}}");
    REQUIRE(sb_agent_sync_queue(sync, newer, &err) == 0);
    sbj *ack = state(100, 101, "{\"dns\":null}", "{}");
    REQUIRE(sb_agent_sync_acknowledge(sync, sent, ack, &err) == 0);
    sbj *pending = sb_agent_sync_request(sync); REQUIRE(pending);
    CHECK_EQ_INT(sbj_get_int(pending, "patch_version", 0), 101);
    CHECK(sbj_has(sbj_get(pending, "patch"), "route"));
    sbj *lost_ack = state(100, 102, "{\"dns\":null,\"route\":{\"final\":\"direct\"}}", "{}");
    REQUIRE(sb_agent_sync_observe(sync, lost_ack, &err) == 0);
    CHECK(sb_agent_sync_request(sync) == NULL);
    sbj *reset = edit(sync, "{}"); REQUIRE(sb_agent_sync_queue(sync, reset, &err) == 0);
    sb_agent_sync_free(sync); sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *reset_request = sb_agent_sync_request(sync); REQUIRE(reset_request);
    CHECK_EQ_INT(sbj_obj_len(sbj_get(reset_request, "patch")), 0);
    CHECK_EQ_INT(sbj_get_int(reset_request, "patch_version", 0), 102);
    sbj_free(reset_request); sbj_free(reset); sbj_free(lost_ack); sbj_free(pending);
    sbj_free(ack); sbj_free(newer); sbj_free(sent); sbj_free(change); sbj_free(first);
    sb_agent_sync_free(sync); unlink(path); free(path);
}

TEST(agent_sync_migrates_only_explicit_legacy_settings_into_absent_patch) {
    sb_err err = {0};
    sbj *legacy = sbj_parse_cstr("{\"local_proxy_egress\":true,\"local_route_rules\":[{\"outbound\":\"direct\"}]}");
    for (int customized = 0; customized < 2; ++customized) {
        char *path = new_path();
        sb_agent_sync *sync = sb_agent_sync_new(path, "device", legacy, &err); REQUIRE(sync);
        sbj *server = state(100, customized ? 101 : 0, "{}", "{}");
        REQUIRE(sb_agent_sync_observe(sync, server, &err) == 0);
        sbj *pending = sb_agent_sync_request(sync);
        CHECK((pending != NULL) == !customized);
        if (pending) CHECK(sbj_equal(sbj_get(pending, "agent_settings"), legacy));
        sbj_free(pending); sbj_free(server); sb_agent_sync_free(sync); unlink(path); free(path);
    }
    char *path = new_path(); sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *server = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, server, &err) == 0);
    CHECK(sb_agent_sync_request(sync) == NULL);
    sbj_free(server); sbj_free(legacy); sb_agent_sync_free(sync); unlink(path); free(path);
}

TEST(agent_sync_durable_write_failure_keeps_previous_memory_and_outbox) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *server = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, server, &err) == 0);
    sbj *before = sb_agent_sync_snapshot(sync);
    REQUIRE(unlink(path) == 0); REQUIRE(mkdir(path, 0700) == 0);
    sbj *change = edit(sync, "{\"route\":null}");
    CHECK(sb_agent_sync_queue(sync, change, &err) != 0);
    sbj *after = sb_agent_sync_snapshot(sync); CHECK(sbj_equal(before, after));
    CHECK(sb_agent_sync_request(sync) == NULL);
    sbj_free(change); sbj_free(before); sbj_free(after); sbj_free(server);
    sb_agent_sync_free(sync); rmdir(path); free(path);
}

TEST(agent_sync_discard_during_inflight_put_is_kept_as_a_conditional_undo) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *first = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, first, &err) == 0);
    sbj *change = edit(sync, "{\"dns\":null}"); REQUIRE(sb_agent_sync_queue(sync, change, &err) == 0);
    sbj *sent = sb_agent_sync_request(sync); REQUIRE(sent);
    sbj *discard = sb_agent_sync_snapshot(sync); sbj_set_str(discard, "resolve", "use_server");
    REQUIRE(sb_agent_sync_queue(sync, discard, &err) == 0);
    sbj *ack = state(100, 101, "{\"dns\":null}", "{}");
    REQUIRE(sb_agent_sync_acknowledge(sync, sent, ack, &err) == 0);
    sbj *undo = sb_agent_sync_request(sync); REQUIRE(undo);
    CHECK_EQ_INT(sbj_get_int(undo, "patch_version", 0), 101);
    CHECK_EQ_INT(sbj_obj_len(sbj_get(undo, "patch")), 0);
    sbj_free(undo); sbj_free(ack); sbj_free(discard); sbj_free(sent); sbj_free(change); sbj_free(first);
    sb_agent_sync_free(sync); unlink(path); free(path);
}

TEST(agent_legacy_settings_migrate_alongside_profile_patch_but_not_after_reset) {
    sb_err err = {0}; sbj *legacy = sbj_parse_cstr("{\"local_proxy_egress\":true}");
    for (int initialized = 0; initialized < 2; ++initialized) {
        char *path = new_path(); sb_agent_sync *sync = sb_agent_sync_new(path, "device", legacy, &err); REQUIRE(sync);
        sbj *server = state(100, 101, "{\"route\":{\"final\":\"direct\"}}", "{}");
        sbj_set_bool(server, "agent_settings_initialized", initialized);
        REQUIRE(sb_agent_sync_observe(sync, server, &err) == 0);
        sbj *pending = sb_agent_sync_request(sync);
        CHECK((pending != NULL) == !initialized);
        if (pending) {
            CHECK(sbj_equal(sbj_get(pending, "patch"), sbj_get(server, "patch")));
            CHECK(sbj_equal(sbj_get(pending, "agent_settings"), legacy));
        }
        sbj_free(pending); sbj_free(server); sb_agent_sync_free(sync); unlink(path); free(path);
    }
    sbj_free(legacy);
}

TEST(agent_sync_discard_survives_a_lost_inflight_response) {
    char *path = new_path(); sb_err err = {0};
    sb_agent_sync *sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    sbj *first = state(100, 0, "{}", "{}"); REQUIRE(sb_agent_sync_observe(sync, first, &err) == 0);
    sbj *change = edit(sync, "{\"dns\":null}"); REQUIRE(sb_agent_sync_queue(sync, change, &err) == 0);
    sbj *discard = sb_agent_sync_snapshot(sync); sbj_set_str(discard, "resolve", "use_server");
    REQUIRE(sb_agent_sync_queue(sync, discard, &err) == 0);
    sb_agent_sync_free(sync); sync = sb_agent_sync_new(path, "device", NULL, &err); REQUIRE(sync);
    /* The earlier edit committed, but its response never reached this agent. */
    sbj *committed = state(100, 101, "{\"dns\":null}", "{}");
    REQUIRE(sb_agent_sync_observe(sync, committed, &err) == 0);
    sbj *snapshot = sb_agent_sync_snapshot(sync);
    CHECK(sbj_get_bool(snapshot, "pending", false)); CHECK(sbj_get_bool(snapshot, "conflict", false));
    CHECK_EQ_INT(sbj_obj_len(sbj_get(snapshot, "patch")), 0);
    CHECK(sbj_has(sbj_get(snapshot, "server_patch"), "dns"));
    sbj_free(snapshot); sbj_free(committed); sbj_free(discard); sbj_free(change); sbj_free(first);
    sb_agent_sync_free(sync); unlink(path); free(path);
}
