#include "test_support.h"
#include "../service/health.h"

typedef struct fixture { test_data local; sbj *remote; unsigned uploads; bool lose_ack; } fixture;
static int exchange(void *context, const sbj *identity, const sbj *update, HANDLE cancel, sbj **out, sbw_error *error) {
    (void)identity; (void)cancel; fixture *f = context; *out = NULL;
    if (update) {
        if (sbj_get_int(update, "base_version", 0) != sbj_get_int(f->remote, "base_version", 0) ||
            sbj_get_int(update, "patch_version", 0) != sbj_get_int(f->remote, "patch_version", 0))
            return sbw_fail(error, "CONFIG_CONFLICT", "Concurrent change; draft retained.");
        ++f->uploads;
        sbj_set(f->remote, "patch", sbj_clone(sbj_get(update, "patch")));
        sbj_set(f->remote, "agent_settings", sbj_clone(sbj_get(update, "agent_settings")));
        sbj_set_int(f->remote, "patch_version", 100 + f->uploads);
        if (f->lose_ack) return sbw_fail(error, "http_error", "Lost acknowledgement.");
    }
    *out = sbj_clone(f->remote); return 0;
}
static sbw_controller *controller(fixture *f) {
    sbw_control_plane *remote = sb_xcalloc(1, sizeof(*remote)); sbw_store *store = sb_xcalloc(1, sizeof(*store));
    remote->context = f; remote->enroll = test_enroll; remote->fetch_config = test_fetch; remote->config_state = exchange;
    store->context = f; store->load = test_load; store->save = test_save; store->clear = test_clear;
    return sbw_controller_new(remote, store, NULL, NULL);
}
static sbj *request(sbw_controller *c, const char *method, const sbj *params) {
    sbw_error err = {0}; sbj *out = sbw_controller_dispatch(c, method, params, true, &err);
    if (!out) fprintf(stderr, "%s: %s\n", err.code, err.message);
    CHECK(out); test_redacted(out); return out;
}
int main(void) {
    fixture f = {0}; test_data_init(&f.local);
    f.remote = sbj_object();
    sbj_set_int(f.remote, "base_version", 100); sbj_set_int(f.remote, "patch_version", 0);
    sbj *config = sbj_parse_cstr(sbj_get_str(f.local.download, "content", ""));
    sbj_set(f.remote, "base", sbj_clone(config)); sbj_set(f.remote, "config", config);
    sbj_set(f.remote, "patch", sbj_object()); sbj_set(f.remote, "agent_settings", sbj_object());
    sbj_set_str(f.remote, "etag", "revision-1");
    sbw_controller *c = controller(&f); CHECK(c);
    sbj *empty = sbj_object(), *enrollment = test_enrollment(), *out = request(c, "enrollment.apply", enrollment); sbj_free(out);
    out = request(c, "config.refresh", empty);
    CHECK(!sbj_get_bool(out, "config_sync_pending", true)); CHECK(f.uploads == 0); sbj_free(out);
    sbj *policy = sbw_health_policy(sbj_get(f.local.saved, "identity")); sbj_set_int(policy, "interval_seconds", 180);
    out = request(c, "routing.health.set", policy); CHECK(sbj_get_bool(out, "config_sync_pending", false)); sbj_free(out);
    sbw_controller_free(c); c = controller(&f); CHECK(c); /* Disk is the durable outbox. */
    f.lose_ack = true; sbw_error err = {0};
    out = sbw_controller_dispatch(c, "config.refresh", empty, true, &err); CHECK(!out && f.uploads == 1);
    f.lose_ack = false; out = request(c, "config.refresh", empty);
    CHECK(!sbj_get_bool(out, "config_sync_pending", true)); CHECK(f.uploads == 1); sbj_free(out);
    sbj_set_int(policy, "interval_seconds", 240); out = request(c, "routing.health.set", policy); sbj_free(out);
    sbj_set_int(f.remote, "base_version", 500);
    out = sbw_controller_dispatch(c, "config.refresh", empty, true, &err); CHECK(!out && sb_streq(err.code, "CONFIG_CONFLICT"));
    out = request(c, "config.summary", empty); CHECK(sbj_get_bool(out, "config_sync_pending", false)); sbj_free(out);
    sbj *resolve = sbj_object(); sbj_set_bool(resolve, "keep_local", true);
    out = request(c, "config.resolve", resolve); CHECK(!sbj_get_bool(out, "config_sync_pending", true)); CHECK(f.uploads == 2); sbj_free(out);
    CHECK(sbj_get_int(sbj_get(sbj_get(sbj_get(f.remote, "agent_settings"), "windows_preferences"), "windows_health"), "interval_seconds", 0) == 240);
    sbj_set_int(policy, "interval_seconds", 300); out = request(c, "routing.health.set", policy); sbj_free(out);
    sbj_set_bool(resolve, "keep_local", false); out = request(c, "config.resolve", resolve); sbj_free(out);
    CHECK(f.uploads == 2);
    /* Management choices round-trip through the same durable device version. */
    sbj *management = sbj_object(); sbj_set_bool(management, "auto_connect", true);
    sbj_set_bool(management, "auto_reconnect", false); sbj_set_bool(management, "telemetry_enabled", false);
    sbj_set_int(management, "sync_interval_seconds", 120);
    out = request(c, "management.settings.set", management); sbj_free(out);
    out = request(c, "config.summary", empty); CHECK(sbj_get_bool(out, "config_sync_pending", false)); sbj_free(out);
    sbw_controller_free(c); c = controller(&f); CHECK(c);
    out = request(c, "config.refresh", empty); CHECK(!sbj_get_bool(out, "config_sync_pending", true)); sbj_free(out);
    const sbj *cloud_management = sbj_get(sbj_get(f.remote, "agent_settings"), "windows_management");
    CHECK(sbj_get_bool(cloud_management, "auto_connect", false)); CHECK(!sbj_get_bool(cloud_management, "telemetry_enabled", true));
    CHECK(sbj_get_int(cloud_management, "sync_interval_seconds", 0) == 120);
    CHECK(!sbj_has(cloud_management, "manual_disconnect"));
    sbj *remote_management = sbj_get_or_object(sbj_get(f.remote, "agent_settings"), "windows_management");
    sbj_set_bool(remote_management, "auto_connect", false); sbj_set_int(remote_management, "sync_interval_seconds", 45);
    sbj_set_str(remote_management, "future_option", "keep");
    sbj_set_str(sbj_get_or_object(sbj_get(f.remote, "agent_settings"), "windows_preferences"), "future_pref", "preserved");
    sbj_set_int(f.remote, "patch_version", 800);
    /* A failed durable commit cannot acknowledge or publish the server policy. */
    f.local.fail_write = true; out = sbw_controller_dispatch(c, "config.refresh", empty, true, &err); CHECK(!out);
    out = request(c, "management.settings.get", empty); CHECK(sbj_get_bool(out, "auto_connect", false)); sbj_free(out);
    f.local.fail_write = false; out = request(c, "config.refresh", empty); sbj_free(out);
    out = request(c, "management.settings.get", empty); CHECK(!sbj_get_bool(out, "auto_connect", true));
    CHECK(sbj_get_int(out, "sync_interval_seconds", 0) == 45); sbj_free(out);
    out = request(c, "config.summary", empty); CHECK(!sbj_get_bool(out, "config_sync_pending", true)); sbj_free(out);
    sbj_set_int(management, "sync_interval_seconds", 60); out = request(c, "management.settings.set", management); sbj_free(out);
    out = request(c, "config.refresh", empty); sbj_free(out);
    CHECK(sbj_string_is(sbj_get(sbj_get(sbj_get(f.remote, "agent_settings"), "windows_management"), "future_option"), "keep"));
    CHECK(sbj_string_is(sbj_get(sbj_get(sbj_get(f.remote, "agent_settings"), "windows_preferences"), "future_pref"), "preserved"));
    remote_management = sbj_get_or_object(sbj_get(f.remote, "agent_settings"), "windows_management");
    sbj_set_int(remote_management, "sync_interval_seconds", 1); sbj_set_int(f.remote, "patch_version", 900);
    out = sbw_controller_dispatch(c, "config.refresh", empty, true, &err); CHECK(!out && sb_streq(err.code, "INVALID_RESPONSE"));
    out = request(c, "management.settings.get", empty); CHECK(sbj_get_int(out, "sync_interval_seconds", 0) == 60); sbj_free(out);
    sbj_set_int(remote_management, "sync_interval_seconds", 60); sbj_set_bool(remote_management, "kill_switch_enabled", true);
    out = sbw_controller_dispatch(c, "config.refresh", empty, true, &err); CHECK(!out && sb_streq(err.code, "CORE_UNAVAILABLE"));
    out = request(c, "management.settings.get", empty); CHECK(!sbj_get_bool(out, "kill_switch_enabled", false)); sbj_free(out);
    sbj_del(remote_management, "kill_switch_enabled");
    sbj_del(sbj_get(f.remote, "agent_settings"), "windows_management");
    out = request(c, "config.refresh", empty); sbj_free(out);
    out = request(c, "management.settings.get", empty); CHECK(!sbj_get_bool(out, "auto_connect", true));
    CHECK(sbj_get_bool(out, "auto_reconnect", false) && sbj_get_bool(out, "telemetry_enabled", false));
    CHECK(sbj_get_int(out, "sync_interval_seconds", 0) == 30); sbj_free(out);
    sbj_free(management);
    sbw_controller_free(c); sbj_free(empty); sbj_free(enrollment); sbj_free(policy); sbj_free(resolve); sbj_free(f.remote); test_data_free(&f.local);
    puts("config sync tests passed"); return 0;
}
