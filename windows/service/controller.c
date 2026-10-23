#include <winsock2.h>
#include <ws2tcpip.h>
#include "subscriptions.h"
#include "independent.h"
#include "controller.h"
#include "runtime_config.h"
#include "dashboard.h"
#include "routing.h"
#include "traffic.h"
#include "capture.h"
#include "extensions.h"
#include "extension_store.h"
#include "extension_process.h"
#include "http_debug.h"
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "route_probe.h"
#include "kill_switch.h"
#include "health.h"
#include "preferences.h"
#include "preferences_cloud.h"
#include <bcrypt.h>

struct sbw_controller {
    sbw_control_plane *remote;
    sbw_store *store;
    HANDLE cancel;
    SRWLOCK state_lock, mutation_lock, user_operation_lock;
    sbj *identity, *candidate, *last_good, *active;
    sbj *managed_archive, *independent_archive;
    sbw_error startup_error;
    sbw_core *core;
    sbw_error core_error;
    char *checked_etag, *auto_attempted_etag;
    bool checked_valid;
    sb_windows_runtime_state runtime;
    sbw_runtime_config active_config;
    sbw_error runtime_error;
    bool last_stop_forced;
    HANDLE monitor_stop, monitor;
    HANDLE management_stop, management_thread, management_io_cancel;
    sbj *management_settings, *command_receipts, *kill_switch;
    sbw_health *health;
    sbj *health_snapshot;
    sbw_preferences_cloud *preferences_cloud;
    sbw_updater *updater;
    sbj *preferences_pending, *preferences_base, *preferences_source;
    char preferences_preview_id[65];
    uint64_t preferences_preview_expires;
    sb_windows_recovery recovery;
    uint64_t next_sync_ms, last_sync_at, last_report_at, kill_switch_checked_ms;
    sbw_error management_error;
    bool management_running;
    HANDLE interface_notification;
    volatile LONG network_generation;
    LONG network_observed;
    uint64_t network_due_ms;
    uint64_t extensions_checked_ms;
    int64_t telemetry_upload, telemetry_download;
    uint64_t telemetry_sample_ms;
    sbw_traffic *traffic;
    ULONGLONG traffic_saved;
    bool traffic_storage_ok, traffic_load_ok;
    sbw_capture *capture;
    sbw_extension_process *httpdebug;
    char *httpdebug_base;
    sbj *httpdebug_domains;
    HANDLE upload_thread, upload_cancel;
    SRWLOCK upload_lock;
    char upload_status[256];
    ULONGLONG upload_attempt;

};
static DWORD WINAPI monitor_main(void *context);
static DWORD WINAPI management_main(void *context);
static int refresh_configuration(sbw_controller *controller, bool force, HANDLE cancel, sbw_error *error);
static sbj *management_status(sbw_controller *controller);
static sbj *default_management_settings(void) {
    sbj *settings = sbj_object();
    sbj_set_bool(settings, "auto_connect", false);
    sbj_set_bool(settings, "auto_reconnect", true);
    sbj_set_bool(settings, "telemetry_enabled", true);
    /* Absence is distinct from an explicit opt-out. A missing/corrupt profile
     * must never remove persistent WFP rules installed by an earlier service. */
    sbj_set_bool(settings, "manual_disconnect", false);
    sbj_set_int(settings, "sync_interval_seconds", 30);
    return settings;
}
static bool collect_traffic(sbw_controller *controller);
static void persist_traffic(sbw_controller *controller);
static void capture_upload_join(sbw_controller *controller);
static void capture_auto_upload(sbw_controller *controller);
static sbj *capture_dispatch(sbw_controller *controller, const char *method, const sbj *params, sbw_error *error);
static sbj *httpdebug_dispatch(sbw_controller *controller, const char *method, const sbj *params, sbw_error *error);
static int extension_stop(sbw_controller *controller, const char *id, bool revoked, sbw_error *error);
static void extensions_tick(sbw_controller *controller, uint64_t now, bool force);
static sbj *config_counts(const sbj *candidate, sbw_error *error) {
    const sbj *content = sbj_get(candidate, "content");
    if (!sbw_json_string(content, 8U * 1024U * 1024U, false)) goto invalid;
    sbj *config = sbw_json_parse(content->v.str.ptr, content->v.str.len, 32, NULL);
    if (!config) goto invalid;
    const sbj *inbounds = sbj_get(config, "inbounds"), *outbounds = sbj_get(config, "outbounds");
    const sbj *route = sbj_get(config, "route"), *rules = sbj_get(route, "rules");
    if (!sbj_is_object(config) || (inbounds && !sbj_is_array(inbounds)) ||
        (outbounds && !sbj_is_array(outbounds)) || (route && !sbj_is_object(route)) ||
        (rules && !sbj_is_array(rules))) { sbj_free(config); goto invalid; }
    sbj *result = sbj_object();
    sbj_set_int(result, "inbounds", (int64_t)sbj_arr_len(inbounds));
    sbj_set_int(result, "outbounds", (int64_t)sbj_arr_len(outbounds));
    sbj_set_int(result, "rules", (int64_t)sbj_arr_len(rules));
    sbj_free(config); return result;
invalid:
    sbw_fail(error, "INVALID_CONFIGURATION", "The downloaded configuration is invalid."); return NULL;
}
static bool identity_valid(const sbj *identity) {
    if (sbw_identity_is_independent(identity)) {
        const char *empty[] = {"server", "host_id", "agent_token"};
        for (size_t i = 0; i < 3; ++i) if (!sbj_string_is(sbj_get(identity, empty[i]), "")) return false;
        return sbj_is_array(sbj_get(identity, "local_subscriptions")) &&
            sbw_json_string(sbj_get(identity, "profile_id"), 4096, false) &&
            sbw_json_string(sbj_get(identity, "profile_name"), 4096, false);
    }
    const char *required[] = {"server", "host_id", "agent_token"};
    const char *optional[] = {"host_name", "profile_id", "profile_name"};
    if (!sbj_is_object(identity)) return false;
    for (size_t i = 0; i < 3; ++i) {
        if (!sbw_json_string(sbj_get(identity, required[i]), 4096, false) ||
            !sbw_json_string(sbj_get(identity, optional[i]), 4096, true)) return false;
    }
    const char *server = sbj_get_str(identity, "server", "");
    return strncmp(server, "https://", 8) == 0 || strncmp(server, "http://", 7) == 0;
}
static sbj *profile(const sbj *source) {
    if (!source) return sbj_null();
    sbj *result = sbj_object();
    sbj_set_str(result, "id", sbj_get_str(source, "profile_id", ""));
    sbj_set_str(result, "name", sbj_get_str(source, "profile_name", ""));
    return result;
}
static sbj *enrollment_status(sbw_controller *controller) {
    sbj *result = sbj_object();
    bool independent = sbw_identity_is_independent(controller->identity);
    sbj_set_bool(result, "enrolled", controller->identity != NULL && !independent);
    sbj_set_str(result, "mode", independent ? "independent" : controller->identity ? "managed" : "unconfigured");
    sbj_set_bool(result, "managed_available", (!independent && controller->identity) || controller->managed_archive);
    sbj_set_bool(result, "independent_available", independent || controller->independent_archive);
    sbj_set_str(result, "phase", controller->startup_error.code[0] ? "ERROR" : sb_windows_phase_name(controller->runtime.phase));
    sbj_set_str(result, "host_id", sbj_get_str(controller->identity, "host_id", NULL));
    sbj_set_str(result, "host_name", sbj_get_str(controller->identity, "host_name", NULL));
    sbj_set_str(result, "server_origin", sbj_get_str(controller->identity, "server", NULL));
    sbj_set(result, "profile", profile(controller->identity));
    if (controller->startup_error.code[0]) {
        sbj *failure = sbj_object();
        sbj_set_str(failure, "code", controller->startup_error.code);
        sbj_set_str(failure, "message", "Stored device state is unavailable; it was left unchanged.");
        sbj_set(result, "error", failure);
    }
    return result;
}
static sbj *config_summary(sbw_controller *controller) {
    sbj *result = sbj_object(), *counts;
    sbj_set_bool(result, "gpt_use_default", sbj_get_bool(controller->identity, "windows_gpt_use_default", false));
    sbj_set_str(result, "gpt_outbound", sbj_get_str(controller->identity, "windows_gpt_outbound", NULL));
    sbj_set(result, "subscriptions", sbw_subscriptions_summary(controller->active ? controller->active : controller->candidate, controller->identity));
    sbj_set(result, "routing_groups", sbw_routing_groups(controller->active ? controller->active : controller->candidate, controller->identity));
    sbj_set(result, "health_policy", sbw_health_policy(controller->identity));
    sbj_set(result, "health", sbj_clone(controller->health_snapshot));
    sbj_set_bool(result, "routing_live", controller->active && controller->runtime.core_running);
    sbj_set_bool(result, "candidate_available", controller->candidate != NULL);
    sbj_set_str(result, "downloaded_etag", sbj_get_str(controller->candidate, "etag", NULL));
    sbj_set_str(result, "active_etag", sbj_get_str(controller->active, "etag", NULL));
    sbj_set_str(result, "last_good_etag", sbj_get_str(controller->last_good, "etag", NULL));
    sbj_set_str(result, "rule_source", sbj_get_str(controller->candidate, "rule_source", NULL));
    sbj_set(result, "profile", profile(controller->candidate ? controller->candidate : controller->identity));
    if (controller->candidate) counts = config_counts(controller->candidate, NULL);
    else {
        counts = sbj_object();
        sbj_set_int(counts, "inbounds", 0); sbj_set_int(counts, "outbounds", 0); sbj_set_int(counts, "rules", 0);
    }
    sbj_set(result, "counts", counts ? counts : sbj_null());
    sbj *validation = sbj_object();
    sbj_set_str(validation, "state", !controller->core ? "unavailable" :
        !controller->checked_etag ? "not_checked" : controller->checked_valid ? "valid" : "invalid");
    sbj_set_str(validation, "checked_etag", controller->checked_etag);
    sbj_set_str(validation, "core_version", SB_EASY_CORE_VERSION);
    if (controller->core_error.code[0]) {
        sbj *error = sbj_object();
        sbj_set_str(error, "code", controller->core_error.code); sbj_set_str(error, "message", controller->core_error.message);
        sbj_set(validation, "error", error);
    }
    sbj_set(result, "validation", validation);
    return result;
}
static sbj *persisted_state(sbw_controller *controller, const sbj *identity, const sbj *candidate, const sbj *last_good) {
    sbj *state = sbj_object();
    sbj_set_int(state, "version", 1);
    sbj_set(state, "management", sbj_clone(controller->management_settings));
    sbj_set(state, "command_receipts", sbj_clone(controller->command_receipts));
    sbj_set(state, "managed_archive", sbj_clone(controller->managed_archive));
    sbj_set(state, "independent_archive", sbj_clone(controller->independent_archive));
    sbj_set(state, "identity", sbj_clone(identity));
    sbj_set(state, "candidate", candidate ? sbj_clone(candidate) : sbj_null());
    sbj *good = last_good ? sbj_clone(last_good) : sbj_null();
    /* Saved node credentials and local policy are part of the known-good
     * configuration. Keep them with the base bytes across stopped edits. */
    if (last_good && (last_good != controller->last_good || controller->runtime.core_running || !sbj_has(good, "local_identity")))
        sbj_set(good, "local_identity", sbj_clone(identity));
    sbj_set(state, "last_good", good);
    return state;
}
static int save_state(sbw_controller *controller, const sbj *identity, const sbj *candidate, const sbj *last_good, sbw_error *error) {
    sbj *saved = persisted_state(controller, identity, candidate, last_good);
    int result = controller->store->save(controller->store->context, saved, error);
    if (!result && last_good && last_good == controller->last_good && controller->runtime.core_running) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_set(controller->last_good, "local_identity", sbj_clone(identity));
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    sbj_free(saved); return result;
}
static bool saved_config_valid(const sbj *candidate) {
    if (!candidate || sbj_is_null(candidate)) return true;
    const char *keys[] = {"etag", "rule_source", "profile_id", "profile_name"};
    for (size_t i = 0; i < 4; ++i)
        if (!sbw_json_string(sbj_get(candidate, keys[i]), 4096, i >= 2)) return false;
    const sbj *local_identity = sbj_get(candidate, "local_identity");
    if (local_identity && !identity_valid(local_identity)) return false;
    sbj *counts = config_counts(candidate, NULL);
    bool valid = counts != NULL; sbj_free(counts); return valid;
}
static bool archive_valid(const sbj *archive, bool independent) {
    return !archive || sbj_is_null(archive) || (sbj_is_object(archive) &&
        identity_valid(sbj_get(archive, "identity")) &&
        sbw_identity_is_independent(sbj_get(archive, "identity")) == independent &&
        saved_config_valid(sbj_get(archive, "candidate")) && saved_config_valid(sbj_get(archive, "last_good")));
}
sbw_controller *sbw_controller_new(sbw_control_plane *remote, sbw_store *store, HANDLE cancel, sbw_error *error) {
    if (!remote || !store) {
        sbw_control_plane_free(remote); sbw_store_free(store);
        sbw_fail(error, "INITIALIZATION_FAILED", "Service dependencies are unavailable."); return NULL;
    }
    sbw_controller *controller = sb_xcalloc(1, sizeof *controller);
    controller->traffic_storage_ok = controller->traffic_load_ok = true;
    controller->management_settings = default_management_settings();
    controller->command_receipts = sbj_array();
    controller->kill_switch = sbw_kill_switch_status();
    controller->health = sbw_health_new(); controller->health_snapshot = sbw_health_snapshot(NULL);
    controller->preferences_cloud = sbw_preferences_cloud_new(NULL, NULL);
    controller->remote = remote; controller->store = store; controller->cancel = cancel;
    InitializeSRWLock(&controller->state_lock); InitializeSRWLock(&controller->mutation_lock);
    InitializeSRWLock(&controller->user_operation_lock); InitializeSRWLock(&controller->upload_lock);
    sb_windows_runtime_init(&controller->runtime);
    sbj *saved = NULL;
    if (store->load(store->context, &saved, &controller->startup_error) != 0) return controller;
    if (!saved) return controller;
    const sbj *identity = sbj_get(saved, "identity"), *candidate = sbj_get(saved, "candidate");
    bool valid = sbj_is_object(saved) && sbj_is_integer(sbj_get(saved, "version")) &&
        sbj_get_int(saved, "version", 0) == 1 && (sbj_is_null(identity) || identity_valid(identity));
    const sbj *last_good = sbj_get(saved, "last_good");
    const sbj *managed = sbj_get(saved, "managed_archive"), *independent = sbj_get(saved, "independent_archive");
    valid = valid && saved_config_valid(candidate) && saved_config_valid(last_good) &&
        archive_valid(managed, false) && archive_valid(independent, true);
    if (valid) {
        controller->managed_archive = managed && !sbj_is_null(managed) ? sbj_clone(managed) : NULL;
        controller->independent_archive = independent && !sbj_is_null(independent) ? sbj_clone(independent) : NULL;
        const sbj *settings = sbj_get(saved, "management"), *receipts = sbj_get(saved, "command_receipts");
        const char *flags[] = {"auto_connect", "auto_reconnect", "telemetry_enabled", "manual_disconnect", "kill_switch_enabled"};
        for (size_t i = 0; i < sizeof flags / sizeof *flags; ++i)
            if (sbj_is_bool(sbj_get(settings, flags[i])))
                sbj_set_bool(controller->management_settings, flags[i], sbj_get_bool(settings, flags[i], false));
        int64_t interval = sbj_get_int(settings, "sync_interval_seconds", 30);
        if (interval >= 15 && interval <= 3600) sbj_set_int(controller->management_settings, "sync_interval_seconds", interval);
        if (sbj_is_array(receipts) && sbj_arr_len(receipts) <= 128) {
            sbj_free(controller->command_receipts); controller->command_receipts = sbj_clone(receipts);
        }
        sb_windows_recovery_request(&controller->recovery,
            sbj_get_bool(controller->management_settings, "auto_connect", false) &&
            !sbj_get_bool(controller->management_settings, "manual_disconnect", false), GetTickCount64());
        controller->identity = sbj_is_null(identity) ? NULL : sbj_clone(identity);
        controller->candidate = sbj_is_null(candidate) ? NULL : sbj_clone(candidate);
        controller->last_good = !last_good || sbj_is_null(last_good) ? NULL : sbj_clone(last_good);
        if (controller->identity) sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ENROLL);
    } else sbw_fail(&controller->startup_error, "STORAGE_CORRUPT", "Stored device state is unavailable; it was left unchanged.");
    sbj_free(saved); return controller;
}
void sbw_controller_free(sbw_controller *controller) {
    if (!controller) return;
    if (controller->interface_notification) CancelMibChangeNotify2(controller->interface_notification);
    if (controller->management_stop) SetEvent(controller->management_stop);
    if (controller->management_io_cancel) SetEvent(controller->management_io_cancel);
    if (controller->management_thread) {
        WaitForSingleObject(controller->management_thread, INFINITE); CloseHandle(controller->management_thread);
    }
    if (controller->management_stop) CloseHandle(controller->management_stop);
    if (controller->management_io_cancel) CloseHandle(controller->management_io_cancel);
    sbw_store_join();
    if (controller->monitor_stop) SetEvent(controller->monitor_stop);
    if (controller->monitor) { WaitForSingleObject(controller->monitor, INFINITE); CloseHandle(controller->monitor); }
    if (controller->monitor_stop) CloseHandle(controller->monitor_stop);
    sbj_free(controller->management_settings); sbj_free(controller->command_receipts); sbj_free(controller->kill_switch);
    sbw_health_free(controller->health); sbj_free(controller->health_snapshot);
    sbw_preferences_cloud_free(controller->preferences_cloud);
    sbw_updater_free(controller->updater);
    sbj_free(controller->preferences_pending); sbj_free(controller->preferences_base); sbj_free(controller->preferences_source);
    free(controller->auto_attempted_etag);
    capture_upload_join(controller); sbw_capture_free(controller->capture); controller->capture = NULL;
    sbw_extension_process_free(controller->httpdebug);sbw_secret_free(controller->httpdebug_base);sbj_free(controller->httpdebug_domains);
    /* All IPC workers are joined by the caller before freeing this owner. */
    sbw_core_stop(controller->core, NULL);
    sbw_runtime_config_free(&controller->active_config);
    sbj_free(controller->managed_archive); sbj_free(controller->independent_archive);
    sbj_free(controller->identity); sbj_free(controller->candidate);
    sbj_free(controller->last_good); sbj_free(controller->active);
    persist_traffic(controller); sbw_traffic_free(controller->traffic);
    sbw_core_free(controller->core); free(controller->checked_etag);
    sbw_control_plane_free(controller->remote); sbw_store_free(controller->store); free(controller);
}
void sbw_controller_set_core(sbw_controller *controller, sbw_core *core, const sbw_error *error) {
    sbw_core_free(controller->core); controller->core = core;
    memset(&controller->core_error, 0, sizeof controller->core_error);
    if (error && !core) controller->core_error = *error;
    free(controller->checked_etag); controller->checked_etag = NULL; controller->checked_valid = false;
    if (core && !controller->monitor) {
        controller->monitor_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
        controller->monitor = controller->monitor_stop ? CreateThread(NULL, 0, monitor_main, controller, 0, NULL) : NULL;
        if (!controller->monitor) {
            if (controller->monitor_stop) CloseHandle(controller->monitor_stop);
            controller->monitor_stop = NULL;
            sbw_core_free(controller->core); controller->core = NULL;
            sbw_fail(&controller->core_error, "INITIALIZATION_FAILED", "The core health monitor could not be started.");
        }
    }
}
void sbw_controller_set_updater(sbw_controller *controller, sbw_updater *updater) {
    sbw_updater_free(controller->updater); controller->updater = updater;
}
bool sbw_is_mutating_method(const char *method) {
    if (!strncmp(method, "updates.", 8) && strcmp(method, "updates.status")) return true;
    if (!strncmp(method, "preferences.", 12)) return true;
    if (sb_streq(method, "routing.health.set") || sb_streq(method, "routing.automatic.set") || sb_streq(method, "routing.health.check")) return true;
    if(sb_streq(method,"httpdebug.start")||sb_streq(method,"httpdebug.attach")||sb_streq(method,"httpdebug.stop"))return true;
    return sb_streq(method,"mode.set") || sb_streq(method,"management.settings.set") || sb_streq(method,"routing.group_save") || sb_streq(method,"routing.group_remove") || sb_streq(method,"routing.probe") || sb_streq(method,"routing.delay") || sb_streq(method,"extensions.install") || sb_streq(method,"extensions.change") || sb_streq(method,"extensions.catalog_update") || sb_streq(method,"extensions.rollback") || (sb_streq(method,"subscriptions.fetch") || sb_streq(method,"subscriptions.save") || sb_streq(method,"subscriptions.remove") || sb_streq(method,"subscriptions.import") || sb_streq(method,"subscriptions.refresh")) || sb_streq(method, "traffic.clear") || sb_streq(method, "routing.gpt_default") || sb_streq(method, "routing.gpt_server") || sb_streq(method, "routing.gpt_node") || sb_streq(method, "routing.set") || sb_streq(method, "enrollment.apply") || sb_streq(method, "enrollment.forget") ||
        sb_streq(method, "config.refresh") || sb_streq(method, "config.validate") ||
        sb_streq(method, "connection.start") || sb_streq(method, "connection.stop");
}
static bool ready(sbw_controller *controller, sbw_error *error) {
    if (!controller->startup_error.code[0]) return true;
    sbw_fail(error, controller->startup_error.code, "Stored device state is unavailable; it was left unchanged."); return false;
}
static bool cancelled(sbw_controller *controller, sbw_error *error) {
    if (!controller->cancel || WaitForSingleObject(controller->cancel, 0) != WAIT_OBJECT_0) return false;
    sbw_fail(error, "CANCELLED", "The service is stopping."); return true;
}
/* Call with state_lock held. Process existence is insufficient for activation. */
static sbj *runtime_status(sbw_controller *controller) {
    sbj *result = enrollment_status(controller);
    sbj_set_bool(result, "core_running", controller->runtime.core_running);
    sbj_set_bool(result, "stop_forced", controller->last_stop_forced);
    sbj_set_bool(result, "connection_available", controller->core && controller->identity &&
        controller->candidate && !controller->startup_error.code[0] &&
        (!sbw_identity_is_independent(controller->identity) || sbj_arr_len(sbj_get(controller->identity,"local_subscriptions"))));
    sbj_set_bool(result, "tun_active", controller->runtime.core_running && controller->active_config.has_tun &&
        controller->active_config.auto_route);
    sbj_set_str(result, "connection_mode", controller->active ?
        (controller->active_config.has_tun ? "tun" : "local") : NULL);
    sbj_set(result, "config", config_summary(controller));
    sbj_set(result, "management", management_status(controller));
    sbj_set(result, "ipv6", sbw_runtime_ipv6_status(&controller->active_config, controller->runtime.core_running));
    if (controller->runtime_error.code[0]) {
        sbj *failure = sbj_object();
        sbj_set_str(failure, "code", controller->runtime_error.code);
        sbj_set_str(failure, "message", controller->runtime_error.message);
        sbj_set(result, "runtime_error", failure);
    }
    return result;
}
static void clear_active(sbw_controller *controller) {
    sbw_extension_process_free(controller->httpdebug);controller->httpdebug=NULL;
    sbw_secret_free(controller->httpdebug_base);controller->httpdebug_base=NULL;
    sbj_free(controller->httpdebug_domains);controller->httpdebug_domains=NULL;
    sbw_capture_observe(controller->capture, 0, NULL, NULL);
    sbj_free(controller->active); controller->active = NULL;
    sbw_runtime_config_free(&controller->active_config);
    controller->runtime.core_running = false;
}
static void record_check(sbw_controller *controller, bool valid, const sbw_error *error) {
    AcquireSRWLockExclusive(&controller->state_lock);
    sb_str_set(&controller->checked_etag, sbj_get_str(controller->candidate, "etag", ""));
    controller->checked_valid = valid;
    memset(&controller->core_error, 0, sizeof controller->core_error);
    if (!valid && error) controller->core_error = *error;
    ReleaseSRWLockExclusive(&controller->state_lock);
}
static int prepare_with_identity(const sbj *identity, const sbj *source, sbw_runtime_config *config, sbw_error *error) {
    const sbj *content = sbj_get(source, "content");
    if (!content) return sbw_fail(error, "NO_CANDIDATE", "Download a candidate configuration before starting.");
    sbj *effective = sbw_routing_apply(source, identity, true, error);
    if (!effective) return -1;
    content = sbj_get(effective, "content");
    int result = sbw_runtime_config_prepare(content->v.str.ptr, content->v.str.len,
        sbj_get_str(identity, "server", ""), config, error);
    sbj_free(effective); return result;
}
static int prepare_candidate(sbw_controller *controller,const sbj *source,sbw_runtime_config *config,sbw_error *error) {
    return prepare_with_identity(controller->identity,source,config,error);
}
static int check_config(sbw_controller *controller, sbw_runtime_config *config, sbw_error *error) {
    return sbw_core_config_check(controller->core, config->json, strlen(config->json), controller->cancel, NULL, error);
}
static int apply_kill_switch(sbw_controller *controller, bool enabled, const wchar_t *tun, sbw_error *error) {
    if (enabled && sbw_kill_switch_recovery_disabled())
        return sbw_fail(error, "KILL_SWITCH_RECOVERY_ACTIVE", "Administrator recovery must be persisted before leak protection can be enabled again.");
    if (enabled && !controller->core) return sbw_fail(error, "CORE_UNAVAILABLE", "A pinned core executable is required before enabling leak protection.");
    int result = sbw_kill_switch_apply(enabled, sbw_core_executable(controller->core), tun, error);
    sbj *status = sbw_kill_switch_status();
    AcquireSRWLockExclusive(&controller->state_lock);
    sbj_free(controller->kill_switch); controller->kill_switch = status;
    ReleaseSRWLockExclusive(&controller->state_lock);
    return result;
}
static int launch_healthy(sbw_controller *controller, sbw_runtime_config *config, sbw_error *error) {
    bool protection = sbj_get_bool(controller->management_settings, "kill_switch_enabled", false);
    if (protection && apply_kill_switch(controller, true, NULL, error) != 0) return -1;
    if (sbw_core_start(controller->core, config->json, strlen(config->json), controller->cancel, error) != 0) return -1;
    sbw_traffic_new_core(controller->traffic);
    sbw_core_status status = {0};
    if (sbw_core_poll(controller->core, &status, error) != 0 || !status.process_running)
        return sbw_fail(error, "CORE_EXITED", "The core exited during startup.");
    /* The Clash API starts after remote rule sets initialize. Cold downloads
     * must not be treated as a failed TUN after the old three-second deadline.
     * A cold Wintun adapter also takes over three seconds on some machines. */
    if (sbw_runtime_config_health(config, status.process_id, controller->cancel,
                                 config->remote_rule_sets ? 25000 : config->has_tun ? 10000 : 3000, error) != 0) return -1;
    sbj *runtime = sbj_parse_cstr(config->json);
    const sbj *nodes = sbj_get(runtime, "outbounds");
    int selected = 0;
    for (size_t i = 0; i < sbj_arr_len(nodes); ++i) {
        const sbj *node = sbj_arr_at(nodes, i);
        if (!strncmp(sbj_get_str(node, "tag", ""), "sb-easy-local-", 14)) {
            selected = sbw_runtime_select_group(config, status.process_id, controller->cancel,
                sbj_get_str(node, "tag", ""), sbj_get_str(node, "default", ""), error);
            if (selected != 0) break;
        }
    }
    sbj_free(runtime);
    if (selected != 0 || cancelled(controller, error)) return -1;
    if (protection && apply_kill_switch(controller, true, config->interface_name, error) != 0) return -1;
    return 0;
}
/* mutation_lock serializes this with start/stop; only short state commits take
 * state_lock so the GUI can read STARTING/ROLLING_BACK while I/O is in progress. */
static void observe_core(sbw_controller *controller, bool health) {
    if (!controller->core || !controller->active || !controller->runtime.core_running) return;
    sbw_error error = {0}; sbw_core_status status = {0};
    int polled = sbw_core_poll(controller->core, &status, &error);
    if (polled != 0 && sb_streq(error.code, "CORE_BUSY")) return;
    if (polled == 0 && status.process_running && (!health ||
        sbw_runtime_config_health(&controller->active_config, status.process_id, controller->monitor_stop, 600, &error) == 0)) return;
    bool tun = controller->active_config.has_tun;
    sbw_core_stop(controller->core, NULL);
    AcquireSRWLockExclusive(&controller->state_lock);
    clear_active(controller);
    sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_CORE_FAILED);
    if (sbj_get_bool(controller->management_settings, "auto_reconnect", true))
        sb_windows_recovery_failed(&controller->recovery, GetTickCount64());
    sbw_fail(&controller->runtime_error, tun ? "TUN_CORE_LOST" : "CORE_EXITED", tun ?
        "The TUN core stopped unexpectedly. Its connection is no longer active; verify network recovery before reconnecting." :
        "The core exited or its authenticated local health endpoint became unavailable.");
    ReleaseSRWLockExclusive(&controller->state_lock);
}
void sbw_controller_poll(sbw_controller *controller) {
    if (!controller || !TryAcquireSRWLockExclusive(&controller->mutation_lock)) return;
    observe_core(controller, false);
    ReleaseSRWLockExclusive(&controller->mutation_lock);
}
static DWORD WINAPI monitor_main(void *context) {
    sbw_controller *controller = context;
    while (WaitForSingleObject(controller->monitor_stop, 2000) == WAIT_TIMEOUT) {
        if (controller->cancel && WaitForSingleObject(controller->cancel, 0) == WAIT_OBJECT_0) break;
        if (TryAcquireSRWLockExclusive(&controller->mutation_lock)) {
            if (!sbw_updater_installing(controller->updater)) {
                observe_core(controller, true);
                collect_traffic(controller);
                capture_auto_upload(controller);
            }
            ReleaseSRWLockExclusive(&controller->mutation_lock);
        }
    }
    return 0;
}
static void persist_traffic(sbw_controller *controller) {
    if (!controller->core || !controller->traffic || !controller->traffic_load_ok) return;
    sbj *data = sbw_traffic_snapshot(controller->traffic); sbw_error error = {0};
    if(!data){controller->traffic_storage_ok=false;return;}
    controller->traffic_storage_ok = sbw_core_traffic_save(controller->core, data, &error) == 0;
    if (!controller->traffic_storage_ok)
        sbw_core_event(controller->core, "traffic-save", error.code);
    sbj_free(data); controller->traffic_saved = GetTickCount64();
}
static void ensure_statistics(sbw_controller *controller) {
    if(controller->traffic||!controller->core||!sbw_extension_is_enabled("statistics"))return;
    controller->traffic=sbw_traffic_new();sbj *saved=NULL;sbw_error error={0};
    controller->traffic_storage_ok=sbw_core_traffic_load(controller->core,&saved,&error)==0;
    if(saved&&controller->traffic_storage_ok)controller->traffic_storage_ok=sbw_traffic_restore(controller->traffic,saved);
    controller->traffic_load_ok=controller->traffic_storage_ok;sbj_free(saved);controller->traffic_saved=GetTickCount64();
}
static bool collect_traffic(sbw_controller *controller) {
    ensure_statistics(controller);
    if(!controller->traffic&&!sbw_extension_enabled())return true;
    if (!controller->active || !controller->runtime.core_running) return true;
    if (!controller->capture && controller->identity && controller->core && sbw_extension_enabled())
        controller->capture = sbw_capture_new(sbw_core_work_directory(controller->core), controller->identity, NULL);
    sbw_core_status process = {0}; sbj *connections = NULL; sbw_error error = {0}; bool collected = false;
    if (sbw_core_poll(controller->core, &process, &error) == 0 && process.process_running &&
        sbw_runtime_config_get(&controller->active_config, process.process_id, controller->monitor_stop,
                               "/connections", &connections, &error) == 0) {
        sbw_traffic_record(controller->traffic, connections, process.process_id);
        sbw_capture_observe(controller->capture, process.process_id, controller->active_config.interface_name, connections);
        collected = true;
    }
    sbj_free(connections);
    if (GetTickCount64() - controller->traffic_saved >= 30000) persist_traffic(controller);
    return collected;
}
static int connection_stop(sbw_controller *controller, sbw_error *error) {
    collect_traffic(controller); persist_traffic(controller);
    sbw_capture_observe(controller->capture, 0, NULL, NULL);
    bool had_tun = controller->active_config.has_tun;
    int stopped = sbw_core_stop(controller->core, error);
    if (sbj_get_bool(controller->management_settings, "kill_switch_enabled", false)) {
        sbw_error protection_error = {0};
        if (apply_kill_switch(controller, true, NULL, &protection_error) != 0 && stopped == 0) {
            stopped = sbw_fail(error, protection_error.code, protection_error.message);
        }
    }
    sbw_core_status status = {0};
    if (stopped == 0 && controller->core) (void)sbw_core_poll(controller->core, &status, NULL);
    if (stopped == 0 && had_tun && status.last_stop_forced) {
        char message[256];
        (void)sprintf_s(message, sizeof(message), "The TUN core required forced termination (stop helper: %lu); network cleanup has not been verified.", status.stop_signal_code);
        stopped = sbw_fail(error, "TUN_FORCE_STOPPED", message);
    }
    AcquireSRWLockExclusive(&controller->state_lock);
    clear_active(controller);
    sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_STOP);
    controller->last_stop_forced = status.last_stop_forced;
    memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
    if (stopped != 0) {
        controller->runtime.phase = SB_WINDOWS_DEGRADED;
        if (error) controller->runtime_error = *error;
    }
    ReleaseSRWLockExclusive(&controller->state_lock);
    return stopped;
}
static int connection_activate(sbw_controller *controller, const sbj *source, const sbj *identity, bool force, sbw_error *error) {
    if (!controller->identity) return sbw_fail(error, "NOT_ENROLLED", "Enroll this device before starting a connection.");
    if (!source) return sbw_fail(error, "NO_CANDIDATE", "Download a candidate configuration before starting.");
    if (sbw_identity_is_independent(identity) && !sbj_arr_len(sbj_get(identity, "local_subscriptions")))
        return sbw_fail(error, "NO_SUBSCRIPTIONS", "Import at least one proxy subscription before connecting independently.");
    if (!controller->core) return sbw_fail(error, "CORE_UNAVAILABLE", "Prepare the pinned core and restart the service first.");
    if (!force && controller->active && sbj_equal(controller->active, source)) return 0;
    sbw_runtime_config next = {0}; sbw_error failure = {0};
    /* A rejected candidate must never interrupt a healthy old instance. */
    if (prepare_with_identity(identity, source, &next, &failure) != 0 ||
        check_config(controller, &next, &failure) != 0) {
        record_check(controller, false, &failure);
        sbw_runtime_config_free(&next); return sbw_fail(error, failure.code, failure.message);
    }
    record_check(controller, true, NULL);
    if (sbw_core_preflight(controller->core, next.has_tun, &failure) != 0) {
        AcquireSRWLockExclusive(&controller->state_lock); controller->runtime_error = failure;
        ReleaseSRWLockExclusive(&controller->state_lock);
        sbw_runtime_config_free(&next); return sbw_fail(error, failure.code, failure.message);
    }
    if (connection_stop(controller, &failure) != 0) {
        sbw_runtime_config_free(&next); return sbw_fail(error, failure.code, failure.message);
    }
    AcquireSRWLockExclusive(&controller->state_lock);
    sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_START);
    ReleaseSRWLockExclusive(&controller->state_lock);
    bool started = launch_healthy(controller, &next, &failure) == 0;
    /* Commit last-good only after exact-config check, process start and health.
     * If durable commit fails, restore the previous known-good process. */
    if (started && save_state(controller, identity, sbw_identity_is_independent(identity) ? source : controller->candidate, source, &failure) == 0) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj *saved_identity = sbj_clone(identity), *saved_good = sbj_clone(source), *saved_active = sbj_clone(source);
        sbj_set(saved_good, "local_identity", sbj_clone(identity));
        if (sbw_identity_is_independent(identity)) {
            sbj *saved_candidate = sbj_clone(source); sbj_free(controller->candidate); controller->candidate = saved_candidate;
        }
        sbj_free(controller->identity); controller->identity = saved_identity;
        sbj_free(controller->last_good); controller->last_good = saved_good;
        controller->active = saved_active;
        controller->active_config = next; memset(&next, 0, sizeof next);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_CORE_HEALTHY);
        sb_windows_recovery_healthy(&controller->recovery, GetTickCount64());
        memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        ReleaseSRWLockExclusive(&controller->state_lock);
        return 0;
    }
    sbw_error cleanup_error = {0}; sbw_core_status cleaned = {0};
    bool safe_to_restore = sbw_core_stop(controller->core, &cleanup_error) == 0;
    if (safe_to_restore && sbw_core_poll(controller->core, &cleaned, &cleanup_error) != 0) safe_to_restore = false;
    if (safe_to_restore && next.has_tun && cleaned.last_stop_forced) {
        safe_to_restore = false;
        sbw_fail(&cleanup_error, "TUN_FORCE_STOPPED", "The failed TUN core required forced termination; network cleanup must be verified before restoring another configuration.");
    }
    if (!safe_to_restore) {
        char message[256];
        (void)sprintf_s(message, sizeof(message),
            "Core startup failed (%s). Cleanup also failed (%s); verify network recovery before reconnecting.",
            failure.code, cleanup_error.code);
        sbw_fail(&failure, cleanup_error.code, message);
    }
    sbw_runtime_config_free(&next);
    bool rollback = safe_to_restore && controller->last_good && !cancelled(controller, NULL);
    if (rollback) {
        AcquireSRWLockExclusive(&controller->state_lock);
        controller->runtime.phase = SB_WINDOWS_ROLLING_BACK;
        ReleaseSRWLockExclusive(&controller->state_lock);
        sbw_error restore_error = {0};
        const sbj *good_identity = sbj_get(controller->last_good, "local_identity");
        rollback = prepare_with_identity(good_identity ? good_identity : controller->identity, controller->last_good, &next, &restore_error) == 0 &&
            sbw_core_preflight(controller->core, next.has_tun, &restore_error) == 0 &&
            launch_healthy(controller, &next, &restore_error) == 0;
    }
    if (!rollback && safe_to_restore) {
        sbw_error restore_cleanup = {0}; sbw_core_status restored = {0};
        bool stopped = sbw_core_stop(controller->core, &restore_cleanup) == 0 &&
            sbw_core_poll(controller->core, &restored, &restore_cleanup) == 0;
        if (!stopped) failure = restore_cleanup;
        else if (next.has_tun && restored.last_stop_forced)
            sbw_fail(&failure, "TUN_FORCE_STOPPED", "Restoring the TUN configuration failed and required forced termination; verify network recovery before reconnecting.");
    }
    AcquireSRWLockExclusive(&controller->state_lock);
    if (rollback) {
        const sbj *good_identity = sbj_get(controller->last_good, "local_identity");
        if (good_identity) { sbj *restored_identity = sbj_clone(good_identity); sbj_free(controller->identity); controller->identity = restored_identity; }
        controller->active = sbj_clone(controller->last_good);
        controller->active_config = next; memset(&next, 0, sizeof next);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ROLLBACK_SUCCEEDED);
        sbw_fail(&controller->runtime_error, "ROLLED_BACK", "The new configuration could not be activated. The last working configuration was restored.");
    } else {
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_CORE_FAILED);
        controller->runtime_error = failure;
    }
    sbw_error final_error = controller->runtime_error;
    ReleaseSRWLockExclusive(&controller->state_lock);
    sbw_runtime_config_free(&next);
    return sbw_fail(error, final_error.code, final_error.message);
}
/* All helpers below run under mutation_lock; readers take state_lock. */
static int refresh_configuration(sbw_controller *controller, bool force, HANDLE cancel, sbw_error *error) {
    if (!controller->identity) return sbw_fail(error, "NOT_ENROLLED", "Enroll this device before downloading configuration.");
    if (sbw_identity_is_independent(controller->identity))
        return sbw_fail(error, "INDEPENDENT_MODE", "This device uses local subscriptions; refresh a subscription to update its nodes.");
    sbj *download = NULL;
    const char *etag = force ? "" : sbj_get_str(controller->candidate, "etag", "");
    if (controller->remote->fetch_config(controller->remote->context, controller->identity, etag,
                                         cancel, &download, error) != 0) return -1;
    int result = -1;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
        sbw_fail(error, "CANCELLED", "The background operation was interrupted."); goto done;
    }
    if (sbj_get_bool(download, "not_modified", false)) {
        if (!controller->candidate) sbw_fail(error, "INVALID_RESPONSE", "The server returned no configuration for this device.");
        else result = 0;
        goto done;
    }
    sbj *counts = config_counts(download, error);
    if (!counts) goto done;
    sbj_free(counts);
    if (!sbw_json_string(sbj_get(download, "etag"), 4096, false)) {
        sbw_fail(error, "INVALID_RESPONSE", "The downloaded configuration has no valid revision."); goto done;
    }
    const char *source = sbj_get_str(download, "rule_source", "");
    if (!sb_streq(source, "profile") && !sb_streq(source, "quickjs")) sbj_set_str(download, "rule_source", "unknown");
    const char *keys[] = {"profile_id", "profile_name"};
    for (size_t i = 0; i < 2; ++i)
        if (!sbw_json_string(sbj_get(download, keys[i]), 4096, false))
            sbj_set_str(download, keys[i], sbj_get_str(controller->identity, keys[i], ""));
    sbj_del(download, "not_modified");
    sbj *effective = sbw_routing_apply(download, controller->identity, false, error);
    if (!effective) goto done;
    sbj_free(effective);
    /* Equal revisions may still carry profile/source metadata updates. */
    if (sbj_equal(download, controller->candidate)) { result = 0; goto done; }
    if (save_state(controller, controller->identity, download, controller->last_good, error) != 0) goto done;
    AcquireSRWLockExclusive(&controller->state_lock);
    sbj_free(controller->candidate); controller->candidate = download; download = NULL;
    free(controller->checked_etag); controller->checked_etag = NULL;
    controller->checked_valid = false;
    if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
    ReleaseSRWLockExclusive(&controller->state_lock);
    result = 0;
done:
    sbj_free(download); return result;
}
static sbj *management_status(sbw_controller *controller) {
    sbj *result = sbj_clone(controller->management_settings);
    bool known = sbj_is_bool(sbj_get(controller->management_settings, "kill_switch_enabled"));
    sbj_set_bool(result, "kill_switch_enabled", sbj_get_bool(controller->management_settings, "kill_switch_enabled", false));
    sbj_set_bool(result, "kill_switch_preference_known", known);
    sbj_set_bool(result, "kill_switch_recovery_required", !known && sbj_get_int(controller->kill_switch, "filter_count", 0) > 0);
    sbj_set(result, "kill_switch", sbj_clone(controller->kill_switch));
    sbj_set_bool(result, "desired_connected", controller->recovery.desired_connected);
    sbj_set_bool(result, "worker_running", controller->management_running);
    sbj_set_int(result, "retry_attempt", controller->recovery.attempts);
    uint64_t now = GetTickCount64(), due = controller->recovery.retry_at_ms;
    sbj_set_int(result, "retry_in_seconds", due > now ? (int64_t)((due - now + 999) / 1000) : 0);
    sbj_set_int(result, "last_sync_at", (int64_t)controller->last_sync_at);
    sbj_set_int(result, "last_report_at", (int64_t)controller->last_report_at);
    sbj_set_str(result, "last_error", controller->management_error.code[0] ? controller->management_error.message : NULL);
    sbj_set_str(result, "last_error_code", controller->management_error.code[0] ? controller->management_error.code : NULL);
    return result;
}
static int replace_management_settings(sbw_controller *controller, sbj *settings, sbw_error *error) {
    /* Store before publishing, so failed writes cannot make UI claim durability. */
    sbj *saved = persisted_state(controller, controller->identity, controller->candidate, controller->last_good);
    sbj_set(saved, "management", sbj_clone(settings));
    int result = controller->store->save(controller->store->context, saved, error);
    sbj_free(saved);
    if (!result) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->management_settings); controller->management_settings = sbj_clone(settings);
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    return result;
}
static int management_settings_change(sbw_controller *controller, const sbj *params, sbw_error *error) {
    if (!sbj_obj_len(params)) return sbw_fail(error, "INVALID_REQUEST", "Choose at least one management setting.");
    sbj *next = sbj_clone(controller->management_settings);
    for (size_t i = 0; i < sbj_obj_len(params); ++i) {
        const char *key = sbj_obj_key(params, i); const sbj *value = sbj_obj_val(params, i);
        bool flag = sb_streq(key, "auto_connect") || sb_streq(key, "auto_reconnect") || sb_streq(key, "telemetry_enabled") || sb_streq(key, "kill_switch_enabled");
        if (flag && sbj_is_bool(value)) sbj_set(next, key, sbj_clone(value));
        else if (sb_streq(key, "sync_interval_seconds") && sbj_is_integer(value) &&
                 sbj_get_int(params, key, 0) >= 15 && sbj_get_int(params, key, 0) <= 3600)
            sbj_set(next, key, sbj_clone(value));
        else { sbj_free(next); return sbw_fail(error, "INVALID_REQUEST", "Invalid management setting or synchronization interval (15 to 3600 seconds)."); }
    }
    bool previous_protection = sbj_get_bool(controller->management_settings, "kill_switch_enabled",
        sbj_get_int(controller->kill_switch, "filter_count", 0) > 0);
    bool desired_protection = sbj_get_bool(next, "kill_switch_enabled", false);
    bool change_protection = sbj_has(params, "kill_switch_enabled");
    if (change_protection && desired_protection && sbw_kill_switch_recovery_disabled()) {
        sbj_free(next); return sbw_fail(error, "KILL_SWITCH_RECOVERY_ACTIVE", "Leak protection was disabled by administrator recovery. Restart the service successfully before enabling it again.");
    }
    const wchar_t *tun = controller->runtime.core_running ? controller->active_config.interface_name : NULL;
    int result = change_protection ? apply_kill_switch(controller, desired_protection, tun, error) : 0;
    if (!result) {
        result = replace_management_settings(controller, next, error);
        if (result && change_protection) {
            sbw_error restore = {0};
            if (apply_kill_switch(controller, previous_protection, tun, &restore) != 0) {
                AcquireSRWLockExclusive(&controller->state_lock); controller->runtime_error = restore;
                ReleaseSRWLockExclusive(&controller->state_lock);
                sbw_fail(error, "KILL_SWITCH_STATE_UNCERTAIN", "Settings could not be saved and the previous leak-protection policy could not be restored. Check the reported firewall state before continuing.");
            }
        }
    }
    sbj_free(next);
    if (!result) {
        controller->next_sync_ms = 0;
        AcquireSRWLockExclusive(&controller->state_lock);
        if (controller->recovery.desired_connected && !controller->runtime.core_running &&
            sbj_get_bool(controller->management_settings, "auto_reconnect", true) && !controller->recovery.retry_at_ms)
            controller->recovery.retry_at_ms = GetTickCount64();
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    return result;
}
static int connection_intent(sbw_controller *controller, bool connect, sbw_error *error) {
    sbj *next = sbj_clone(controller->management_settings);
    sbj_set_bool(next, "manual_disconnect", !connect);
    int result = replace_management_settings(controller, next, error); sbj_free(next);
    if (!result || !connect) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sb_windows_recovery_request(&controller->recovery, connect, GetTickCount64());
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    return result;
}
static sbj *mode_snapshot(const sbj *identity, const sbj *candidate, const sbj *last_good) {
    sbj *result = sbj_object(); sbj_set(result, "identity", sbj_clone(identity));
    sbj_set(result, "candidate", sbj_clone(candidate)); sbj_set(result, "last_good", sbj_clone(last_good)); return result;
}
static int switch_mode(sbw_controller *controller, bool independent, sbw_error *error) {
    if (controller->runtime.core_running || (controller->runtime.phase != SB_WINDOWS_STOPPED &&
        controller->runtime.phase != SB_WINDOWS_UNENROLLED))
        return sbw_fail(error, "INVALID_STATE", "Disconnect before switching usage modes.");
    if (controller->identity && sbw_identity_is_independent(controller->identity) == independent) return 0;
    sbj *managed = sbj_clone(controller->managed_archive), *local = sbj_clone(controller->independent_archive);
    if (controller->identity) {
        sbj *previous = mode_snapshot(controller->identity, controller->candidate, controller->last_good);
        if (sbw_identity_is_independent(controller->identity)) { sbj_free(local); local = previous; }
        else { sbj_free(managed); managed = previous; }
    }
    const sbj *archive = independent ? local : managed;
    sbj *identity = archive ? sbj_clone(sbj_get(archive, "identity")) : independent ? sbw_independent_identity() : NULL;
    const sbj *prior_candidate = sbj_get(archive, "candidate"), *prior_good = sbj_get(archive, "last_good");
    sbj *candidate = archive && prior_candidate && !sbj_is_null(prior_candidate) ? sbj_clone(prior_candidate) :
        independent ? sbw_independent_snapshot(identity, error) : NULL;
    sbj *last_good = prior_good && !sbj_is_null(prior_good) ? sbj_clone(prior_good) : NULL;
    int result = -1;
    if (independent && !candidate) goto done;
    sbj *settings = sbj_clone(controller->management_settings); sbj_set_bool(settings, "manual_disconnect", true);
    sbj *saved = persisted_state(controller, identity, candidate, last_good);
    sbj_set(saved, "managed_archive", sbj_clone(managed)); sbj_set(saved, "independent_archive", sbj_clone(local));
    sbj_set(saved, "management", sbj_clone(settings));
    result = controller->store->save(controller->store->context, saved, error); sbj_free(saved);
    if (!result) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->identity); controller->identity = identity; identity = NULL;
        sbj_free(controller->candidate); controller->candidate = candidate; candidate = NULL;
        sbj_free(controller->last_good); controller->last_good = last_good; last_good = NULL;
        sbj_free(controller->managed_archive); controller->managed_archive = managed; managed = NULL;
        sbj_free(controller->independent_archive); controller->independent_archive = local; local = NULL;
        sbj_free(controller->management_settings); controller->management_settings = settings; settings = NULL;
        sb_windows_runtime_init(&controller->runtime);
        if (controller->identity) sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ENROLL);
        sb_windows_recovery_request(&controller->recovery, false, GetTickCount64());
        free(controller->checked_etag); controller->checked_etag = NULL; controller->checked_valid = false;
        free(controller->auto_attempted_etag); controller->auto_attempted_etag = NULL;
        memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        memset(&controller->management_error, 0, sizeof controller->management_error);
        controller->last_sync_at = controller->last_report_at = controller->next_sync_ms = 0;
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    sbj_free(settings);
done:
    sbj_free(identity); sbj_free(candidate); sbj_free(last_good); sbj_free(managed); sbj_free(local); return result;
}
/* Apply local policy/subscription data and its candidate as a single durable
 * change. No network content or identity update can replace working bytes
 * until the exact composed configuration has passed the native checks. */
static int apply_local_identity(sbw_controller *controller, const sbj *identity, sbw_error *error) {
    bool live = controller->active && controller->runtime.core_running;
    sbj *source = sbw_identity_is_independent(identity) ? sbw_independent_snapshot(identity, error) :
        sbj_clone(live ? controller->active : controller->candidate);
    if (!source) return error && error->code[0] ? -1 : sbw_fail(error, "NO_CANDIDATE", "Download the shared configuration first.");
    int result = -1;
    if (live) result = connection_activate(controller, source, identity, true, error);
    else {
        sbw_runtime_config next = {0};
        result = prepare_with_identity(identity, source, &next, error);
        if (!result && controller->core) result = check_config(controller, &next, error);
        const sbj *candidate = sbw_identity_is_independent(identity) ? source : controller->candidate;
        if (!result) result = save_state(controller, identity, candidate, controller->last_good, error);
        if (!result) {
            AcquireSRWLockExclusive(&controller->state_lock);
            sbj *saved_identity = sbj_clone(identity), *saved_candidate = sbj_clone(candidate);
            sbj_free(controller->identity); controller->identity = saved_identity;
            sbj_free(controller->candidate); controller->candidate = saved_candidate;
            if (!controller->runtime.enrolled) sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ENROLL);
            ReleaseSRWLockExclusive(&controller->state_lock);
        }
        sbw_runtime_config_free(&next);
    }
    if (!result) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sb_str_set(&controller->checked_etag, controller->core ? sbj_get_str(controller->candidate, "etag", "") : NULL);
        controller->checked_valid = controller->core != NULL;
        if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    sbj_free(source); return result;
}
static void preferences_clear_preview(sbw_controller *c) {
    sbj_free(c->preferences_pending); sbj_free(c->preferences_base); sbj_free(c->preferences_source);
    c->preferences_pending = c->preferences_base = c->preferences_source = NULL;
    SecureZeroMemory(c->preferences_preview_id, sizeof c->preferences_preview_id); c->preferences_preview_expires = 0;
}
static sbj *preferences_export(sbw_controller *c, const char *password, sbw_error *error) {
    if (!c->identity) { sbw_fail(error, "NOT_CONFIGURED", "Set up local preferences before exporting."); return NULL; }
    sbj *payload = sbw_preferences_payload(c->identity, error);
    sbj *envelope = payload ? sbw_preferences_encrypt(payload, password, error) : NULL; sbj_free(payload); return envelope;
}
static sbj *preferences_dispatch(sbw_controller *c, const char *method, const sbj *params, sbw_error *error) {
    if (sb_streq(method, "preferences.export")) {
        if (sbj_obj_len(params) != 1 || !sbw_json_string(sbj_get(params, "password"), 1024, false)) goto invalid;
        sbj *envelope = preferences_export(c, sbj_get_str(params, "password", ""), error);
        if (!envelope) return NULL;
        sbj *result = sbj_object(); sbj_set(result, "envelope", envelope); return result;
    }
    if (sb_streq(method, "preferences.preview")) {
        if (sbj_obj_len(params) != 2 || !sbw_json_string(sbj_get(params, "password"), 1024, false)) goto invalid;
        preferences_clear_preview(c);
        sbj *payload = sbw_preferences_decrypt(sbj_get(params, "envelope"), sbj_get_str(params, "password", ""), error);
        if (!payload) return NULL;
        sbj *base = c->identity ? sbj_clone(c->identity) : sbw_independent_identity();
        sbj *merged = sbw_preferences_merge(base, payload, error); sbj_free(base); sbj_free(payload);
        if (!merged) return NULL;
        sbj *source = sbw_identity_is_independent(merged) ? sbw_independent_snapshot(merged, error) : sbj_clone(c->active ? c->active : c->candidate);
        sbw_runtime_config next = {0};
        int valid = source ? prepare_with_identity(merged, source, &next, error) : sbw_fail(error, "NO_CANDIDATE", "Download the shared configuration before importing preferences.");
        if (!valid && c->core) valid = check_config(c, &next, error);
        sbw_runtime_config_free(&next); sbj_free(source);
        if (valid) { sbj_free(merged); return NULL; }
        unsigned char random[32];
        if (BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { sbj_free(merged); sbw_fail(error, "ARCHIVE_INVALID", "Cannot create the import preview."); return NULL; }
        for (size_t i = 0; i < sizeof random; ++i) sprintf_s(c->preferences_preview_id + i * 2, 3, "%02x", random[i]);
        SecureZeroMemory(random, sizeof random);
        c->preferences_pending = merged; c->preferences_base = sbj_clone(c->identity); c->preferences_source = sbj_clone(c->candidate);
        c->preferences_preview_expires = GetTickCount64() + 300000;
        sbj *result = sbw_preferences_preview(merged); sbj_set_str(result, "preview_id", c->preferences_preview_id);
        sbj_set_int(result, "expires_in_seconds", 300); return result;
    }
    if (sb_streq(method, "preferences.apply")) {
        if (sbj_obj_len(params) != 1 || !sbw_json_string(sbj_get(params, "preview_id"), 64, false)) goto invalid;
        if (!c->preferences_pending || strcmp(sbj_get_str(params, "preview_id", ""), c->preferences_preview_id) || c->preferences_preview_expires <= GetTickCount64()) {
            sbw_fail(error, "PREFERENCES_PREVIEW_EXPIRED", "Decrypt and review the archive again before applying it."); return NULL;
        }
        if (!sbj_equal(c->identity, c->preferences_base) || !sbj_equal(c->candidate, c->preferences_source)) {
            preferences_clear_preview(c); sbw_fail(error, "PREFERENCES_LOCAL_CONFLICT", "Local preferences changed after the preview. Review the archive again."); return NULL;
        }
        sbj *pending = c->preferences_pending; c->preferences_pending = NULL; preferences_clear_preview(c);
        int applied = apply_local_identity(c, pending, error); sbj_free(pending);
        if (applied) return NULL;
        AcquireSRWLockShared(&c->state_lock); sbj *result = config_summary(c); ReleaseSRWLockShared(&c->state_lock); return result;
    }
    if (!strncmp(method, "preferences.cloud.", 18)) {
        const char *operation = method + 18;
        if (!strcmp(operation, "put")) {
            if (sbj_obj_len(params) != 3 || !sbw_json_string(sbj_get(params, "password"), 1024, false)) goto invalid;
            sbj *envelope = preferences_export(c, sbj_get_str(params, "password", ""), error); if (!envelope) return NULL;
            sbj *request = sbj_object(); sbj_set(request, "envelope", envelope);
            sbj_set(request, "session_id", sbj_clone(sbj_get(params, "session_id"))); sbj_set(request, "revision", sbj_clone(sbj_get(params, "revision")));
            sbj *result = sbw_preferences_cloud_call(c->preferences_cloud, operation, request, c->cancel, error); sbj_free(request); return result;
        }
        return sbw_preferences_cloud_call(c->preferences_cloud, operation, params, c->cancel, error);
    }
invalid:
    sbw_fail(error, "INVALID_REQUEST", "Invalid encrypted preference operation."); return NULL;
}
static void record_subscription_failure(sbw_controller *controller, const char *id, const sbw_error *error) {
    sbj *failed = sbw_subscriptions_failure(controller->identity, id, error->code, (uint64_t)time(NULL));
    if (!failed) return;
    if (save_state(controller, failed, controller->candidate, controller->last_good, NULL) == 0) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->identity); controller->identity = failed; failed = NULL;
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    sbj_free(failed);
}
static void refresh_due_subscription(sbw_controller *controller, HANDLE cancel) {
    const char *due = sbw_subscriptions_due(controller->identity, (uint64_t)time(NULL));
    if (!due) return;
    char *id = sb_strdup(due); sbw_error error = {0};
    sbj *identity = sbw_subscriptions_refresh(controller->identity, id, cancel, &error);
    if (!identity || apply_local_identity(controller, identity, &error) != 0)
        record_subscription_failure(controller, id, &error);
    sbj_free(identity); free(id);
}

static bool command_id_valid(const sbj *id) {
    if (!sbw_json_string(id, 128, false)) return false;
    for (const unsigned char *p = (const unsigned char *)id->v.str.ptr; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) return false;
    return true;
}
static const sbj *command_receipt(sbw_controller *controller, const char *id) {
    for (size_t i = 0; i < sbj_arr_len(controller->command_receipts); ++i) {
        const sbj *receipt = sbj_arr_at(controller->command_receipts, i);
        if (sbj_string_is(sbj_get(receipt, "id"), id)) return receipt;
    }
    return NULL;
}
static int save_receipt(sbw_controller *controller, const sbj *receipt, sbw_error *error) {
    sbj *next = sbj_array();
    const char *id = sbj_get_str(receipt, "id", "");
    size_t count = sbj_arr_len(controller->command_receipts);
    for (size_t i = count >= 128 ? count - 127 : 0; i < count; ++i) {
        const sbj *old = sbj_arr_at(controller->command_receipts, i);
        if (!sbj_string_is(sbj_get(old, "id"), id)) sbj_arr_push(next, sbj_clone(old));
    }
    sbj_arr_push(next, sbj_clone(receipt));
    sbj *saved = persisted_state(controller, controller->identity, controller->candidate, controller->last_good);
    sbj_set(saved, "command_receipts", sbj_clone(next));
    int result = controller->store->save(controller->store->context, saved, error); sbj_free(saved);
    if (!result) { sbj_free(controller->command_receipts); controller->command_receipts = next; }
    else sbj_free(next);
    return result;
}
static int management_commands(sbw_controller *controller, HANDLE cancel, sbw_error *error) {
    if (!controller->remote->pending_commands || !controller->remote->acknowledge_command) return 0;
    sbj *commands = NULL;
    if (controller->remote->pending_commands(controller->remote->context, controller->identity, cancel, &commands, error) != 0) return -1;
    int result = 0;
    if (!sbj_is_array(commands) || sbj_arr_len(commands) > 128) {
        sbj_free(commands); return sbw_fail(error, "INVALID_RESPONSE", "The command list is invalid.");
    }
    for (size_t i = 0; i < sbj_arr_len(commands); ++i) {
        const sbj *command = sbj_arr_at(commands, i);
        if (!command_id_valid(sbj_get(command, "id")) || !sbw_json_string(sbj_get(command, "command"), 128, false)) {
            result = sbw_fail(error, "INVALID_RESPONSE", "The command list contains an invalid entry."); break;
        }
        const char *id = sbj_get_str(command, "id", ""), *name = sbj_get_str(command, "command", "");
        const sbj *prior = command_receipt(controller, id);
        sbj *receipt = prior ? sbj_clone(prior) : sbj_object();
        if (!prior) {
            sbj_set_str(receipt, "id", id);
            /* Persist intent BEFORE executing. A crash cannot execute the same
             * restart twice; its uncertain outcome is reported on next poll. */
            sbj_set_str(receipt, "status", "pending");
            sbj_set_str(receipt, "result", "Command was interrupted before its outcome was durably recorded.");
            if (save_receipt(controller, receipt, error) != 0) { sbj_free(receipt); result = -1; break; }
            sbw_error operation = {0}; int executed = -1;
            if (sb_streq(name, "reload")) {
                executed = refresh_configuration(controller, true, cancel, &operation);
                if (!executed && controller->runtime.core_running)
                    executed = connection_activate(controller, controller->candidate, controller->identity, false, &operation);
            } else if (sb_streq(name, "restart")) {
                if (!controller->recovery.desired_connected || sbj_get_bool(controller->management_settings, "manual_disconnect", false))
                    sbw_fail(&operation, "MANUALLY_DISCONNECTED", "The user disconnected this device; reconnect locally before restarting remotely.");
                else executed = connection_activate(controller, controller->candidate, controller->identity, true, &operation);
            } else sbw_fail(&operation, "UNKNOWN_COMMAND", "This client does not implement the requested command.");
            sbj_set_str(receipt, "status", !executed ? "done" : "failed");
            sbj_set_str(receipt, "result", !executed ? "Command completed." : operation.message);
            if (save_receipt(controller, receipt, error) != 0) { sbj_free(receipt); result = -1; break; }
        } else if (sbj_string_is(sbj_get(receipt, "status"), "pending")) {
            sbj_set_str(receipt, "status", "failed");
            if (save_receipt(controller, receipt, error) != 0) { sbj_free(receipt); result = -1; break; }
        }
        sbj_del(receipt, "id");
        result = controller->remote->acknowledge_command(controller->remote->context, controller->identity, id, receipt, cancel, error);
        sbj_free(receipt);
        if (result != 0) break;
    }
    sbj_free(commands); return result;
}
static int management_telemetry(sbw_controller *controller, uint64_t now, HANDLE cancel, sbw_error *error) {
    if (!controller->remote->report_telemetry || !sbj_get_bool(controller->management_settings, "telemetry_enabled", true)) return 0;
    sbj *connections = NULL; sbw_core_status process = {0};
    if (controller->runtime.core_running &&
        (sbw_core_poll(controller->core, &process, error) != 0 || !process.process_running ||
         sbw_runtime_config_get(&controller->active_config, process.process_id, cancel, "/connections", &connections, error) != 0)) return -1;
    int64_t upload = sbj_get_int(connections, "uploadTotal", 0), download = sbj_get_int(connections, "downloadTotal", 0);
    uint64_t elapsed = now > controller->telemetry_sample_ms ? now - controller->telemetry_sample_ms : 0;
    int64_t up_rate = 0, down_rate = 0;
    if (elapsed && controller->telemetry_sample_ms) {
        if (upload >= controller->telemetry_upload) up_rate = (int64_t)((double)(upload - controller->telemetry_upload) * 1000.0 / (double)elapsed);
        if (download >= controller->telemetry_download) down_rate = (int64_t)((double)(download - controller->telemetry_download) * 1000.0 / (double)elapsed);
    }
    controller->telemetry_sample_ms = now; controller->telemetry_upload = upload; controller->telemetry_download = download;
    sbj *body = sbj_object();
    sbj_set_int(body, "up", up_rate); sbj_set_int(body, "down", down_rate);
    sbj_set_int(body, "up_total", upload); sbj_set_int(body, "down_total", download);
    sbj_set_int(body, "conn_count", (int64_t)sbj_arr_len(sbj_get(connections, "connections")));
    /* Only aggregate counters leave the device. Process names, URLs, domains,
     * addresses and logs require an explicit diagnostic upload. */
    int result = controller->remote->report_telemetry(controller->remote->context, controller->identity, body, cancel, error);
    sbj_free(body); sbj_free(connections); return result;
}
typedef struct health_io { sbw_controller *controller; DWORD pid; HANDLE cancel; } health_io;
static int health_proxies(void *context, sbj **out, sbw_error *error) {
    health_io *io = context;
    return sbw_runtime_config_get(&io->controller->active_config, io->pid, io->cancel, "/proxies", out, error);
}
static int health_probe(void *context, const char *target, const char *url, DWORD timeout, int64_t *delay, sbw_error *error) {
    health_io *io = context; sbj *response = NULL;
    int rc = sbw_runtime_delay(&io->controller->active_config, io->pid, io->cancel, target, url, timeout, &response, error);
    if (!rc) *delay = sbj_get_int(response, "delay", -1);
    sbj_free(response); return rc;
}
static int health_select(void *context, const char *selector, const char *target, sbw_error *error) {
    health_io *io = context;
    return sbw_runtime_select_group(&io->controller->active_config, io->pid, io->cancel, selector, target, error);
}
static void health_tick(sbw_controller *controller) {
    HANDLE cancel = controller->management_io_cancel ? controller->management_io_cancel : controller->cancel;
    if (!ready(controller, NULL) || (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)) return;
    sbw_core_status process = {0};
    if (controller->core && controller->runtime.core_running) sbw_core_poll(controller->core, &process, NULL);
    health_io io = {controller, process.process_running ? process.process_id : 0, cancel};
    sbw_health_transport transport = {&io, health_proxies, health_probe, health_select};
    sbj *groups = sbw_routing_groups(controller->active ? controller->active : controller->candidate, controller->identity);
    sbj *policy = sbw_health_policy(controller->identity);
    sbw_health_step(controller->health, groups, policy, io.pid,
        InterlockedCompareExchange(&controller->network_generation, 0, 0), GetTickCount64(), &transport);
    sbj_free(groups); sbj_free(policy);
    sbj *snapshot = sbw_health_snapshot(controller->health);
    AcquireSRWLockExclusive(&controller->state_lock);
    sbj_free(controller->health_snapshot); controller->health_snapshot = snapshot;
    ReleaseSRWLockExclusive(&controller->state_lock);
}
void sbw_controller_background_tick(sbw_controller *controller, uint64_t now) {
    if (!controller || !TryAcquireSRWLockExclusive(&controller->user_operation_lock)) return;
    if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) {
        ReleaseSRWLockExclusive(&controller->user_operation_lock); return;
    }
    if (controller->management_stop && WaitForSingleObject(controller->management_stop, 0) == WAIT_OBJECT_0) {
        ReleaseSRWLockExclusive(&controller->mutation_lock);
        ReleaseSRWLockExclusive(&controller->user_operation_lock); return;
    }
    if (controller->management_io_cancel) ResetEvent(controller->management_io_cancel);
    ReleaseSRWLockExclusive(&controller->user_operation_lock);
    if (sbw_updater_installing(controller->updater)) {
        ReleaseSRWLockExclusive(&controller->mutation_lock); return;
    }
    extensions_tick(controller, now, false);
    if (!ready(controller, NULL) || cancelled(controller, NULL)) goto done;
    HANDLE cancel = controller->management_io_cancel ? controller->management_io_cancel : controller->cancel;
    if (!controller->kill_switch_checked_ms || now - controller->kill_switch_checked_ms >= 5000) {
        sbj *protection = sbw_kill_switch_status(); controller->kill_switch_checked_ms = now;
        bool desired = sbj_get_bool(controller->management_settings, "kill_switch_enabled", false);
        bool enabled = sbj_get_bool(protection, "enabled", false);
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->kill_switch); controller->kill_switch = protection;
        if (desired && !enabled)
            sbw_fail(&controller->runtime_error, "KILL_SWITCH_NOT_ACTIVE", "Leak protection was requested, but its blocking rules could not be confirmed. Check the system firewall state.");
        ReleaseSRWLockExclusive(&controller->state_lock);
        if (desired && !enabled && !sbw_kill_switch_recovery_disabled()) {
            sbw_error protection_error = {0};
            int restored = apply_kill_switch(controller, true, controller->runtime.core_running ? controller->active_config.interface_name : NULL, &protection_error);
            AcquireSRWLockExclusive(&controller->state_lock);
            if (restored) controller->runtime_error = protection_error;
            else if (sb_streq(controller->runtime_error.code, "KILL_SWITCH_NOT_ACTIVE")) memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
            ReleaseSRWLockExclusive(&controller->state_lock);
        }
    }
    observe_core(controller, false);
    LONG generation = InterlockedCompareExchange(&controller->network_generation, 0, 0);
    if (generation != controller->network_observed) {
        controller->network_observed = generation; controller->network_due_ms = now + 2000;
    }
    if (controller->network_due_ms && now >= controller->network_due_ms) {
        controller->network_due_ms = 0;
        if (controller->recovery.desired_connected && controller->core && controller->identity &&
            controller->candidate && sbj_get_bool(controller->management_settings, "auto_reconnect", true)) {
            sbw_error network_error = {0};
            const sbj *source = controller->last_good ? controller->last_good : controller->candidate;
            const sbj *identity = source == controller->last_good ? sbj_get(source, "local_identity") : NULL;
            if (connection_activate(controller, source, identity ? identity : controller->identity, true, &network_error) != 0 && !controller->runtime.core_running) {
                AcquireSRWLockExclusive(&controller->state_lock);
                sb_windows_recovery_failed(&controller->recovery, now); controller->runtime_error = network_error;
                ReleaseSRWLockExclusive(&controller->state_lock);
            }
        }
    }
    if (controller->runtime.core_running) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sb_windows_recovery_healthy(&controller->recovery, now);
        ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (controller->core && controller->identity && controller->candidate &&
               sb_windows_recovery_due(&controller->recovery, now) &&
               (controller->recovery.attempts == 0 || sbj_get_bool(controller->management_settings, "auto_reconnect", true))) {
        sbw_error recovery_error = {0};
        /* First boot/connect uses the newest candidate. Subsequent recovery
         * falls back to the last actually working bytes after rejection. */
        const sbj *source = controller->recovery.attempts && controller->last_good ? controller->last_good : controller->candidate;
        const sbj *identity = source == controller->last_good ? sbj_get(source, "local_identity") : NULL;
        int activated = connection_activate(controller, source, identity ? identity : controller->identity, false, &recovery_error);
        if (activated != 0 && !controller->runtime.core_running) {
            AcquireSRWLockExclusive(&controller->state_lock);
            sb_windows_recovery_failed(&controller->recovery, now);
            controller->runtime_error = recovery_error;
            ReleaseSRWLockExclusive(&controller->state_lock);
        }
    }
    if (controller->identity) refresh_due_subscription(controller, cancel);
    if (!controller->identity || sbw_identity_is_independent(controller->identity) || now < controller->next_sync_ms ||
        !sbw_json_string(sbj_get(controller->identity, "agent_token"), 4096, false)) goto done;
    controller->next_sync_ms = now + (uint64_t)sbj_get_int(controller->management_settings, "sync_interval_seconds", 30) * 1000;
    sbw_error cycle_error = {0}, operation = {0};
    if (refresh_configuration(controller, false, cancel, &operation) == 0) {
        if (controller->runtime.core_running && !sbj_equal(controller->active, controller->candidate)) {
            /* Failed revisions are retried only after a new revision or explicit
             * reload; this prevents restart/rollback loops every poll. */
            const char *etag = sbj_get_str(controller->candidate, "etag", "");
            if (!controller->auto_attempted_etag || !sb_streq(controller->auto_attempted_etag, etag)) {
                sb_str_set(&controller->auto_attempted_etag, etag);
                if (connection_activate(controller, controller->candidate, controller->identity, false, &operation) != 0) cycle_error = operation;
            } else if (controller->core_error.code[0]) cycle_error = controller->core_error;
            else if (controller->runtime_error.code[0]) cycle_error = controller->runtime_error;
        }
        AcquireSRWLockExclusive(&controller->state_lock);
        controller->last_sync_at = (uint64_t)time(NULL) * 1000;
        ReleaseSRWLockExclusive(&controller->state_lock);
    } else cycle_error = operation;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) goto done;
    memset(&operation, 0, sizeof operation);
    if (management_commands(controller, cancel, &operation) != 0 && !cycle_error.code[0]) cycle_error = operation;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) goto done;
    memset(&operation, 0, sizeof operation);
    if (management_telemetry(controller, now, cancel, &operation) != 0 && !cycle_error.code[0]) cycle_error = operation;
    if (controller->remote->report_status) {
        sbj *status = sbj_object();
        sbj_set_str(status, "singbox_version", controller->core ? SB_EASY_CORE_VERSION : NULL); sbj_set_str(status, "app_version", SB_EASY_VERSION);
        sbj_set_bool(status, "singbox_running", controller->runtime.core_running);
        sbj_set_str(status, "config_etag", sbj_get_str(controller->active, "etag", NULL));
        sbj_set_str(status, "last_error", cycle_error.code[0] ? cycle_error.message :
            controller->runtime_error.code[0] ? controller->runtime_error.message : NULL);
        memset(&operation, 0, sizeof operation);
        int reported = controller->remote->report_status(controller->remote->context, controller->identity, status, cancel, &operation);
        sbj_free(status);
        AcquireSRWLockExclusive(&controller->state_lock);
        if (!reported) controller->last_report_at = (uint64_t)time(NULL) * 1000;
        else if (!cycle_error.code[0]) cycle_error = operation;
        ReleaseSRWLockExclusive(&controller->state_lock);
    }
    AcquireSRWLockExclusive(&controller->state_lock); controller->management_error = cycle_error;
    ReleaseSRWLockExclusive(&controller->state_lock);
done:
    /* Center reporting precedes the single bounded probe, including in
     * independent mode where there is no center management cycle. */
    health_tick(controller);
    ReleaseSRWLockExclusive(&controller->mutation_lock);
}
static DWORD WINAPI management_main(void *context) {
    sbw_controller *controller = context;
    while (WaitForSingleObject(controller->management_stop, 500) == WAIT_TIMEOUT) {
        if (cancelled(controller, NULL)) break;
        sbw_controller_background_tick(controller, GetTickCount64());
    }
    AcquireSRWLockExclusive(&controller->state_lock); controller->management_running = false;
    ReleaseSRWLockExclusive(&controller->state_lock); return 0;
}
void sbw_controller_network_changed(sbw_controller *controller) {
    if (controller) InterlockedIncrement(&controller->network_generation);
}
static VOID CALLBACK interface_changed(PVOID context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type) {
    (void)type;
    if (!row) return;
    MIB_IF_ROW2 adapter = {0}; adapter.InterfaceLuid = row->InterfaceLuid;
    /* Ignore the core's own virtual interfaces: otherwise opening a TUN would
     * recursively trigger another reconnect. Physical link/address changes
     * and explicit system resume notifications restart with a short debounce. */
    if (GetIfEntry2(&adapter) == NO_ERROR && adapter.InterfaceAndOperStatusFlags.HardwareInterface)
        sbw_controller_network_changed(context);
}
int sbw_controller_start_background(sbw_controller *controller, sbw_error *error) {
    if (controller->management_thread) return 0;
    if (!sbw_updater_installing(controller->updater)) {
    if (sbw_kill_switch_recovery_disabled()) {
        sbw_error protection_error = {0};
        int restored = apply_kill_switch(controller, false, NULL, &protection_error);
        if (!restored && !controller->startup_error.code[0]) {
            sbj *settings = sbj_clone(controller->management_settings); sbj_set_bool(settings, "kill_switch_enabled", false);
            restored = replace_management_settings(controller, settings, &protection_error); sbj_free(settings);
            if (!restored) restored = sbw_kill_switch_set_recovery_disabled(false, &protection_error);
        }
        if (restored) { controller->management_error = protection_error; controller->runtime_error = protection_error; }
    } else if (sbw_kill_switch_startup_action(sbj_get(controller->management_settings, "kill_switch_enabled"), controller->kill_switch) == SBW_KILL_PRESERVE_UNKNOWN) {
        sbw_fail(&controller->runtime_error, "KILL_SWITCH_RECOVERY_REQUIRED", "Existing leak-protection rules were preserved because the saved preference is missing or invalid. Explicitly enable or disable protection to reconcile the policy, or use administrator recovery if device storage is unavailable.");
        controller->management_error = controller->runtime_error;
    } else if (!controller->startup_error.code[0] &&
        sbw_kill_switch_startup_action(sbj_get(controller->management_settings, "kill_switch_enabled"), controller->kill_switch) != SBW_KILL_UNCHANGED) {
        sbw_error protection_error = {0};
        if (apply_kill_switch(controller, sbj_get_bool(controller->management_settings, "kill_switch_enabled", false), NULL, &protection_error) != 0) {
            controller->management_error = protection_error; controller->runtime_error = protection_error;
        }
    }
    }
    controller->management_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    controller->management_io_cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (controller->management_stop && controller->management_io_cancel)
        controller->management_thread = CreateThread(NULL, 0, management_main, controller, CREATE_SUSPENDED, NULL);
    if (!controller->management_thread) {
        if (controller->management_stop) CloseHandle(controller->management_stop);
        if (controller->management_io_cancel) CloseHandle(controller->management_io_cancel);
        controller->management_stop = controller->management_io_cancel = NULL;
        return sbw_fail(error, "INITIALIZATION_FAILED", "The background management worker could not start.");
    }
    (void)NotifyIpInterfaceChange(AF_UNSPEC, interface_changed, controller, FALSE, &controller->interface_notification);
    controller->management_running = true;
    ResumeThread(controller->management_thread); return 0;
}

static sbj *dashboard_snapshot(sbw_controller *controller, sbw_error *error) {
    if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) {
        sbw_fail(error, "BUSY", "A connection operation is in progress."); return NULL;
    }
    sbj *result = NULL, *connections = NULL, *proxies = NULL;
    sbw_core_status process = {0};
    if (!ready(controller, error) || cancelled(controller, error)) goto done;
    observe_core(controller, false);
    bool running = controller->runtime.phase == SB_WINDOWS_RUNNING && controller->active != NULL;
    if (running) {
        if (sbw_core_poll(controller->core, &process, error) != 0 || !process.process_running ||
            sbw_runtime_config_get(&controller->active_config, process.process_id, controller->cancel, "/connections", &connections, error) != 0 ||
            sbw_runtime_config_get(&controller->active_config, process.process_id, controller->cancel, "/proxies", &proxies, error) != 0) goto done;
        if ((!sbj_is_array(sbj_get(connections, "connections")) && !sbj_is_null(sbj_get(connections, "connections"))) ||
            !sbj_is_integer(sbj_get(connections, "uploadTotal")) || !sbj_is_integer(sbj_get(connections, "downloadTotal")) ||
            !sbj_is_object(sbj_get(proxies, "proxies"))) {
            sbw_fail(error, "INVALID_RESPONSE", "The core returned an invalid runtime snapshot."); goto done;
        }
    }
    if (running) sbw_traffic_record(controller->traffic, connections, process.process_id);
    result = sbw_dashboard_snapshot(connections, proxies);
    sbj_set_bool(result, "running", running);
    sbj_set_int(result, "core_pid", process.process_id);
    sbj_set_int(result, "sample_ms", (int64_t)GetTickCount64());
    sbj_set_str(result, "etag", sbj_get_str(controller->active, "etag", NULL));
done:
    sbj_free(connections); sbj_free(proxies);
    ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
}
static int extension_stop(sbw_controller *c, const char *id, bool revoked, sbw_error *error) {
    if (revoked && sb_streq(id, "http-debug")) {
        /* Revoke execution before any bounded but potentially slow core
         * configuration check needed to restore the intercepted routes. */
        sbw_extension_process_free(c->httpdebug); c->httpdebug = NULL;
    }
    if (sb_streq(id, "http-debug") && (c->httpdebug || c->httpdebug_base)) {
        sbj *stopped = httpdebug_dispatch(c, "httpdebug.stop", NULL, error);
        if (!stopped) {
            if (!revoked) return -1;
            /* A revoked engine cannot remain alive when routing restoration
             * fails. Stop the tunnel before retaining a recoverable error. */
            sbw_extension_process_free(c->httpdebug); c->httpdebug = NULL;
            sbw_error ignored = {0}; connection_stop(c, &ignored);
            AcquireSRWLockExclusive(&c->state_lock);
            if (error) c->runtime_error = *error;
            ReleaseSRWLockExclusive(&c->state_lock);
        }
        sbj_free(stopped);
    }
    if (sb_streq(id, "capture")) {
        capture_upload_join(c); sbw_capture_free(c->capture); c->capture = NULL;
    }
    if (sb_streq(id, "statistics")) {
        if (!revoked) persist_traffic(c);
        sbw_traffic_free(c->traffic); c->traffic = NULL;
    }
    return 0;
}
static sbj *extensions_snapshot(sbw_controller *c) {
    sbj *out = sbw_extensions_snapshot(c->capture, sbw_traffic_running(c->traffic), c->traffic && !sbw_traffic_running(c->traffic));
    sbj *items = sbj_get(out, "extensions");
    for (size_t i = 0; i < sbj_arr_len(items); ++i) {
        sbj *item = sbj_arr_at(items, i);
        if (sbj_string_is(sbj_get(item, "id"), "http-debug")) {
            bool running = sbw_extension_process_running(c->httpdebug);
            sbj_set_bool(item, "running", running);
            sbj_set_bool(item, "failed", sbj_get_bool(item, "enabled", false) && c->httpdebug && !running);
        }
    }
    return out;
}
static int extension_enable(sbw_controller *c, const char *id, sbw_error *error) {
    if (sb_streq(id, "network-tools"))
        return sbw_fail(error, "BUILTIN_FEATURE", "Connections, rules and logs are included in the app.");
    if (sbw_extension_change(id, "enable", error)) return -1;
    sbj *reply = NULL;
    if (sb_streq(id, "capture")) {
        c->capture = sbw_capture_new(c->core ? sbw_core_work_directory(c->core) : NULL, c->identity, error);
        reply = sbw_capture_snapshot(c->capture);
    } else if (sb_streq(id, "statistics")) {
        ensure_statistics(c);
        if (!c->traffic) c->traffic = sbw_traffic_new();
        reply = sbw_traffic_snapshot(c->traffic);
    } else if (sb_streq(id, "http-debug")) {
        /* Enabling checks the packaged engine without starting MITM or routing. */
        sbw_extension_process *probe = sbw_extension_process_new(L"extensions\\http-debug\\sb-easy-http-debug.exe", error);
        reply = sbw_extension_process_call(probe, "snapshot", NULL, error);
        sbw_extension_process_free(probe);
    } else return sbw_fail(error, "BUILTIN_FEATURE", "Connections, rules and logs are included in the app.");
    bool healthy = sbj_is_object(reply); sbj_free(reply);
    if (healthy && !sbw_store_confirm(id, error)) return 0;
    sbw_error ignored = {0}; extension_stop(c, id, true, &ignored);
    (void)sbw_extension_change(id, "disable", &ignored);
    sbj *state = sbw_store_status(id);
    bool rollback = sbj_get_bool(state, "pending_health", false) && sbj_get_bool(state, "rollback_available", false);
    sbj_free(state);
    if (rollback) {
        if (!sbw_store_rollback(id, &ignored))
            return sbw_fail(error, "EXTENSION_HEALTH_ROLLED_BACK", "The new extension did not pass its worker check. The previous verified version was restored and remains disabled.");
        return sbw_fail(error, "EXTENSION_HEALTH_ROLLBACK_FAILED", "The extension check failed and its previous version could not be restored. It remains disabled; retry rollback in Extensions.");
    }
    if (!error || !error->code[0]) sbw_fail(error, "EXTENSION_HEALTH_FAILED", "The isolated extension did not pass its worker check and remains disabled.");
    return -1;
}
static void extensions_tick(sbw_controller *c, uint64_t now, bool force) {
    if (force || !c->extensions_checked_ms || now - c->extensions_checked_ms >= 30000) {
        c->extensions_checked_ms = now;
        const char *ids[] = {"capture", "statistics", "http-debug"};
        bool running[] = {c->capture != NULL, c->traffic != NULL, c->httpdebug != NULL};
        for (size_t i = 0; i < 3; ++i) if (running[i] && !sbw_store_verified(ids[i], NULL)) {
            sbw_error error = {0}; extension_stop(c, ids[i], true, &error);
            (void)sbw_extension_change(ids[i], "disable", NULL);
        }
    }
    if (sbw_store_ready()) {
        const char *id = sbw_store_pending_id(); sbw_error error = {0};
        if (id && !extension_stop(c, id, false, &error)) (void)sbw_store_commit(&error);
        else sbw_store_abort(&error);
    }
}
static sbj *httpdebug_dispatch(sbw_controller *c,const char *method,const sbj *params,sbw_error *error) {
    if(sb_streq(method,"httpdebug.start")) {
        if(!sbw_extension_is_enabled("http-debug")){sbw_fail(error,"EXTENSION_MISSING","Install and enable HTTP(S) debugging first.");return NULL;}
        if(!c->active||!c->runtime.core_running){sbw_fail(error,"NOT_CONNECTED","Connect the proxy first.");return NULL;}
        if(c->httpdebug){sbw_fail(error,"BUSY","Stop the existing capture session first.");return NULL;}
        c->httpdebug=sbw_extension_process_new(L"extensions\\http-debug\\sb-easy-http-debug.exe",error);
        sbj *p=sbj_object();const wchar_t *work=sbw_extension_process_work_directory(c->httpdebug);wchar_t *dir=work?sbw_path_join(work,L"http-debug"):NULL;char *utf=dir?sbw_utf8(dir,error):NULL;free(dir);
        sbj_set_str(p,"directory",utf?utf:"");free(utf);
        sbj *r=sbw_extension_process_call(c->httpdebug,"start",p,error);sbj_free(p);
        if(!r){sbw_extension_process_free(c->httpdebug);c->httpdebug=NULL;}return r;
    }
    if(sb_streq(method,"httpdebug.stop")) {
        if(c->httpdebug_base) {
            sbw_runtime_config restored={0};
            if(prepare_candidate(c,c->active,&restored,error))return NULL;
            if(check_config(c,&restored,error)){sbw_runtime_config_free(&restored);return NULL;}
            sbw_core_stop(c->core,NULL);
            if(launch_healthy(c,&restored,error)) {
                sbw_runtime_config_free(&restored);
                sbw_error ignored={0};sbw_core_stop(c->core,NULL);launch_healthy(c,&c->active_config,&ignored);
                return NULL;
            }
            sbw_runtime_config_free(&c->active_config);c->active_config=restored;
            sbw_secret_free(c->httpdebug_base);c->httpdebug_base=NULL;
            sbj_free(c->httpdebug_domains);c->httpdebug_domains=NULL;
        }
        sbw_extension_process_free(c->httpdebug);c->httpdebug=NULL;
    }
    if(!c->httpdebug){sbj *r=sbj_object();sbj_set_str(r,"phase","stopped");sbj_set_str(r,"url","");sbj_set_str(r,"error","");sbj_set_bool(r,"attached",false);return r;}
    if(sb_streq(method,"httpdebug.certificate"))return sbw_extension_process_call(c->httpdebug,"certificate",NULL,error);
    sbj *r=sbw_extension_process_call(c->httpdebug,"snapshot",NULL,error);
    if(!r)return NULL;
    if(sb_streq(method,"httpdebug.attach")) {
        if(c->httpdebug_base||!sbj_string_is(sbj_get(r,"phase"),"running")){sbj_free(r);sbw_fail(error,"BUSY","Wait for the engine, or stop the existing capture first.");return NULL;}
        char *adapted=sbw_http_debug_overlay(c->active_config.json,sbj_get(params,"domains"),sbj_get_str(r,"password",""),error);
        if(!adapted){sbj_free(r);return NULL;}
        char *original=c->active_config.json;c->active_config.json=adapted;
        if(check_config(c,&c->active_config,error)){c->active_config.json=original;sbw_secret_free(adapted);sbj_free(r);return NULL;}
        sbw_core_stop(c->core,NULL);
        if(launch_healthy(c,&c->active_config,error)) {
            c->active_config.json=original;sbw_secret_free(adapted);
            sbw_error ignored={0};sbw_core_stop(c->core,NULL);launch_healthy(c,&c->active_config,&ignored);sbj_free(r);return NULL;
        }
        c->httpdebug_base=original;
        c->httpdebug_domains=sbj_clone(sbj_get(params,"domains"));
    }
    sbj_del(r,"password");sbj_del(r,"username");sbj_set_bool(r,"attached",c->httpdebug_base!=NULL);return r;
}
sbj *sbw_controller_dispatch(sbw_controller *controller, const char *method, const sbj *params, bool authorized, sbw_error *error) {
    if (!controller || !method) { sbw_fail(error, "INVALID_REQUEST", "Invalid service operation."); return NULL; }
    if (sbw_updater_installing(controller->updater) && strncmp(method, "updates.", 8) &&
        strcmp(method, "status.get") && strcmp(method, "enrollment.status") && strcmp(method, "config.summary") &&
        strcmp(method, "management.settings.get") && strcmp(method, "logs.snapshot")) {
        sbw_fail(error, "UPDATE_BUSY", "An installer transaction is in progress. Device changes resume after it finishes or recovery succeeds."); return NULL;
    }
    if(!strncmp(method,"httpdebug.",10)) {
        if(!authorized){sbw_fail(error,"FORBIDDEN","HTTP debugging requires the active console session.");return NULL;}
        if(!sbj_is_object(params)||(!sb_streq(method,"httpdebug.attach")&&sbj_obj_len(params))||
           (sb_streq(method,"httpdebug.attach")&&sbj_obj_len(params)!=1)||
           !(sb_streq(method,"httpdebug.start")||sb_streq(method,"httpdebug.stop")||sb_streq(method,"httpdebug.snapshot")||sb_streq(method,"httpdebug.attach")||sb_streq(method,"httpdebug.certificate"))){sbw_fail(error,"INVALID_REQUEST","Invalid HTTP debug request.");return NULL;}
        if(!TryAcquireSRWLockExclusive(&controller->mutation_lock)){sbw_fail(error,"BUSY","A connection operation is in progress.");return NULL;}
        sbj *result=httpdebug_dispatch(controller,method,params,error);
        if(result){sbj_del(result,"password");sbj_del(result,"username");if(!sbj_has(result,"der")){sbj_set_bool(result,"attached",controller->httpdebug_base!=NULL);sbj_set(result,"domains",controller->httpdebug_domains?sbj_clone(controller->httpdebug_domains):sbj_array());}}
        ReleaseSRWLockExclusive(&controller->mutation_lock);return result;
    }
    bool is_apply = strcmp(method, "enrollment.apply") == 0;
    if (!sbj_is_object(params) || (!is_apply && strncmp(method,"updates.",8) && strncmp(method,"preferences.",12) && strncmp(method,"subscriptions.",14) && strncmp(method,"extensions.",11) && !sb_streq(method, "mode.set") && !sb_streq(method, "management.settings.set") && !sb_streq(method, "routing.health.set") && !sb_streq(method, "routing.automatic.set") && !sb_streq(method, "routing.group_save") && !sb_streq(method, "routing.group_remove") && !sb_streq(method, "routing.probe") && !sb_streq(method, "routing.delay") && !sb_streq(method, "routing.gpt_node") && !sb_streq(method, "routing.set") && strncmp(method, "capture.", 8) && sbj_obj_len(params) != 0)) {
        sbw_fail(error, "INVALID_REQUEST", "This operation expects object params."); return NULL;
    }
    if (!strncmp(method, "extensions.", 11)) {
        if (!authorized) { sbw_fail(error,"FORBIDDEN","Extension management requires the active console session."); return NULL; }
        if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) { sbw_fail(error,"BUSY","A connection operation is in progress."); return NULL; }
        sbj *result=NULL;
        if (sb_streq(method,"extensions.list") && !sbj_obj_len(params)) result=extensions_snapshot(controller);
        else if (sb_streq(method,"extensions.catalog") && !sbj_obj_len(params)) result=sbw_store_catalog();
        else if (sb_streq(method,"extensions.progress") && !sbj_obj_len(params)) result=sbw_store_progress();
        else if (sb_streq(method,"extensions.catalog_update") && sbj_obj_len(params)==1 && sbw_json_string(sbj_get(params,"envelope"),900U*1024U,false)) {
            const sbj *envelope=sbj_get(params,"envelope");
            if (!sbw_store_catalog_update(envelope->v.str.ptr,envelope->v.str.len,error)) {
                extensions_tick(controller,GetTickCount64(),true); result=sbw_store_catalog();
            }
        }
        else if (sb_streq(method,"extensions.install") && sbj_obj_len(params)==1 && sbw_extension_release_find(sbj_get_str(params,"id",""))) {
            const char *id=sbj_get_str(params,"id","");
            if (sb_streq(id,"network-tools")) sbw_fail(error,"BUILTIN_FEATURE","Connections, rules and logs are included in the app.");
            else if (!sbw_store_install(id,error)) result=sbw_store_progress();
        }
        else if (sb_streq(method,"extensions.rollback") && sbj_obj_len(params)==1 && sbw_extension_release_find(sbj_get_str(params,"id",""))) {
            const char *id=sbj_get_str(params,"id","");
            if (sbw_store_busy()) sbw_fail(error,"BUSY","An extension installation is in progress.");
            else if (!extension_stop(controller,id,false,error) && !sbw_store_rollback(id,error)) result=extensions_snapshot(controller);
        }
        else if (sb_streq(method,"extensions.change") && sbj_obj_len(params)==2 && sbw_extension_release_find(sbj_get_str(params,"id",""))) {
            const char *action=sbj_get_str(params,"action",""),*id=sbj_get_str(params,"id","");
            if (sbw_store_busy()) sbw_fail(error,"BUSY","An extension installation is in progress.");
            else if (sb_streq(action,"enable") || sb_streq(action,"disable") || sb_streq(action,"remove")) {
                if (!extension_stop(controller,id,false,error) &&
                    !(sb_streq(action,"enable") ? extension_enable(controller,id,error) : sbw_extension_change(id,action,error))) result=extensions_snapshot(controller);
            } else sbw_fail(error,"INVALID_REQUEST","Unknown extension action.");
        } else sbw_fail(error,"INVALID_REQUEST","Invalid extension request.");
        ReleaseSRWLockExclusive(&controller->mutation_lock);return result;
    }
    if (!strncmp(method, "capture.", 8)) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "Capture requires the active console session or an administrator."); return NULL; }
        if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) { sbw_fail(error, "BUSY", "A connection operation is in progress."); return NULL; }
        sbj *result = capture_dispatch(controller, method, params, error);
        ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
    }
    if (sb_streq(method, "traffic.snapshot") || sb_streq(method, "traffic.clear") || sb_streq(method, "logs.snapshot")) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "This operation requires the active console session."); return NULL; }
        if (!sb_streq(method,"logs.snapshot") && !sbw_extension_is_enabled("statistics")) {sbw_fail(error,"EXTENSION_MISSING","Install and enable this extension in the store.");return NULL;}
        if (sb_streq(method, "logs.snapshot")) return sbw_core_logs(controller->core);
        if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) {
            sbw_fail(error, "BUSY", "A connection operation is in progress."); return NULL;
        }
        ensure_statistics(controller);
        if(!sbw_traffic_running(controller->traffic)){ReleaseSRWLockExclusive(&controller->mutation_lock);sbw_fail(error,"EXTENSION_FAILED","Statistics worker stopped. Re-enable it in the store.");return NULL;}
        if (sb_streq(method, "traffic.clear")) {
            if (!collect_traffic(controller) || !controller->core) {
                ReleaseSRWLockExclusive(&controller->mutation_lock);
                sbw_fail(error, "TRAFFIC_UNAVAILABLE", "Cannot clear statistics until collection and storage are available."); return NULL;
            }
            sbw_traffic *blank = sbw_traffic_new(); sbj *saved = sbw_traffic_snapshot(blank); sbw_traffic_free(blank);
            int stored = saved?sbw_core_traffic_save(controller->core, saved, error):sbw_fail(error,"EXTENSION_FAILED","Statistics worker did not respond."); sbj_free(saved);
            if (stored != 0) { ReleaseSRWLockExclusive(&controller->mutation_lock); return NULL; }
            controller->traffic_storage_ok = controller->traffic_load_ok = true;
            sbw_traffic_clear(controller->traffic);
        }
        sbj *result = sbw_traffic_snapshot(controller->traffic);
        if(!result){ReleaseSRWLockExclusive(&controller->mutation_lock);sbw_fail(error,"EXTENSION_FAILED","Statistics worker did not respond.");return NULL;}
        sbj_set_bool(result, "storage_ok", controller->traffic_storage_ok);
        ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
    }
    if (sb_streq(method, "runtime.snapshot") || sb_streq(method, "config.inspect")) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "This operation requires an administrator or the active console session."); return NULL; }
        if (sb_streq(method, "runtime.snapshot")) return dashboard_snapshot(controller, error);
        sbj *result = NULL;
        AcquireSRWLockShared(&controller->state_lock);
        if (ready(controller, error)) {
            result = sbj_object();
            sbw_error routing_error = {0};
            sbj *candidate = sbw_routing_apply(controller->candidate, controller->identity, false, &routing_error);
            sbj *active = sbw_routing_apply(controller->active, controller->identity, false, &routing_error);
            if ((controller->candidate && !candidate) || (controller->active && !active)) {
                sbj_set_bool(result, "routing_warning", true);
            }
            sbj_set(result, "candidate", sbw_config_catalog(candidate ? candidate : controller->candidate));
            sbj_set(result, "active", sbw_config_catalog(active ? active : controller->active));
            sbj_free(candidate); sbj_free(active);
        }
        ReleaseSRWLockShared(&controller->state_lock); return result;
    }
    if (sb_streq(method, "updates.status")) {
        if (sbj_obj_len(params)) { sbw_fail(error, "INVALID_REQUEST", "Update status expects empty parameters."); return NULL; }
        return sbw_updater_status(controller->updater);
    }
    if (sb_streq(method, "management.settings.get")) {
        AcquireSRWLockShared(&controller->state_lock);
        sbj *result = management_status(controller);
        ReleaseSRWLockShared(&controller->state_lock); return result;
    }
    if (sb_streq(method, "status.get") || sb_streq(method, "enrollment.status") || sb_streq(method, "config.summary")) {
        sbw_controller_poll(controller);
        sbj *result = NULL;
        AcquireSRWLockShared(&controller->state_lock);
        if (sb_streq(method, "config.summary")) { if (ready(controller, error)) result = config_summary(controller); }
        else result = sb_streq(method, "status.get") ? runtime_status(controller) : enrollment_status(controller);
        ReleaseSRWLockShared(&controller->state_lock); return result;
    }
    if (!sbw_is_mutating_method(method)) {
        sbw_fail(error, "NOT_IMPLEMENTED", "This service build does not implement this operation."); return NULL;
    }
    if (!authorized) {
        sbw_fail(error, "FORBIDDEN", "This operation requires an administrator or the active console session."); return NULL;
    }
    if (!TryAcquireSRWLockExclusive(&controller->user_operation_lock)) {
        sbw_fail(error, "BUSY", "Another device operation is in progress. Try again after it finishes."); return NULL;
    }
    /* A periodic health check or telemetry snapshot is not another user action.
     * Let its bounded I/O finish instead of randomly rejecting a stop/sync click.
     * The separate gate still rejects overlapping mutations, never queues a
     * duplicate enrollment or a second connection start behind the first. */
    if (controller->management_io_cancel) SetEvent(controller->management_io_cancel);
    AcquireSRWLockExclusive(&controller->mutation_lock);
    sbw_core_event(controller->core, method, "begin");
    sbj *result = NULL, *new_identity = NULL;
    sbw_enrollment_target target = {0};
    if (cancelled(controller, error) || !ready(controller, error)) goto done;
    observe_core(controller, false);
    if (!strncmp(method, "updates.", 8)) {
        int updated = -1;
        if (!strcmp(method, "updates.check") && sbj_obj_len(params) == 1 && sbw_json_string(sbj_get(params, "manifest_url"), 4096, false))
            updated = sbw_updater_check(controller->updater, sbj_get_str(params, "manifest_url", ""), error);
        else if ((!strcmp(method, "updates.download") || !strcmp(method, "updates.install")) && sbj_obj_len(params) == 1 &&
            sbw_json_string(sbj_get(params, "release_id"), 64, false)) {
            updated = !strcmp(method, "updates.download") ? sbw_updater_download(controller->updater, sbj_get_str(params, "release_id", ""), error) :
                sbw_updater_install(controller->updater, sbj_get_str(params, "release_id", ""), controller->runtime.core_running, error);
        } else if (!strcmp(method, "updates.cancel") && !sbj_obj_len(params)) updated = sbw_updater_cancel(controller->updater, error);
        else if (!strcmp(method, "updates.recover") && !sbj_obj_len(params)) updated = sbw_updater_recover(controller->updater, error);
        else if (!strcmp(method, "updates.health") && sbj_obj_len(params) == 2 && sbj_is_bool(sbj_get(params, "rollback")) &&
            sbw_json_string(sbj_get(params, "nonce"), 64, false)) {
            bool rollback = sbj_get_bool(params, "rollback", false), resume = false;
            updated = sbw_updater_health_parameters(controller->updater, sbj_get_str(params, "nonce", ""), rollback, &resume, error);
            if (!updated) updated = sbw_core_version_check(controller->core, SB_EASY_CORE_VERSION, controller->cancel, error);
            const sbj *source = controller->last_good ? controller->last_good : controller->candidate;
            const sbj *identity = source == controller->last_good ? sbj_get(source, "local_identity") : NULL;
            if (!identity) identity = controller->identity;
            if (!updated && source) {
                sbw_runtime_config adapted = {0};
                updated = prepare_with_identity(identity, source, &adapted, error);
                if (!updated) updated = check_config(controller, &adapted, error);
                sbw_runtime_config_free(&adapted);
            }
            if (!updated && resume) {
                if (!source || !identity) updated = sbw_fail(error, "UPDATE_HEALTH_FAILED", "The previous connected configuration is unavailable.");
                else {
                    updated = connection_activate(controller, source, identity, false, error);
                    if (!updated) { AcquireSRWLockExclusive(&controller->state_lock);
                        sb_windows_recovery_request(&controller->recovery, true, GetTickCount64());
                        ReleaseSRWLockExclusive(&controller->state_lock); }
                }
            }
            if (!updated) updated = sbw_updater_health_record(controller->updater, rollback, error);
            if (!updated) { result = sbj_object(); sbj_set_bool(result, "healthy", true); sbj_set_str(result, "version", SB_EASY_VERSION); }
        } else sbw_fail(error, "INVALID_REQUEST", "Invalid update operation or parameters.");
        if (!updated && !result) result = sbw_updater_status(controller->updater);
    } else if (!strncmp(method, "preferences.", 12)) {
        result = preferences_dispatch(controller, method, params, error);
    } else if (sb_streq(method, "mode.set")) {
        if (sbj_obj_len(params) != 1 || (!sbj_string_is(sbj_get(params,"mode"),"managed") && !sbj_string_is(sbj_get(params,"mode"),"independent"))) {
            sbw_fail(error, "INVALID_REQUEST", "Choose managed or independent mode."); goto done;
        }
        if (switch_mode(controller, sbj_string_is(sbj_get(params,"mode"),"independent"), error) == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = runtime_status(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method, "management.settings.set")) {
        if (management_settings_change(controller, params, error) == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = management_status(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method, "routing.health.check")) {
        sbw_health_reset(controller->health);
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->health_snapshot); controller->health_snapshot = sbw_health_snapshot(NULL);
        result = config_summary(controller); ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (sb_streq(method, "routing.health.set")) {
        if (!controller->identity) { sbw_fail(error, "NOT_ENROLLED", "Set up managed or independent mode first."); goto done; }
        new_identity = sbw_health_change(controller->identity, params, error);
        if (new_identity && !save_state(controller, new_identity, controller->candidate, controller->last_good, error)) {
            AcquireSRWLockExclusive(&controller->state_lock);
            sbj_free(controller->identity); controller->identity = new_identity; new_identity = NULL;
            result = config_summary(controller); ReleaseSRWLockExclusive(&controller->state_lock);
        }
    } else if (sb_streq(method, "routing.automatic.set")) {
        new_identity = sbw_routing_automatic(controller->active ? controller->active : controller->candidate, controller->identity, params, error);
        if (new_identity && !apply_local_identity(controller, new_identity, error)) {
            AcquireSRWLockShared(&controller->state_lock); result = config_summary(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method, "routing.probe") || sb_streq(method, "routing.delay")) {
        sbw_core_status process = {0};
        if (!controller->active || !controller->runtime.core_running ||
            sbw_core_poll(controller->core, &process, error) != 0 || !process.process_running) {
            sbw_fail(error, "NOT_CONNECTED", "Connect before running a routing diagnostic."); goto done;
        }
        result = sb_streq(method, "routing.probe") ?
            sbw_route_probe(&controller->active_config, controller->core, process.process_id, controller->cancel, params, error) :
            sbw_route_delay(&controller->active_config, process.process_id, controller->cancel, params, error);
    } else if (sb_streq(method, "connection.start") || sb_streq(method, "connection.stop")) {
        bool connect = sb_streq(method, "connection.start");
        sbw_error intent_error = {0};
        int intended = connection_intent(controller, connect, &intent_error);
        if (intended != 0 && connect) { if (error) *error = intent_error; goto done; }
        int changed = connect ? connection_activate(controller, controller->candidate, controller->identity, false, error) : connection_stop(controller, error);
        if (connect && changed != 0 && !controller->runtime.core_running) {
            AcquireSRWLockExclusive(&controller->state_lock);
            sb_windows_recovery_failed(&controller->recovery, GetTickCount64());
            ReleaseSRWLockExclusive(&controller->state_lock);
        }
        if (intended != 0) { if (error) *error = intent_error; changed = -1; }
        if (changed == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = runtime_status(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method,"subscriptions.fetch")) {
        const char *url=sbj_get_str(params,"url",NULL),*id=sbj_get_str(params,"id",NULL);
        if(sbj_obj_len(params)!=1 || (!url && !id)){sbw_fail(error,"INVALID_REQUEST","Choose a subscription address or ID.");goto done;}
        if(id){const sbj *subs=sbj_get(controller->identity,"local_subscriptions");for(size_t i=0;i<sbj_arr_len(subs);++i)if(sbj_string_is(sbj_get(sbj_arr_at(subs,i),"id"),id))url=sbj_get_str(sbj_arr_at(subs,i),"url",NULL);}
        result=sbw_subscription_fetch(url,controller->cancel,error);
    } else if (sb_streq(method,"subscriptions.import") || sb_streq(method,"subscriptions.refresh")) {
        if (sb_streq(method,"subscriptions.refresh")) {
            if (sbj_obj_len(params) != 1 || !sbw_json_string(sbj_get(params,"id"),36,false)) {
                sbw_fail(error,"INVALID_REQUEST","Choose one local subscription to refresh."); goto done;
            }
            new_identity = sbw_subscriptions_refresh(controller->identity, sbj_get_str(params,"id",""), controller->cancel, error);
        } else {
            sbj *base = controller->identity ? sbj_clone(controller->identity) : sbw_independent_identity();
            new_identity = sbw_subscriptions_import(base, params, controller->cancel, error); sbj_free(base);
        }
        if (new_identity && apply_local_identity(controller, new_identity, error) == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = config_summary(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        } else if (sb_streq(method,"subscriptions.refresh") && controller->identity && error)
            record_subscription_failure(controller, sbj_get_str(params,"id",""), error);
    } else if (sb_streq(method,"subscriptions.save") || sb_streq(method,"subscriptions.remove") ||
               sb_streq(method,"routing.group_save") || sb_streq(method,"routing.group_remove")) {
        new_identity = !strncmp(method, "routing.", 8) ?
            sbw_routing_change(controller->identity, params, sb_streq(method,"routing.group_remove"), error) :
            sbw_subscriptions_change(controller->identity,params,sb_streq(method,"subscriptions.remove"),error);
        if (new_identity && apply_local_identity(controller, new_identity, error) == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = config_summary(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method, "routing.set")) {
        if (!controller->identity) { sbw_fail(error,"NOT_ENROLLED","Enroll this device first."); goto done; }
        const char *id=sbj_get_str(params,"group",""), *mode=sbj_get_str(params,"mode","");
        const char *node=sbj_get_str(params,"node","");
        bool custom=sb_streq(mode,"node"), live=controller->active && controller->runtime.core_running;
        if (!sbw_json_string(sbj_get(params,"group"),64,false) ||
            (!custom && !sb_streq(mode,"server") && !sb_streq(mode,"default")) ||
            sbj_obj_len(params)!=(custom?3U:2U) ||
            (custom && !sbw_json_string(sbj_get(params,"node"),512,false)) ||
            (sb_streq(id,"default") && sb_streq(mode,"default"))) {
            sbw_fail(error,"INVALID_REQUEST","Choose a service group and routing mode."); goto done;
        }
        const sbj *source=live?controller->active:controller->candidate;
        if (!source) { sbw_fail(error,"NO_CANDIDATE","Download configuration first."); goto done; }
        sbj *groups=sbw_routing_groups(source,controller->identity); bool found=false, was_automatic=false;
        for(size_t i=0;i<sbj_arr_len(groups);++i)
            if(sbj_string_is(sbj_get(sbj_arr_at(groups,i),"id"),id)) {
                found=true; was_automatic=sbj_string_is(sbj_get(sbj_arr_at(groups,i),"mode"),"automatic");
            }
        sbj_free(groups);
        if(!found) { sbw_fail(error,"ROUTING_UNSUPPORTED","The service group is no longer present."); goto done; }
        new_identity=sbj_clone(controller->identity);
        sbj *overrides=sbj_get(new_identity,"windows_routing");
        if(!overrides){overrides=sbj_object();sbj_set(new_identity,"windows_routing",overrides);}
        sbj *pref=sbj_object();sbj_set_str(pref,"mode",mode);if(custom)sbj_set_str(pref,"node",node);
        sbj_set(overrides,id,pref);
        if(sb_streq(id,"gpt")) {
            sbj_set_bool(new_identity,"windows_gpt_use_default",sb_streq(mode,"default"));
            sbj_del(new_identity,"windows_gpt_outbound");if(custom)sbj_set_str(new_identity,"windows_gpt_outbound",node);
        }
        /* Automatic selectors have restricted members. Rebuild their validated
         * config when returning to a fixed/manual group so future switches can
         * use the ordinary catalog again. */
        if (was_automatic) {
            if (!apply_local_identity(controller, new_identity, error)) {
                AcquireSRWLockShared(&controller->state_lock); result = config_summary(controller);
                ReleaseSRWLockShared(&controller->state_lock);
            }
            goto done;
        }
        sbj *next=sbw_routing_apply(source,new_identity,true,error);
        if(!next)goto done;
        sbj *cfg=sbj_parse_cstr(sbj_get_str(next,"content",""));sbj_free(next);
        char selector[96];sprintf_s(selector,sizeof(selector),"sb-easy-local-%s",id);
        char *selected=NULL,*previous=NULL;
        const sbj *nodes=sbj_get(cfg,"outbounds");
        for(size_t i=0;i<sbj_arr_len(nodes);++i)
            if(sbj_string_is(sbj_get(sbj_arr_at(nodes,i),"tag"),selector)) selected=sb_strdup(sbj_get_str(sbj_arr_at(nodes,i),"default",""));
        sbj_free(cfg);
        if(!selected && !sb_streq(mode,"server")){sbw_fail(error,"ROUTING_UNSUPPORTED","This service cannot be safely changed locally.");goto done;}
        bool switch_live=live && selected;
        sbw_core_status process={0};sbj *proxies=NULL;
        if(switch_live) {
            if(sbw_core_poll(controller->core,&process,error)!=0 ||
                sbw_runtime_config_get(&controller->active_config,process.process_id,controller->cancel,"/proxies",&proxies,error)!=0) {
                free(selected);sbj_free(proxies);goto done;
            }
            previous=sb_strdup(sbj_get_str(sbj_get(sbj_get(proxies,"proxies"),selector),"now",""));sbj_free(proxies);
            if(!*previous){free(previous);free(selected);sbw_fail(error,"LIVE_ROUTING_UNAVAILABLE","Apply the updated configuration once to enable live service switching.");goto done;}
        }
        int applied=switch_live?sbw_runtime_select_group(&controller->active_config,process.process_id,controller->cancel,selector,selected,error):0;
        if(applied==0)applied=save_state(controller,new_identity,controller->candidate,controller->last_good,error);
        if(applied!=0) {
            sbw_error rollback={0};
            if(switch_live && sbw_runtime_select_group(&controller->active_config,process.process_id,NULL,selector,previous,&rollback)!=0) {
                sbw_fail(error,"LIVE_ROUTING_UNCERTAIN","The switch could not be rolled back. Check the running node.");
                AcquireSRWLockExclusive(&controller->state_lock);if(error)controller->runtime_error=*error;ReleaseSRWLockExclusive(&controller->state_lock);
            }
            free(previous);free(selected);goto done;
        }
        free(previous);free(selected);
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->identity);controller->identity=new_identity;new_identity=NULL;
        free(controller->checked_etag);controller->checked_etag=NULL;controller->checked_valid=false;
        if(live)memset(&controller->runtime_error,0,sizeof(controller->runtime_error));
        result=config_summary(controller);ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (sb_streq(method, "routing.gpt_default") || sb_streq(method, "routing.gpt_server") || sb_streq(method, "routing.gpt_node")) {
        if (!controller->identity) { sbw_fail(error, "NOT_ENROLLED", "Enroll this device first."); goto done; }
        bool local = sb_streq(method, "routing.gpt_default");
        const char *outbound = NULL;
        if (sb_streq(method, "routing.gpt_node")) {
            if (sbj_obj_len(params) != 1 || !sbw_json_string(sbj_get(params, "outbound"), 512, false)) {
                sbw_fail(error, "INVALID_REQUEST", "Choose one valid outbound tag."); goto done;
            }
            outbound = sbj_get_str(params, "outbound", "");
        }
        bool live = controller->active && controller->runtime.core_running;
        const sbj *routing_source = live ? controller->active : controller->candidate;
        if (local || outbound || live) {
            if (!routing_source) { sbw_fail(error, "NO_CANDIDATE", "Download configuration first."); goto done; }
            sbj *effective = sbw_routing_snapshot_node(routing_source, local, outbound, error);
            if (!effective) goto done;
            const char *content = sbj_get_str(effective, "content", "");
            sbw_runtime_config adapted = {0};
            int checked = sbw_runtime_config_prepare(content, strlen(content),
                sbj_get_str(controller->identity, "server", ""), &adapted, error);
            if (checked == 0) checked = check_config(controller, &adapted, error);
            sbw_runtime_config_free(&adapted); sbj_free(effective);
            if (checked != 0) goto done;
        }
        new_identity = sbj_clone(controller->identity);
        if (sbj_get(new_identity, "windows_routing")) sbj_del(sbj_get(new_identity, "windows_routing"), "gpt");
        sbj_set_bool(new_identity, "windows_gpt_use_default", local);
        sbj_del(new_identity, "windows_gpt_outbound");
        if (outbound) sbj_set_str(new_identity, "windows_gpt_outbound", outbound);
        char *previous = NULL, *selected = NULL;
        sbw_core_status process = {0};
        if (live) {
            sbj *next = sbw_routing_snapshot_node(controller->active, local, outbound, error);
            if (!next) goto done;
            selected = sbw_routing_target(next); sbj_free(next);
            sbj *proxies = NULL;
            if (!selected || !*selected) {
                free(selected); sbw_fail(error, "LIVE_ROUTING_UNAVAILABLE", "This running configuration has no GPT route."); goto done;
            }
            if (sbw_core_poll(controller->core, &process, error) != 0 ||
                sbw_runtime_config_get(&controller->active_config, process.process_id, controller->cancel, "/proxies", &proxies, error) != 0) {
                free(selected); sbj_free(proxies); goto done;
            }
            previous = sb_strdup(sbj_get_str(sbj_get(sbj_get(proxies, "proxies"), SBW_GPT_SELECTOR), "now", ""));
            sbj_free(proxies);
            if (!*previous) {
                free(previous); free(selected);
                sbw_fail(error, "LIVE_ROUTING_UNAVAILABLE", "This running configuration has no live GPT group."); goto done;
            }
        }
        int applied = live ? sbw_runtime_select_gpt(&controller->active_config, process.process_id,
            controller->cancel, selected, error) : 0;
        if (applied == 0) applied = save_state(controller, new_identity, controller->candidate, controller->last_good, error);
        if (applied != 0) {
            sbw_error rollback_error = {0};
            if (live && sbw_runtime_select_gpt(&controller->active_config, process.process_id, NULL, previous, &rollback_error) != 0) {
                sbw_fail(error, "LIVE_ROUTING_UNCERTAIN", "The live switch could not be rolled back. Check the current node before retrying.");
                AcquireSRWLockExclusive(&controller->state_lock);
                if (error) controller->runtime_error = *error;
                ReleaseSRWLockExclusive(&controller->state_lock);
            }
            free(previous); free(selected); goto done;
        }
        free(previous); free(selected);
        AcquireSRWLockExclusive(&controller->state_lock);
        if (live) memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        sbj_free(controller->identity); controller->identity = new_identity; new_identity = NULL;
        free(controller->checked_etag); controller->checked_etag = NULL; controller->checked_valid = false;
        result = config_summary(controller);
        ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (is_apply) {
        const sbj *uri = sbj_get(params, "uri");
        if (sbj_obj_len(params) != 1 || !sbw_json_string(uri, 16384, false)) {
            sbw_fail(error, "INVALID_REQUEST", "Enrollment expects one registration URI."); goto done;
        }
        if (sbw_identity_is_independent(controller->identity)) { sbw_fail(error, "INDEPENDENT_MODE", "Switch to managed mode before enrolling a device."); goto done; }
        if (controller->identity) {
            sbw_fail(error, "ALREADY_ENROLLED", "Forget the stopped device before enrolling another device."); goto done;
        }
        if (sbw_parse_enrollment_uri(uri->v.str.ptr, &target, error) != 0 ||
            controller->remote->enroll(controller->remote->context, &target, controller->cancel, &new_identity, error) != 0) goto done;
        if (!identity_valid(new_identity)) { sbw_fail(error, "INVALID_RESPONSE", "The server returned invalid device information."); goto done; }
        sbj_del(new_identity, "windows_gpt_use_default");
        sbj_del(new_identity, "windows_gpt_outbound");
        sbj_del(new_identity, "windows_routing");
        sbj_del(new_identity, "local_subscriptions");
        sbj_del(new_identity, "windows_local_groups");
        /* A redeemed single-use identity must be saved even during shutdown. */
        if (save_state(controller, new_identity, NULL, NULL, error) != 0) goto done;
        AcquireSRWLockExclusive(&controller->state_lock);
        controller->identity = new_identity; new_identity = NULL;
        sbj_free(controller->candidate); controller->candidate = NULL;
        sbj_free(controller->last_good); controller->last_good = NULL;
        memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        free(controller->checked_etag); controller->checked_etag = NULL;
        controller->checked_valid = false;
        if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ENROLL);
        result = enrollment_status(controller);
        ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (sb_streq(method, "enrollment.forget")) {
        if (controller->runtime.phase != SB_WINDOWS_STOPPED) {
            sbw_fail(error, "INVALID_STATE", "Only a stopped enrolled device can be forgotten."); goto done;
        }
        if (sbw_identity_is_independent(controller->identity)) {
            sbw_fail(error,"INDEPENDENT_MODE","Independent mode has no device enrollment to forget."); goto done;
        }
        if (controller->independent_archive) {
            sbj *saved = persisted_state(controller, NULL, NULL, NULL); sbj_set_null(saved,"managed_archive"); sbj_set(saved,"command_receipts",sbj_array());
            int stored = controller->store->save(controller->store->context,saved,error); sbj_free(saved);
            if (stored != 0) goto done;
        } else if (controller->store->clear(controller->store->context, error) != 0) goto done;
        capture_upload_join(controller); sbw_capture_free(controller->capture); controller->capture = NULL;
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->managed_archive); controller->managed_archive = NULL;
        sbj_free(controller->identity); controller->identity = NULL;
        sbj_free(controller->candidate); controller->candidate = NULL;
        sbj_free(controller->last_good); controller->last_good = NULL;
        memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        free(controller->checked_etag); controller->checked_etag = NULL;
        controller->checked_valid = false;
        if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_FORGET);
        sb_windows_recovery_request(&controller->recovery, false, GetTickCount64());
        sbj_free(controller->command_receipts); controller->command_receipts = sbj_array();
        result = enrollment_status(controller);
        ReleaseSRWLockExclusive(&controller->state_lock);
    } else if (sb_streq(method, "config.validate")) {
        if (!controller->candidate) { sbw_fail(error, "NO_CANDIDATE", "Download a candidate configuration before validating it."); goto done; }
        if (!controller->core) { sbw_fail(error, "CORE_UNAVAILABLE", "The pinned sing-box core is not available. Run the core preparation script first."); goto done; }
        sbw_error check_error = {0}; sbw_runtime_config adapted = {0};
        int checked = prepare_candidate(controller, controller->candidate, &adapted, &check_error);
        if (checked == 0) checked = check_config(controller, &adapted, &check_error);
        sbw_runtime_config_free(&adapted);
        record_check(controller, checked == 0, &check_error);
        AcquireSRWLockShared(&controller->state_lock);
        if (checked == 0) result = config_summary(controller);
        ReleaseSRWLockShared(&controller->state_lock);
        if (checked != 0) sbw_fail(error, check_error.code, check_error.message);
    } else {
        if (refresh_configuration(controller, false, controller->cancel, error) != 0) goto done;
        AcquireSRWLockShared(&controller->state_lock);
        result = config_summary(controller);
        ReleaseSRWLockShared(&controller->state_lock);
    }
done:
    sbj_free(new_identity); sbw_enrollment_target_free(&target);
    sbw_core_event(controller->core, method, result ? "ok" : error && error->code[0] ? error->code : "failed");
    ReleaseSRWLockExclusive(&controller->mutation_lock);
    ReleaseSRWLockExclusive(&controller->user_operation_lock); return result;
}

typedef struct capture_upload_job {
    sbw_controller *controller;
    sbj *identity;
    unsigned char *bytes;
    size_t length;
    char digest[65];
    bool remove_after;
} capture_upload_job;
static DWORD WINAPI capture_upload_main(void *context) {
    capture_upload_job *job = context; sbw_controller *c = job->controller; sbw_error error = {0};
    int result = c->remote->upload_capture(c->remote->context, job->identity, job->digest,
                                         job->bytes, job->length, c->upload_cancel, &error);
    if (!result) result = sbw_capture_mark_uploaded(c->capture, job->digest, &error);
    if (!result && job->remove_after) result = sbw_capture_delete(c->capture, job->digest, &error);
    AcquireSRWLockExclusive(&c->upload_lock);
    strcpy_s(c->upload_status, sizeof c->upload_status, result ? error.message : "Upload confirmed by server.");
    ReleaseSRWLockExclusive(&c->upload_lock);
    SecureZeroMemory(job->bytes, job->length); free(job->bytes); sbj_free(job->identity); free(job); return 0;
}
static void capture_upload_join(sbw_controller *c) {
    if (c->upload_cancel) SetEvent(c->upload_cancel);
    if (c->upload_thread) { WaitForSingleObject(c->upload_thread, INFINITE); CloseHandle(c->upload_thread); c->upload_thread = NULL; }
    if (c->upload_cancel) { CloseHandle(c->upload_cancel); c->upload_cancel = NULL; }
}
static bool capture_uploading(sbw_controller *c) {
    return c->upload_thread && WaitForSingleObject(c->upload_thread, 0) == WAIT_TIMEOUT;
}
static int capture_upload_begin(sbw_controller *c, const char *digest, sbw_error *error) {
    if (capture_uploading(c)) return sbw_fail(error, "BUSY", "A capture upload is already running.");
    if (!c->remote->upload_capture) return sbw_fail(error, "NOT_IMPLEMENTED", "Capture upload is unavailable.");
    sbj *snapshot = sbw_capture_snapshot(c->capture); const sbj *config = sbj_get(snapshot, "config");
    bool wifi_only = sbj_get_bool(config, "wifi_only", true), remove_after = sbj_get_bool(config, "delete_after_upload", false);
    sbj_free(snapshot);
    if (wifi_only && !sbw_capture_wifi()) return sbw_fail(error, "WIFI_REQUIRED", "Capture upload is restricted to Wi-Fi. Change capture settings to use Ethernet.");
    capture_upload_join(c);
    capture_upload_job *job = sb_xcalloc(1, sizeof *job); job->controller = c; job->remove_after = remove_after;
    if (sbw_capture_read(c->capture, digest, &job->bytes, &job->length, error) != 0) { free(job); return -1; }
    strcpy_s(job->digest, sizeof job->digest, digest); job->identity = sbj_clone(c->identity);
    c->upload_cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    c->upload_attempt = GetTickCount64();
    AcquireSRWLockExclusive(&c->upload_lock); strcpy_s(c->upload_status, sizeof c->upload_status, "Uploading capture..."); ReleaseSRWLockExclusive(&c->upload_lock);
    c->upload_thread = c->upload_cancel ? CreateThread(NULL, 0, capture_upload_main, job, 0, NULL) : NULL;
    if (!c->upload_thread) { free(job->bytes); sbj_free(job->identity); free(job); capture_upload_join(c); return sbw_fail(error, "CAPTURE_FAILED", "Upload worker could not start."); }
    return 0;
}
static void capture_auto_upload(sbw_controller *c) {
    if (!c->capture || !c->identity || capture_uploading(c) || !c->runtime.core_running) return;
    sbj *snapshot = sbw_capture_snapshot(c->capture); const sbj *config = sbj_get(snapshot, "config");
    bool allowed = sbj_get_bool(config, "auto_upload", false) &&
        GetTickCount64() - c->upload_attempt >= (ULONGLONG)sbj_get_int(config, "upload_seconds", 60) * 1000;
    sbj_free(snapshot); if (!allowed) return;
    c->upload_attempt = GetTickCount64(); sbw_capture_rotate(c->capture, NULL);
    snapshot = sbw_capture_snapshot(c->capture); const sbj *files = sbj_get(snapshot, "files");
    for (size_t i = 0; i < sbj_arr_len(files); ++i) {
        const sbj *file = sbj_arr_at(files, i);
        if (!sbj_get_bool(file, "uploaded", false)) {
            sbw_error error = {0};
            if (capture_upload_begin(c, sbj_get_str(file, "digest", ""), &error) != 0) {
                AcquireSRWLockExclusive(&c->upload_lock); strcpy_s(c->upload_status, sizeof c->upload_status, error.message); ReleaseSRWLockExclusive(&c->upload_lock);
            }
            break;
        }
    }
    sbj_free(snapshot);
}
static sbj *capture_snapshot(sbw_controller *c) {
    sbj *result = sbw_capture_snapshot(c->capture);
    if (!result) return NULL;
    AcquireSRWLockShared(&c->upload_lock); sbj_set_str(result, "upload_status", c->upload_status); ReleaseSRWLockShared(&c->upload_lock);
    sbj_set_bool(result, "uploading", capture_uploading(c));
    sbj *apps = sbj_array(); HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {0}; entry.dwSize = sizeof entry;
    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Process32FirstW(snapshot, &entry)) do {
            char *name = sbw_utf8(entry.szExeFile, NULL);
            if (name && strlen(name) <= 96 && sbj_arr_len(apps) < 512) sbj_arr_push(apps, sbj_str(name));
            free(name);
        } while (Process32NextW(snapshot, &entry));
        CloseHandle(snapshot);
    }
    sbj_set(result, "apps", apps); return result;
}
static sbj *capture_dispatch(sbw_controller *c, const char *method, const sbj *params, sbw_error *error) {
    if (!sbw_extension_enabled()) { sbw_fail(error,"EXTENSION_MISSING","Install and enable the capture extension first."); return NULL; }
    if (!c->identity || !c->core) { sbw_fail(error,"NOT_ENROLLED","Register this device first."); return NULL; }
    if (!c->capture) c->capture=sbw_capture_new(sbw_core_work_directory(c->core),c->identity,error);
    if (!c->capture) return NULL;
    if (!sbw_capture_worker_running(c->capture)) { sbw_fail(error,"EXTENSION_FAILED","Re-enable the capture extension in Extensions. Proxy remains connected."); return NULL; }
    if (sb_streq(method, "capture.validate")) {
        if (sbj_obj_len(params) != 1 || !sbj_is_object(sbj_get(params, "config"))) goto invalid;
        sbj *config = sbw_capture_worker_validate(c->capture, sbj_get(params, "config"), error); if (!config) return NULL;
        sbj *result = sbj_object(); sbj_set(result, "config", config); return result;
    }
    if (!c->identity || !c->core) { sbw_fail(error, "NOT_ENROLLED", "Register the device and prepare the core first."); return NULL; }
    if (!c->capture) c->capture = sbw_capture_new(sbw_core_work_directory(c->core), c->identity, error);
    if (!c->capture) return NULL;
    if (sb_streq(method, "capture.configure")) {
        if (sbj_obj_len(params) != 1 || !sbj_is_object(sbj_get(params, "config"))) goto invalid;
        capture_upload_join(c);
        if (sbw_capture_configure(c->capture, sbj_get(params, "config"), error) != 0) return NULL;
        collect_traffic(c);
    } else if (sb_streq(method, "capture.snapshot") || sb_streq(method, "capture.rotate")) {
        if (sbj_obj_len(params)) goto invalid;
        if (sb_streq(method, "capture.rotate") && sbw_capture_rotate(c->capture, error) != 0) return NULL;
    } else if (sb_streq(method, "capture.delete") || sb_streq(method, "capture.upload") || sb_streq(method, "capture.read")) {
        const char *digest = sbj_get_str(params, "digest", "");
        bool read = sb_streq(method, "capture.read");
        if (sbj_obj_len(params) != (read ? 2U : 1U) || !sbw_capture_digest_valid(digest)) goto invalid;
        if (sb_streq(method, "capture.delete")) {
            if (capture_uploading(c)) { sbw_fail(error, "BUSY", "Wait for the capture upload before deleting files."); return NULL; }
            if (sbw_capture_delete(c->capture, digest, error) != 0) return NULL;
        } else if (read) {
            if (!sbj_is_integer(sbj_get(params, "offset"))) goto invalid;
            int64_t offset = sbj_get_int(params, "offset", -1); unsigned char *bytes = NULL; size_t length = 0;
            if (offset < 0 || offset > 768 * 1024) goto invalid;
            if (sbw_capture_read(c->capture, digest, &bytes, &length, error) != 0) return NULL;
            if ((size_t)offset > length) { free(bytes); goto invalid; }
            size_t count = length - (size_t)offset; if (count > 65536) count = 65536;
            DWORD chars = 0; CryptBinaryToStringA(bytes + offset, (DWORD)count, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &chars);
            char *encoded = sb_xcalloc((size_t)chars + 1, 1);
            bool ok = CryptBinaryToStringA(bytes + offset, (DWORD)count, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded, &chars) != FALSE;
            SecureZeroMemory(bytes, length); free(bytes);
            if (!ok) { free(encoded); sbw_fail(error, "CAPTURE_FAILED", "Capture export failed."); return NULL; }
            sbj *result = sbj_object(); sbj_set_str(result, "data", encoded); free(encoded);
            sbj_set_int(result, "total", (int64_t)length); sbj_set_int(result, "offset", offset); sbj_set_int(result, "next", offset + (int64_t)count); return result;
        } else if (capture_upload_begin(c, digest, error) != 0) return NULL;
    } else { sbw_fail(error, "NOT_IMPLEMENTED", "Unknown capture operation."); return NULL; }
    sbj *snapshot=capture_snapshot(c);
    if(!snapshot)sbw_fail(error,"EXTENSION_FAILED","Capture extension stopped. Re-enable it in Extensions. Proxy remains connected.");
    return snapshot;
 invalid:
    sbw_fail(error, "INVALID_REQUEST", "Invalid capture operation parameters."); return NULL;
}
