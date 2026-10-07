#include "controller.h"
#include "runtime_config.h"
#include "dashboard.h"
#include <stdlib.h>
#include <string.h>

struct sbw_controller {
    sbw_control_plane *remote;
    sbw_store *store;
    HANDLE cancel;
    SRWLOCK state_lock, mutation_lock;
    sbj *identity, *candidate, *last_good, *active;
    sbw_error startup_error;
    sbw_core *core;
    sbw_error core_error;
    char *checked_etag;
    bool checked_valid;
    sb_windows_runtime_state runtime;
    sbw_runtime_config active_config;
    sbw_error runtime_error;
    bool last_stop_forced;
    HANDLE monitor_stop, monitor;
};
static DWORD WINAPI monitor_main(void *context);
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
    sbj_set_bool(result, "enrolled", controller->identity != NULL);
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
    sbj_set_str(validation, "core_version", "1.13.12");
    if (controller->core_error.code[0]) {
        sbj *error = sbj_object();
        sbj_set_str(error, "code", controller->core_error.code); sbj_set_str(error, "message", controller->core_error.message);
        sbj_set(validation, "error", error);
    }
    sbj_set(result, "validation", validation);
    return result;
}
static sbj *persisted_state(const sbj *identity, const sbj *candidate, const sbj *last_good) {
    sbj *state = sbj_object();
    sbj_set_int(state, "version", 1);
    sbj_set(state, "identity", sbj_clone(identity));
    sbj_set(state, "candidate", candidate ? sbj_clone(candidate) : sbj_null());
    sbj_set(state, "last_good", last_good ? sbj_clone(last_good) : sbj_null());
    return state;
}
static int save_state(sbw_controller *controller, const sbj *identity, const sbj *candidate, const sbj *last_good, sbw_error *error) {
    sbj *saved = persisted_state(identity, candidate, last_good);
    int result = controller->store->save(controller->store->context, saved, error);
    sbj_free(saved); return result;
}
static bool saved_config_valid(const sbj *candidate) {
    if (!candidate || sbj_is_null(candidate)) return true;
    const char *keys[] = {"etag", "rule_source", "profile_id", "profile_name"};
    for (size_t i = 0; i < 4; ++i)
        if (!sbw_json_string(sbj_get(candidate, keys[i]), 4096, i >= 2)) return false;
    sbj *counts = config_counts(candidate, NULL);
    bool valid = counts != NULL; sbj_free(counts); return valid;
}
sbw_controller *sbw_controller_new(sbw_control_plane *remote, sbw_store *store, HANDLE cancel, sbw_error *error) {
    if (!remote || !store) {
        sbw_control_plane_free(remote); sbw_store_free(store);
        sbw_fail(error, "INITIALIZATION_FAILED", "Service dependencies are unavailable."); return NULL;
    }
    sbw_controller *controller = sb_xcalloc(1, sizeof *controller);
    controller->remote = remote; controller->store = store; controller->cancel = cancel;
    InitializeSRWLock(&controller->state_lock); InitializeSRWLock(&controller->mutation_lock);
    sb_windows_runtime_init(&controller->runtime);
    sbj *saved = NULL;
    if (store->load(store->context, &saved, &controller->startup_error) != 0) return controller;
    if (!saved) return controller;
    const sbj *identity = sbj_get(saved, "identity"), *candidate = sbj_get(saved, "candidate");
    bool valid = sbj_is_object(saved) && sbj_is_integer(sbj_get(saved, "version")) &&
        sbj_get_int(saved, "version", 0) == 1 && identity_valid(identity);
    const sbj *last_good = sbj_get(saved, "last_good");
    valid = valid && saved_config_valid(candidate) && saved_config_valid(last_good);
    if (valid) {
        controller->identity = sbj_clone(identity);
        controller->candidate = sbj_is_null(candidate) ? NULL : sbj_clone(candidate);
        controller->last_good = !last_good || sbj_is_null(last_good) ? NULL : sbj_clone(last_good);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_ENROLL);
    } else sbw_fail(&controller->startup_error, "STORAGE_CORRUPT", "Stored device state is unavailable; it was left unchanged.");
    sbj_free(saved); return controller;
}
void sbw_controller_free(sbw_controller *controller) {
    if (!controller) return;
    if (controller->monitor_stop) SetEvent(controller->monitor_stop);
    if (controller->monitor) { WaitForSingleObject(controller->monitor, INFINITE); CloseHandle(controller->monitor); }
    if (controller->monitor_stop) CloseHandle(controller->monitor_stop);
    /* All IPC workers are joined by the caller before freeing this owner. */
    sbw_core_stop(controller->core, NULL);
    sbw_runtime_config_free(&controller->active_config);
    sbj_free(controller->identity); sbj_free(controller->candidate);
    sbj_free(controller->last_good); sbj_free(controller->active);
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
bool sbw_is_mutating_method(const char *method) {
    return sb_streq(method, "enrollment.apply") || sb_streq(method, "enrollment.forget") ||
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
        controller->candidate && !controller->startup_error.code[0]);
    sbj_set_bool(result, "tun_active", controller->runtime.core_running && controller->active_config.has_tun &&
        controller->active_config.auto_route);
    sbj_set_str(result, "connection_mode", controller->active ?
        (controller->active_config.has_tun ? "tun" : "local") : NULL);
    sbj_set(result, "config", config_summary(controller));
    if (controller->runtime_error.code[0]) {
        sbj *failure = sbj_object();
        sbj_set_str(failure, "code", controller->runtime_error.code);
        sbj_set_str(failure, "message", controller->runtime_error.message);
        sbj_set(result, "runtime_error", failure);
    }
    return result;
}
static void clear_active(sbw_controller *controller) {
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
static int prepare_candidate(sbw_controller *controller, const sbj *source, sbw_runtime_config *config, sbw_error *error) {
    const sbj *content = sbj_get(source, "content");
    if (!content) return sbw_fail(error, "NO_CANDIDATE", "Download a candidate configuration before starting.");
    return sbw_runtime_config_prepare(content->v.str.ptr, content->v.str.len,
        sbj_get_str(controller->identity, "server", ""), config, error);
}
static int check_config(sbw_controller *controller, sbw_runtime_config *config, sbw_error *error) {
    return sbw_core_config_check(controller->core, config->json, strlen(config->json), controller->cancel, NULL, error);
}
static int launch_healthy(sbw_controller *controller, sbw_runtime_config *config, sbw_error *error) {
    if (sbw_core_start(controller->core, config->json, strlen(config->json), controller->cancel, error) != 0) return -1;
    sbw_core_status status = {0};
    if (sbw_core_poll(controller->core, &status, error) != 0 || !status.process_running)
        return sbw_fail(error, "CORE_EXITED", "The core exited during startup.");
    if (sbw_runtime_config_health(config, status.process_id, controller->cancel, 3000, error) != 0) return -1;
    if (cancelled(controller, error)) return -1;
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
            observe_core(controller, true);
            ReleaseSRWLockExclusive(&controller->mutation_lock);
        }
    }
    return 0;
}
static int connection_stop(sbw_controller *controller, sbw_error *error) {
    bool had_tun = controller->active_config.has_tun;
    int stopped = sbw_core_stop(controller->core, error);
    sbw_core_status status = {0};
    if (stopped == 0 && controller->core) (void)sbw_core_poll(controller->core, &status, NULL);
    if (stopped == 0 && had_tun && status.last_stop_forced)
        stopped = sbw_fail(error, "TUN_FORCE_STOPPED", "The TUN core required forced termination; network cleanup has not been verified.");
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
static int connection_start(sbw_controller *controller, sbw_error *error) {
    if (!controller->identity) return sbw_fail(error, "NOT_ENROLLED", "Enroll this device before starting a connection.");
    if (!controller->candidate) return sbw_fail(error, "NO_CANDIDATE", "Download a candidate configuration before starting.");
    if (!controller->core) return sbw_fail(error, "CORE_UNAVAILABLE", "Prepare the pinned core and restart the service first.");
    if (controller->active && sbj_equal(controller->active, controller->candidate)) return 0;
    sbw_runtime_config next = {0}; sbw_error failure = {0};
    /* A rejected candidate must never interrupt a healthy old instance. */
    if (prepare_candidate(controller, controller->candidate, &next, &failure) != 0 ||
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
    if (started && save_state(controller, controller->identity, controller->candidate, controller->candidate, &failure) == 0) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->last_good); controller->last_good = sbj_clone(controller->candidate);
        controller->active = sbj_clone(controller->candidate);
        controller->active_config = next; memset(&next, 0, sizeof next);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_CORE_HEALTHY);
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
    if (!safe_to_restore) failure = cleanup_error;
    sbw_runtime_config_free(&next);
    bool rollback = safe_to_restore && controller->last_good && !cancelled(controller, NULL);
    if (rollback) {
        AcquireSRWLockExclusive(&controller->state_lock);
        controller->runtime.phase = SB_WINDOWS_ROLLING_BACK;
        ReleaseSRWLockExclusive(&controller->state_lock);
        sbw_error restore_error = {0};
        rollback = prepare_candidate(controller, controller->last_good, &next, &restore_error) == 0 &&
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
    result = sbw_dashboard_snapshot(connections, proxies);
    sbj_set_bool(result, "running", running);
    sbj_set_int(result, "core_pid", process.process_id);
    sbj_set_int(result, "sample_ms", (int64_t)GetTickCount64());
    sbj_set_str(result, "etag", sbj_get_str(controller->active, "etag", NULL));
done:
    sbj_free(connections); sbj_free(proxies);
    ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
}
sbj *sbw_controller_dispatch(sbw_controller *controller, const char *method, const sbj *params, bool authorized, sbw_error *error) {
    if (!controller || !method) { sbw_fail(error, "INVALID_REQUEST", "Invalid service operation."); return NULL; }
    bool is_apply = strcmp(method, "enrollment.apply") == 0;
    if (!sbj_is_object(params) || (!is_apply && sbj_obj_len(params) != 0)) {
        sbw_fail(error, "INVALID_REQUEST", "This operation expects object params."); return NULL;
    }
    if (sb_streq(method, "runtime.snapshot") || sb_streq(method, "config.inspect")) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "This operation requires an administrator or the active console session."); return NULL; }
        if (sb_streq(method, "runtime.snapshot")) return dashboard_snapshot(controller, error);
        sbj *result = NULL;
        AcquireSRWLockShared(&controller->state_lock);
        if (ready(controller, error)) {
            result = sbj_object();
            sbj_set(result, "candidate", sbw_config_catalog(controller->candidate));
            sbj_set(result, "active", sbw_config_catalog(controller->active));
        }
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
    if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) {
        sbw_fail(error, "BUSY", "Another device operation is in progress. Try again after it finishes."); return NULL;
    }
    sbj *result = NULL, *new_identity = NULL, *download = NULL;
    sbw_enrollment_target target = {0};
    if (cancelled(controller, error) || !ready(controller, error)) goto done;
    observe_core(controller, false);
    if (sb_streq(method, "connection.start") || sb_streq(method, "connection.stop")) {
        int changed = sb_streq(method, "connection.start") ? connection_start(controller, error) : connection_stop(controller, error);
        if (changed == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = runtime_status(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (is_apply) {
        const sbj *uri = sbj_get(params, "uri");
        if (sbj_obj_len(params) != 1 || !sbw_json_string(uri, 16384, false)) {
            sbw_fail(error, "INVALID_REQUEST", "Enrollment expects one registration URI."); goto done;
        }
        if (controller->identity) {
            sbw_fail(error, "ALREADY_ENROLLED", "Forget the stopped device before enrolling another device."); goto done;
        }
        if (sbw_parse_enrollment_uri(uri->v.str.ptr, &target, error) != 0 ||
            controller->remote->enroll(controller->remote->context, &target, controller->cancel, &new_identity, error) != 0) goto done;
        if (!identity_valid(new_identity)) { sbw_fail(error, "INVALID_RESPONSE", "The server returned invalid device information."); goto done; }
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
        if (controller->store->clear(controller->store->context, error) != 0) goto done;
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj_free(controller->identity); controller->identity = NULL;
        sbj_free(controller->candidate); controller->candidate = NULL;
        sbj_free(controller->last_good); controller->last_good = NULL;
        memset(&controller->runtime_error, 0, sizeof controller->runtime_error);
        free(controller->checked_etag); controller->checked_etag = NULL;
        controller->checked_valid = false;
        if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
        sb_windows_runtime_apply(&controller->runtime, SB_WINDOWS_FORGET);
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
        if (!controller->identity) { sbw_fail(error, "NOT_ENROLLED", "Enroll this device before downloading configuration."); goto done; }
        const char *etag = sbj_get_str(controller->candidate, "etag", "");
        if (controller->remote->fetch_config(controller->remote->context, controller->identity, etag,
            controller->cancel, &download, error) != 0 || cancelled(controller, error)) goto done;
        if (sbj_get_bool(download, "not_modified", false)) {
            if (!controller->candidate) { sbw_fail(error, "INVALID_RESPONSE", "The server returned no configuration for this device."); goto done; }
        } else {
            sbj *counts = config_counts(download, error);
            if (!counts) goto done;
            sbj_free(counts);
            if (!sbw_json_string(sbj_get(download, "etag"), 4096, false)) {
                sbw_fail(error, "INVALID_RESPONSE", "The downloaded configuration has no valid revision."); goto done;
            }
            const char *source = sbj_get_str(download, "rule_source", "");
            if (!sb_streq(source, "profile") && !sb_streq(source, "quickjs")) sbj_set_str(download, "rule_source", "unknown");
            for (size_t i = 0; i < 2; ++i) {
                const char *key = i == 0 ? "profile_id" : "profile_name";
                if (!sbw_json_string(sbj_get(download, key), 4096, false))
                    sbj_set_str(download, key, sbj_get_str(controller->identity, key, ""));
            }
            sbj_del(download, "not_modified");
            if (save_state(controller, controller->identity, download, controller->last_good, error) != 0) goto done;
            AcquireSRWLockExclusive(&controller->state_lock);
            sbj_free(controller->candidate); controller->candidate = download; download = NULL;
            free(controller->checked_etag); controller->checked_etag = NULL;
            controller->checked_valid = false;
            if (controller->core) memset(&controller->core_error, 0, sizeof controller->core_error);
            ReleaseSRWLockExclusive(&controller->state_lock);
        }
        AcquireSRWLockShared(&controller->state_lock);
        result = config_summary(controller);
        ReleaseSRWLockShared(&controller->state_lock);
    }
done:
    sbj_free(new_identity); sbj_free(download); sbw_enrollment_target_free(&target);
    ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
}
