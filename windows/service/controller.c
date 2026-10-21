#include "subscriptions.h"
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
#include "ip_check.h"
#include <wincrypt.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct sbw_controller {
    sbw_control_plane *remote;
    sbw_store *store;
    HANDLE cancel;
    SRWLOCK state_lock, mutation_lock, user_operation_lock;
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
    sbw_traffic *traffic;
    ULONGLONG traffic_saved;
    bool traffic_storage_ok, traffic_load_ok;
    sbw_capture *capture;
    sbw_extension_process *httpdebug;
    char *httpdebug_base;
    sbj *httpdebug_domains;
    sbw_extension_process *ipcheck;
    sbj *ipcheck_latest;
    HANDLE upload_thread, upload_cancel;
    SRWLOCK upload_lock;
    char upload_status[256];
    ULONGLONG upload_attempt;

};
static DWORD WINAPI monitor_main(void *context);
static bool collect_traffic(sbw_controller *controller);
static void persist_traffic(sbw_controller *controller);
static void capture_upload_join(sbw_controller *controller);
static void capture_auto_upload(sbw_controller *controller);
static sbj *capture_dispatch(sbw_controller *controller, const char *method, const sbj *params, sbw_error *error);
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
    sbj_set_bool(result, "gpt_use_default", sbj_get_bool(controller->identity, "windows_gpt_use_default", false));
    sbj_set_str(result, "gpt_outbound", sbj_get_str(controller->identity, "windows_gpt_outbound", NULL));
    sbj_set(result, "subscriptions", sbw_subscriptions_summary(controller->active ? controller->active : controller->candidate, controller->identity));
    sbj_set(result, "routing_groups", sbw_routing_groups(controller->active ? controller->active : controller->candidate, controller->identity));
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
    controller->traffic_storage_ok = controller->traffic_load_ok = true;
    controller->remote = remote; controller->store = store; controller->cancel = cancel;
    InitializeSRWLock(&controller->state_lock); InitializeSRWLock(&controller->mutation_lock);
    InitializeSRWLock(&controller->user_operation_lock); InitializeSRWLock(&controller->upload_lock);
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
    sbw_store_join();
    if (controller->monitor_stop) SetEvent(controller->monitor_stop);
    if (controller->monitor) { WaitForSingleObject(controller->monitor, INFINITE); CloseHandle(controller->monitor); }
    if (controller->monitor_stop) CloseHandle(controller->monitor_stop);
    capture_upload_join(controller); sbw_capture_free(controller->capture); controller->capture = NULL;
    sbw_extension_process_free(controller->httpdebug);sbw_secret_free(controller->httpdebug_base);sbj_free(controller->httpdebug_domains);
    sbw_extension_process_free_graceful(controller->ipcheck);
    sbj_free(controller->ipcheck_latest);
    /* All IPC workers are joined by the caller before freeing this owner. */
    sbw_core_stop(controller->core, NULL);
    sbw_runtime_config_free(&controller->active_config);
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
bool sbw_is_mutating_method(const char *method) {
    if(sb_streq(method,"ipcheck.start")||sb_streq(method,"ipcheck.cancel"))return true;
    if(sb_streq(method,"httpdebug.start")||sb_streq(method,"httpdebug.attach")||sb_streq(method,"httpdebug.stop"))return true;
    return sb_streq(method,"extensions.install") || sb_streq(method,"extensions.change") || !strncmp(method,"subscriptions.",14) || sb_streq(method, "traffic.clear") || sb_streq(method, "routing.gpt_default") || sb_streq(method, "routing.gpt_server") || sb_streq(method, "routing.gpt_node") || sb_streq(method, "routing.set") || sb_streq(method, "enrollment.apply") || sb_streq(method, "enrollment.forget") ||
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
static int launch_healthy(sbw_controller *controller, sbw_runtime_config *config, sbw_error *error) {
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
            collect_traffic(controller);
            capture_auto_upload(controller);
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
    if (started && save_state(controller, identity, controller->candidate, source, &failure) == 0) {
        AcquireSRWLockExclusive(&controller->state_lock);
        sbj *saved_identity=sbj_clone(identity);sbj_free(controller->identity);controller->identity=saved_identity;
        sbj_free(controller->last_good); controller->last_good = sbj_clone(source);
        controller->active = sbj_clone(source);
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
static sbj *ipcheck_dispatch(sbw_controller *c,const char *method,const sbj *params,sbw_error *error) {
    if(!c->identity){sbw_fail(error,"NOT_ENROLLED","Enroll with the center before checking node IPs.");return NULL;}
    if(!c->remote->ipcheck){sbw_fail(error,"CENTER_UNAVAILABLE","The center IP check service is unavailable.");return NULL;}
    sbj *result=NULL;
    if(c->remote->ipcheck(c->remote->context,c->identity,method+8,params,c->cancel,&result,error))return NULL;
    return result;
}
static sbj *httpdebug_dispatch(sbw_controller *c,const char *method,const sbj *params,sbw_error *error) {
    if(sb_streq(method,"httpdebug.start")) {
        if(!sbw_extension_is_enabled("http-debug")){sbw_fail(error,"EXTENSION_MISSING","The bundled HTTP(S) engine is missing. Repair the application installation.");return NULL;}
        if(!c->active||!c->runtime.core_running){sbw_fail(error,"NOT_CONNECTED","Connect the proxy first.");return NULL;}
        if(c->httpdebug){sbw_fail(error,"BUSY","Stop the existing capture session first.");return NULL;}
        c->httpdebug=sbw_extension_process_new(L"extensions\\http-debug\\sb-easy-http-debug.exe",error);
        sbj *p=sbj_object();wchar_t *dir=sbw_path_join(sbw_core_work_directory(c->core),L"http-debug");char *utf=sbw_utf8(dir,error);free(dir);
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
    if(!strncmp(method,"ipcheck.",8)) {
        if(!authorized){sbw_fail(error,"FORBIDDEN","IP detection requires the active console session.");return NULL;}
        bool start=sb_streq(method,"ipcheck.start");
        if(start) {
            const sbj *tags=sbj_get(params,"tags");
            if(!sbj_is_object(params)||sbj_obj_len(params)!=2||!sbj_is_bool(sbj_get(params,"ipv6"))||
               !sbj_is_array(tags)||!sbj_arr_len(tags)||sbj_arr_len(tags)>100) {
                sbw_fail(error,"INVALID_REQUEST","Select up to 100 center nodes and an IPv6 option.");return NULL;
            }
            for(size_t i=0;i<sbj_arr_len(tags);++i) {
                const sbj *tag=sbj_arr_at(tags,i);
                if(!sbj_is_string(tag)||!tag->v.str.len||tag->v.str.len>512||strlen(tag->v.str.ptr)!=tag->v.str.len) {
                    sbw_fail(error,"INVALID_REQUEST","Invalid center node tag.");return NULL;
                }
                for(size_t j=0;j<i;++j)if(sbj_equal(tag,sbj_arr_at(tags,j))) {
                    sbw_fail(error,"INVALID_REQUEST","Duplicate center node tag.");return NULL;
                }
            }
        }
        if(!sbj_is_object(params)||(!start&&sbj_obj_len(params))||
           !(start||sb_streq(method,"ipcheck.daily")||sb_streq(method,"ipcheck.catalog")||sb_streq(method,"ipcheck.snapshot")||sb_streq(method,"ipcheck.cancel"))) {
            sbw_fail(error,"INVALID_REQUEST","Invalid IP detection request.");return NULL;
        }
        if(sb_streq(method,"ipcheck.daily")) {
            /* A cache read must not hold the connection-operation lock while
             * waiting for the network. Take a private enrollment snapshot. */
            if(!TryAcquireSRWLockShared(&controller->mutation_lock)){sbw_fail(error,"BUSY","Wait for the current connection operation to finish.");return NULL;}
            sbj *identity=controller->identity?sbj_clone(controller->identity):NULL;
            ReleaseSRWLockShared(&controller->mutation_lock);
            if(!identity){sbw_fail(error,"NOT_ENROLLED","Enroll with the center before reading node IPs.");return NULL;}
            sbj *result=NULL;
            if(!controller->remote->ipcheck)sbw_fail(error,"CENTER_UNAVAILABLE","The center IP check service is unavailable.");
            else if(controller->remote->ipcheck(controller->remote->context,identity,"daily",params,NULL,&result,error)) {
                sbj_free(result);result=NULL;
            }
            sbj_free(identity);return result;
        }
        if(!TryAcquireSRWLockExclusive(&controller->mutation_lock)){sbw_fail(error,"BUSY","Wait for the current connection operation to finish.");return NULL;}
        sbj *result=ipcheck_dispatch(controller,method,params,error);
        ReleaseSRWLockExclusive(&controller->mutation_lock);return result;
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
    if (!sbj_is_object(params) || (!is_apply && strncmp(method,"subscriptions.",14) && strncmp(method,"extensions.",11) && !sb_streq(method, "routing.gpt_node") && !sb_streq(method, "routing.set") && strncmp(method, "capture.", 8) && sbj_obj_len(params) != 0)) {
        sbw_fail(error, "INVALID_REQUEST", "This operation expects object params."); return NULL;
    }
    if (!strncmp(method, "extensions.", 11)) {
        if(!authorized){sbw_fail(error,"FORBIDDEN","Tool management requires the active console session.");return NULL;}
        sbw_fail(error,"BUILTIN_FEATURE","All tools are built into the app; no store installation is needed.");return NULL;
    }
    if (!strncmp(method, "capture.", 8)) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "Capture requires the active console session or an administrator."); return NULL; }
        if (!TryAcquireSRWLockExclusive(&controller->mutation_lock)) { sbw_fail(error, "BUSY", "A connection operation is in progress."); return NULL; }
        sbj *result = capture_dispatch(controller, method, params, error);
        ReleaseSRWLockExclusive(&controller->mutation_lock); return result;
    }
    if (sb_streq(method, "traffic.snapshot") || sb_streq(method, "traffic.clear") || sb_streq(method, "logs.snapshot")) {
        if (!authorized) { sbw_fail(error, "FORBIDDEN", "This operation requires the active console session."); return NULL; }
        if (!sb_streq(method,"logs.snapshot") && !sbw_extension_is_enabled("statistics")) {sbw_fail(error,"EXTENSION_MISSING","The bundled statistics engine is missing. Repair the application installation.");return NULL;}
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
    AcquireSRWLockExclusive(&controller->mutation_lock);
    sbw_core_event(controller->core, method, "begin");
    sbj *result = NULL, *new_identity = NULL, *download = NULL;
    sbw_enrollment_target target = {0};
    if (cancelled(controller, error) || !ready(controller, error)) goto done;
    observe_core(controller, false);
    if (sb_streq(method, "connection.start") || sb_streq(method, "connection.stop")) {
        int changed = sb_streq(method, "connection.start") ? connection_activate(controller, controller->candidate, controller->identity, false, error) : connection_stop(controller, error);
        if (changed == 0) {
            AcquireSRWLockShared(&controller->state_lock); result = runtime_status(controller);
            ReleaseSRWLockShared(&controller->state_lock);
        }
    } else if (sb_streq(method,"subscriptions.fetch")) {
        const char *url=sbj_get_str(params,"url",NULL),*id=sbj_get_str(params,"id",NULL);
        if(sbj_obj_len(params)!=1 || (!url && !id)){sbw_fail(error,"INVALID_REQUEST","Choose a subscription address or ID.");goto done;}
        if(id){const sbj *subs=sbj_get(controller->identity,"local_subscriptions");for(size_t i=0;i<sbj_arr_len(subs);++i)if(sbj_string_is(sbj_get(sbj_arr_at(subs,i),"id"),id))url=sbj_get_str(sbj_arr_at(subs,i),"url",NULL);}
        result=sbw_subscription_fetch(url,controller->cancel,error);
    } else if (sb_streq(method,"subscriptions.save") || sb_streq(method,"subscriptions.remove")) {
        bool live=controller->active && controller->runtime.core_running;
        const sbj *source=live?controller->active:controller->candidate;
        if(!source){sbw_fail(error,"NO_CANDIDATE","Download the shared configuration first.");goto done;}
        new_identity=sbw_subscriptions_change(controller->identity,params,sb_streq(method,"subscriptions.remove"),error);
        if(!new_identity)goto done;
        if(live){
            sbj *snapshot=sbj_clone(source);
            int changed=connection_activate(controller,snapshot,new_identity,true,error);sbj_free(snapshot);
            if(!changed)result=config_summary(controller);
        }else{
            sbw_runtime_config next={0};
            int changed=prepare_with_identity(new_identity,source,&next,error);
            if(!changed)changed=check_config(controller,&next,error);
            if(!changed)changed=save_state(controller,new_identity,controller->candidate,controller->last_good,error);
            if(!changed){AcquireSRWLockExclusive(&controller->state_lock);sbj_free(controller->identity);controller->identity=new_identity;new_identity=NULL;result=config_summary(controller);ReleaseSRWLockExclusive(&controller->state_lock);}
            sbw_runtime_config_free(&next);
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
        sbj *groups=sbw_routing_groups(source,controller->identity); bool found=false;
        for(size_t i=0;i<sbj_arr_len(groups);++i)
            if(sbj_string_is(sbj_get(sbj_arr_at(groups,i),"id"),id)) found=true;
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
        sbw_extension_process_free_graceful(controller->ipcheck);controller->ipcheck=NULL;sbj_free(controller->ipcheck_latest);controller->ipcheck_latest=NULL;
        capture_upload_join(controller); sbw_capture_free(controller->capture); controller->capture = NULL;
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
            sbj *effective = sbw_routing_apply(download, controller->identity, false, error);
            if (!effective) goto done;
            sbj_free(effective);
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
    if (!sbw_extension_enabled()) { sbw_fail(error,"EXTENSION_MISSING","The bundled capture engine is missing. Repair the application installation."); return NULL; }
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
