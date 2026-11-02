#include "test_support.h"
#include <wchar.h>

static void redacted(const sbj *result) {
    test_redacted(result);
    char *text = sbj_dump(result, -1);
    CHECK(!strstr(text, "CONNECTION_FIXTURE_SECRET_NEVER_RETURN_THIS"));
    CHECK(!strstr(text, "external_controller") && !strstr(text, "Bearer "));
    free(text);
}
static sbj *call(sbw_controller *controller, const char *method, bool authorized) {
    sbj *params = sbj_object();
    sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    sbj_free(params);
    if (!result)
        fprintf(stderr, "%s: %s: %s\n", method, error.code, error.message);
    CHECK(result);
    redacted(result);
    return result;
}
static void error_call(sbw_controller *controller, const char *method, bool authorized,
                       const char *code) {
    sbj *params = sbj_object();
    sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    sbj_free(params);
    if (result || !sb_streq(error.code, code))
        fprintf(stderr, "%s: expected %s, got %s\n", method, code, error.code);
    CHECK(!result && sb_streq(error.code, code));
    CHECK(!strstr(error.message, "CONNECTION_FIXTURE_SECRET_NEVER_RETURN_THIS"));
}
static void expect_state(const sbj *result, const char *phase, const char *active,
                         const char *last_good) {
    CHECK(sbj_is_object(result));
    CHECK(sb_streq(sbj_get_str(result, "phase", ""), phase));
    CHECK(sbj_get_bool(result, "core_running", !active) == (active != NULL));
    CHECK(!sbj_get_bool(result, "tun_active", true));
    const sbj *config = sbj_get(result, "config");
    CHECK(active ? sb_streq(sbj_get_str(config, "active_etag", ""), active)
                 : sbj_is_null(sbj_get(config, "active_etag")));
    CHECK(last_good ? sb_streq(sbj_get_str(config, "last_good_etag", ""), last_good)
                    : sbj_is_null(sbj_get(config, "last_good_etag")));
    redacted(result);
}
static void expect_last_good(test_data *data, const char *etag) {
    const sbj *last_good = sbj_get(data->saved, "last_good");
    CHECK(etag ? sb_streq(sbj_get_str(last_good, "etag", ""), etag) : sbj_is_null(last_good));
    char *text = sbj_dump(data->saved, -1);
    CHECK(!strstr(text, "external_controller") && !strstr(text, "Bearer "));
    free(text);
}
static sbw_core_status core_status(sbw_core *core) {
    sbw_core_status status = {0};
    sbw_error error = {0};
    ULONGLONG deadline = GetTickCount64() + 1000;
    while (sbw_core_poll(core, &status, &error) != 0) {
        CHECK(sb_streq(error.code, "CORE_BUSY") && GetTickCount64() < deadline);
        Sleep(5);
    }
    return status;
}
static sbw_core *attach_core(sbw_controller *controller, const wchar_t *fixture,
                             const wchar_t *directory) {
    sbw_core_options options = {fixture, directory, 3000, 2000};
    sbw_error error = {0};
    sbw_core *core = sbw_core_new(&options, &error);
    if (!core)
        fprintf(stderr, "core: %s: %s\n", error.code, error.message);
    CHECK(core);
    sbw_controller_set_core(controller, core, NULL);
    return core;
}
static void download(sbw_controller *controller, test_data *data, const char *etag,
                     const char *content) {
    sbj_set_bool(data->download, "not_modified", false);
    sbj_set_str(data->download, "etag", etag);
    sbj_set_str(data->download, "content", content);
    sbj *result = call(controller, "config.refresh", true);
    CHECK(sb_streq(sbj_get_str(result, "downloaded_etag", ""), etag));
    sbj_free(result);
}
static void enroll(sbw_controller *controller) {
    sbj *params = test_enrollment();
    sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, "enrollment.apply", params, true, &error);
    CHECK(result && sbj_get_bool(result, "enrolled", false));
    redacted(result);
    sbj_free(result);
    sbj_free(params);
}
typedef struct start_task {
    sbw_controller *controller;
    sbj *result;
    sbw_error error;
} start_task;
static DWORD WINAPI start_worker(void *context) {
    start_task *task = context;
    sbj *params = sbj_object();
    task->result =
        sbw_controller_dispatch(task->controller, "connection.start", params, true, &task->error);
    sbj_free(params);
    return 0;
}

typedef struct test_state {
    const wchar_t *fixture;
    wchar_t *directory;
    HANDLE health_gate;
    char *gated_json;
    test_data data;
    sbw_controller *controller;
    sbw_core *core;
} test_state;

static void scenario_preconditions(test_state *s) {
    error_call(s->controller, "connection.start", false, "FORBIDDEN");
    error_call(s->controller, "connection.stop", false, "FORBIDDEN");
    error_call(s->controller, "connection.start", true, "NOT_ENROLLED");
    enroll(s->controller);
    error_call(s->controller, "connection.start", true, "NO_CANDIDATE");
    download(s->controller, &s->data, "good-1", s->gated_json);
    free(s->gated_json);
    s->gated_json = NULL;
    error_call(s->controller, "connection.start", true, "CORE_UNAVAILABLE");
    s->core = attach_core(s->controller, s->fixture, s->directory);
    sbj *result = call(s->controller, "status.get", false);
    expect_state(result, "STOPPED", NULL, NULL);
    CHECK(sbj_get_bool(result, "connection_available", false));
    sbj_free(result);
}

static void scenario_delayed_start_and_stop(test_state *s) {
    /* Delayed loopback readiness makes it observable that process creation
     * alone cannot publish an active configuration or a healthy running core. */
    start_task task = {s->controller, NULL, {0}};
    HANDLE thread = CreateThread(NULL, 0, start_worker, &task, 0, NULL);
    CHECK(thread);
    bool saw_starting = false;
    ULONGLONG deadline = GetTickCount64() + 3000;
    while (WaitForSingleObject(thread, 0) == WAIT_TIMEOUT && GetTickCount64() < deadline) {
        sbj *result = call(s->controller, "status.get", false);
        if (sb_streq(sbj_get_str(result, "phase", ""), "STARTING")) {
            expect_state(result, "STARTING", NULL, NULL);
            saw_starting = true;
        }
        sbj_free(result);
        if (saw_starting)
            break;
        Sleep(5);
    }
    CHECK(saw_starting);
    error_call(s->controller, "connection.start", true, "BUSY");
    error_call(s->controller, "connection.stop", true, "BUSY");
    CHECK(SetEvent(s->health_gate));
    CHECK(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    if (!task.result)
        fprintf(stderr, "initial start: %s: %s\n", task.error.code, task.error.message);
    CHECK(task.result);
    expect_state(task.result, "RUNNING", "good-1", "good-1");
    sbj_free(task.result);
    expect_last_good(&s->data, "good-1");
    sbw_core_status process = core_status(s->core);
    CHECK(process.process_running && process.process_id);
    DWORD original_pid = process.process_id;
    sbj *result = call(s->controller, "connection.start", true);
    expect_state(result, "RUNNING", "good-1", "good-1");
    sbj_free(result);
    error_call(s->controller, "routing.gpt_default", true, "GPT_OUTBOUND_UNAVAILABLE");
    error_call(s->controller, "routing.gpt_server", true, "LIVE_ROUTING_UNAVAILABLE");
    CHECK(core_status(s->core).process_id == original_pid); /* Identical config is idempotent. */
    result = call(s->controller, "connection.stop", true);
    expect_state(result, "STOPPED", NULL, "good-1");
    sbj_free(result);
    process = core_status(s->core);
    CHECK(!process.process_running && !process.last_stop_forced);
    expect_last_good(&s->data, "good-1");
}

static void scenario_restart_and_rejected_candidates(test_state *s) {
    sbw_controller_free(s->controller);
    s->controller = test_controller(&s->data, NULL);
    s->core = attach_core(s->controller, s->fixture, s->directory);
    sbj *result = call(s->controller, "status.get", false);
    expect_state(result, "STOPPED", NULL, "good-1");
    sbj_free(result);
    result = call(s->controller, "connection.start", true);
    expect_state(result, "RUNNING", "good-1", "good-1");
    sbj_free(result);
    DWORD original_pid = core_status(s->core).process_id;
    download(s->controller, &s->data, "bad-check", "{\"mode\":\"check_fail\"}");
    result = call(s->controller, "status.get", false);
    expect_state(result, "RUNNING", "good-1", "good-1");
    sbj_free(result);
    CHECK(core_status(s->core).process_id == original_pid);
    sbj *saved = sbj_clone(s->data.saved);
    error_call(s->controller, "connection.start", true, "CORE_CHECK_FAILED");
    CHECK(core_status(s->core).process_id == original_pid && sbj_equal(saved, s->data.saved));
    sbj_free(saved);
    result = call(s->controller, "status.get", false);
    expect_state(result, "RUNNING", "good-1", "good-1");
    sbj_free(result);

    download(s->controller, &s->data, "bad-health", "{\"mode\":\"health_fail\"}");
    saved = sbj_clone(s->data.saved);
    error_call(s->controller, "connection.start", true, "ROLLED_BACK");
    CHECK(sbj_equal(saved, s->data.saved));
    sbj_free(saved);
    expect_last_good(&s->data, "good-1");
    result = call(s->controller, "status.get", false);
    expect_state(result, "RUNNING", "good-1", "good-1");
    CHECK(sb_streq(sbj_get_str(sbj_get(result, "runtime_error"), "code", ""), "ROLLED_BACK"));
    sbj_free(result);
    sbw_core_status process = core_status(s->core);
    CHECK(process.process_running && process.process_id != original_pid);
}

static void scenario_durable_activation(test_state *s) {
    download(s->controller, &s->data, "good-2", "{\"mode\":\"good\"}");
    sbj *saved = sbj_clone(s->data.saved);
    DWORD original_pid = core_status(s->core).process_id;
    /* Intent must be durable before changing the running core. */
    s->data.fail_write = true;
    error_call(s->controller, "connection.start", true, "STORAGE_ERROR");
    CHECK(core_status(s->core).process_id == original_pid && sbj_equal(saved, s->data.saved));
    s->data.fail_write = false;
    /* Fail the healthy candidate's activation commit, after intent was saved. */
    s->data.fail_activation_etag = "good-2";
    error_call(s->controller, "connection.start", true, "ROLLED_BACK");
    CHECK(s->data.activation_write_failures == 1 && sbj_equal(saved, s->data.saved));
    sbj_free(saved);
    s->data.fail_activation_etag = NULL;
    sbj *result = call(s->controller, "status.get", false);
    expect_state(result, "RUNNING", "good-1", "good-1");
    sbj_free(result);
    expect_last_good(&s->data, "good-1");
    result = call(s->controller, "connection.start", true);
    expect_state(result, "RUNNING", "good-2", "good-2");
    CHECK(!sbj_get(result, "runtime_error"));
    sbj_free(result);
    expect_last_good(&s->data, "good-2");
}

static void scenario_crash_and_forget(test_state *s) {
    download(s->controller, &s->data, "crashing", "{\"mode\":\"crash\"}");
    sbj *result = call(s->controller, "connection.start", true);
    expect_state(result, "RUNNING", "crashing", "crashing");
    sbj_free(result);
    sbw_core_status process = core_status(s->core);
    HANDLE crashed = OpenProcess(SYNCHRONIZE, FALSE, process.process_id);
    CHECK(crashed);
    CHECK(WaitForSingleObject(crashed, 5000) == WAIT_OBJECT_0);
    CloseHandle(crashed);
    sbw_controller_poll(s->controller);
    result = call(s->controller, "status.get", false);
    expect_state(result, "DEGRADED", NULL, "crashing");
    CHECK(sb_streq(sbj_get_str(sbj_get(result, "runtime_error"), "code", ""), "CORE_EXITED"));
    sbj_free(result);
    result = call(s->controller, "connection.stop", true);
    expect_state(result, "STOPPED", NULL, "crashing");
    sbj_free(result);
    result = call(s->controller, "enrollment.forget", true);
    CHECK(!sbj_get_bool(result, "enrolled", true) && !s->data.saved);
    sbj_free(result);
}

static void scenario_first_activation_failure(test_state *s) {
    /* Without a previous good version, a failed durable activation must leave
     * neither a running child nor an invented active/last-good revision. */
    enroll(s->controller);
    download(s->controller, &s->data, "first-unsaved", "{}");
    sbj *saved = sbj_clone(s->data.saved);
    sbj_set_bool(sbj_get(saved, "management"), "manual_disconnect", false);
    s->data.fail_activation_etag = "first-unsaved";
    error_call(s->controller, "connection.start", true, "STORAGE_ERROR");
    CHECK(s->data.activation_write_failures == 2 && sbj_equal(saved, s->data.saved));
    sbj_free(saved);
    s->data.fail_activation_etag = NULL;
    sbj *result = call(s->controller, "status.get", false);
    expect_state(result, "DEGRADED", NULL, NULL);
    sbj_free(result);
    CHECK(!core_status(s->core).process_running);
    result = call(s->controller, "connection.stop", true);
    expect_state(result, "STOPPED", NULL, NULL);
    sbj_free(result);
}

static const struct {
    const char *name;
    void (*run)(test_state *);
} scenarios[] = {
    {"preconditions", scenario_preconditions},
    {"delayed_start_and_stop", scenario_delayed_start_and_stop},
    {"restart_and_rejected_candidates", scenario_restart_and_rejected_candidates},
    {"durable_activation", scenario_durable_activation},
    {"crash_and_forget", scenario_crash_and_forget},
    {"first_activation_failure", scenario_first_activation_failure},
};

int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv);
    if (helper >= 0)
        return helper;
    CHECK(argc == 2);
    wchar_t temporary[32768], name[128];
    DWORD length = GetTempPathW(32768, temporary);
    CHECK(length && length < 32768);
    CHECK(swprintf_s(name, 128, L"sb-easy-connection-%lu-%llu", GetCurrentProcessId(),
                     (unsigned long long)GetTickCount64()) > 0);
    test_state state = {0};
    test_state *s = &state;
    s->fixture = argv[1];
    s->directory = sbw_path_join(temporary, name);
    CHECK(GetFileAttributesW(s->directory) == INVALID_FILE_ATTRIBUTES &&
          GetLastError() == ERROR_FILE_NOT_FOUND);
    wchar_t gate_name[160];
    CHECK(swprintf_s(gate_name, 160, L"Local\\%ls", name) > 0);
    s->health_gate = CreateEventW(NULL, TRUE, FALSE, gate_name);
    CHECK(s->health_gate && GetLastError() != ERROR_ALREADY_EXISTS);
    char *gate_utf8 = sbw_utf8(gate_name, NULL);
    CHECK(gate_utf8);
    sbj *gated_config = sbj_object();
    sbj_set_str(gated_config, "health_event", gate_utf8);
    free(gate_utf8);
    s->gated_json = sbj_dump(gated_config, -1);
    sbj_free(gated_config);
    test_data_init(&s->data);
    s->controller = test_controller(&s->data, NULL);
    for (size_t i = 0; i < sizeof scenarios / sizeof *scenarios; ++i)
        scenarios[i].run(s);

    sbw_controller_free(s->controller);
    test_data_free(&s->data);
    CloseHandle(s->health_gate);
    wchar_t *lock = sbw_path_join(s->directory, L"state.lock");
    test_remove_diagnostics(s->directory);
    CHECK(DeleteFileW(lock));
    wchar_t *traffic_file = sbw_path_join(s->directory, L"device-state.dat");
    DeleteFileW(traffic_file);
    free(traffic_file);
    test_remove_capture_dirs(s->directory);
    CHECK(RemoveDirectoryW(s->directory));
    free(lock);
    free(s->directory);
    puts("C11 connection controller: local health, activation, stop, persistence, replacement, "
         "rollback, crash and redaction passed.");
    return 0;
}
