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
    sbj *params = sbj_object(); sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    sbj_free(params);
    if (!result) fprintf(stderr, "%s: %s: %s\n", method, error.code, error.message);
    CHECK(result); redacted(result); return result;
}
static void error_call(sbw_controller *controller, const char *method, bool authorized, const char *code) {
    sbj *params = sbj_object(); sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    sbj_free(params);
    if (result || !sb_streq(error.code, code)) fprintf(stderr, "%s: expected %s, got %s\n", method, code, error.code);
    CHECK(!result && sb_streq(error.code, code));
    CHECK(!strstr(error.message, "CONNECTION_FIXTURE_SECRET_NEVER_RETURN_THIS"));
}
static void expect_state(const sbj *result, const char *phase, const char *active, const char *last_good) {
    CHECK(sbj_is_object(result));
    CHECK(sb_streq(sbj_get_str(result, "phase", ""), phase));
    CHECK(sbj_get_bool(result, "core_running", !active) == (active != NULL));
    CHECK(!sbj_get_bool(result, "tun_active", true));
    const sbj *config = sbj_get(result, "config");
    CHECK(active ? sb_streq(sbj_get_str(config, "active_etag", ""), active) : sbj_is_null(sbj_get(config, "active_etag")));
    CHECK(last_good ? sb_streq(sbj_get_str(config, "last_good_etag", ""), last_good) : sbj_is_null(sbj_get(config, "last_good_etag")));
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
    sbw_core_status status = {0}; sbw_error error = {0};
    ULONGLONG deadline = GetTickCount64() + 1000;
    while (sbw_core_poll(core, &status, &error) != 0) {
        CHECK(sb_streq(error.code, "CORE_BUSY") && GetTickCount64() < deadline);
        Sleep(5);
    }
    return status;
}
static sbw_core *attach_core(sbw_controller *controller, const wchar_t *fixture, const wchar_t *directory) {
    sbw_core_options options = {fixture, directory, 3000, 2000}; sbw_error error = {0};
    sbw_core *core = sbw_core_new(&options, &error);
    if (!core) fprintf(stderr, "core: %s: %s\n", error.code, error.message);
    CHECK(core); sbw_controller_set_core(controller, core, NULL); return core;
}
static void download(sbw_controller *controller, test_data *data, const char *etag, const char *content) {
    sbj_set_bool(data->download, "not_modified", false);
    sbj_set_str(data->download, "etag", etag); sbj_set_str(data->download, "content", content);
    sbj *result = call(controller, "config.refresh", true);
    CHECK(sb_streq(sbj_get_str(result, "downloaded_etag", ""), etag)); sbj_free(result);
}
static void enroll(sbw_controller *controller) {
    sbj *params = test_enrollment(); sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, "enrollment.apply", params, true, &error);
    CHECK(result && sbj_get_bool(result, "enrolled", false)); redacted(result); sbj_free(result); sbj_free(params);
}
typedef struct start_task { sbw_controller *controller; sbj *result; sbw_error error; } start_task;
static DWORD WINAPI start_worker(void *context) {
    start_task *task = context; sbj *params = sbj_object();
    task->result = sbw_controller_dispatch(task->controller, "connection.start", params, true, &task->error);
    sbj_free(params); return 0;
}

int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv); if (helper >= 0) return helper;
    CHECK(argc == 2);
    wchar_t temporary[32768], name[128];
    DWORD length = GetTempPathW(32768, temporary); CHECK(length && length < 32768);
    CHECK(swprintf_s(name, 128, L"sb-easy-connection-%lu-%llu", GetCurrentProcessId(), (unsigned long long)GetTickCount64()) > 0);
    wchar_t *directory = sbw_path_join(temporary, name);
    CHECK(GetFileAttributesW(directory) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
    wchar_t gate_name[160]; CHECK(swprintf_s(gate_name, 160, L"Local\\%ls", name) > 0);
    HANDLE health_gate = CreateEventW(NULL, TRUE, FALSE, gate_name); CHECK(health_gate && GetLastError() != ERROR_ALREADY_EXISTS);
    char *gate_utf8 = sbw_utf8(gate_name, NULL); CHECK(gate_utf8);
    sbj *gated_config = sbj_object(); sbj_set_str(gated_config, "health_event", gate_utf8); free(gate_utf8);
    char *gated_json = sbj_dump(gated_config, -1); sbj_free(gated_config);
    test_data data; test_data_init(&data);
    sbw_controller *controller = test_controller(&data, NULL);
    error_call(controller, "connection.start", false, "FORBIDDEN");
    error_call(controller, "connection.stop", false, "FORBIDDEN");
    error_call(controller, "connection.start", true, "NOT_ENROLLED");
    enroll(controller);
    error_call(controller, "connection.start", true, "NO_CANDIDATE");
    download(controller, &data, "good-1", gated_json); free(gated_json);
    error_call(controller, "connection.start", true, "CORE_UNAVAILABLE");
    sbw_core *core = attach_core(controller, argv[1], directory);
    sbj *result = call(controller, "status.get", false);
    expect_state(result, "STOPPED", NULL, NULL);
    CHECK(sbj_get_bool(result, "connection_available", false)); sbj_free(result);

    /* Delayed loopback readiness makes it observable that process creation
     * alone cannot publish an active configuration or a healthy running core. */
    start_task task = {controller, NULL, {0}};
    HANDLE thread = CreateThread(NULL, 0, start_worker, &task, 0, NULL); CHECK(thread);
    bool saw_starting = false; ULONGLONG deadline = GetTickCount64() + 3000;
    while (WaitForSingleObject(thread, 0) == WAIT_TIMEOUT && GetTickCount64() < deadline) {
        result = call(controller, "status.get", false);
        if (sb_streq(sbj_get_str(result, "phase", ""), "STARTING")) {
            expect_state(result, "STARTING", NULL, NULL); saw_starting = true;
        }
        sbj_free(result);
        if (saw_starting) break;
        Sleep(5);
    }
    CHECK(saw_starting);
    error_call(controller, "connection.start", true, "BUSY");
    error_call(controller, "connection.stop", true, "BUSY");
    CHECK(SetEvent(health_gate));
    CHECK(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0); CloseHandle(thread);
    if (!task.result) fprintf(stderr, "initial start: %s: %s\n", task.error.code, task.error.message);
    CHECK(task.result); expect_state(task.result, "RUNNING", "good-1", "good-1"); sbj_free(task.result);
    expect_last_good(&data, "good-1");
    sbw_core_status process = core_status(core); CHECK(process.process_running && process.process_id);
    DWORD original_pid = process.process_id;
    result = call(controller, "connection.start", true); expect_state(result, "RUNNING", "good-1", "good-1"); sbj_free(result);
    CHECK(core_status(core).process_id == original_pid); /* Identical config is idempotent. */
    result = call(controller, "connection.stop", true); expect_state(result, "STOPPED", NULL, "good-1"); sbj_free(result);
    process = core_status(core); CHECK(!process.process_running && !process.last_stop_forced);
    expect_last_good(&data, "good-1");

    sbw_controller_free(controller); controller = test_controller(&data, NULL);
    core = attach_core(controller, argv[1], directory);
    result = call(controller, "status.get", false); expect_state(result, "STOPPED", NULL, "good-1"); sbj_free(result);
    result = call(controller, "connection.start", true); expect_state(result, "RUNNING", "good-1", "good-1"); sbj_free(result);
    original_pid = core_status(core).process_id;
    download(controller, &data, "bad-check", "{\"mode\":\"check_fail\"}");
    result = call(controller, "status.get", false); expect_state(result, "RUNNING", "good-1", "good-1"); sbj_free(result);
    CHECK(core_status(core).process_id == original_pid);
    sbj *saved = sbj_clone(data.saved);
    error_call(controller, "connection.start", true, "CORE_CHECK_FAILED");
    CHECK(core_status(core).process_id == original_pid && sbj_equal(saved, data.saved)); sbj_free(saved);
    result = call(controller, "status.get", false); expect_state(result, "RUNNING", "good-1", "good-1"); sbj_free(result);

    download(controller, &data, "bad-health", "{\"mode\":\"health_fail\"}"); saved = sbj_clone(data.saved);
    error_call(controller, "connection.start", true, "ROLLED_BACK");
    CHECK(sbj_equal(saved, data.saved)); sbj_free(saved); expect_last_good(&data, "good-1");
    result = call(controller, "status.get", false); expect_state(result, "RUNNING", "good-1", "good-1");
    CHECK(sb_streq(sbj_get_str(sbj_get(result, "runtime_error"), "code", ""), "ROLLED_BACK")); sbj_free(result);
    process = core_status(core); CHECK(process.process_running && process.process_id != original_pid);

    download(controller, &data, "good-2", "{\"mode\":\"good\"}"); saved = sbj_clone(data.saved);
    data.fail_write = true;
    error_call(controller, "connection.start", true, "ROLLED_BACK");
    CHECK(sbj_equal(saved, data.saved)); sbj_free(saved); data.fail_write = false;
    result = call(controller, "status.get", false); expect_state(result, "RUNNING", "good-1", "good-1"); sbj_free(result);
    expect_last_good(&data, "good-1");
    result = call(controller, "connection.start", true); expect_state(result, "RUNNING", "good-2", "good-2");
    CHECK(!sbj_get(result, "runtime_error")); sbj_free(result); expect_last_good(&data, "good-2");

    download(controller, &data, "crashing", "{\"mode\":\"crash\"}");
    result = call(controller, "connection.start", true); expect_state(result, "RUNNING", "crashing", "crashing"); sbj_free(result);
    process = core_status(core);
    HANDLE crashed = OpenProcess(SYNCHRONIZE, FALSE, process.process_id); CHECK(crashed);
    CHECK(WaitForSingleObject(crashed, 5000) == WAIT_OBJECT_0); CloseHandle(crashed);
    sbw_controller_poll(controller);
    result = call(controller, "status.get", false); expect_state(result, "DEGRADED", NULL, "crashing");
    CHECK(sb_streq(sbj_get_str(sbj_get(result, "runtime_error"), "code", ""), "CORE_EXITED")); sbj_free(result);
    result = call(controller, "connection.stop", true); expect_state(result, "STOPPED", NULL, "crashing"); sbj_free(result);
    result = call(controller, "enrollment.forget", true); CHECK(!sbj_get_bool(result, "enrolled", true) && !data.saved); sbj_free(result);

    /* Without a previous good version, a failed durable activation must leave
     * neither a running child nor an invented active/last-good revision. */
    enroll(controller); download(controller, &data, "first-unsaved", "{}"); saved = sbj_clone(data.saved);
    data.fail_write = true; error_call(controller, "connection.start", true, "STORAGE_ERROR");
    CHECK(sbj_equal(saved, data.saved)); sbj_free(saved); data.fail_write = false;
    result = call(controller, "status.get", false); expect_state(result, "DEGRADED", NULL, NULL); sbj_free(result);
    CHECK(!core_status(core).process_running);
    result = call(controller, "connection.stop", true); expect_state(result, "STOPPED", NULL, NULL); sbj_free(result);
    sbw_controller_free(controller); test_data_free(&data); CloseHandle(health_gate);
    wchar_t *lock = sbw_path_join(directory, L"state.lock");
    CHECK(DeleteFileW(lock)); CHECK(RemoveDirectoryW(directory)); free(lock); free(directory);
    puts("C11 connection controller: local health, activation, stop, persistence, replacement, rollback, crash and redaction passed.");
    return 0;
}
