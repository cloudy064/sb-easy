#include "test_support.h"
#include "../service/protocol.h"
#include <wchar.h>

static sbj *call(sbw_controller *controller, const char *method, const sbj *params, bool authorized) {
    sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    if (!result) fprintf(stderr, "%s: %s\n", error.code, error.message);
    CHECK(result); test_redacted(result); return result;
}
static void expect_error(sbw_controller *controller, const char *method, const sbj *params, bool authorized, const char *expected) {
    sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    CHECK(!result && sb_streq(error.code, expected));
    CHECK(!strstr(error.message, "private-agent-token"));
    CHECK(!strstr(error.message, "FIXTURE_SECRET_NEVER_RETURN_THIS"));
}

static void expect_validation(const sbj *summary, const char *state, const char *etag, const char *error_code) {
    const sbj *validation = sbj_get(summary, "validation");
    CHECK(sbj_is_object(validation));
    CHECK(sb_streq(sbj_get_str(validation, "state", ""), state));
    CHECK(sb_streq(sbj_get_str(validation, "core_version", ""), "1.13.12"));
    CHECK(etag ? sb_streq(sbj_get_str(validation, "checked_etag", ""), etag) : sbj_is_null(sbj_get(validation, "checked_etag")));
    if (error_code) {
        const sbj *error = sbj_get(validation, "error");
        CHECK(sb_streq(sbj_get_str(error, "code", ""), error_code));
        CHECK(sbw_json_string(sbj_get(error, "message"), 256, false));
    } else CHECK(!sbj_get(validation, "error"));
    CHECK(sbj_is_null(sbj_get(summary, "active_etag")));
    char *serialized = sbj_dump(summary, -1);
    CHECK(!strstr(serialized, "FIXTURE_SECRET_NEVER_RETURN_THIS"));
    free(serialized); test_redacted(summary);
}

static sbw_core *attach_fixture(sbw_controller *controller, const wchar_t *fixture, const wchar_t *directory) {
    sbw_error error = {0};
    sbw_core_options options = {fixture, directory, 3000, 2000};
    sbw_core *core = sbw_core_new(&options, &error);
    if (!core) fprintf(stderr, "fixture core: %s: %s\n", error.code, error.message);
    CHECK(core);
    sbw_controller_set_core(controller, core, NULL);
    return core; /* Borrowed until the controller is freed. */
}

static void test_validation(const wchar_t *fixture) {
    wchar_t temporary[32768], name[128];
    DWORD length = GetTempPathW(32768, temporary);
    CHECK(length && length < 32768);
    CHECK(swprintf_s(name, 128, L"sb-easy-controller-check-%lu-%llu", GetCurrentProcessId(),
        (unsigned long long)GetTickCount64()) > 0);
    wchar_t *directory = sbw_path_join(temporary, name);
    CHECK(GetFileAttributesW(directory) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
    test_data data; test_data_init(&data);
    sbj *empty = sbj_object(), *enrollment = test_enrollment();
    sbw_controller *controller = test_controller(&data, NULL);
    sbw_core *core = attach_fixture(controller, fixture, directory);
    expect_error(controller, "config.validate", empty, true, "NO_CANDIDATE");
    sbj *result = call(controller, "enrollment.apply", enrollment, true); sbj_free(result);
    result = call(controller, "config.refresh", empty, true);
    expect_validation(result, "not_checked", NULL, NULL); sbj_free(result);
    expect_error(controller, "config.validate", empty, false, "FORBIDDEN");
    sbj *bad = sbj_object(); sbj_set_bool(bad, "activate", true);
    expect_error(controller, "config.validate", bad, true, "INVALID_REQUEST"); sbj_free(bad);
    result = call(controller, "config.summary", empty, false);
    expect_validation(result, "not_checked", NULL, NULL); sbj_free(result);

    result = call(controller, "config.validate", empty, true);
    expect_validation(result, "valid", "revision-1", NULL);
    sbw_error error = {0}; sbw_core_status process = {0};
    CHECK(sbw_core_poll(core, &process, &error) == 0 && !process.process_running && !process.process_id);
    sbj *status = call(controller, "status.get", empty, false);
    CHECK(sb_streq(sbj_get_str(status, "phase", ""), "STOPPED"));
    CHECK(!sbj_get_bool(status, "core_running", true) && sbj_get_bool(status, "connection_available", false));
    expect_validation(sbj_get(status, "config"), "valid", "revision-1", NULL); sbj_free(status);

    sbj_set_bool(data.download, "not_modified", true);
    sbj *same = call(controller, "config.refresh", empty, true);
    CHECK(sbj_equal(result, same) && sb_streq(data.last_etag, "revision-1")); sbj_free(same);
    data.fail_fetch = true;
    expect_error(controller, "config.refresh", empty, true, "http_error"); data.fail_fetch = false;
    same = call(controller, "config.summary", empty, false); CHECK(sbj_equal(result, same)); sbj_free(same); sbj_free(result);

    sbj_set_bool(data.download, "not_modified", false);
    sbj_set_str(data.download, "etag", "revision-2"); sbj_set_str(data.download, "content", "{\"mode\":\"check_fail\"}");
    result = call(controller, "config.refresh", empty, true);
    expect_validation(result, "not_checked", NULL, NULL); sbj_free(result);
    expect_error(controller, "config.validate", empty, true, "CORE_CHECK_FAILED");
    result = call(controller, "config.summary", empty, false);
    expect_validation(result, "invalid", "revision-2", "CORE_CHECK_FAILED");
    CHECK(sbw_core_poll(core, &process, &error) == 0 && !process.process_running);
    sbj_set_bool(data.download, "not_modified", true);
    same = call(controller, "config.refresh", empty, true);
    CHECK(sbj_equal(result, same) && sb_streq(data.last_etag, "revision-2")); sbj_free(same); sbj_free(result);

    sbj_set_bool(data.download, "not_modified", false);
    sbj_set_str(data.download, "etag", "revision-3"); sbj_set_str(data.download, "content", "{}");
    result = call(controller, "config.refresh", empty, true);
    expect_validation(result, "not_checked", NULL, NULL); sbj_free(result);
    result = call(controller, "config.validate", empty, true);
    expect_validation(result, "valid", "revision-3", NULL); sbj_free(result);
    /* A restarted controller must not claim its new core validated old bytes. */
    sbw_controller_free(controller); controller = test_controller(&data, NULL);
    attach_fixture(controller, fixture, directory);
    result = call(controller, "config.summary", empty, false);
    CHECK(sb_streq(sbj_get_str(result, "downloaded_etag", ""), "revision-3"));
    expect_validation(result, "not_checked", NULL, NULL); sbj_free(result);
    sbw_controller_free(controller);
    sbj_free(empty); sbj_free(enrollment); test_data_free(&data);
    /* Remove only the owned fixture directory and its known lock file. */
    wchar_t *lock = sbw_path_join(directory, L"state.lock");
    CHECK(DeleteFileW(lock)); CHECK(RemoveDirectoryW(directory)); free(lock); free(directory);
}
typedef struct refresh_task { sbw_controller *controller; sbj *params; sbj *result; } refresh_task;
static DWORD WINAPI refresh_worker(void *context) {
    refresh_task *task = context; task->result = call(task->controller, "config.refresh", task->params, true); return 0;
}
int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv);
    if (helper >= 0) return helper;
    CHECK(argc == 2);
    test_data data; test_data_init(&data);
    sbj *empty = sbj_object(), *enrollment = test_enrollment();
    sbw_controller *controller = test_controller(&data, NULL);
    sbj *result = call(controller, "config.summary", empty, false);
    CHECK(sbj_is_null(sbj_get(result, "active_etag")) && !sbj_get_bool(result, "candidate_available", true));
    expect_validation(result, "unavailable", NULL, NULL); sbj_free(result);
    expect_error(controller, "config.validate", empty, false, "FORBIDDEN");
    expect_error(controller, "config.validate", empty, true, "NO_CANDIDATE");
    expect_error(controller, "enrollment.apply", enrollment, false, "FORBIDDEN");
    CHECK(!data.enrollments && !data.saved);
    expect_error(controller, "config.refresh", empty, true, "NOT_ENROLLED");
    sbj *bad_uri = sbj_object(); sbj_set(bad_uri, "uri", sbj_strn("sbeasy\0trailing", 15));
    expect_error(controller, "enrollment.apply", bad_uri, true, "INVALID_REQUEST"); sbj_free(bad_uri);
    result = call(controller, "enrollment.apply", enrollment, true);
    CHECK(sbj_get_bool(result, "enrolled", false) && sb_streq(sbj_get_str(result, "phase", ""), "STOPPED") && data.saved);
    CHECK(sb_streq(sbj_get_str(result, "server_origin", ""), "https://example.test/panel")); sbj_free(result);
    expect_error(controller, "enrollment.apply", enrollment, true, "ALREADY_ENROLLED");
    sbw_controller_free(controller); controller = test_controller(&data, NULL);
    result = call(controller, "config.refresh", empty, true);
    expect_error(controller, "config.validate", empty, false, "FORBIDDEN");
    expect_error(controller, "config.validate", empty, true, "CORE_UNAVAILABLE");
    expect_validation(result, "unavailable", NULL, NULL);
    CHECK(sb_streq(sbj_get_str(result, "downloaded_etag", ""), "revision-1") && sbj_is_null(sbj_get(result, "active_etag")));
    CHECK(sbj_get_int(sbj_get(result, "counts"), "rules", 0) == 1);
    sbw_controller_free(controller); controller = test_controller(&data, NULL);
    sbj_set_bool(data.download, "not_modified", true);
    sbj *same = call(controller, "config.refresh", empty, true);
    CHECK(sbj_equal(same, result) && sb_streq(data.last_etag, "revision-1")); sbj_free(same);
    data.fail_fetch = true;
    expect_error(controller, "config.refresh", empty, true, "http_error"); data.fail_fetch = false;
    sbj_set_bool(data.download, "not_modified", false); sbj_set_str(data.download, "content", "{");
    expect_error(controller, "config.refresh", empty, true, "INVALID_CONFIGURATION");
    same = call(controller, "config.summary", empty, false); CHECK(sbj_equal(result, same)); sbj_free(same);
    sbj_set_str(data.download, "content", "{}"); data.fail_write = true;
    expect_error(controller, "config.refresh", empty, true, "STORAGE_ERROR");
    same = call(controller, "config.summary", empty, false); CHECK(sbj_equal(result, same)); sbj_free(same); sbj_free(result);
    data.fail_write = false;
    data.entered = CreateEventW(NULL, TRUE, FALSE, NULL); data.release = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(data.entered && data.release);
    refresh_task task = {controller, empty, NULL};
    HANDLE thread = CreateThread(NULL, 0, refresh_worker, &task, 0, NULL); CHECK(thread);
    CHECK(WaitForSingleObject(data.entered, 3000) == WAIT_OBJECT_0);
    expect_error(controller, "enrollment.forget", empty, true, "BUSY");
    expect_error(controller, "config.validate", empty, true, "BUSY");
    same = call(controller, "status.get", empty, false); CHECK(sbj_get_bool(same, "enrolled", false)); sbj_free(same);
    SetEvent(data.release); CHECK(WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0); CloseHandle(thread); sbj_free(task.result);
    CloseHandle(data.entered); CloseHandle(data.release); data.entered = data.release = NULL;
    result = call(controller, "enrollment.forget", empty, true); CHECK(!sbj_get_bool(result, "enrolled", true) && !data.saved); sbj_free(result);
    expect_error(controller, "enrollment.forget", empty, true, "INVALID_STATE");
    sbw_controller_free(controller);
    data.saved = sbj_parse_cstr("{\"version\":999}"); controller = test_controller(&data, NULL);
    result = call(controller, "status.get", empty, false); CHECK(sb_streq(sbj_get_str(result, "phase", ""), "ERROR")); sbj_free(result);
    expect_error(controller, "enrollment.apply", enrollment, true, "STORAGE_CORRUPT"); CHECK(sbj_get_int(data.saved, "version", 0) == 999);
    sbw_controller_free(controller); sbj_free(data.saved); data.saved = NULL;
    HANDLE cancel = CreateEventW(NULL, TRUE, TRUE, NULL); CHECK(cancel);
    controller = test_controller(&data, cancel);
    expect_error(controller, "config.validate", empty, true, "CANCELLED");
    expect_error(controller, "enrollment.apply", enrollment, true, "CANCELLED");
    ResetEvent(cancel); data.cancel_after_enroll = cancel;
    result = call(controller, "enrollment.apply", enrollment, true); CHECK(data.saved && sbj_get_bool(result, "enrolled", false)); sbj_free(result);
    sbw_controller_free(controller); CloseHandle(cancel);
    sbj_free(enrollment); sbj_free(empty); test_data_free(&data);
    test_validation(argv[1]);
    puts("C controller: enrollment, persistence, 304, fixture validation, revision binding, authorization, concurrency and redaction passed."); return 0;
}
