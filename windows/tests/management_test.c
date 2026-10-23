#include "test_support.h"
#include <wchar.h>

typedef struct management_fixture {
    test_data storage; /* test_support callbacks expect this as the first member. */
    sbj *commands, *last_status, *last_ack, *last_telemetry;
    unsigned reports, polls, acknowledgements, telemetry;
    bool fail_ack;
    HANDLE reported;
} management_fixture;
static int report_status(void *context, const sbj *identity, const sbj *status, HANDLE cancel, sbw_error *error) {
    (void)identity; (void)cancel; (void)error;
    management_fixture *data = context;
    ++data->reports; sbj_free(data->last_status); data->last_status = sbj_clone(status);
    if (data->reported) SetEvent(data->reported);
    return 0;
}
static int commands(void *context, const sbj *identity, HANDLE cancel, sbj **out, sbw_error *error) {
    (void)identity; (void)cancel; (void)error;
    management_fixture *data = context; ++data->polls; *out = sbj_clone(data->commands); return 0;
}
static int acknowledge(void *context, const sbj *identity, const char *id, const sbj *receipt, HANDLE cancel, sbw_error *error) {
    (void)identity; (void)cancel; CHECK(id && *id);
    management_fixture *data = context;
    ++data->acknowledgements; sbj_free(data->last_ack); data->last_ack = sbj_clone(receipt);
    return data->fail_ack ? sbw_fail(error, "http_error", "The command acknowledgement could not be delivered.") : 0;
}
static int telemetry(void *context, const sbj *identity, const sbj *snapshot, HANDLE cancel, sbw_error *error) {
    (void)identity; (void)cancel; (void)error;
    management_fixture *data = context;
    ++data->telemetry; sbj_free(data->last_telemetry); data->last_telemetry = sbj_clone(snapshot); return 0;
}
static sbw_controller *controller_new(management_fixture *data) {
    sbw_control_plane *remote = sb_xcalloc(1, sizeof *remote); sbw_store *store = sb_xcalloc(1, sizeof *store);
    remote->context = data; remote->enroll = test_enroll; remote->fetch_config = test_fetch;
    remote->report_status = report_status; remote->pending_commands = commands;
    remote->acknowledge_command = acknowledge; remote->report_telemetry = telemetry;
    store->context = data; store->load = test_load; store->save = test_save; store->clear = test_clear;
    sbw_controller *controller = sbw_controller_new(remote, store, NULL, NULL); CHECK(controller); return controller;
}
static void fixture_init(management_fixture *data) {
    memset(data, 0, sizeof *data); test_data_init(&data->storage);
    sbj_set_str(data->storage.download, "content", "{}"); data->commands = sbj_array();
}
static void fixture_free(management_fixture *data) {
    test_data_free(&data->storage); sbj_free(data->commands); sbj_free(data->last_status);
    sbj_free(data->last_ack); sbj_free(data->last_telemetry);
    if (data->reported) CloseHandle(data->reported);
}
static sbj *call(sbw_controller *controller, const char *method, const char *json) {
    sbj *params = sbj_parse_cstr(json ? json : "{}"); sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, method, params, true, &error); sbj_free(params);
    if (!result) fprintf(stderr, "%s: %s: %s\n", method, error.code, error.message);
    CHECK(result); test_redacted(result); return result;
}
static void enroll(sbw_controller *controller) {
    sbj *params = test_enrollment(); sbw_error error = {0};
    sbj *result = sbw_controller_dispatch(controller, "enrollment.apply", params, true, &error);
    CHECK(result); sbj_free(result); sbj_free(params);
}
static void add_command(management_fixture *data, const char *id, const char *name) {
    sbj_free(data->commands); data->commands = sbj_array(); sbj *command = sbj_object();
    sbj_set_str(command, "id", id); sbj_set_str(command, "command", name); sbj_arr_push(data->commands, command);
}
static void settings_and_commands(void) {
    management_fixture data; fixture_init(&data); sbw_controller *controller = controller_new(&data);
    sbj *params = sbj_parse_cstr("{\"auto_connect\":true}"); sbw_error error = {0};
    CHECK(!sbw_controller_dispatch(controller, "management.settings.set", params, false, &error));
    CHECK(sb_streq(error.code, "FORBIDDEN")); sbj_free(params);
    sbj *result = call(controller, "management.settings.set", "{\"auto_connect\":true,\"sync_interval_seconds\":15}");
    CHECK(sbj_get_bool(result, "auto_connect", false)); sbj_free(result);
    sbw_controller_free(controller); controller = controller_new(&data);
    result = call(controller, "status.get", NULL);
    CHECK(!sbj_get_bool(result, "enrolled", true));
    CHECK(sbj_get_bool(sbj_get(result, "management"), "auto_connect", false)); sbj_free(result);
    params = sbj_parse_cstr("{\"sync_interval_seconds\":1}");
    CHECK(!sbw_controller_dispatch(controller, "management.settings.set", params, true, &error));
    CHECK(sb_streq(error.code, "INVALID_REQUEST")); sbj_free(params);
    params = sbj_parse_cstr("{\"manual_disconnect\":false}");
    CHECK(!sbw_controller_dispatch(controller, "management.settings.set", params, true, &error)); sbj_free(params);
    enroll(controller);
    uint64_t now = GetTickCount64() + 100;
    sbw_controller_background_tick(controller, now);
    CHECK(data.storage.downloads == 1 && data.reports == 1 && data.polls == 1 && data.telemetry == 1);
    CHECK(!sbj_get_bool(data.last_status, "singbox_running", true));
    CHECK(sbj_get_int(data.last_telemetry, "conn_count", -1) == 0);
    CHECK(!sbj_has(data.last_telemetry, "connections") && !sbj_has(data.last_telemetry, "logs"));
    data.storage.fail_fetch = true;
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(data.reports == 2 && sbw_json_string(sbj_get(data.last_status, "last_error"), 256, false));
    data.storage.fail_fetch = false;
    add_command(&data, "reload-1", "reload"); data.fail_ack = true;
    unsigned before = data.storage.downloads;
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(data.storage.downloads == before + 2 && data.acknowledgements == 1);
    CHECK(sbj_string_is(sbj_get(data.last_ack, "status"), "done"));
    /* A failed ACK and a service restart must not replay reload. */
    sbw_controller_free(controller); controller = controller_new(&data); data.fail_ack = false;
    before = data.storage.downloads;
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(data.storage.downloads == before + 1 && data.acknowledgements == 2);
    CHECK(sbj_string_is(sbj_get(data.last_ack, "status"), "done"));
    result = call(controller, "connection.stop", NULL); sbj_free(result);
    add_command(&data, "restart-1", "restart");
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(sbj_string_is(sbj_get(data.last_ack, "status"), "failed"));
    CHECK(strstr(sbj_get_str(data.last_ack, "result", ""), "disconnected"));
    sbw_controller_free(controller); controller = controller_new(&data);
    result = call(controller, "management.settings.get", NULL);
    CHECK(!sbj_get_bool(result, "desired_connected", true) && sbj_get_bool(result, "manual_disconnect", false)); sbj_free(result);
    /* Recovered pending journal entries are explicitly failed, never replayed. */
    sbw_controller_free(controller);
    sbj *receipts = sbj_array(), *pending = sbj_object();
    sbj_set_str(pending, "id", "uncertain-1"); sbj_set_str(pending, "status", "pending");
    sbj_set_str(pending, "result", "Interrupted command."); sbj_arr_push(receipts, pending);
    sbj_set(data.storage.saved, "command_receipts", receipts); add_command(&data, "uncertain-1", "reload");
    controller = controller_new(&data); before = data.storage.downloads;
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(data.storage.downloads == before + 1 && sbj_string_is(sbj_get(data.last_ack, "status"), "failed"));
    /* The actual thread reports with no UI and no installed core. */
    sbw_controller_free(controller); controller = controller_new(&data);
    data.reported = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(data.reported);
    CHECK(sbw_controller_start_background(controller, &error) == 0);
    CHECK(WaitForSingleObject(data.reported, 3000) == WAIT_OBJECT_0);
    result = call(controller, "management.settings.get", NULL); CHECK(sbj_get_bool(result, "worker_running", false)); sbj_free(result);
    sbw_controller_free(controller); fixture_free(&data);
}
static sbw_core *attach_core(sbw_controller *controller, const wchar_t *fixture, const wchar_t *directory) {
    sbw_core_options options = {fixture, directory, 3000, 2000}; sbw_error error = {0};
    sbw_core *core = sbw_core_new(&options, &error);
    if (!core) fprintf(stderr, "%s: %s\n", error.code, error.message);
    CHECK(core); sbw_controller_set_core(controller, core, NULL); return core;
}
static sbw_core_status process_status(sbw_core *core) {
    sbw_core_status status = {0}; sbw_error error = {0};
    uint64_t deadline = GetTickCount64() + 1000;
    while (sbw_core_poll(core, &status, &error) != 0) {
        CHECK(sb_streq(error.code, "CORE_BUSY") && GetTickCount64() < deadline); Sleep(5);
    }
    return status;
}
static void connection_management(const wchar_t *fixture) {
    wchar_t temporary[32768], name[128]; CHECK(GetTempPathW(32768, temporary));
    swprintf_s(name, 128, L"sb-easy-management-%lu-%llu", GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    wchar_t *directory = sbw_path_join(temporary, name);
    management_fixture data; fixture_init(&data); sbw_controller *controller = controller_new(&data);
    enroll(controller); sbw_core *core = attach_core(controller, fixture, directory);
    sbj *result = call(controller, "management.settings.set", "{\"auto_connect\":true,\"telemetry_enabled\":false,\"sync_interval_seconds\":15}"); sbj_free(result);
    result = call(controller, "config.refresh", NULL); sbj_free(result);
    result = call(controller, "connection.start", NULL); CHECK(sbj_get_bool(result, "core_running", false)); sbj_free(result);
    uint64_t now = GetTickCount64() + 100;
    DWORD initial_pid = process_status(core).process_id; CHECK(initial_pid);
    sbj_set_str(data.storage.download, "etag", "revision-2");
    sbj_set_str(data.storage.download, "content", "{\"revision\":2}");
    sbw_controller_background_tick(controller, now);
    result = call(controller, "status.get", NULL);
    CHECK(sbj_string_is(sbj_get(sbj_get(result, "config"), "active_etag"), "revision-2")); sbj_free(result);
    DWORD second_pid = process_status(core).process_id; CHECK(second_pid && second_pid != initial_pid);
    /* Invalid candidate remains observable without replacing healthy bytes. */
    sbj_set_str(data.storage.download, "etag", "bad-3");
    sbj_set_str(data.storage.download, "content", "{\"mode\":\"check_fail\"}");
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(process_status(core).process_id == second_pid);
    CHECK(sbw_json_string(sbj_get(data.last_status, "last_error"), 256, false));
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(process_status(core).process_id == second_pid);
    CHECK(sbw_json_string(sbj_get(data.last_status, "last_error"), 256, false));
    /* Terminate only our fixture process. Recovery uses last-good revision-2. */
    HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, second_pid); CHECK(process);
    CHECK(TerminateProcess(process, 23)); CHECK(WaitForSingleObject(process, 2000) == WAIT_OBJECT_0); CloseHandle(process);
    sbw_controller_poll(controller);
    sbw_controller_background_tick(controller, now += 15000);
    result = call(controller, "status.get", NULL);
    CHECK(sbj_get_bool(result, "core_running", false));
    CHECK(sbj_string_is(sbj_get(sbj_get(result, "config"), "active_etag"), "revision-2")); sbj_free(result);
    CHECK(process_status(core).process_id != second_pid);
    DWORD recovered_pid = process_status(core).process_id;
    sbw_controller_network_changed(controller);
    sbw_controller_background_tick(controller, now += 10);
    CHECK(process_status(core).process_id == recovered_pid); /* Debounced. */
    sbw_controller_network_changed(controller);
    sbw_controller_background_tick(controller, now += 1000);
    CHECK(process_status(core).process_id == recovered_pid);
    sbw_controller_background_tick(controller, now += 2001);
    CHECK(process_status(core).process_id != recovered_pid); /* Resume/network recovery. */
    result = call(controller, "connection.stop", NULL); sbj_free(result);
    sbw_controller_network_changed(controller);
    sbw_controller_background_tick(controller, now += 15000);
    sbw_controller_background_tick(controller, now += 2001);
    CHECK(!process_status(core).process_running);
    sbw_controller_free(controller); controller = controller_new(&data); core = attach_core(controller, fixture, directory);
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(!process_status(core).process_running);
    result = call(controller, "management.settings.get", NULL);
    CHECK(sbj_get_bool(result, "auto_connect", false) && !sbj_get_bool(result, "desired_connected", true)); sbj_free(result);
    sbj_set_str(data.storage.download, "etag", "good-4"); sbj_set_str(data.storage.download, "content", "{}");
    result = call(controller, "config.refresh", NULL); sbj_free(result);
    result = call(controller, "connection.start", NULL); sbj_free(result);
    sbw_controller_free(controller); controller = controller_new(&data); core = attach_core(controller, fixture, directory);
    sbw_controller_background_tick(controller, now += 15000);
    CHECK(process_status(core).process_running);
    sbw_controller_free(controller); fixture_free(&data);
    test_remove_diagnostics(directory);
    wchar_t *lock = sbw_path_join(directory, L"state.lock"); CHECK(DeleteFileW(lock)); free(lock);
    wchar_t *traffic = sbw_path_join(directory, L"device-state.dat"); DeleteFileW(traffic); free(traffic);
    CHECK(RemoveDirectoryW(directory)); free(directory);
}
int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv); if (helper >= 0) return helper;
    CHECK(argc == 2);
    settings_and_commands(); connection_management(argv[1]);
    puts("Background settings, sync, status, telemetry privacy, durable ACKs, auto-connect, recovery and manual-disconnect tests passed.");
    return 0;
}
