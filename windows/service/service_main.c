#include "pipe_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static HANDLE stop_event;
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS service_status;
static SRWLOCK status_lock = SRWLOCK_INIT, event_lock = SRWLOCK_INIT;
static void report_status(DWORD state, DWORD error) {
    AcquireSRWLockExclusive(&status_lock);
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = state;
    service_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    service_status.dwWin32ExitCode = error;
    service_status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 10000 : 0;
    service_status.dwCheckPoint = service_status.dwWaitHint ? 1 : 0;
    SetServiceStatus(status_handle, &service_status);
    ReleaseSRWLockExclusive(&status_lock);
}
static void signal_stop(void) {
    AcquireSRWLockShared(&event_lock);
    if (stop_event) SetEvent(stop_event);
    ReleaseSRWLockShared(&event_lock);
}
static void close_stop(void) {
    AcquireSRWLockExclusive(&event_lock);
    if (stop_event) CloseHandle(stop_event);
    stop_event = NULL;
    ReleaseSRWLockExclusive(&event_lock);
}
static DWORD WINAPI service_control(DWORD control, DWORD event_type, void *event_data, void *context) {
    (void)event_type; (void)event_data; (void)context;
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        report_status(SERVICE_STOP_PENDING, ERROR_SUCCESS); signal_stop(); return NO_ERROR;
    }
    return control == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}
static BOOL WINAPI console_control(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT || control == CTRL_CLOSE_EVENT ||
        control == CTRL_LOGOFF_EVENT || control == CTRL_SHUTDOWN_EVENT) { signal_stop(); return TRUE; }
    return FALSE;
}
static void ready(void *unused) { (void)unused; report_status(SERVICE_RUNNING, ERROR_SUCCESS); }
static DWORD run(bool console, const wchar_t *directory, sbw_pipe_options *options) {
    sbw_error error = {0};
    wchar_t *default_directory = directory ? NULL : sbw_default_data_directory(console, &error);
    const wchar_t *location = directory ? directory : default_directory;
    sbw_store *store = location ? sbw_secure_store_new(location, &error) : NULL;
    sbw_control_plane *remote = store ? sbw_winhttp_new(25000, &error) : NULL;
    if (!store || !remote) {
        sbw_store_free(store); sbw_control_plane_free(remote); free(default_directory);
        if (console) fprintf(stderr, "%s\n", error.message); return ERROR_OPEN_FAILED;
    }
    sbw_controller *controller = sbw_controller_new(remote, store, stop_event, &error);
    if (!controller) { free(default_directory); if (console) fprintf(stderr, "%s\n", error.message); return ERROR_OPEN_FAILED; }
    sbw_error core_error = {0};
    wchar_t *binary_dir = sbw_executable_directory(&core_error);
    wchar_t *core_binary = binary_dir ? sbw_path_join(binary_dir, L"core\\sing-box.exe") : NULL;
    wchar_t *work_directory = sbw_path_join(location, L"core-work");
    sbw_core_options core_options = {core_binary, work_directory, 8000, 2000};
    sbw_core *core = core_binary && work_directory ? sbw_core_new(&core_options, &core_error) : NULL;
    sbw_controller_set_core(controller, core, &core_error);
    free(binary_dir); free(core_binary); free(work_directory); free(default_directory);
    options->controller = controller;
    DWORD result = sbw_run_pipe_server(options, stop_event);
    sbw_controller_free(controller); options->controller = NULL; return result;
}
static void WINAPI service_main(DWORD argc, wchar_t **argv) {
    (void)argc; (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(L"sb-easy", service_control, NULL);
    if (!status_handle) return;
    report_status(SERVICE_START_PENDING, ERROR_SUCCESS);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) { report_status(SERVICE_STOPPED, GetLastError()); return; }
    sbw_pipe_options options; sbw_pipe_options_init(&options); options.on_ready = ready;
    DWORD result = run(false, NULL, &options);
    report_status(SERVICE_STOPPED, result); close_stop();
}
int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv);
    if (helper >= 0) return helper;
    bool console = false, custom_pipe = false;
    const wchar_t *directory = NULL;
    sbw_pipe_options options; sbw_pipe_options_init(&options);
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--console") == 0) console = true;
        else if (wcscmp(argv[i], L"--pipe-name") == 0 && i + 1 < argc) { options.pipe_name = argv[++i]; custom_pipe = true; }
        else if (wcscmp(argv[i], L"--data-dir") == 0 && i + 1 < argc) directory = argv[++i];
        else if (wcscmp(argv[i], L"--help") == 0) {
            puts("sb-easy-service [--console [--pipe-name \\\\.\\pipe\\name] [--data-dir path]]\n"
                 "C11 Windows service. Managed core connection control; TUN requires an elevated service."); return 0;
        } else { fputs("Unknown or incomplete argument. Use --help.\n", stderr); return 2; }
    }
    if ((!console && (custom_pipe || directory)) || !sbw_valid_pipe_name(options.pipe_name)) {
        fputs("Custom pipe and data locations are supported only with --console.\n", stderr); return 2;
    }
    if (!console) {
        SERVICE_TABLE_ENTRYW table[] = {{L"sb-easy", service_main}, {NULL, NULL}};
        if (!StartServiceCtrlDispatcherW(table)) {
            fprintf(stderr, "SCM startup failed (Windows error %lu); use --console for development.\n", GetLastError()); return 1;
        }
        return 0;
    }
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) return 1;
    if (!SetConsoleCtrlHandler(console_control, TRUE)) { close_stop(); return 1; }
    puts("sb-easy C11 development console: managed core connections. TUN requires elevation. Ctrl+C stops.");
    DWORD result = run(true, directory, &options);
    SetConsoleCtrlHandler(console_control, FALSE); close_stop();
    if (result != ERROR_SUCCESS) fprintf(stderr, "IPC service failed (Windows error %lu).\n", result);
    return result == ERROR_SUCCESS ? 0 : 1;
}
