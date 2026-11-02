#include "../service/core_process.h"

#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (core=%s, win32=%lu)\n", __FILE__, __LINE__, #condition,    \
                    error.code, GetLastError());                                                   \
            goto done;                                                                             \
        }                                                                                          \
    } while (0)

typedef struct check_context {
    sbw_core *core;
    HANDLE cancel;
    int result;
    sbw_error error;
} check_context;

static LONG parent_breaks;
static BOOL WINAPI parent_control(DWORD event) {
    if (event != CTRL_BREAK_EVENT)
        return FALSE;
    InterlockedIncrement(&parent_breaks);
    return TRUE;
}

static HANDLE launch_sentinel(const wchar_t *fixture, DWORD target, const wchar_t *ready,
                              const wchar_t *signaled) {
    size_t capacity = wcslen(fixture) + wcslen(ready) + wcslen(signaled) + 80;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --sentinel %lu \"%ls\" \"%ls\"",
                     fixture, target, ready, signaled) < 0) {
        free(command);
        return NULL;
    }
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    bool started = CreateProcessW(fixture, command, NULL, NULL, FALSE,
                                  target ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE, NULL, NULL,
                                  &startup, &process);
    free(command);
    if (!started)
        return NULL;
    CloseHandle(process.hThread);
    return process.hProcess;
}

static DWORD WINAPI blocking_check(void *value) {
    check_context *context = value;
    const char json[] = "{\"mode\":\"check_timeout\"}";
    context->result = sbw_core_config_check(context->core, json, strlen(json), context->cancel,
                                            NULL, &context->error);
    return 0;
}

static wchar_t *temporary_root(void) {
    wchar_t temporary[32768];
    DWORD size = GetTempPathW((DWORD)(sizeof(temporary) / sizeof(*temporary)), temporary);
    if (!size || size >= sizeof(temporary) / sizeof(*temporary))
        return NULL;
    BYTE random[16];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return NULL;
    wchar_t name[64] = L"sb-easy-core-test-";
    const wchar_t hex[] = L"0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) {
        name[18 + 2 * i] = hex[random[i] >> 4];
        name[19 + 2 * i] = hex[random[i] & 15];
    }
    name[50] = L'\0';
    wchar_t *root = sbw_path_join(temporary, name);
    if (!CreateDirectoryW(root, NULL)) {
        free(root);
        return NULL;
    }
    return root;
}

static unsigned config_count(const wchar_t *directory, bool *write_denied) {
    wchar_t *pattern = sbw_path_join(directory, L"core-*.json");
    WIN32_FIND_DATAW data = {0};
    HANDLE search = FindFirstFileW(pattern, &data);
    free(pattern);
    unsigned count = 0;
    if (write_denied)
        *write_denied = true;
    if (search == INVALID_HANDLE_VALUE)
        return 0;
    do {
        ++count;
        if (write_denied) {
            wchar_t *path = sbw_path_join(directory, data.cFileName);
            HANDLE writer = CreateFileW(path, GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            free(path);
            if (writer != INVALID_HANDLE_VALUE) {
                *write_denied = false;
                CloseHandle(writer);
            }
        }
    } while (FindNextFileW(search, &data));
    FindClose(search);
    return count;
}

static DWORD read_pid(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    char text[32] = {0};
    DWORD read = 0;
    bool ok = ReadFile(file, text, sizeof(text) - 1, &read, NULL) && read > 0;
    CloseHandle(file);
    return ok ? strtoul(text, NULL, 10) : 0;
}

static DWORD wait_pid(const wchar_t *path) {
    ULONGLONG until = GetTickCount64() + 2000;
    DWORD pid = 0;
    do {
        pid = read_pid(path);
        if (pid)
            break;
        Sleep(10);
    } while (GetTickCount64() < until);
    return pid;
}

static char *fixture_config(const char *mode, const wchar_t *marker, HANDLE event) {
    sbj *value = sbj_object();
    sbj_set_str(value, "mode", mode);
    if (marker) {
        char *path = sbw_utf8(marker, NULL);
        sbj_set_str(value, "child_pid_file", path);
        free(path);
    }
    if (event)
        sbj_set_int(value, "leak_handle", (int64_t)(uintptr_t)event);
    char *json = sbj_dump(value, -1);
    sbj_free(value);
    return json;
}

static bool await_exit(sbw_core *core, sbw_core_status *status, sbw_error *error) {
    ULONGLONG until = GetTickCount64() + 3000;
    do {
        if (sbw_core_poll(core, status, error) != 0)
            return false;
        if (!status->process_running)
            return true;
        Sleep(10);
    } while (GetTickCount64() < until);
    return false;
}

static bool write_pid(const wchar_t *path, DWORD pid) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    char text[32];
    int length = sprintf_s(text, sizeof(text), "%lu", pid);
    DWORD written = 0;
    bool result = length > 0 && WriteFile(file, text, (DWORD)length, &written, NULL) &&
                  written == (DWORD)length && FlushFileBuffers(file);
    CloseHandle(file);
    return result;
}

static int owner_mode(wchar_t **argv) {
    sbw_error error = {0};
    sbw_core_options options = {argv[2], argv[3], 2000, 2000};
    sbw_core *core = sbw_core_new(&options, &error);
    char *json = fixture_config("spawn_child", argv[4], NULL);
    sbw_core_status status = {0};
    bool ready = core && sbw_core_start(core, json, strlen(json), NULL, &error) == 0 &&
                 sbw_core_poll(core, &status, &error) == 0 && status.process_running &&
                 write_pid(argv[5], status.process_id);
    free(json);
    if (!ready) {
        sbw_core_free(core);
        return 80;
    }
    Sleep(INFINITE); /* Parent terminates us without invoking sbw_core_free. */
    return 0;
}

static HANDLE launch_owner(const wchar_t *fixture, const wchar_t *directory, const wchar_t *marker,
                           const wchar_t *ready) {
    wchar_t executable[32768];
    DWORD size =
        GetModuleFileNameW(NULL, executable, (DWORD)(sizeof(executable) / sizeof(*executable)));
    if (!size || size >= sizeof(executable) / sizeof(*executable))
        return NULL;
    size_t capacity = wcslen(executable) + wcslen(fixture) + wcslen(directory) + wcslen(marker) +
                      wcslen(ready) + 32;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE,
                     L"\"%ls\" --owner \"%ls\" \"%ls\" \"%ls\" \"%ls\"", executable, fixture,
                     directory, marker, ready) < 0) {
        free(command);
        return NULL;
    }
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    bool started = CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
                                  NULL, &startup, &process) != FALSE;
    free(command);
    if (!started)
        return NULL;
    CloseHandle(process.hThread);
    return process.hProcess;
}

typedef struct test_state {
    const wchar_t *fixture;
    sbw_error error;
    sbw_core *core, *duplicate;
    wchar_t *root, *directory, *marker, *missing, *lock;
    wchar_t *crash_directory, *crash_lock, *ready, *keep, *unsafe;
    wchar_t *sentinel_ready, *sentinel_signal;
    char *json;
    HANDLE cancel, checker, leaked, primary, child, owner, sentinel;
    check_context context;
    sbw_core_options options;
} test_state;

#define CHECK_T(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (core=%s, win32=%lu)\n", __FILE__, __LINE__, #condition,    \
                    t->error.code, GetLastError());                                                \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int scenario_construct(test_state *t) {
    t->options.executable = L"relative.exe";
    CHECK_T(!sbw_core_new(&t->options, &t->error) && !strcmp(t->error.code, "CORE_INVALID_PATH"));
    t->options.executable = t->missing;
    CHECK_T(!sbw_core_new(&t->options, &t->error) && !strcmp(t->error.code, "CORE_UNAVAILABLE"));
    t->options.executable = t->fixture;
    t->core = sbw_core_new(&t->options, &t->error);
    CHECK_T(t->core);
    CHECK_T(sbw_core_preflight(t->core, false, &t->error) == 0);
    int preflight = sbw_core_preflight(t->core, true, &t->error);
    CHECK_T(preflight == 0 || !strcmp(t->error.code, "CORE_ELEVATION_REQUIRED"));
    t->duplicate = sbw_core_new(&t->options, &t->error);
    CHECK_T(!t->duplicate);
    CHECK_T(!DeleteFileW(t->fixture) && GetLastError() == ERROR_SHARING_VIOLATION);
    return 0;
}

static int scenario_versions_and_checks(test_state *t) {
    sbw_core_status status = {0};
    DWORD exit_code = MAXDWORD;
    CHECK_T(sbw_core_version_check(t->core, "1.14.3", NULL, &t->error) == 0);
    memset(&t->error, 0, sizeof(t->error));
    CHECK_T(sbw_core_version_check(t->core, "1.14.4", NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_VERSION_MISMATCH"));
    CHECK_T(sbw_core_config_check(t->core, "{}", 2, NULL, &exit_code, &t->error) == 0 &&
            exit_code == 0);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && !status.process_running &&
            !status.has_exit_code);
    CHECK_T(config_count(t->directory, NULL) == 0);
    return 0;
}

static int scenario_check_cache(test_state *t) {
    /* A check cache is exact-byte and single-use, and survives stopping the old
     * instance. Equivalent JSON with different bytes must be checked again. */
    free(t->json);
    t->json = fixture_config("count_checks", t->marker, NULL);
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, NULL, &t->error) == 0 &&
            read_pid(t->marker) == 1);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            read_pid(t->marker) == 1);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            read_pid(t->marker) == 2);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, NULL, &t->error) == 0 &&
            read_pid(t->marker) == 3);
    char *changed = sb_asprintf("%s ", t->json);
    free(t->json);
    t->json = changed;
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            read_pid(t->marker) == 4);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, NULL, &t->error) == 0 &&
            read_pid(t->marker) == 5);
    CHECK_T(sbw_core_config_check(t->core, "[]", 2, NULL, NULL, &t->error) != 0);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            read_pid(t->marker) == 6);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0 && DeleteFileW(t->marker));
    free(t->json);
    t->json = NULL;
    return 0;
}

static int scenario_graceful_stop(test_state *t) {
    sbw_core_status status = {0};
    /* The fixture acknowledges targeted BREAK with exit 42. A second run
     * ignores it and proves the bounded Job fallback remains available. */
    t->json = fixture_config("graceful", t->marker, NULL);
    t->sentinel = launch_sentinel(t->fixture, 0, t->sentinel_ready, t->sentinel_signal);
    CHECK_T(t->sentinel && wait_pid(t->sentinel_ready));
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            wait_pid(t->marker));
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && status.process_running);
    t->primary =
        OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.process_id);
    CHECK_T(t->primary && sbw_core_stop(t->core, &t->error) == 0);
    DWORD graceful_code = 0;
    CHECK_T(GetExitCodeProcess(t->primary, &graceful_code) && graceful_code == 42);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && !status.last_stop_forced);
    CHECK_T(parent_breaks == 0 && WaitForSingleObject(t->sentinel, 0) == WAIT_TIMEOUT &&
            GetFileAttributesW(t->sentinel_signal) == INVALID_FILE_ATTRIBUTES);
    CHECK_T(TerminateProcess(t->sentinel, 99) &&
            WaitForSingleObject(t->sentinel, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->sentinel);
    t->sentinel = NULL;
    CHECK_T(DeleteFileW(t->sentinel_ready));
    CloseHandle(t->primary);
    t->primary = NULL;
    CHECK_T(DeleteFileW(t->marker));
    free(t->json);
    t->json = fixture_config("ignore_break", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            wait_pid(t->marker));
    ULONGLONG stop_begin = GetTickCount64();
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0 && GetTickCount64() - stop_begin < 3000);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && status.last_stop_forced);
    CHECK_T(DeleteFileW(t->marker));
    free(t->json);
    t->json = NULL;
    return 0;
}

static int scenario_slow_graceful(test_state *t) {
    sbw_core_status status = {0};
    /* Real adapter teardown can exceed the old 1.5 second graceful allowance. */
    sbw_core_free(t->core);
    t->options.stop_timeout_ms = 5000;
    t->core = sbw_core_new(&t->options, &t->error);
    CHECK_T(t->core);
    t->json = fixture_config("slow_graceful", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            wait_pid(t->marker));
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && !status.last_stop_forced &&
            status.stop_signal_code == 0);
    CHECK_T(DeleteFileW(t->marker));
    free(t->json);
    t->json = NULL;
    sbw_core_free(t->core);
    t->options.stop_timeout_ms = 2000;
    t->core = sbw_core_new(&t->options, &t->error);
    CHECK_T(t->core);
    return 0;
}

static int scenario_console_peer(test_state *t) {
    sbw_core_status status = {0};
    /* A third peer attached to the core's console must suppress BREAK entirely;
     * only the core's own Job is terminated, leaving the outsider untouched. */
    t->json = fixture_config("graceful", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0 &&
            wait_pid(t->marker));
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && status.process_running);
    t->sentinel =
        launch_sentinel(t->fixture, status.process_id, t->sentinel_ready, t->sentinel_signal);
    CHECK_T(t->sentinel && wait_pid(t->sentinel_ready));
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && status.last_stop_forced);
    CHECK_T(parent_breaks == 0 && WaitForSingleObject(t->sentinel, 0) == WAIT_TIMEOUT &&
            GetFileAttributesW(t->sentinel_signal) == INVALID_FILE_ATTRIBUTES);
    CHECK_T(TerminateProcess(t->sentinel, 99) &&
            WaitForSingleObject(t->sentinel, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->sentinel);
    t->sentinel = NULL;
    CHECK_T(DeleteFileW(t->marker) && DeleteFileW(t->sentinel_ready));
    free(t->json);
    t->json = NULL;
    return 0;
}

static int scenario_config_failures_and_cancel(test_state *t) {
    sbw_core_status status = {0};
    DWORD exit_code = MAXDWORD;
    CHECK_T(sbw_core_config_check(t->core, "[]", 2, NULL, NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_CONFIG_INVALID"));
    CHECK_T(sbw_core_config_check(t->core, "{", 1, NULL, NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_CONFIG_INVALID"));
    t->json = fixture_config("check_fail", NULL, NULL);
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, &exit_code, &t->error) !=
                0 &&
            !strcmp(t->error.code, "CORE_CHECK_FAILED") && exit_code == 17);
    CHECK_T(!strstr(t->error.message, "FIXTURE_SECRET"));
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_CHECK_FAILED"));
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && !status.process_running);
    free(t->json);
    t->json = fixture_config("check_timeout", NULL, NULL);
    ULONGLONG before = GetTickCount64();
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, &exit_code, &t->error) !=
                0 &&
            !strcmp(t->error.code, "CORE_CHECK_TIMEOUT") && exit_code == MAXDWORD);
    CHECK_T(GetTickCount64() - before < 4000 && config_count(t->directory, NULL) == 0);
    t->cancel = CreateEventW(NULL, TRUE, TRUE, NULL);
    CHECK_T(t->cancel);
    CHECK_T(sbw_core_config_check(t->core, "{}", 2, t->cancel, NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_CANCELLED"));
    CHECK_T(config_count(t->directory, NULL) == 0);
    CHECK_T(ResetEvent(t->cancel));
    t->context.core = t->core;
    t->context.cancel = t->cancel;
    t->checker = CreateThread(NULL, 0, blocking_check, &t->context, 0, NULL);
    CHECK_T(t->checker);
    before = GetTickCount64();
    while (!config_count(t->directory, NULL) && GetTickCount64() - before < 600)
        Sleep(5);
    CHECK_T(config_count(t->directory, NULL) == 1);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) != 0 && !strcmp(t->error.code, "CORE_BUSY"));
    CHECK_T(sbw_core_stop(t->core, &t->error) != 0 && !strcmp(t->error.code, "CORE_BUSY"));
    CHECK_T(SetEvent(t->cancel));
    CHECK_T(WaitForSingleObject(t->checker, 4000) == WAIT_OBJECT_0);
    CloseHandle(t->checker);
    t->checker = NULL;
    CHECK_T(t->context.result != 0 && !strcmp(t->context.error.code, "CORE_CANCELLED"));
    CHECK_T(config_count(t->directory, NULL) == 0);
    return 0;
}

static int scenario_noisy_inherit(test_state *t) {
    sbw_core_status status = {0};
    SECURITY_ATTRIBUTES inheritable = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    t->leaked = CreateEventW(&inheritable, TRUE, FALSE, NULL);
    CHECK_T(t->leaked);
    free(t->json);
    t->json = fixture_config("noisy", NULL, t->leaked);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && status.process_running &&
            !status.has_exit_code);
    t->primary = OpenProcess(SYNCHRONIZE, FALSE, status.process_id);
    CHECK_T(t->primary);
    bool denied = false;
    CHECK_T(config_count(t->directory, &denied) == 1 && denied);
    Sleep(100);
    CHECK_T(WaitForSingleObject(t->leaked, 0) == WAIT_TIMEOUT);
    CHECK_T(sbw_core_start(t->core, "{}", 2, NULL, &t->error) != 0 &&
            !strcmp(t->error.code, "CORE_ALREADY_RUNNING"));
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0 &&
            WaitForSingleObject(t->primary, 0) == WAIT_OBJECT_0);
    CloseHandle(t->primary);
    t->primary = NULL;
    CHECK_T(config_count(t->directory, NULL) == 0);
    CHECK_T(sbw_core_poll(t->core, &status, &t->error) == 0 && !status.process_running);
    return 0;
}

static int scenario_crash(test_state *t) {
    sbw_core_status status = {0};
    free(t->json);
    t->json = fixture_config("crash", NULL, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0);
    CHECK_T(await_exit(t->core, &status, &t->error) && status.has_exit_code &&
            status.exit_code == 23);
    CHECK_T(config_count(t->directory, NULL) == 0);
    return 0;
}

static int scenario_spawn_child(test_state *t) {
    free(t->json);
    t->json = fixture_config("spawn_child", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0);
    DWORD child_pid = wait_pid(t->marker);
    CHECK_T(child_pid);
    t->child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK_T(t->child && WaitForSingleObject(t->child, 0) == WAIT_TIMEOUT);
    CHECK_T(sbw_core_stop(t->core, &t->error) == 0 &&
            WaitForSingleObject(t->child, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->child);
    t->child = NULL;
    CHECK_T(DeleteFileW(t->marker));
    CHECK_T(config_count(t->directory, NULL) == 0);
    return 0;
}

static int scenario_spawn_child_crash(test_state *t) {
    sbw_core_status status = {0};
    free(t->json);
    t->json = fixture_config("spawn_child_crash", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0);
    DWORD child_pid = wait_pid(t->marker);
    CHECK_T(child_pid);
    t->child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK_T(t->child);
    CHECK_T(await_exit(t->core, &status, &t->error) && status.exit_code == 23);
    CHECK_T(WaitForSingleObject(t->child, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->child);
    t->child = NULL;
    CHECK_T(DeleteFileW(t->marker));
    CHECK_T(config_count(t->directory, NULL) == 0);
    return 0;
}

static int scenario_check_child(test_state *t) {
    free(t->json);
    t->json = fixture_config("check_child", t->marker, NULL);
    CHECK_T(sbw_core_config_check(t->core, t->json, strlen(t->json), NULL, NULL, &t->error) == 0);
    DWORD child_pid = wait_pid(t->marker);
    CHECK_T(child_pid);
    t->child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK_T(!t->child || WaitForSingleObject(t->child, 2000) == WAIT_OBJECT_0);
    if (t->child) {
        CloseHandle(t->child);
        t->child = NULL;
    }
    CHECK_T(DeleteFileW(t->marker));
    return 0;
}

static int scenario_free_kills_child(test_state *t) {
    free(t->json);
    t->json = fixture_config("spawn_child", t->marker, NULL);
    CHECK_T(sbw_core_start(t->core, t->json, strlen(t->json), NULL, &t->error) == 0);
    DWORD child_pid = wait_pid(t->marker);
    CHECK_T(child_pid);
    t->child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK_T(t->child);
    sbw_core_free(t->core);
    t->core = NULL;
    CHECK_T(WaitForSingleObject(t->child, 2000) == WAIT_OBJECT_0 &&
            config_count(t->directory, NULL) == 0);
    CloseHandle(t->child);
    t->child = NULL;
    CHECK_T(DeleteFileW(t->marker));
    return 0;
}

static int scenario_owner_crash(test_state *t) {
    t->owner = launch_owner(t->fixture, t->crash_directory, t->marker, t->ready);
    CHECK_T(t->owner);
    DWORD primary_pid = wait_pid(t->ready);
    DWORD child_pid = wait_pid(t->marker);
    CHECK_T(primary_pid && child_pid);
    t->primary = OpenProcess(SYNCHRONIZE, FALSE, primary_pid);
    t->child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK_T(t->primary && t->child && WaitForSingleObject(t->child, 0) == WAIT_TIMEOUT);
    CHECK_T(TerminateProcess(t->owner, 99) && WaitForSingleObject(t->owner, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->owner);
    t->owner = NULL;
    CHECK_T(WaitForSingleObject(t->primary, 2000) == WAIT_OBJECT_0 &&
            WaitForSingleObject(t->child, 2000) == WAIT_OBJECT_0);
    CloseHandle(t->primary);
    t->primary = NULL;
    CloseHandle(t->child);
    t->child = NULL;
    CHECK_T(config_count(t->crash_directory, NULL) == 1);
    CHECK_T(write_pid(t->keep, 123));
    t->options.work_directory = t->crash_directory;
    t->core = sbw_core_new(&t->options, &t->error);
    CHECK_T(t->core && config_count(t->crash_directory, NULL) == 0 && read_pid(t->keep) == 123);
    sbw_core_free(t->core);
    t->core = NULL;
    CHECK_T(CreateDirectoryW(t->unsafe, NULL));
    t->core = sbw_core_new(&t->options, &t->error);
    CHECK_T(!t->core && !strcmp(t->error.code, "CORE_STORAGE_ERROR"));
    CHECK_T(GetFileAttributesW(t->unsafe) & FILE_ATTRIBUTE_DIRECTORY);
    CHECK_T(RemoveDirectoryW(t->unsafe));
    return 0;
}

static const struct {
    const char *name;
    int (*run)(test_state *);
} scenarios[] = {
    {"construct", scenario_construct},
    {"versions_and_checks", scenario_versions_and_checks},
    {"check_cache", scenario_check_cache},
    {"graceful_stop", scenario_graceful_stop},
    {"slow_graceful", scenario_slow_graceful},
    {"console_peer", scenario_console_peer},
    {"config_failures_and_cancel", scenario_config_failures_and_cancel},
    {"noisy_inherit", scenario_noisy_inherit},
    {"crash", scenario_crash},
    {"spawn_child", scenario_spawn_child},
    {"spawn_child_crash", scenario_spawn_child_crash},
    {"check_child", scenario_check_child},
    {"free_kills_child", scenario_free_kills_child},
    {"owner_crash", scenario_owner_crash},
};

int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv);
    if (helper >= 0)
        return helper;
    sbw_error error = {0};
    test_state t = {0};
    int result = 1;
    if (argc == 6 && !wcscmp(argv[1], L"--owner"))
        return owner_mode(argv);
    CHECK(argc == 2);
    t.fixture = argv[1];
    t.root = temporary_root();
    CHECK(t.root);
    t.directory = sbw_path_join(t.root, L"private work");
    t.marker = sbw_path_join(t.root, L"child.pid");
    t.missing = sbw_path_join(t.root, L"missing.exe");
    t.lock = sbw_path_join(t.directory, L"state.lock");
    t.crash_directory = sbw_path_join(t.root, L"crash work");
    t.crash_lock = sbw_path_join(t.crash_directory, L"state.lock");
    t.ready = sbw_path_join(t.root, L"owner-ready.pid");
    t.keep = sbw_path_join(t.crash_directory, L"keep.json");
    t.unsafe = sbw_path_join(t.crash_directory, L"core-00000000000000000000000000000000.json");
    t.sentinel_ready = sbw_path_join(t.root, L"sentinel.ready");
    t.sentinel_signal = sbw_path_join(t.root, L"sentinel.signal");
    CHECK(SetConsoleCtrlHandler(parent_control, TRUE));
    t.options = (sbw_core_options){argv[1], t.directory, 800, 2000};
    for (size_t i = 0; i < sizeof scenarios / sizeof *scenarios; ++i) {
        if (scenarios[i].run(&t) != 0) {
            fprintf(stderr, "core_process_test: scenario '%s' failed\n", scenarios[i].name);
            goto done;
        }
    }
    result = 0;
    puts("core_process_test: passed (dummy processes only; no networking or TUN)");
done:
    if (t.checker) {
        if (t.cancel)
            SetEvent(t.cancel);
        if (WaitForSingleObject(t.checker, 5000) != WAIT_OBJECT_0)
            ExitProcess(2);
        CloseHandle(t.checker);
    }
    sbw_core_free(t.core);
    sbw_core_free(t.duplicate);
    if (t.owner) {
        TerminateProcess(t.owner, 99);
        (void)WaitForSingleObject(t.owner, 2000);
        CloseHandle(t.owner);
    }
    if (t.sentinel) {
        TerminateProcess(t.sentinel, 99);
        (void)WaitForSingleObject(t.sentinel, 2000);
        CloseHandle(t.sentinel);
    }
    if (t.primary)
        CloseHandle(t.primary);
    if (t.child)
        CloseHandle(t.child);
    if (t.leaked)
        CloseHandle(t.leaked);
    if (t.cancel)
        CloseHandle(t.cancel);
    free(t.json);
    /* Exact known paths inside our freshly created random temporary directory;
     * no recursive deletion or traversing user-owned directory contents. */
    if (t.marker)
        DeleteFileW(t.marker);
    if (t.ready)
        DeleteFileW(t.ready);
    if (t.keep)
        DeleteFileW(t.keep);
    if (t.crash_lock)
        DeleteFileW(t.crash_lock);
    if (t.unsafe)
        RemoveDirectoryW(t.unsafe);
    if (t.sentinel_ready)
        DeleteFileW(t.sentinel_ready);
    if (t.sentinel_signal)
        DeleteFileW(t.sentinel_signal);
    for (int i = 0; i < 4; ++i) {
        wchar_t name[40];
        swprintf_s(name, 40, L"diagnostic-%d.log", i);
        if (t.directory) {
            wchar_t *path = sbw_path_join(t.directory, name);
            DeleteFileW(path);
            free(path);
        }
        if (t.crash_directory) {
            wchar_t *path = sbw_path_join(t.crash_directory, name);
            DeleteFileW(path);
            free(path);
        }
    }
    if (t.crash_directory)
        RemoveDirectoryW(t.crash_directory);
    if (t.lock)
        DeleteFileW(t.lock);
    if (t.directory)
        RemoveDirectoryW(t.directory);
    if (t.root)
        RemoveDirectoryW(t.root);
    free(t.lock);
    free(t.missing);
    free(t.marker);
    free(t.directory);
    free(t.root);
    free(t.crash_directory);
    free(t.crash_lock);
    free(t.ready);
    free(t.keep);
    free(t.unsafe);
    free(t.sentinel_ready);
    free(t.sentinel_signal);
    return result;
}
