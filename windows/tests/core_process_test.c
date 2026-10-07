#include "../service/core_process.h"

#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s (core=%s, win32=%lu)\n", __FILE__, __LINE__, #condition, error.code, GetLastError()); \
    goto done; \
} } while (0)

typedef struct check_context {
    sbw_core *core;
    HANDLE cancel;
    int result;
    sbw_error error;
} check_context;

static LONG parent_breaks;
static BOOL WINAPI parent_control(DWORD event) {
    if (event != CTRL_BREAK_EVENT) return FALSE;
    InterlockedIncrement(&parent_breaks); return TRUE;
}

static HANDLE launch_sentinel(const wchar_t *fixture, DWORD target, const wchar_t *ready, const wchar_t *signaled) {
    size_t capacity = wcslen(fixture) + wcslen(ready) + wcslen(signaled) + 80;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --sentinel %lu \"%ls\" \"%ls\"",
        fixture, target, ready, signaled) < 0) { free(command); return NULL; }
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
    bool started = CreateProcessW(fixture, command, NULL, NULL, FALSE,
        target ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE, NULL, NULL, &startup, &process);
    free(command);
    if (!started) return NULL;
    CloseHandle(process.hThread); return process.hProcess;
}

static DWORD WINAPI blocking_check(void *value) {
    check_context *context = value;
    const char json[] = "{\"mode\":\"check_timeout\"}";
    context->result = sbw_core_config_check(context->core, json, strlen(json), context->cancel, NULL, &context->error);
    return 0;
}

static wchar_t *temporary_root(void) {
    wchar_t temporary[32768];
    DWORD size = GetTempPathW((DWORD)(sizeof(temporary) / sizeof(*temporary)), temporary);
    if (!size || size >= sizeof(temporary) / sizeof(*temporary)) return NULL;
    BYTE random[16];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return NULL;
    wchar_t name[64] = L"sb-easy-core-test-";
    const wchar_t hex[] = L"0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) {
        name[18 + 2 * i] = hex[random[i] >> 4];
        name[19 + 2 * i] = hex[random[i] & 15];
    }
    name[50] = L'\0';
    wchar_t *root = sbw_path_join(temporary, name);
    if (!CreateDirectoryW(root, NULL)) { free(root); return NULL; }
    return root;
}

static unsigned config_count(const wchar_t *directory, bool *write_denied) {
    wchar_t *pattern = sbw_path_join(directory, L"core-*.json");
    WIN32_FIND_DATAW data = {0};
    HANDLE search = FindFirstFileW(pattern, &data);
    free(pattern);
    unsigned count = 0;
    if (write_denied) *write_denied = true;
    if (search == INVALID_HANDLE_VALUE) return 0;
    do {
        ++count;
        if (write_denied) {
            wchar_t *path = sbw_path_join(directory, data.cFileName);
            HANDLE writer = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            free(path);
            if (writer != INVALID_HANDLE_VALUE) { *write_denied = false; CloseHandle(writer); }
        }
    } while (FindNextFileW(search, &data));
    FindClose(search);
    return count;
}

static DWORD read_pid(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    char text[32] = {0};
    DWORD read = 0;
    bool ok = ReadFile(file, text, sizeof(text) - 1, &read, NULL) && read > 0;
    CloseHandle(file);
    return ok ? strtoul(text, NULL, 10) : 0;
}

static DWORD wait_pid(const wchar_t *path) {
    ULONGLONG until = GetTickCount64() + 2000;
    DWORD pid = 0;
    do { pid = read_pid(path); if (pid) break; Sleep(10); } while (GetTickCount64() < until);
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
    if (event) sbj_set_int(value, "leak_handle", (int64_t)(uintptr_t)event);
    char *json = sbj_dump(value, -1);
    sbj_free(value);
    return json;
}

static bool await_exit(sbw_core *core, sbw_core_status *status, sbw_error *error) {
    ULONGLONG until = GetTickCount64() + 3000;
    do {
        if (sbw_core_poll(core, status, error) != 0) return false;
        if (!status->process_running) return true;
        Sleep(10);
    } while (GetTickCount64() < until);
    return false;
}

static bool write_pid(const wchar_t *path, DWORD pid) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
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
        sbw_core_poll(core, &status, &error) == 0 && status.process_running && write_pid(argv[5], status.process_id);
    free(json);
    if (!ready) { sbw_core_free(core); return 80; }
    Sleep(INFINITE); /* Parent terminates us without invoking sbw_core_free. */
    return 0;
}

static HANDLE launch_owner(const wchar_t *fixture, const wchar_t *directory, const wchar_t *marker, const wchar_t *ready) {
    wchar_t executable[32768];
    DWORD size = GetModuleFileNameW(NULL, executable, (DWORD)(sizeof(executable) / sizeof(*executable)));
    if (!size || size >= sizeof(executable) / sizeof(*executable)) return NULL;
    size_t capacity = wcslen(executable) + wcslen(fixture) + wcslen(directory) + wcslen(marker) + wcslen(ready) + 32;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --owner \"%ls\" \"%ls\" \"%ls\" \"%ls\"",
                     executable, fixture, directory, marker, ready) < 0) { free(command); return NULL; }
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    bool started = CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                   NULL, NULL, &startup, &process) != FALSE;
    free(command);
    if (!started) return NULL;
    CloseHandle(process.hThread);
    return process.hProcess;
}

int wmain(int argc, wchar_t **argv) {
    int helper = sbw_core_signal_helper(argc, argv);
    if (helper >= 0) return helper;
    sbw_error error = {0};
    sbw_core *core = NULL, *duplicate = NULL;
    wchar_t *root = NULL, *directory = NULL, *marker = NULL, *missing = NULL, *lock = NULL;
    wchar_t *crash_directory = NULL, *crash_lock = NULL, *ready = NULL, *keep = NULL, *unsafe = NULL;
    wchar_t *sentinel_ready = NULL, *sentinel_signal = NULL;
    char *json = NULL;
    HANDLE cancel = NULL, checker = NULL, leaked = NULL, primary = NULL, child = NULL, owner = NULL;
    HANDLE sentinel = NULL;
    check_context context = {0};
    int result = 1;
    if (argc == 6 && !wcscmp(argv[1], L"--owner")) return owner_mode(argv);
    CHECK(argc == 2);
    root = temporary_root();
    CHECK(root);
    directory = sbw_path_join(root, L"private work");
    marker = sbw_path_join(root, L"child.pid");
    missing = sbw_path_join(root, L"missing.exe");
    lock = sbw_path_join(directory, L"state.lock");
    crash_directory = sbw_path_join(root, L"crash work");
    crash_lock = sbw_path_join(crash_directory, L"state.lock");
    ready = sbw_path_join(root, L"owner-ready.pid");
    keep = sbw_path_join(crash_directory, L"keep.json");
    unsafe = sbw_path_join(crash_directory, L"core-00000000000000000000000000000000.json");
    sentinel_ready = sbw_path_join(root, L"sentinel.ready");
    sentinel_signal = sbw_path_join(root, L"sentinel.signal");
    CHECK(SetConsoleCtrlHandler(parent_control, TRUE));
    sbw_core_options options = {argv[1], directory, 800, 2000};
    options.executable = L"relative.exe";
    CHECK(!sbw_core_new(&options, &error) && !strcmp(error.code, "CORE_INVALID_PATH"));
    options.executable = missing;
    CHECK(!sbw_core_new(&options, &error) && !strcmp(error.code, "CORE_UNAVAILABLE"));
    options.executable = argv[1];
    core = sbw_core_new(&options, &error);
    CHECK(core);
    CHECK(sbw_core_preflight(core, false, &error) == 0);
    int preflight = sbw_core_preflight(core, true, &error);
    CHECK(preflight == 0 || !strcmp(error.code, "CORE_ELEVATION_REQUIRED"));
    duplicate = sbw_core_new(&options, &error);
    CHECK(!duplicate);
    CHECK(!DeleteFileW(argv[1]) && GetLastError() == ERROR_SHARING_VIOLATION);

    sbw_core_status status = {0};
    DWORD exit_code = MAXDWORD;
    CHECK(sbw_core_config_check(core, "{}", 2, NULL, &exit_code, &error) == 0 && exit_code == 0);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && !status.process_running && !status.has_exit_code);
    CHECK(config_count(directory, NULL) == 0);

    /* A check cache is exact-byte and single-use, and survives stopping the old
     * instance. Equivalent JSON with different bytes must be checked again. */
    free(json); json = fixture_config("count_checks", marker, NULL);
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, NULL, &error) == 0 && read_pid(marker) == 1);
    CHECK(sbw_core_stop(core, &error) == 0);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && read_pid(marker) == 1);
    CHECK(sbw_core_stop(core, &error) == 0);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && read_pid(marker) == 2);
    CHECK(sbw_core_stop(core, &error) == 0);
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, NULL, &error) == 0 && read_pid(marker) == 3);
    char *changed = sb_asprintf("%s ", json);
    free(json); json = changed;
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && read_pid(marker) == 4);
    CHECK(sbw_core_stop(core, &error) == 0);
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, NULL, &error) == 0 && read_pid(marker) == 5);
    CHECK(sbw_core_config_check(core, "[]", 2, NULL, NULL, &error) != 0);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && read_pid(marker) == 6);
    CHECK(sbw_core_stop(core, &error) == 0 && DeleteFileW(marker));
    free(json); json = NULL;

    /* The fixture acknowledges targeted BREAK with exit 42. A second run
     * ignores it and proves the bounded Job fallback remains available. */
    json = fixture_config("graceful", marker, NULL);
    sentinel = launch_sentinel(argv[1], 0, sentinel_ready, sentinel_signal);
    CHECK(sentinel && wait_pid(sentinel_ready));
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && wait_pid(marker));
    CHECK(sbw_core_poll(core, &status, &error) == 0 && status.process_running);
    primary = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.process_id);
    CHECK(primary && sbw_core_stop(core, &error) == 0);
    DWORD graceful_code = 0;
    CHECK(GetExitCodeProcess(primary, &graceful_code) && graceful_code == 42);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && !status.last_stop_forced);
    CHECK(parent_breaks == 0 && WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT &&
        GetFileAttributesW(sentinel_signal) == INVALID_FILE_ATTRIBUTES);
    CHECK(TerminateProcess(sentinel, 99) && WaitForSingleObject(sentinel, 2000) == WAIT_OBJECT_0);
    CloseHandle(sentinel); sentinel = NULL; CHECK(DeleteFileW(sentinel_ready));
    CloseHandle(primary); primary = NULL; CHECK(DeleteFileW(marker));
    free(json); json = fixture_config("ignore_break", marker, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && wait_pid(marker));
    ULONGLONG stop_begin = GetTickCount64();
    CHECK(sbw_core_stop(core, &error) == 0 && GetTickCount64() - stop_begin < 3000);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && status.last_stop_forced);
    CHECK(DeleteFileW(marker)); free(json); json = NULL;

    /* A third peer attached to the core's console must suppress BREAK entirely;
     * only the core's own Job is terminated, leaving the outsider untouched. */
    json = fixture_config("graceful", marker, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0 && wait_pid(marker));
    CHECK(sbw_core_poll(core, &status, &error) == 0 && status.process_running);
    sentinel = launch_sentinel(argv[1], status.process_id, sentinel_ready, sentinel_signal);
    CHECK(sentinel && wait_pid(sentinel_ready));
    CHECK(sbw_core_stop(core, &error) == 0);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && status.last_stop_forced);
    CHECK(parent_breaks == 0 && WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT &&
        GetFileAttributesW(sentinel_signal) == INVALID_FILE_ATTRIBUTES);
    CHECK(TerminateProcess(sentinel, 99) && WaitForSingleObject(sentinel, 2000) == WAIT_OBJECT_0);
    CloseHandle(sentinel); sentinel = NULL;
    CHECK(DeleteFileW(marker) && DeleteFileW(sentinel_ready)); free(json); json = NULL;
    CHECK(sbw_core_config_check(core, "[]", 2, NULL, NULL, &error) != 0 && !strcmp(error.code, "CORE_CONFIG_INVALID"));
    CHECK(sbw_core_config_check(core, "{", 1, NULL, NULL, &error) != 0 && !strcmp(error.code, "CORE_CONFIG_INVALID"));
    json = fixture_config("check_fail", NULL, NULL);
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, &exit_code, &error) != 0 &&
          !strcmp(error.code, "CORE_CHECK_FAILED") && exit_code == 17);
    CHECK(!strstr(error.message, "FIXTURE_SECRET"));
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) != 0 && !strcmp(error.code, "CORE_CHECK_FAILED"));
    CHECK(sbw_core_poll(core, &status, &error) == 0 && !status.process_running);
    free(json); json = fixture_config("check_timeout", NULL, NULL);
    ULONGLONG before = GetTickCount64();
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, &exit_code, &error) != 0 &&
          !strcmp(error.code, "CORE_CHECK_TIMEOUT") && exit_code == MAXDWORD);
    CHECK(GetTickCount64() - before < 4000 && config_count(directory, NULL) == 0);
    cancel = CreateEventW(NULL, TRUE, TRUE, NULL);
    CHECK(cancel);
    CHECK(sbw_core_config_check(core, "{}", 2, cancel, NULL, &error) != 0 && !strcmp(error.code, "CORE_CANCELLED"));
    CHECK(config_count(directory, NULL) == 0);
    CHECK(ResetEvent(cancel));
    context.core = core; context.cancel = cancel;
    checker = CreateThread(NULL, 0, blocking_check, &context, 0, NULL);
    CHECK(checker);
    before = GetTickCount64();
    while (!config_count(directory, NULL) && GetTickCount64() - before < 600) Sleep(5);
    CHECK(config_count(directory, NULL) == 1);
    CHECK(sbw_core_poll(core, &status, &error) != 0 && !strcmp(error.code, "CORE_BUSY"));
    CHECK(sbw_core_stop(core, &error) != 0 && !strcmp(error.code, "CORE_BUSY"));
    CHECK(SetEvent(cancel));
    CHECK(WaitForSingleObject(checker, 4000) == WAIT_OBJECT_0);
    CloseHandle(checker); checker = NULL;
    CHECK(context.result != 0 && !strcmp(context.error.code, "CORE_CANCELLED"));
    CHECK(config_count(directory, NULL) == 0);

    SECURITY_ATTRIBUTES inheritable = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    leaked = CreateEventW(&inheritable, TRUE, FALSE, NULL);
    CHECK(leaked);
    free(json); json = fixture_config("noisy", NULL, leaked);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && status.process_running && !status.has_exit_code);
    primary = OpenProcess(SYNCHRONIZE, FALSE, status.process_id);
    CHECK(primary);
    bool denied = false;
    CHECK(config_count(directory, &denied) == 1 && denied);
    Sleep(100);
    CHECK(WaitForSingleObject(leaked, 0) == WAIT_TIMEOUT);
    CHECK(sbw_core_start(core, "{}", 2, NULL, &error) != 0 && !strcmp(error.code, "CORE_ALREADY_RUNNING"));
    CHECK(sbw_core_stop(core, &error) == 0 && WaitForSingleObject(primary, 0) == WAIT_OBJECT_0);
    CloseHandle(primary); primary = NULL;
    CHECK(config_count(directory, NULL) == 0);
    CHECK(sbw_core_poll(core, &status, &error) == 0 && !status.process_running);

    free(json); json = fixture_config("crash", NULL, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0);
    CHECK(await_exit(core, &status, &error) && status.has_exit_code && status.exit_code == 23);
    CHECK(config_count(directory, NULL) == 0);

    free(json); json = fixture_config("spawn_child", marker, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0);
    DWORD child_pid = wait_pid(marker);
    CHECK(child_pid);
    child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK(child && WaitForSingleObject(child, 0) == WAIT_TIMEOUT);
    CHECK(sbw_core_stop(core, &error) == 0 && WaitForSingleObject(child, 2000) == WAIT_OBJECT_0);
    CloseHandle(child); child = NULL;
    CHECK(DeleteFileW(marker));
    CHECK(config_count(directory, NULL) == 0);

    free(json); json = fixture_config("spawn_child_crash", marker, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0);
    child_pid = wait_pid(marker);
    CHECK(child_pid);
    child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK(child);
    CHECK(await_exit(core, &status, &error) && status.exit_code == 23);
    CHECK(WaitForSingleObject(child, 2000) == WAIT_OBJECT_0);
    CloseHandle(child); child = NULL;
    CHECK(DeleteFileW(marker));
    CHECK(config_count(directory, NULL) == 0);

    free(json); json = fixture_config("check_child", marker, NULL);
    CHECK(sbw_core_config_check(core, json, strlen(json), NULL, NULL, &error) == 0);
    child_pid = wait_pid(marker);
    CHECK(child_pid);
    child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK(!child || WaitForSingleObject(child, 2000) == WAIT_OBJECT_0);
    if (child) { CloseHandle(child); child = NULL; }
    CHECK(DeleteFileW(marker));

    free(json); json = fixture_config("spawn_child", marker, NULL);
    CHECK(sbw_core_start(core, json, strlen(json), NULL, &error) == 0);
    child_pid = wait_pid(marker);
    CHECK(child_pid);
    child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK(child);
    sbw_core_free(core); core = NULL;
    CHECK(WaitForSingleObject(child, 2000) == WAIT_OBJECT_0 && config_count(directory, NULL) == 0);
    CloseHandle(child); child = NULL;
    CHECK(DeleteFileW(marker));

    owner = launch_owner(argv[1], crash_directory, marker, ready);
    CHECK(owner);
    DWORD primary_pid = wait_pid(ready);
    child_pid = wait_pid(marker);
    CHECK(primary_pid && child_pid);
    primary = OpenProcess(SYNCHRONIZE, FALSE, primary_pid);
    child = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
    CHECK(primary && child && WaitForSingleObject(child, 0) == WAIT_TIMEOUT);
    CHECK(TerminateProcess(owner, 99) && WaitForSingleObject(owner, 2000) == WAIT_OBJECT_0);
    CloseHandle(owner); owner = NULL;
    CHECK(WaitForSingleObject(primary, 2000) == WAIT_OBJECT_0 && WaitForSingleObject(child, 2000) == WAIT_OBJECT_0);
    CloseHandle(primary); primary = NULL;
    CloseHandle(child); child = NULL;
    CHECK(config_count(crash_directory, NULL) == 1);
    CHECK(write_pid(keep, 123));
    options.work_directory = crash_directory;
    core = sbw_core_new(&options, &error);
    CHECK(core && config_count(crash_directory, NULL) == 0 && read_pid(keep) == 123);
    sbw_core_free(core); core = NULL;
    CHECK(CreateDirectoryW(unsafe, NULL));
    core = sbw_core_new(&options, &error);
    CHECK(!core && !strcmp(error.code, "CORE_STORAGE_ERROR"));
    CHECK(GetFileAttributesW(unsafe) & FILE_ATTRIBUTE_DIRECTORY);
    CHECK(RemoveDirectoryW(unsafe));
    result = 0;
    puts("core_process_test: passed (dummy processes only; no networking or TUN)");
done:
    if (checker) {
        if (cancel) SetEvent(cancel);
        if (WaitForSingleObject(checker, 5000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(checker);
    }
    sbw_core_free(core);
    sbw_core_free(duplicate);
    if (owner) { TerminateProcess(owner, 99); (void)WaitForSingleObject(owner, 2000); CloseHandle(owner); }
    if (sentinel) { TerminateProcess(sentinel, 99); (void)WaitForSingleObject(sentinel, 2000); CloseHandle(sentinel); }
    if (primary) CloseHandle(primary);
    if (child) CloseHandle(child);
    if (leaked) CloseHandle(leaked);
    if (cancel) CloseHandle(cancel);
    free(json);
    /* Exact known paths inside our freshly created random temporary directory;
     * no recursive deletion or traversing user-owned directory contents. */
    if (marker) DeleteFileW(marker);
    if (ready) DeleteFileW(ready);
    if (keep) DeleteFileW(keep);
    if (crash_lock) DeleteFileW(crash_lock);
    if (unsafe) RemoveDirectoryW(unsafe);
    if (sentinel_ready) DeleteFileW(sentinel_ready);
    if (sentinel_signal) DeleteFileW(sentinel_signal);
    if (crash_directory) RemoveDirectoryW(crash_directory);
    if (lock) DeleteFileW(lock);
    if (directory) RemoveDirectoryW(directory);
    if (root) RemoveDirectoryW(root);
    free(lock); free(missing); free(marker); free(directory); free(root);
    free(crash_directory); free(crash_lock); free(ready); free(keep); free(unsafe);
    free(sentinel_ready); free(sentinel_signal);
    return result;
}
