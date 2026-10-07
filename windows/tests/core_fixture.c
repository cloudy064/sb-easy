#include "../common.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static HANDLE break_event;
static bool ignore_break;
static BOOL WINAPI control_event(DWORD event) {
    if (event != CTRL_BREAK_EVENT) return FALSE;
    if (!ignore_break) SetEvent(break_event);
    return TRUE;
}

static int number_file(const char *name, DWORD value, bool increment) {
    wchar_t *path = sbw_wide(name, NULL);
    HANDLE file = path ? CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL) : INVALID_HANDLE_VALUE;
    free(path);
    if (file == INVALID_HANDLE_VALUE) return 75;
    char text[32] = {0}; DWORD count = 0;
    if (increment && ReadFile(file, text, sizeof(text) - 1, &count, NULL)) value = strtoul(text, NULL, 10) + 1;
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    int size = sprintf_s(text, sizeof(text), "%lu", value);
    bool ok = size > 0 && WriteFile(file, text, (DWORD)size, &count, NULL) &&
        count == (DWORD)size && SetEndOfFile(file) && FlushFileBuffers(file);
    CloseHandle(file); return ok ? 0 : 76;
}

static sbj *read_config(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    DWORD size = GetFileSize(file, NULL), read = 0;
    if (size == INVALID_FILE_SIZE || size > 8 * 1024 * 1024) { CloseHandle(file); return NULL; }
    char *text = sb_xcalloc((size_t)size + 1, 1);
    bool ok = ReadFile(file, text, size, &read, NULL) && read == size;
    CloseHandle(file);
    sbj *value = ok ? sbw_json_parse(text, size, 32, NULL) : NULL;
    sbw_secret_free(text);
    return value;
}

static int spawn_child(const char *marker) {
    wchar_t executable[32768];
    DWORD size = GetModuleFileNameW(NULL, executable, (DWORD)(sizeof(executable) / sizeof(*executable)));
    if (!size || size >= sizeof(executable) / sizeof(*executable)) return 61;
    size_t capacity = wcslen(executable) + 32;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --child", executable) < 0) { free(command); return 62; }
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    bool started = CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                   NULL, NULL, &startup, &process) != FALSE;
    free(command);
    if (!started) return 63;
    wchar_t *path = sbw_wide(marker, NULL);
    HANDLE file = path ? CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                                     FILE_ATTRIBUTE_NORMAL, NULL) : INVALID_HANDLE_VALUE;
    free(path);
    char pid[32];
    int length = sprintf_s(pid, sizeof(pid), "%lu", process.dwProcessId);
    DWORD written = 0;
    bool saved = file != INVALID_HANDLE_VALUE && length > 0 &&
        WriteFile(file, pid, (DWORD)length, &written, NULL) && written == (DWORD)length && FlushFileBuffers(file);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return saved ? 0 : 64;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 5 && !wcscmp(argv[1], L"--sentinel")) {
        DWORD target = wcstoul(argv[2], NULL, 10);
        if (target) { FreeConsole(); if (!AttachConsole(target)) return 81; }
        break_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!break_event || !SetConsoleCtrlHandler(control_event, TRUE)) return 82;
        char *ready = sbw_utf8(argv[3], NULL), *signaled = sbw_utf8(argv[4], NULL);
        if (!ready || !signaled || number_file(ready, GetCurrentProcessId(), false)) return 83;
        free(ready);
        WaitForSingleObject(break_event, INFINITE);
        int result = number_file(signaled, 1, false);
        free(signaled);
        if (result) return result;
        Sleep(INFINITE);
        return 0;
    }
    BOOL in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job) return 70;
    if (argc == 2 && !wcscmp(argv[1], L"--child")) { Sleep(INFINITE); return 0; }
    if (argc != 5 || (wcscmp(argv[1], L"check") && wcscmp(argv[1], L"run")) ||
        wcscmp(argv[2], L"-c") || wcscmp(argv[4], L"--disable-color")) return 71;
    sbj *config = read_config(argv[3]);
    if (!sbj_is_object(config)) { sbj_free(config); return 72; }
    const char *mode = sbj_get_str(config, "mode", "run");
    uintptr_t leak = (uintptr_t)sbj_get_int(config, "leak_handle", 0);
    if (leak) (void)SetEvent((HANDLE)leak);
    if (!wcscmp(argv[1], L"check")) {
        if (!strcmp(mode, "count_checks")) {
            int counted = number_file(sbj_get_str(config, "child_pid_file", ""), 0, true);
            if (counted) { sbj_free(config); return counted; }
        }
        if (!strcmp(mode, "check_fail")) {
            fputs("FIXTURE_SECRET_NEVER_RETURN_THIS\n", stderr);
            sbj_free(config);
            return 17;
        }
        if (!strcmp(mode, "check_timeout")) { sbj_free(config); Sleep(INFINITE); return 0; }
        if (!strcmp(mode, "check_child")) {
            int result = spawn_child(sbj_get_str(config, "child_pid_file", ""));
            sbj_free(config);
            return result;
        }
        sbj_free(config);
        return 0;
    }
    if (!strcmp(mode, "graceful") || !strcmp(mode, "ignore_break")) {
        break_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        ignore_break = !strcmp(mode, "ignore_break");
        if (!break_event || !SetConsoleCtrlHandler(control_event, TRUE)) { sbj_free(config); return 77; }
        int ready = number_file(sbj_get_str(config, "child_pid_file", ""), GetCurrentProcessId(), false);
        sbj_free(config);
        if (ready) return ready;
        WaitForSingleObject(break_event, INFINITE);
        CloseHandle(break_event);
        return 42; /* Only our handler path, never default console termination. */
    }
    if (!strcmp(mode, "noisy")) {
        char noise[4096];
        memset(noise, 'x', sizeof(noise));
        for (size_t i = 0; i < 256; ++i) {
            DWORD written = 0;
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), noise, sizeof(noise), &written, NULL)) return 73;
        }
    }
    bool crash = !strcmp(mode, "crash") || !strcmp(mode, "spawn_child_crash");
    if (!strcmp(mode, "spawn_child") || !strcmp(mode, "spawn_child_crash")) {
        int result = spawn_child(sbj_get_str(config, "child_pid_file", ""));
        if (result) { sbj_free(config); return result; }
    }
    sbj_free(config);
    if (crash) { Sleep(200); return 23; }
    Sleep(INFINITE);
    return 0;
}
