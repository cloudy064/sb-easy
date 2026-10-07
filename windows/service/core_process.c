#include "core_process.h"
#include "secure_store.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct private_config {
    wchar_t *path;
    HANDLE reader;
} private_config;

typedef struct child_process {
    HANDLE job;
    HANDLE process;
    DWORD id;
    bool private_console;
} child_process;

struct sbw_core {
    SRWLOCK mutex;
    wchar_t *executable;
    wchar_t *directory;
    HANDLE executable_file;
    HANDLE *executable_parents;
    size_t parent_count;
    sbw_store *directory_guard;
    DWORD check_timeout_ms;
    DWORD stop_timeout_ms;
    child_process child;
    private_config config;
    bool has_exit_code;
    DWORD exit_code;
    bool last_stop_forced;
    char *checked_json;
    size_t checked_length;
};

static int core_fail(sbw_error *error, const char *code) {
    const char *message = "The sing-box process operation failed.";
    if (!strcmp(code, "CORE_UNAVAILABLE")) message = "The configured sing-box executable is unavailable.";
    else if (!strcmp(code, "CORE_INVALID_PATH")) message = "Core locations must be fixed absolute local paths without reparse points.";
    else if (!strcmp(code, "CORE_BUSY")) message = "Another core operation is in progress.";
    else if (!strcmp(code, "CORE_CHECK_FAILED")) message = "sing-box rejected the candidate configuration.";
    else if (!strcmp(code, "CORE_CHECK_TIMEOUT")) message = "sing-box configuration validation exceeded its deadline.";
    else if (!strcmp(code, "CORE_CANCELLED")) message = "The core operation was cancelled.";
    else if (!strcmp(code, "CORE_STOP_TIMEOUT")) message = "The core process tree did not stop within its deadline.";
    else if (!strcmp(code, "CORE_ALREADY_RUNNING")) message = "Stop the current core before starting another configuration.";
    else if (!strcmp(code, "CORE_CONFIG_INVALID")) message = "The candidate configuration is not a supported JSON object.";
    else if (!strcmp(code, "CORE_STORAGE_ERROR")) message = "The private core configuration file could not be safely managed.";
    else if (!strcmp(code, "CORE_ELEVATION_REQUIRED")) message = "TUN requires the service to run with an elevated administrator token.";
    return sbw_fail(error, code, message);
}

static bool cancelled(HANDLE event) {
    return event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
}

static wchar_t *absolute_path(const wchar_t *input, sbw_error *error) {
    if (!input || wcslen(input) < 4 || input[1] != L':' || (input[2] != L'\\' && input[2] != L'/') ||
        !((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z')) ||
        wcschr(input, L'"') || wcschr(input + 2, L':')) {
        core_fail(error, "CORE_INVALID_PATH");
        return NULL;
    }
    DWORD size = GetFullPathNameW(input, 0, NULL, NULL);
    if (!size || size > 32760) { core_fail(error, "CORE_INVALID_PATH"); return NULL; }
    wchar_t *path = sb_xcalloc((size_t)size + 1, sizeof(*path));
    DWORD written = GetFullPathNameW(input, size + 1, path, NULL);
    if (!written || written > size) { free(path); core_fail(error, "CORE_INVALID_PATH"); return NULL; }
    for (wchar_t *p = path; *p; ++p) if (*p == L'/') *p = L'\\';
    size_t length = wcslen(path);
    while (length > 3 && path[length - 1] == L'\\') path[--length] = L'\0';
    wchar_t root[] = {path[0], L':', L'\\', L'\0'};
    if (length < 4 || GetDriveTypeW(root) != DRIVE_FIXED) {
        free(path); core_fail(error, "CORE_INVALID_PATH"); return NULL;
    }
    return path;
}

static int require_regular(HANDLE handle, bool directory, sbw_error *error) {
    FILE_ATTRIBUTE_TAG_INFO attributes = {0};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)))
        return core_fail(error, "CORE_UNAVAILABLE");
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)
        return core_fail(error, "CORE_INVALID_PATH");
    return 0;
}

static int pin_executable(sbw_core *core, sbw_error *error) {
    size_t length = wcslen(core->executable);
    if (length < 4 || CompareStringOrdinal(core->executable + length - 4, 4, L".exe", 4, TRUE) != CSTR_EQUAL)
        return core_fail(error, "CORE_INVALID_PATH");
    wchar_t *prefix = sb_xmalloc((length + 1) * sizeof(*prefix));
    memcpy(prefix, core->executable, (length + 1) * sizeof(*prefix));
    core->executable_parents = sb_xcalloc(length + 1, sizeof(*core->executable_parents));
    for (size_t i = 3; i < length; ++i) {
        if (prefix[i] != L'\\') continue;
        prefix[i] = L'\0';
        HANDLE directory = CreateFileW(prefix, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        prefix[i] = L'\\';
        if (directory == INVALID_HANDLE_VALUE) { free(prefix); return core_fail(error, "CORE_UNAVAILABLE"); }
        if (require_regular(directory, true, error) != 0) { CloseHandle(directory); free(prefix); return -1; }
        core->executable_parents[core->parent_count++] = directory;
    }
    free(prefix);
    core->executable_file = CreateFileW(core->executable, GENERIC_READ | FILE_EXECUTE, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (core->executable_file == INVALID_HANDLE_VALUE) return core_fail(error, "CORE_UNAVAILABLE");
    return require_regular(core->executable_file, false, error);
}

static bool owned_config_name(const wchar_t *name) {
    if (wcslen(name) != 42 || wcsncmp(name, L"core-", 5) || wcscmp(name + 37, L".json")) return false;
    for (size_t i = 5; i < 37; ++i)
        if (!((name[i] >= L'0' && name[i] <= L'9') || (name[i] >= L'a' && name[i] <= L'f'))) return false;
    return true;
}

static int remove_stale_configs(sbw_core *core, sbw_error *error) {
    HANDLE token = NULL;
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return core_fail(error, "CORE_STORAGE_ERROR");
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = size ? sb_xmalloc(size) : NULL;
    bool token_ok = user && GetTokenInformation(token, TokenUser, user, size, &size);
    CloseHandle(token);
    if (!token_ok) { free(user); return core_fail(error, "CORE_STORAGE_ERROR"); }
    wchar_t *pattern = sbw_path_join(core->directory, L"core-*.json");
    WIN32_FIND_DATAW data = {0};
    HANDLE search = FindFirstFileW(pattern, &data);
    free(pattern);
    int result = 0;
    if (search == INVALID_HANDLE_VALUE) {
        bool absent = GetLastError() == ERROR_FILE_NOT_FOUND;
        free(user);
        return absent ? 0 : core_fail(error, "CORE_STORAGE_ERROR");
    }
    do {
        if (!owned_config_name(data.cFileName)) continue;
        wchar_t *path = sbw_path_join(core->directory, data.cFileName);
        HANDLE file = CreateFileW(path, DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
        free(path);
        if (file == INVALID_HANDLE_VALUE) { result = -1; break; }
        PSID owner = NULL;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        bool trusted = require_regular(file, false, NULL) == 0 &&
            GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL,
                            &descriptor) == ERROR_SUCCESS && sbw_trusted_storage_owner(owner, user->User.Sid);
        FILE_DISPOSITION_INFO disposition = {TRUE};
        if (!trusted || !SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition))) result = -1;
        LocalFree(descriptor);
        CloseHandle(file);
        if (result != 0) break;
    } while (FindNextFileW(search, &data));
    if (result == 0 && GetLastError() != ERROR_NO_MORE_FILES) result = -1;
    FindClose(search);
    free(user);
    return result == 0 ? 0 : core_fail(error, "CORE_STORAGE_ERROR");
}

static int remove_config(private_config *config, sbw_error *error) {
    if (config->reader && config->reader != INVALID_HANDLE_VALUE) CloseHandle(config->reader);
    config->reader = NULL;
    if (!config->path) return 0;
    bool removed = DeleteFileW(config->path) != FALSE || GetLastError() == ERROR_FILE_NOT_FOUND;
    free(config->path);
    config->path = NULL;
    return removed ? 0 : core_fail(error, "CORE_STORAGE_ERROR");
}

static int prepare_config(sbw_core *core, const char *json, size_t length, private_config *config, sbw_error *error) {
    if (!json || !length || length > 8U * 1024U * 1024U) return core_fail(error, "CORE_CONFIG_INVALID");
    sbj *parsed = sbw_json_parse(json, length, 32, error);
    bool valid = sbj_is_object(parsed);
    sbj_free(parsed);
    if (!valid) return core_fail(error, "CORE_CONFIG_INVALID");
    BYTE random[16] = {0};
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return core_fail(error, "CORE_STORAGE_ERROR");
    wchar_t name[48] = L"core-";
    const wchar_t hex[] = L"0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) {
        name[5 + 2 * i] = hex[random[i] >> 4];
        name[6 + 2 * i] = hex[random[i] & 15];
    }
    memcpy(name + 37, L".json", 6 * sizeof(wchar_t));
    config->path = sbw_path_join(core->directory, name);
    /* CREATE_NEW in the already-private, pinned directory inherits only the
     * System/Admin/service-user DACL. No existing path is ever truncated. */
    HANDLE writer = CreateFileW(config->path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    if (writer == INVALID_HANDLE_VALUE) {
        free(config->path); config->path = NULL;
        return core_fail(error, "CORE_STORAGE_ERROR");
    }
    DWORD written = 0;
    bool saved = WriteFile(writer, json, (DWORD)length, &written, NULL) && written == length && FlushFileBuffers(writer);
    CloseHandle(writer);
    if (!saved) { remove_config(config, NULL); return core_fail(error, "CORE_STORAGE_ERROR"); }
    config->reader = CreateFileW(config->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (config->reader == INVALID_HANDLE_VALUE || require_regular(config->reader, false, error) != 0) {
        remove_config(config, NULL);
        return core_fail(error, "CORE_STORAGE_ERROR");
    }
    return 0;
}

static DWORD remaining(ULONGLONG deadline) {
    ULONGLONG now = GetTickCount64();
    return now >= deadline ? 0 : (DWORD)(deadline - now);
}

static HANDLE inherited_handle(const wchar_t *text) {
    if (!text || !*text) return NULL;
    for (const wchar_t *p = text; *p; ++p) if (*p < L'0' || *p > L'9') return NULL;
    errno = 0;
    unsigned long long value = wcstoull(text, NULL, 10);
    if (errno || !value || value >= UINTPTR_MAX) return NULL;
    HANDLE handle = (HANDLE)(uintptr_t)value;
    DWORD flags = 0;
    return GetHandleInformation(handle, &flags) && (flags & HANDLE_FLAG_INHERIT) ? handle : NULL;
}

static BOOL WINAPI helper_control(DWORD event) { return event == CTRL_BREAK_EVENT; }

int sbw_core_signal_helper(int argc, wchar_t **argv) {
    if (argc < 2 || wcscmp(argv[1], L"--internal-core-break")) return -1;
    if (argc != 3) return 90;
    HANDLE process = inherited_handle(argv[2]);
    DWORD pid = process ? GetProcessId(process) : 0;
    BOOL owned = FALSE;
    if (!pid || pid == GetCurrentProcessId() ||
        !IsProcessInJob(process, NULL, &owned) || !owned ||
        WaitForSingleObject(process, 0) != WAIT_TIMEOUT) return 91;
    /* Only this short-lived helper changes its console association. The service
     * keeps its original console and handlers on every path. */
    FreeConsole();
    if (!AttachConsole(pid)) return 92;
    DWORD members[64];
    DWORD count = GetConsoleProcessList(members, 64);
    bool safe = count == 2;
    for (DWORD i = 0; safe && i < count; ++i) {
        if (members[i] == GetCurrentProcessId()) continue;
        /* The supported core does not create console children. Refuse a console
         * with any extra peer instead of signaling an unverified participant. */
        safe = members[i] == pid;
    }
    /* CREATE_NEW_CONSOLE ignores CREATE_NEW_PROCESS_GROUP, so a PID-targeted
     * event is invalid. Group 0 is safe only in this privately created console
     * after verifying the sole peers are the pinned target and this helper.
     * Neither the caller's console nor any third-party peer is signaled. */
    bool sent = safe && SetConsoleCtrlHandler(helper_control, TRUE) &&
        WaitForSingleObject(process, 0) == WAIT_TIMEOUT && GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
    /* Keep our handler registered until process exit. FreeConsole resets the
     * handler table and can race delivery of our own asynchronous BREAK. */
    return sent ? 0 : 93;
}

static bool request_graceful_stop(child_process *child, DWORD timeout) {
    wchar_t executable[32768];
    DWORD size = GetModuleFileNameW(NULL, executable, 32768);
    if (!size || size >= 32768 || !timeout) return false;
    HANDLE target = NULL;
    HANDLE current = GetCurrentProcess();
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION process = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    SIZE_T bytes = 0;
    bool initialized = false, result = false;
    wchar_t *command = NULL;
    if (!DuplicateHandle(current, child->process, current, &target,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)) goto done;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    if (!bytes) goto done;
    attributes = sb_xmalloc(bytes);
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) goto done;
    initialized = true;
    HANDLE allowed[] = {target};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   allowed, sizeof(allowed), NULL, NULL)) goto done;
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.lpAttributeList = attributes;
    size_t capacity = wcslen(executable) + 100;
    command = sb_xcalloc(capacity, sizeof(*command));
    if (_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --internal-core-break %llu",
        executable, (unsigned long long)(uintptr_t)target) < 0) goto done;
    if (!CreateProcessW(executable, command, NULL, NULL, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &startup.StartupInfo, &process)) goto done;
    if (!AssignProcessToJobObject(child->job, process.hProcess) || ResumeThread(process.hThread) == (DWORD)-1) goto done;
    if (WaitForSingleObject(process.hProcess, timeout) == WAIT_OBJECT_0) {
        DWORD code = MAXDWORD;
        result = GetExitCodeProcess(process.hProcess, &code) && code == 0;
    }
done:
    if (process.hProcess) {
        if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        CloseHandle(process.hProcess);
    }
    if (process.hThread) CloseHandle(process.hThread);
    if (initialized) DeleteProcThreadAttributeList(attributes);
    free(attributes); free(command);
    if (target) CloseHandle(target);
    return result;
}

static int dispose_child(child_process *child, DWORD timeout, sbw_error *error) {
    bool completed = true;
    ULONGLONG deadline = GetTickCount64() + timeout;
    if (child->job) {
        if (!TerminateJobObject(child->job, ERROR_PROCESS_ABORTED)) completed = false;
        for (;;) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};
            if (!QueryInformationJobObject(child->job, JobObjectBasicAccountingInformation,
                                           &accounting, sizeof(accounting), NULL)) { completed = false; break; }
            if (!accounting.ActiveProcesses) break;
            DWORD left = remaining(deadline);
            if (!left) { completed = false; break; }
            Sleep(left > 10 ? 10 : left);
        }
        /* The kill-on-close limit still applies even if an earlier query or
         * explicit termination failed. Never leave the job handle inherited. */
        CloseHandle(child->job);
        child->job = NULL;
    }
    if (child->process) {
        if (WaitForSingleObject(child->process, remaining(deadline)) != WAIT_OBJECT_0) completed = false;
        CloseHandle(child->process);
        child->process = NULL;
    }
    child->id = 0;
    return completed ? 0 : core_fail(error, "CORE_STOP_TIMEOUT");
}

static int stop_child(sbw_core *core, sbw_error *error) {
    ULONGLONG deadline = GetTickCount64() + core->stop_timeout_ms;
    core->last_stop_forced = false;
    if (core->child.process && WaitForSingleObject(core->child.process, 0) == WAIT_TIMEOUT) {
        DWORD grace = core->stop_timeout_ms * 3 / 4;
        ULONGLONG grace_deadline = GetTickCount64() + grace;
        if (core->child.private_console && request_graceful_stop(&core->child, grace))
            (void)WaitForSingleObject(core->child.process, remaining(grace_deadline));
        core->last_stop_forced = WaitForSingleObject(core->child.process, 0) != WAIT_OBJECT_0;
    }
    return dispose_child(&core->child, remaining(deadline), error);
}

static int launch(sbw_core *core, const wchar_t *verb, const private_config *config,
                   child_process *child, sbw_error *error) {
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION process = {0};
    SECURITY_ATTRIBUTES inheritable = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE input = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    wchar_t *command = NULL;
    SIZE_T attribute_bytes = 0;
    bool attributes_initialized = false;
    int result = -1;
    child->job = CreateJobObjectW(NULL, NULL);
    if (!child->job) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(child->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto done;
    input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, 0, NULL);
    output = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, 0, NULL);
    if (input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE) goto done;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_bytes);
    if (!attribute_bytes) goto done;
    attributes = sb_xmalloc(attribute_bytes);
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_bytes)) goto done;
    attributes_initialized = true;
    HANDLE allowed[] = {input, output};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, allowed, sizeof(allowed), NULL, NULL)) goto done;
    startup.StartupInfo.cb = sizeof(startup);
    bool running = !wcscmp(verb, L"run");
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = output;
    startup.lpAttributeList = attributes;
    size_t command_length = wcslen(core->executable) + wcslen(config->path) + wcslen(verb) + 32;
    command = sb_xcalloc(command_length, sizeof(*command));
    if (_snwprintf_s(command, command_length, _TRUNCATE, L"\"%ls\" %ls -c \"%ls\" --disable-color",
                    core->executable, verb, config->path) < 0) goto done;
    if (!CreateProcessW(core->executable, command, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | (running ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW) | EXTENDED_STARTUPINFO_PRESENT,
                        NULL, core->directory, &startup.StartupInfo, &process)) goto done;
    if (!AssignProcessToJobObject(child->job, process.hProcess)) {
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        (void)WaitForSingleObject(process.hProcess, core->stop_timeout_ms);
        goto done;
    }
    child->process = process.hProcess;
    child->id = process.dwProcessId;
    child->private_console = running;
    process.hProcess = NULL;
    if (ResumeThread(process.hThread) == (DWORD)-1) goto done;
    result = 0;
done:
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (attributes_initialized) DeleteProcThreadAttributeList(attributes);
    free(attributes);
    free(command);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    if (result != 0) { dispose_child(child, core->stop_timeout_ms, NULL); return core_fail(error, "CORE_START_FAILED"); }
    return 0;
}

static int check_file(sbw_core *core, const private_config *config, HANDLE cancel, DWORD *exit_code, sbw_error *error) {
    child_process check = {0};
    if (exit_code) *exit_code = MAXDWORD;
    if (cancelled(cancel)) return core_fail(error, "CORE_CANCELLED");
    if (launch(core, L"check", config, &check, error) != 0) return -1;
    HANDLE events[] = {cancel, check.process};
    DWORD waited = cancel ? WaitForMultipleObjects(2, events, FALSE, core->check_timeout_ms)
                         : WaitForSingleObject(check.process, core->check_timeout_ms);
    bool exited = waited == (cancel ? WAIT_OBJECT_0 + 1 : WAIT_OBJECT_0);
    DWORD code = MAXDWORD;
    if (exited && !GetExitCodeProcess(check.process, &code)) exited = false;
    if (exited && exit_code) *exit_code = code;
    int result = exited && code == 0 ? 0 :
        core_fail(error, waited == WAIT_TIMEOUT ? "CORE_CHECK_TIMEOUT" :
            cancel && waited == WAIT_OBJECT_0 ? "CORE_CANCELLED" : "CORE_CHECK_FAILED");
    sbw_error cleanup = {0};
    if (dispose_child(&check, core->stop_timeout_ms, &cleanup) != 0 && result == 0)
        result = core_fail(error, "CORE_STOP_TIMEOUT");
    return result;
}

static int reap(sbw_core *core, sbw_error *error) {
    if (!core->child.process || WaitForSingleObject(core->child.process, 0) == WAIT_TIMEOUT) return 0;
    DWORD code = 0;
    if (GetExitCodeProcess(core->child.process, &code)) { core->has_exit_code = true; core->exit_code = code; }
    int result = dispose_child(&core->child, core->stop_timeout_ms, error);
    if (remove_config(&core->config, result == 0 ? error : NULL) != 0 && result == 0) result = -1;
    return result;
}

sbw_core *sbw_core_new(const sbw_core_options *options, sbw_error *error) {
    if (!options || options->check_timeout_ms > 60000 || options->stop_timeout_ms > 10000) {
        core_fail(error, "CORE_INVALID_PATH"); return NULL;
    }
    sbw_core *core = sb_xcalloc(1, sizeof(*core));
    InitializeSRWLock(&core->mutex);
    core->check_timeout_ms = options->check_timeout_ms ? options->check_timeout_ms : 15000;
    core->stop_timeout_ms = options->stop_timeout_ms ? options->stop_timeout_ms : 2000;
    core->executable = absolute_path(options->executable, error);
    core->directory = absolute_path(options->work_directory, error);
    if (!core->executable || !core->directory || pin_executable(core, error) != 0) goto failed;
    core->directory_guard = sbw_secure_store_new(core->directory, error);
    if (!core->directory_guard) goto failed;
    /* Go opens -c without FILE_SHARE_DELETE, so a DELETE_ON_CLOSE handle would
     * prevent sing-box reading it. After a hard service termination, remove
     * only our exact filenames, only after the private directory is pinned and
     * exclusively locked, and only through validated regular-file handles. */
    if (remove_stale_configs(core, error) != 0) goto failed;
    return core;
failed:
    sbw_core_free(core);
    return NULL;
}

int sbw_core_preflight(sbw_core *core, bool has_tun, sbw_error *error) {
    if (!core) return core_fail(error, "CORE_UNAVAILABLE");
    if (!TryAcquireSRWLockExclusive(&core->mutex)) return core_fail(error, "CORE_BUSY");
    int result = require_regular(core->executable_file, false, error);
    if (result == 0 && has_tun) {
        HANDLE token = NULL;
        DWORD bytes = 0;
        TOKEN_ELEVATION elevation = {0};
        BYTE admin[SECURITY_MAX_SID_SIZE];
        DWORD admin_size = sizeof(admin);
        bool allowed = false;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
            GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated &&
            CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin, &admin_size)) {
            (void)GetTokenInformation(token, TokenGroups, NULL, 0, &bytes);
            TOKEN_GROUPS *groups = bytes ? sb_xmalloc(bytes) : NULL;
            if (groups && GetTokenInformation(token, TokenGroups, groups, bytes, &bytes)) {
                for (DWORD i = 0; i < groups->GroupCount; ++i) {
                    DWORD flags = groups->Groups[i].Attributes;
                    if ((flags & SE_GROUP_ENABLED) && !(flags & SE_GROUP_USE_FOR_DENY_ONLY) &&
                        EqualSid(groups->Groups[i].Sid, admin)) { allowed = true; break; }
                }
            }
            free(groups);
        }
        if (token) CloseHandle(token);
        if (!allowed) result = core_fail(error, "CORE_ELEVATION_REQUIRED");
    }
    /* sing-box v1.13.12 -> sing-tun v0.8.9 embeds its signed Wintun DLL and
     * loads it from memory. A sibling wintun.dll is neither used nor required.
     * Loading/creating an adapter here would mutate the machine, so do not. */
    ReleaseSRWLockExclusive(&core->mutex);
    return result;
}

static void clear_checked(sbw_core *core) {
    if (core->checked_json) { SecureZeroMemory(core->checked_json, core->checked_length); free(core->checked_json); }
    core->checked_json = NULL; core->checked_length = 0;
}

int sbw_core_config_check(sbw_core *core, const char *json, size_t length, HANDLE cancel,
                          DWORD *exit_code, sbw_error *error) {
    if (exit_code) *exit_code = MAXDWORD;
    if (!core) return core_fail(error, "CORE_UNAVAILABLE");
    if (!TryAcquireSRWLockExclusive(&core->mutex)) return core_fail(error, "CORE_BUSY");
    clear_checked(core);
    private_config config = {0};
    int result = cancelled(cancel) ? core_fail(error, "CORE_CANCELLED") : prepare_config(core, json, length, &config, error);
    if (result == 0) result = check_file(core, &config, cancel, exit_code, error);
    if (remove_config(&config, result == 0 ? error : NULL) != 0 && result == 0) result = -1;
    if (result == 0) { core->checked_json = sb_strndup(json, length); core->checked_length = length; }
    ReleaseSRWLockExclusive(&core->mutex);
    return result;
}

int sbw_core_start(sbw_core *core, const char *json, size_t length, HANDLE cancel, sbw_error *error) {
    if (!core) return core_fail(error, "CORE_UNAVAILABLE");
    if (!TryAcquireSRWLockExclusive(&core->mutex)) return core_fail(error, "CORE_BUSY");
    bool checked = json && core->checked_json && length == core->checked_length &&
        memcmp(json, core->checked_json, length) == 0;
    clear_checked(core);
    private_config config = {0};
    int result = reap(core, error);
    if (result == 0 && core->child.process) result = core_fail(error, "CORE_ALREADY_RUNNING");
    if (result == 0 && cancelled(cancel)) result = core_fail(error, "CORE_CANCELLED");
    if (result == 0) result = prepare_config(core, json, length, &config, error);
    if (result == 0 && !checked) result = check_file(core, &config, cancel, NULL, error);
    if (result == 0 && cancelled(cancel)) result = core_fail(error, "CORE_CANCELLED");
    if (result == 0) result = launch(core, L"run", &config, &core->child, error);
    if (result == 0) {
        core->config = config;
        memset(&config, 0, sizeof(config));
        core->has_exit_code = false;
    }
    if (remove_config(&config, result == 0 ? error : NULL) != 0 && result == 0) result = -1;
    ReleaseSRWLockExclusive(&core->mutex);
    return result;
}

int sbw_core_stop(sbw_core *core, sbw_error *error) {
    if (!core) return 0;
    if (!TryAcquireSRWLockExclusive(&core->mutex)) return core_fail(error, "CORE_BUSY");
    int result = stop_child(core, error);
    if (remove_config(&core->config, result == 0 ? error : NULL) != 0 && result == 0) result = -1;
    ReleaseSRWLockExclusive(&core->mutex);
    return result;
}

int sbw_core_poll(sbw_core *core, sbw_core_status *status, sbw_error *error) {
    if (!core || !status) return core_fail(error, "CORE_UNAVAILABLE");
    if (!TryAcquireSRWLockExclusive(&core->mutex)) return core_fail(error, "CORE_BUSY");
    int result = reap(core, error);
    status->process_running = core->child.process != NULL;
    status->process_id = core->child.id;
    status->has_exit_code = core->has_exit_code;
    status->exit_code = core->exit_code;
    status->last_stop_forced = core->last_stop_forced;
    ReleaseSRWLockExclusive(&core->mutex);
    return result;
}

void sbw_core_free(sbw_core *core) {
    if (!core) return;
    stop_child(core, NULL);
    clear_checked(core);
    remove_config(&core->config, NULL);
    sbw_store_free(core->directory_guard);
    if (core->executable_file && core->executable_file != INVALID_HANDLE_VALUE) CloseHandle(core->executable_file);
    for (size_t i = core->parent_count; i > 0; --i) CloseHandle(core->executable_parents[i - 1]);
    free(core->executable_parents);
    free(core->executable);
    free(core->directory);
    free(core);
}
