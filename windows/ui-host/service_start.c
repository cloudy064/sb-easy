#include "service_start.h"
#include "server_identity.h"
#include <sddl.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

/* Probe without sending a frame or credentials. A busy pipe is already present;
 * the actual request still verifies its server before transmitting any data. */
static int probe(const sbw_service_start_options *options, sbw_error *error) {
    HANDLE pipe = CreateFileW(options->pipe_name,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe != INVALID_HANDLE_VALUE) {
        bool trusted = sbw_verified_pipe_server(pipe, options->binary);
        CloseHandle(pipe);
        return trusted ? 1 : sbw_fail(error, "UNTRUSTED_SERVICE", "本地后台身份校验失败，请检查桌面程序与后台是否来自同一安装目录。");
    }
    DWORD code = GetLastError();
    if (code == ERROR_PIPE_BUSY) return 1;
    if (code == ERROR_FILE_NOT_FOUND) return 0;
    return sbw_fail(error, "SERVICE_ACCESS_DENIED", "无法访问本地后台，请检查安装文件和当前账户的访问权限。");
}

static HANDLE startup_mutex(const wchar_t *pipe, sbw_error *error) {
    HANDLE token = NULL, mutex = NULL;
    TOKEN_USER *user = NULL;
    LPWSTR sid = NULL;
    DWORD size = 0;
    wchar_t name[256];
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const wchar_t *c = pipe; *c; ++c) { hash ^= (uint16_t)*c; hash *= UINT64_C(1099511628211); }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (!size || size > 65536) goto done;
    user = sb_xmalloc(size);
    if (!GetTokenInformation(token, TokenUser, user, size, &size) ||
        !ConvertSidToStringSidW(user->User.Sid, &sid)) goto done;
    if (swprintf_s(name, 256, L"Local\\sb-easy-start-%ls-%016llx", sid, (unsigned long long)hash) < 0) goto done;
    mutex = CreateMutexW(NULL, FALSE, name);
done:
    if (token) CloseHandle(token);
    if (sid) LocalFree(sid);
    free(user);
    if (!mutex) sbw_fail(error, "SERVICE_START_FAILED", "无法创建后台启动锁，请刷新重试。");
    return mutex;
}

/* Return 1 when SCM owns this installation, 0 when it is not installed, -1 on
 * error. Never fall back to a portable process alongside an installed service. */
static int start_installed(const sbw_service_start_options *options, sbw_error *error) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service = NULL;
    QUERY_SERVICE_CONFIGW *config = NULL;
    LPWSTR *argv = NULL;
    int argc = 0, result = -1;
    DWORD size = 0;
    SERVICE_STATUS_PROCESS status = {0};
    wchar_t expanded[32768];
    if (!manager) { sbw_fail(error, "SERVICE_ACCESS_DENIED", "无法读取 Windows 后台服务状态。"); goto done; }
    service = OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!service) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) result = 0;
        else sbw_fail(error, "SERVICE_ACCESS_DENIED", "无法读取已安装的 sb-easy 后台服务。");
        goto done;
    }
    QueryServiceConfigW(service, NULL, 0, &size);
    if (!size || size > 65536) goto invalid;
    config = sb_xmalloc(size);
    if (!QueryServiceConfigW(service, config, size, &size)) goto invalid;
    DWORD length = ExpandEnvironmentStringsW(config->lpBinaryPathName, expanded, 32768);
    if (!length || length > 32768) goto invalid;
    argv = CommandLineToArgvW(expanded, &argc);
    if (!argv || argc != 1 || !sbw_same_file(argv[0], options->binary)) goto invalid;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &size)) goto invalid;
    if (status.dwCurrentState == SERVICE_STOPPED) {
        CloseServiceHandle(service);
        service = OpenServiceW(manager, L"sb-easy", SERVICE_START);
        if (!service) {
            sbw_fail(error, "SERVICE_ELEVATION_REQUIRED", "已安装的后台已停止，当前账户没有启动权限。请以管理员身份运行 sb-easy 一次。");
            goto done;
        }
        if (!StartServiceW(service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            sbw_fail(error, "SERVICE_START_FAILED", "Windows 无法启动已安装的后台，请检查服务配置后重试。"); goto done;
        }
    } else if (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING) {
        sbw_fail(error, "SERVICE_START_FAILED", "Windows 后台正在停止或暂停，请稍后刷新。"); goto done;
    }
    result = 1; goto done;
invalid:
    sbw_fail(error, "SERVICE_INSTALL_MISMATCH", "已安装的后台与当前桌面程序不匹配，请从已安装目录运行 sb-easy。");
done:
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    if (argv) LocalFree(argv);
    free(config);
    return result;
}

static int launch_portable(const sbw_service_start_options *options, PROCESS_INFORMATION *process, sbw_error *error) {
    STARTUPINFOW startup = {0};
    size_t capacity = wcslen(options->binary) + wcslen(options->pipe_name) +
        (options->data_directory ? wcslen(options->data_directory) * 2 : 0) + 128;
    wchar_t *command = sb_xcalloc(capacity, sizeof(wchar_t));
    /* Windows file/pipe names cannot contain quotes. A data path ending in a
     * backslash needs doubling before the closing command-line quote. */
    const wchar_t *directory = options->data_directory;
    size_t trailing = 0, directory_length = directory ? wcslen(directory) : 0;
    while (trailing < directory_length && directory[directory_length - trailing - 1] == L'\\') ++trailing;
    wchar_t *tail = sb_xcalloc(trailing + 1, sizeof(wchar_t));
    for (size_t i = 0; i < trailing; ++i) tail[i] = L'\\';
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    int length = directory ? swprintf_s(command, capacity, L"\"%ls\" --console --pipe-name \"%ls\" --data-dir \"%ls%ls\"",
        options->binary, options->pipe_name, directory, tail) :
        swprintf_s(command, capacity, L"\"%ls\" --console --pipe-name \"%ls\"", options->binary, options->pipe_name);
    BOOL created = length >= 0 && CreateProcessW(options->binary, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &startup, process);
    free(command); free(tail);
    if (!created) return sbw_fail(error, "SERVICE_START_FAILED", "无法启动随附的后台，请检查安装文件是否完整或被安全软件阻止。");
    CloseHandle(process->hThread); process->hThread = NULL;
    return 0;
}

int sbw_service_ensure(const sbw_service_start_options *options, HANDLE cancel,
                       DWORD timeout_ms, DWORD *started_pid, sbw_error *error) {
    HANDLE mutex = NULL, pinned = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION process = {0};
    bool locked = false;
    int result = -1, available;
    ULONGLONG deadline = GetTickCount64() + timeout_ms;
    if (started_pid) *started_pid = 0;
    if (!options || !options->pipe_name || !options->binary || !*options->binary ||
        wcschr(options->binary, L'"') || (options->data_directory && wcschr(options->data_directory, L'"')) ||
        wcsncmp(options->pipe_name, L"\\\\.\\pipe\\", 9) || !options->pipe_name[9] ||
        wcslen(options->pipe_name) > 240 || wcspbrk(options->pipe_name + 9, L"\\/\"") ||
        !cancel || !timeout_ms || timeout_ms > 15000)
        return sbw_fail(error, "INVALID_REQUEST", "后台启动参数无效。");
    if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
        return sbw_fail(error, "CANCELLED", "后台启动已取消。");
    available = probe(options, error);
    if (available != 0) return available > 0 ? 0 : -1;
    mutex = startup_mutex(options->pipe_name, error);
    if (!mutex) goto done;
    HANDLE waits[] = {cancel, mutex};
    ULONGLONG now = GetTickCount64();
    DWORD wait = WaitForMultipleObjects(2, waits, FALSE, now < deadline ? (DWORD)(deadline - now) : 0);
    if (wait != WAIT_OBJECT_0 + 1 && wait != WAIT_ABANDONED_0 + 1) {
        sbw_fail(error, wait == WAIT_OBJECT_0 ? "CANCELLED" : "SERVICE_START_TIMEOUT",
            wait == WAIT_OBJECT_0 ? "后台启动已取消。" : "等待后台启动超时，请刷新重试。"); goto done;
    }
    locked = true;
    if (GetTickCount64() >= deadline) { sbw_fail(error, "SERVICE_START_TIMEOUT", "等待后台启动超时，请刷新重试。"); goto done; }
    available = probe(options, error);
    if (available != 0) { result = available > 0 ? 0 : -1; goto done; }
    /* Hold the executable against replacement until launch and identity check. */
    pinned = CreateFileW(options->binary, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pinned == INVALID_HANDLE_VALUE) {
        sbw_fail(error, "SERVICE_BINARY_MISSING", "无法读取随附的 sb-easy-service.exe，请完整解压安装包后重新打开 sb-easy。"); goto done;
    }
    int installed = options->use_scm ? start_installed(options, error) : 0;
    if (installed < 0) goto done;
    if (!installed && launch_portable(options, &process, error)) goto done;
    while (GetTickCount64() < deadline) {
        if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) { sbw_fail(error, "CANCELLED", "后台启动已取消。"); goto done; }
        available = probe(options, error);
        if (available < 0) goto done;
        if (available > 0) { result = 0; if (started_pid) *started_pid = process.dwProcessId; goto done; }
        if (process.hProcess && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
            sbw_fail(error, "SERVICE_START_FAILED", "后台启动后退出，请检查本地设备资料和安装文件，再刷新重试。"); goto done;
        }
        WaitForSingleObject(cancel, 50);
    }
    sbw_fail(error, "SERVICE_START_TIMEOUT", "后台启动超时，请刷新重试。");
done:
    if (process.hProcess) {
        /* Only this failed startup's child may be stopped. Existing services
         * and successfully started background processes are never stopped. */
        if (result && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, ERROR_OPERATION_ABORTED);
            WaitForSingleObject(process.hProcess, 2000);
        }
        CloseHandle(process.hProcess);
    }
    if (pinned != INVALID_HANDLE_VALUE) CloseHandle(pinned);
    if (locked) ReleaseMutex(mutex);
    if (mutex) CloseHandle(mutex);
    return result;
}
