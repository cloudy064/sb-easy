#include "pipe_server.h"
#include "protocol.h"
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct pipe_worker { HANDLE pipe, stop; DWORD timeout; sbw_controller *controller; } pipe_worker;
static DWORD remaining(ULONGLONG deadline) {
    ULONGLONG now = GetTickCount64(); return now >= deadline ? 0 : (DWORD)(deadline - now);
}
static bool complete(HANDLE pipe, HANDLE stop, OVERLAPPED *pending, DWORD timeout, DWORD *transferred) {
    HANDLE events[] = {stop, pending->hEvent};
    if (WaitForMultipleObjects(2, events, FALSE, timeout) == WAIT_OBJECT_0 + 1)
        return GetOverlappedResult(pipe, pending, transferred, FALSE) != FALSE;
    CancelIoEx(pipe, pending);
    GetOverlappedResult(pipe, pending, transferred, TRUE); /* keep buffers alive through cancellation */
    return false;
}
static bool transfer(HANDLE pipe, HANDLE stop, void *data, DWORD length, bool writing, ULONGLONG deadline) {
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event) return false;
    DWORD offset = 0;
    bool result = false;
    while (offset < length) {
        if (WaitForSingleObject(stop, 0) == WAIT_OBJECT_0 || !remaining(deadline)) goto done;
        ResetEvent(event);
        OVERLAPPED pending = {0}; pending.hEvent = event;
        DWORD transferred = 0;
        unsigned char *cursor = (unsigned char *)data + offset;
        BOOL immediate = writing ? WriteFile(pipe, cursor, length - offset, &transferred, &pending) :
                                   ReadFile(pipe, cursor, length - offset, &transferred, &pending);
        if (!immediate && (GetLastError() != ERROR_IO_PENDING ||
            !complete(pipe, stop, &pending, remaining(deadline), &transferred))) goto done;
        if (!transferred) goto done;
        offset += transferred;
    }
    result = true;
done:
    CloseHandle(event); return result;
}
static bool accept_client(HANDLE pipe, HANDLE stop) {
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event) return false;
    OVERLAPPED pending = {0}; pending.hEvent = event;
    DWORD transferred = 0;
    bool accepted = ConnectNamedPipe(pipe, &pending) != FALSE;
    if (!accepted) {
        DWORD error = GetLastError();
        accepted = error == ERROR_PIPE_CONNECTED ||
            (error == ERROR_IO_PENDING && complete(pipe, stop, &pending, INFINITE, &transferred));
    }
    CloseHandle(event); return accepted;
}
static bool authorized(HANDLE pipe, HANDLE stop) {
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    bool allowed = false;
    HANDLE token = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        unsigned char admin_sid[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof admin_sid;
        BOOL admin = FALSE;
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &size)) CheckTokenMembership(token, admin_sid, &admin);
        DWORD session = 0, returned = 0, active = WTSGetActiveConsoleSessionId();
        bool console = active != 0xffffffff && GetTokenInformation(token, TokenSessionId, &session, sizeof session, &returned) && session == active;
        allowed = admin || console; CloseHandle(token);
    }
    if (!RevertToSelf()) { SetEvent(stop); return false; }
    return allowed;
}
static void serve_client(pipe_worker *worker) {
    for (;;) {
        unsigned char header[4];
        ULONGLONG deadline = GetTickCount64() + worker->timeout;
        if (!transfer(worker->pipe, worker->stop, header, 4, false, deadline)) return;
        DWORD length = (DWORD)header[0] | ((DWORD)header[1] << 8) | ((DWORD)header[2] << 16) | ((DWORD)header[3] << 24);
        if (!length || length > SBW_MAX_FRAME) return;
        char *request = sb_xcalloc((size_t)length + 1, 1);
        if (!transfer(worker->pipe, worker->stop, request, length, false, deadline)) { free(request); return; }
        sbj *parsed = sbw_json_parse(request, length, 32, NULL);
        const sbj *method = sbj_get(parsed, "method");
        bool mutation = sbw_json_string(method, 128, false) && sbw_is_mutating_method(method->v.str.ptr);
        bool private_read = sbw_json_string(method, 128, false) &&
            (sb_streq(method->v.str.ptr, "runtime.snapshot") || sb_streq(method->v.str.ptr, "config.inspect"));
        bool permitted = (mutation || private_read) && authorized(worker->pipe, worker->stop);
        sbj_free(parsed);
        if (WaitForSingleObject(worker->stop, 0) == WAIT_OBJECT_0) { sbw_secret_free(request); return; }
        char *response = sbw_handle_request(request, length, worker->controller, permitted);
        SecureZeroMemory(request, length); free(request);
        if (!response) return;
        size_t response_size = strlen(response);
        if (!response_size || response_size > SBW_MAX_FRAME) { free(response); return; }
        length = (DWORD)response_size;
        for (unsigned i = 0; i < 4; ++i) header[i] = (unsigned char)(length >> (8U * i));
        deadline = GetTickCount64() + worker->timeout;
        bool written = transfer(worker->pipe, worker->stop, header, 4, true, deadline) &&
            transfer(worker->pipe, worker->stop, response, length, true, deadline);
        free(response);
        if (!written) return;
        /* Await the next frame/peer close instead of discarding the reply through
         * an immediate DisconnectNamedPipe. FlushFileBuffers is unbounded. */
    }
}
static DWORD WINAPI worker_main(void *context) {
    pipe_worker *worker = context;
    while (WaitForSingleObject(worker->stop, 0) != WAIT_OBJECT_0) {
        if (accept_client(worker->pipe, worker->stop)) serve_client(worker);
        else if (WaitForSingleObject(worker->stop, 10) == WAIT_OBJECT_0) break;
        DisconnectNamedPipe(worker->pipe);
    }
    return 0;
}
void sbw_pipe_options_init(sbw_pipe_options *options) {
    memset(options, 0, sizeof *options);
    options->pipe_name = SBW_DEFAULT_PIPE; options->io_timeout_ms = 5000; options->worker_count = 4;
}
bool sbw_valid_pipe_name(const wchar_t *name) {
    const wchar_t *prefix = L"\\\\.\\pipe\\";
    if (!name || wcslen(name) <= wcslen(prefix) || wcslen(name) > 240 || wcsncmp(name, prefix, wcslen(prefix))) return false;
    for (const wchar_t *p = name + wcslen(prefix); *p; ++p)
        if (!((*p >= L'a' && *p <= L'z') || (*p >= L'A' && *p <= L'Z') ||
              (*p >= L'0' && *p <= L'9') || *p == L'-' || *p == L'_' || *p == L'.')) return false;
    return true;
}
DWORD sbw_run_pipe_server(const sbw_pipe_options *options, HANDLE stop) {
    if (!options || !stop || !sbw_valid_pipe_name(options->pipe_name) || !options->worker_count ||
        options->worker_count > 16 || !options->io_timeout_ms || options->io_timeout_ms > 60000) return ERROR_INVALID_PARAMETER;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)(A;;GA;;;OW)",
        SDDL_REVISION_1, &descriptor, NULL)) return GetLastError();
    SECURITY_ATTRIBUTES attributes = {sizeof attributes, descriptor, FALSE};
    pipe_worker workers[16] = {0}; HANDLE threads[16] = {0};
    unsigned pipe_count = 0, thread_count = 0; DWORD result = ERROR_SUCCESS;
    for (unsigned i = 0; i < options->worker_count; ++i) {
        HANDLE pipe = CreateNamedPipeW(options->pipe_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
            (i == 0 ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0), PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            options->worker_count, 65536, 65536, 1000, &attributes);
        if (pipe == INVALID_HANDLE_VALUE) { result = GetLastError(); goto done; }
        workers[i].pipe = pipe; workers[i].stop = stop; workers[i].timeout = options->io_timeout_ms; workers[i].controller = options->controller;
        ++pipe_count;
    }
    for (unsigned i = 0; i < pipe_count; ++i) {
        threads[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (!threads[i]) { result = GetLastError(); SetEvent(stop); goto done; }
        ++thread_count;
    }
    if (options->on_ready) options->on_ready(options->on_ready_context);
    if (options->ready_event) SetEvent(options->ready_event);
    WaitForSingleObject(stop, INFINITE);
done:
    LocalFree(descriptor);
    for (unsigned i = 0; i < thread_count; ++i) { WaitForSingleObject(threads[i], INFINITE); CloseHandle(threads[i]); }
    for (unsigned i = 0; i < pipe_count; ++i) CloseHandle(workers[i].pipe);
    return result;
}
