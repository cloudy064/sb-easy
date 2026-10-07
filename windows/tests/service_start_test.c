#include "../ui-host/service_start.h"
#include "../ui-host/pipe_client.h"
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

typedef struct startup_call {
    const sbw_service_start_options *options;
    HANDLE cancel, begin;
    DWORD pid;
    int result;
    sbw_error error;
} startup_call;

static unsigned __stdcall start(void *context) {
    startup_call *call = context;
    CHECK(WaitForSingleObject(call->begin, 5000) == WAIT_OBJECT_0);
    call->result = sbw_service_ensure(call->options, call->cancel, 8000, &call->pid, &call->error);
    return 0;
}

static DWORD pipe_pid(const wchar_t *name) {
    HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ULONG pid = 0;
    CHECK(pipe != INVALID_HANDLE_VALUE);
    CHECK(GetNamedPipeServerProcessId(pipe, &pid)); CloseHandle(pipe);
    return pid;
}

static void stop_owned(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    CHECK(process); CHECK(TerminateProcess(process, 0));
    CHECK(WaitForSingleObject(process, 3000) == WAIT_OBJECT_0); CloseHandle(process);
}

static void hello(const wchar_t *pipe, HANDLE cancel) {
    char *response = NULL;
    sbw_error error = {0};
    CHECK(!sbw_pipe_request(pipe, "{\"id\":\"startup-test\",\"version\":1,\"method\":\"protocol.hello\",\"params\":{}}", cancel, 5000, &response, &error));
    sbj *json = sbj_parse_cstr(response);
    CHECK(json && sbj_get_bool(json, "ok", false));
    CHECK(sbj_get_int(sbj_get(json, "result"), "protocol_version", 0) == 1);
    sbj_free(json); free(response);
}

int wmain(int argc, wchar_t **argv) {
    /* The test binary also provides an immediately failing launch fixture. */
    if (argc > 1 && !wcscmp(argv[1], L"--console")) return 3;
    CHECK(argc == 2);
    wchar_t temporary[32768], directory[32768], pipe[240], absent[32768], self[32768];
    CHECK(GetTempPathW(32768, temporary));
    CHECK(swprintf_s(directory, 32768, L"%lssb-easy-start-%lu-%llu with space\\", temporary,
        GetCurrentProcessId(), (unsigned long long)GetTickCount64()) > 0);
    CHECK(swprintf_s(pipe, 240, L"\\\\.\\pipe\\sb-easy-start-test-%lu-%llu", GetCurrentProcessId(),
        (unsigned long long)GetTickCount64()) > 0);
    HANDLE cancel = CreateEventW(NULL, TRUE, FALSE, NULL), begin = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(cancel && begin);
    sbw_service_start_options options = {pipe, argv[1], directory, false};
    startup_call calls[2] = {{&options, cancel, begin, 0, -1, {0}}, {&options, cancel, begin, 0, -1, {0}}};
    HANDLE threads[2] = {(HANDLE)_beginthreadex(NULL, 0, start, &calls[0], 0, NULL),
        (HANDLE)_beginthreadex(NULL, 0, start, &calls[1], 0, NULL)};
    CHECK(threads[0] && threads[1]); CHECK(SetEvent(begin));
    CHECK(WaitForMultipleObjects(2, threads, TRUE, 10000) == WAIT_OBJECT_0);
    CloseHandle(threads[0]); CloseHandle(threads[1]);
    for (unsigned i = 0; i < 2; ++i) {
        if (calls[i].result) fprintf(stderr, "startup: %s: %s\n", calls[i].error.code, calls[i].error.message);
        CHECK(!calls[i].result);
    }
    CHECK((calls[0].pid != 0) != (calls[1].pid != 0));
    DWORD first = calls[0].pid ? calls[0].pid : calls[1].pid;
    CHECK(pipe_pid(pipe) == first); hello(pipe, cancel);
    DWORD launched = 0;
    sbw_error error = {0};
    CHECK(!sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(!launched && pipe_pid(pipe) == first);
    stop_owned(first);
    CHECK(!sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(launched && launched != first && pipe_pid(pipe) == launched); hello(pipe, cancel);
    stop_owned(launched);

    SetEvent(cancel);
    CHECK(sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(!strcmp(error.code, "CANCELLED") && !launched); ResetEvent(cancel);
    CHECK(swprintf_s(absent, 32768, L"%lsmissing.exe", directory) > 0);
    options.binary = absent;
    CHECK(sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(!strcmp(error.code, "SERVICE_BINARY_MISSING") && !launched);

    options.binary = argv[1];
    HANDLE impostor = CreateNamedPipeW(pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 1000, NULL);
    CHECK(impostor != INVALID_HANDLE_VALUE);
    CHECK(sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(!strcmp(error.code, "UNTRUSTED_SERVICE") && !launched); CloseHandle(impostor);
    CHECK(GetModuleFileNameW(NULL, self, 32768)); options.binary = self;
    CHECK(sbw_service_ensure(&options, cancel, 8000, &launched, &error));
    CHECK(!strcmp(error.code, "SERVICE_START_FAILED") && !launched);
    CloseHandle(cancel); CloseHandle(begin);
    /* These two fixture files are known, credential-free and confined to this
     * unique temp directory. No recursive deletion or user data is involved. */
    wchar_t *lock = sbw_path_join(directory, L"state.lock"), *work = sbw_path_join(directory, L"core-work");
    DeleteFileW(lock); RemoveDirectoryW(work); RemoveDirectoryW(directory); free(lock); free(work);
    puts("PASS: hidden startup, concurrent/repeated reuse, crash recovery, cancellation, missing binary, impostor and failed startup");
    return 0;
}
