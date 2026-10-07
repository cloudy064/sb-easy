#include "../service/pipe_server.h"
#include "../service/protocol.h"
#include "test_support.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include <wchar.h>

typedef struct server_fixture {
    HANDLE stop, ready, done, thread;
    wchar_t name[192];
    DWORD result;
    sbw_pipe_options options;
} server_fixture;

static DWORD WINAPI run_server(void *context) {
    server_fixture *fixture = context;
    fixture->result = sbw_run_pipe_server(&fixture->options, fixture->stop);
    SetEvent(fixture->done);
    return 0;
}

static void fixture_init(server_fixture *fixture, sbw_controller *controller) {
    memset(fixture, 0, sizeof(*fixture));
    fixture->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    fixture->ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    fixture->done = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(fixture->stop && fixture->ready && fixture->done);
    DWORD random[4];
    CHECK(BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0);
    CHECK(swprintf_s(fixture->name, sizeof(fixture->name) / sizeof(wchar_t),
        L"\\\\.\\pipe\\sb-easy-test-%lu-%08lx%08lx%08lx%08lx", GetCurrentProcessId(), random[0], random[1], random[2], random[3]) > 0);
    sbw_pipe_options_init(&fixture->options);
    fixture->options.pipe_name = fixture->name;
    fixture->options.io_timeout_ms = 350;
    fixture->options.ready_event = fixture->ready;
    fixture->options.controller = controller;
    fixture->thread = CreateThread(NULL, 0, run_server, fixture, 0, NULL);
    CHECK(fixture->thread);
    HANDLE events[] = {fixture->ready, fixture->done};
    if (WaitForMultipleObjects(2, events, FALSE, 5000) != WAIT_OBJECT_0) {
        fprintf(stderr, "IPC server readiness failure: %lu\n", fixture->result);
        SetEvent(fixture->stop); WaitForSingleObject(fixture->thread, 5000); exit(1);
    }
}

static void fixture_stop(server_fixture *fixture) {
    SetEvent(fixture->stop);
    CHECK(WaitForSingleObject(fixture->done, 1500) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(fixture->thread, 1500) == WAIT_OBJECT_0);
    CHECK(fixture->result == ERROR_SUCCESS);
    CloseHandle(fixture->thread); fixture->thread = NULL;
}
static void fixture_free(server_fixture *fixture) {
    if (fixture->thread) fixture_stop(fixture);
    CloseHandle(fixture->stop); CloseHandle(fixture->ready); CloseHandle(fixture->done);
}

static HANDLE connect_pipe(const wchar_t *name, bool anonymous) {
    ULONGLONG deadline = GetTickCount64() + 5000;
    for (;;) {
        HANDLE pipe = CreateFileW(name, FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE,
            0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
            (anonymous ? SECURITY_ANONYMOUS : SECURITY_IMPERSONATION), NULL);
        if (pipe != INVALID_HANDLE_VALUE) return pipe;
        DWORD error = GetLastError();
        CHECK(error == ERROR_PIPE_BUSY || error == ERROR_FILE_NOT_FOUND);
        CHECK(GetTickCount64() < deadline);
        WaitNamedPipeW(name, 100);
    }
}

static bool transfer(HANDLE pipe, void *bytes, DWORD length, bool writing) {
    DWORD offset = 0;
    while (offset < length) {
        HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
        CHECK(event);
        OVERLAPPED pending = {0}; pending.hEvent = event;
        DWORD count = 0;
        unsigned char *buffer = (unsigned char *)bytes + offset;
        BOOL immediate = writing ? WriteFile(pipe, buffer, length - offset, &count, &pending) :
                                   ReadFile(pipe, buffer, length - offset, &count, &pending);
        if (!immediate) {
            if (GetLastError() != ERROR_IO_PENDING) { CloseHandle(event); return false; }
            if (WaitForSingleObject(event, 2000) != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &pending);
                GetOverlappedResult(pipe, &pending, &count, TRUE);
                CloseHandle(event);
                CHECK(false); /* Test peer must not outlive its I/O buffer. */
            }
            if (!GetOverlappedResult(pipe, &pending, &count, FALSE)) { CloseHandle(event); return false; }
        }
        CloseHandle(event);
        if (!count) return false;
        offset += count;
    }
    return true;
}

static void frame_header(unsigned char bytes[4], uint32_t length) {
    bytes[0] = (unsigned char)length; bytes[1] = (unsigned char)(length >> 8);
    bytes[2] = (unsigned char)(length >> 16); bytes[3] = (unsigned char)(length >> 24);
}
static sbj *exchange(HANDLE pipe, const char *request, bool fragmented) {
    size_t length = strlen(request);
    CHECK(length <= UINT32_MAX);
    unsigned char prefix[4]; frame_header(prefix, (uint32_t)length);
    if (fragmented) {
        CHECK(length > 0);
        CHECK(transfer(pipe, prefix, 1, true) && transfer(pipe, prefix + 1, 3, true));
        CHECK(transfer(pipe, (void *)request, 1, true) && transfer(pipe, (void *)(request + 1), (DWORD)length - 1, true));
    } else {
        CHECK(transfer(pipe, prefix, 4, true) && transfer(pipe, (void *)request, (DWORD)length, true));
    }
    CHECK(transfer(pipe, prefix, 4, false));
    uint32_t size = (uint32_t)prefix[0] | ((uint32_t)prefix[1] << 8) |
        ((uint32_t)prefix[2] << 16) | ((uint32_t)prefix[3] << 24);
    CHECK(size && size <= SBW_MAX_FRAME);
    char *response = sb_xcalloc((size_t)size + 1, 1);
    CHECK(transfer(pipe, response, size, false));
    sbj *parsed = sbw_json_parse(response, size, 32, NULL);
    free(response); CHECK(parsed); return parsed;
}
static char *request_text(const char *method, sbj *params) {
    sbj *value = sbj_object();
    sbj_set_str(value, "id", "integration"); sbj_set_int(value, "version", 1);
    sbj_set_str(value, "method", method); sbj_set(value, "params", params ? params : sbj_object());
    char *text = sbj_dump(value, -1); sbj_free(value); return text;
}
static sbj *request(HANDLE pipe, const char *method) {
    char *text = request_text(method, NULL); sbj *reply = exchange(pipe, text, false); free(text); return reply;
}
static bool error_is(const sbj *reply, const char *code) { return sbj_string_is(sbj_get(sbj_get(reply, "error"), "code"), code); }

static void check_pipe_acl(HANDLE pipe) {
    PACL acl = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
    CHECK(GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
        &acl, NULL, &descriptor) == ERROR_SUCCESS);
    bool interactive_safe = false, network_denied = false;
    if (acl) for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *value = NULL;
        if (!GetAce(acl, i, &value)) continue;
        ACE_HEADER *header = value;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *ace = value;
            if (IsWellKnownSid(&ace->SidStart, WinInteractiveSid))
                interactive_safe = !(ace->Mask & FILE_CREATE_PIPE_INSTANCE) &&
                    (ace->Mask & (FILE_READ_DATA | FILE_WRITE_DATA)) == (FILE_READ_DATA | FILE_WRITE_DATA);
        } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *ace = value;
            if (IsWellKnownSid(&ace->SidStart, WinNetworkSid)) network_denied = true;
        }
    }
    LocalFree(descriptor); CHECK(interactive_safe && network_denied);
}

static DWORD WINAPI concurrent_client(void *context) {
    const wchar_t *name = context;
    HANDLE pipe = connect_pipe(name, false);
    for (unsigned i = 0; i < 8; ++i) {
        sbj *reply = request(pipe, "status.get"); CHECK(sbj_get_bool(reply, "ok", false)); sbj_free(reply);
    }
    CloseHandle(pipe); return 0;
}

static void main_scenarios(void) {
    server_fixture fixture; fixture_init(&fixture, NULL);
    HANDLE pipe = connect_pipe(fixture.name, false); check_pipe_acl(pipe);
    char *hello_request = request_text("protocol.hello", NULL);
    sbj *reply = exchange(pipe, hello_request, true); free(hello_request);
    CHECK(sbj_get_bool(reply, "ok", false) && sbj_get_int(sbj_get(reply, "result"), "protocol_version", 0) == 1); sbj_free(reply);
    reply = exchange(pipe, "{", false); CHECK(error_is(reply, "INVALID_REQUEST")); sbj_free(reply);
    reply = request(pipe, "status.get"); const sbj *status = sbj_get(reply, "result");
    CHECK(sbj_string_is(sbj_get(status, "phase"), "UNENROLLED") && !sbj_get_bool(status, "core_running", true)); sbj_free(reply);
    reply = request(pipe, "vpn.start"); CHECK(error_is(reply, "NOT_IMPLEMENTED")); sbj_free(reply);
    char *normal = request_text("status.get", NULL), *maximum = sb_xmalloc(SBW_MAX_FRAME + 1);
    memset(maximum, ' ', SBW_MAX_FRAME); memcpy(maximum, normal, strlen(normal)); maximum[SBW_MAX_FRAME] = 0;
    reply = exchange(pipe, maximum, false); CHECK(sbj_get_bool(reply, "ok", false));
    sbj_free(reply); free(normal); free(maximum); CloseHandle(pipe);
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(stop);
    sbw_pipe_options collision; sbw_pipe_options_init(&collision); collision.pipe_name = fixture.name;
    DWORD result = sbw_run_pipe_server(&collision, stop);
    CHECK(result == ERROR_ACCESS_DENIED || result == ERROR_PIPE_BUSY); CloseHandle(stop);
    const uint32_t invalid_lengths[] = {0, UINT32_MAX};
    for (size_t i = 0; i < 2; ++i) {
        pipe = connect_pipe(fixture.name, false);
        unsigned char prefix[4], byte = 0; frame_header(prefix, invalid_lengths[i]);
        CHECK(transfer(pipe, prefix, 4, true)); CHECK(!transfer(pipe, &byte, 1, false)); CloseHandle(pipe);
    }
    pipe = connect_pipe(fixture.name, false);
    unsigned char prefix[4], byte = '{'; frame_header(prefix, 100);
    CHECK(transfer(pipe, prefix, 4, true) && transfer(pipe, &byte, 1, true));
    CHECK(!transfer(pipe, &byte, 1, false)); CloseHandle(pipe);
    pipe = connect_pipe(fixture.name, false);
    CHECK(!transfer(pipe, &byte, 1, false)); CloseHandle(pipe);
    HANDLE clients[8];
    for (size_t i = 0; i < 8; ++i) { clients[i] = CreateThread(NULL, 0, concurrent_client, fixture.name, 0, NULL); CHECK(clients[i]); }
    CHECK(WaitForMultipleObjects(8, clients, TRUE, 15000) == WAIT_OBJECT_0);
    for (size_t i = 0; i < 8; ++i) CloseHandle(clients[i]);
    for (unsigned i = 0; i < 32; ++i) { pipe = connect_pipe(fixture.name, false); CloseHandle(pipe); }
    pipe = connect_pipe(fixture.name, false); reply = request(pipe, "status.get");
    CHECK(sbj_get_bool(reply, "ok", false)); sbj_free(reply); CloseHandle(pipe);
    fixture_stop(&fixture); fixture_free(&fixture);
}

static void pending_io_cancellation(void) {
    server_fixture fixture; fixture_init(&fixture, NULL);
    HANDLE clients[4];
    for (size_t i = 0; i < 4; ++i) {
        clients[i] = connect_pipe(fixture.name, false);
        unsigned char prefix[4]; frame_header(prefix, 100);
        CHECK(transfer(clients[i], prefix, 2, true));
    }
    fixture_stop(&fixture);
    for (size_t i = 0; i < 4; ++i) CloseHandle(clients[i]);
    fixture_free(&fixture);
}

static void mutation_authorization(void) {
    test_data data; test_data_init(&data);
    sbw_controller *controller = test_controller(&data, NULL);
    server_fixture fixture; fixture_init(&fixture, controller);
    HANDLE pipe = connect_pipe(fixture.name, true);
    sbj *reply = request(pipe, "enrollment.forget"); CHECK(error_is(reply, "FORBIDDEN")); sbj_free(reply);
    reply = request(pipe, "status.get"); CHECK(sbj_get_bool(reply, "ok", false)); sbj_free(reply); CloseHandle(pipe);
    pipe = connect_pipe(fixture.name, false);
    char *text = request_text("enrollment.apply", test_enrollment());
    reply = exchange(pipe, text, false); free(text);
    if (sbj_get_bool(reply, "ok", false)) {
        CHECK(sbj_get_bool(sbj_get(reply, "result"), "enrolled", false)); test_redacted(reply); sbj_free(reply);
        reply = request(pipe, "config.refresh");
        const sbj *status = sbj_get(reply, "result");
        CHECK(sbj_string_is(sbj_get(status, "downloaded_etag"), "revision-1") && sbj_is_null(sbj_get(status, "active_etag")));
        test_redacted(reply); sbj_free(reply);
        reply = request(pipe, "enrollment.forget");
        CHECK(!sbj_get_bool(sbj_get(reply, "result"), "enrolled", true));
        CHECK(data.enrollments == 1); /* test_enroll also verifies RevertToSelf. */
    } else {
        /* Noninteractive nonadministrator CI identities must remain forbidden. */
        CHECK(error_is(reply, "FORBIDDEN"));
    }
    sbj_free(reply); CloseHandle(pipe);
    fixture_stop(&fixture); fixture_free(&fixture);
    sbw_controller_free(controller); test_data_free(&data);
}

int main(void) {
    main_scenarios(); pending_io_cancellation(); mutation_authorization();
    server_fixture idle; fixture_init(&idle, NULL); fixture_stop(&idle); fixture_free(&idle);
    puts("C11 named-pipe integration tests passed (random local pipe; no service installation or network changes).");
    return 0;
}
