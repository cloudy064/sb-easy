#include "pipe_client.h"
#include "server_identity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FRAME (1024U * 1024U)
static int transfer(HANDLE pipe, void *data, DWORD size, bool writing, HANDLE cancel, ULONGLONG deadline, sbw_error *error) {
    unsigned char *cursor = data;
    while (size) {
        HANDLE event;
        OVERLAPPED operation = {0};
        DWORD count = 0;
        BOOL done;
        const char *failure = NULL;
        if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return sbw_fail(error, "CANCELLED", "Request cancelled");
        if (GetTickCount64() >= deadline) return sbw_fail(error, "TIMEOUT", "Service request timed out");
        event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!event) return sbw_fail(error, "IO_ERROR", "Cannot allocate pipe I/O event");
        operation.hEvent = event;
        done = writing ? WriteFile(pipe, cursor, size, &count, &operation) : ReadFile(pipe, cursor, size, &count, &operation);
        if (!done) {
            if (GetLastError() != ERROR_IO_PENDING) failure = "Service pipe disconnected";
            else {
                ULONGLONG now = GetTickCount64();
                DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
                HANDLE events[] = {cancel, event};
                DWORD result = WaitForMultipleObjects(2, events, FALSE, remaining);
                if (result != WAIT_OBJECT_0 + 1) {
                    CancelIoEx(pipe, &operation);
                    GetOverlappedResult(pipe, &operation, &count, TRUE);
                    failure = result == WAIT_OBJECT_0 ? "Request cancelled" : "Service request timed out";
                } else if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) failure = "Service pipe disconnected";
            }
        }
        CloseHandle(event);
        if (failure) return sbw_fail(error, "IO_ERROR", failure);
        if (!count || count > size) return sbw_fail(error, "IO_ERROR", "Service returned an incomplete frame");
        cursor += count; size -= count;
    }
    return 0;
}
int sbw_pipe_request(const wchar_t *pipe, const char *body, HANDLE cancel, DWORD timeout_ms,
                     char **response, sbw_error *error) {
    HANDLE connection = INVALID_HANDLE_VALUE;
    const size_t length = body ? strlen(body) : 0;
    ULONGLONG started, deadline;
    unsigned char header[4];
    uint32_t response_size = 0;
    wchar_t *expected = NULL;
    char *result = NULL;
    int rc = -1;
    *response = NULL;
    if (!length || length > MAX_FRAME || !timeout_ms || timeout_ms > 35000)
        return sbw_fail(error, "INVALID_REQUEST", "Invalid request frame or deadline");
    started = GetTickCount64(); deadline = started + timeout_ms;
    while (GetTickCount64() < started + (timeout_ms < 4000 ? timeout_ms : 4000)) {
        DWORD code;
        if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) { sbw_fail(error, "CANCELLED", "Request cancelled"); goto done; }
        connection = CreateFileW(pipe, FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
        if (connection != INVALID_HANDLE_VALUE) break;
        code = GetLastError();
        if (code != ERROR_PIPE_BUSY) { sbw_fail(error, "SERVICE_UNAVAILABLE", "Local service is unavailable"); goto done; }
        WaitNamedPipeW(pipe, 100);
    }
    if (connection == INVALID_HANDLE_VALUE) { sbw_fail(error, "SERVICE_UNAVAILABLE", "Local service is unavailable"); goto done; }
    expected = sbw_expected_service_binary();
    if (!sbw_verified_pipe_server(connection, expected)) { sbw_fail(error, "UNTRUSTED_SERVICE", "Local service identity verification failed"); goto done; }
    for (unsigned i = 0; i < 4; ++i) header[i] = (unsigned char)(((uint32_t)length >> (8U * i)) & 0xffU);
    if (transfer(connection, header, 4, true, cancel, deadline, error) ||
        transfer(connection, (void *)body, (DWORD)length, true, cancel, deadline, error) ||
        transfer(connection, header, 4, false, cancel, deadline, error)) goto done;
    for (unsigned i = 0; i < 4; ++i) response_size |= (uint32_t)header[i] << (8U * i);
    if (!response_size || response_size > MAX_FRAME) { sbw_fail(error, "INVALID_RESPONSE", "Invalid response frame size"); goto done; }
    result = sb_xcalloc((size_t)response_size + 1, 1);
    if (transfer(connection, result, response_size, false, cancel, deadline, error)) goto done;
    if (memchr(result, '\0', response_size)) { sbw_fail(error, "INVALID_RESPONSE", "Invalid response encoding"); goto done; }
    *response = result; result = NULL; rc = 0;
done:
    free(expected); free(result);
    if (connection != INVALID_HANDLE_VALUE) CloseHandle(connection);
    return rc;
}
