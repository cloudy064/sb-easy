#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/tailscale_status.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bytes { unsigned char data[8192]; size_t length; } bytes;
static void append(bytes *out, const void *data, size_t length) {
    assert(out->length + length <= sizeof(out->data));
    memcpy(out->data + out->length, data, length); out->length += length;
}
static void integer(bytes *out, uint64_t value) {
    do { unsigned char next = (unsigned char)(value & 127U); value >>= 7;
        if (value) next |= 128; append(out, &next, 1);
    } while (value);
}
static void blob(bytes *out, unsigned field, const void *data, size_t length) {
    integer(out, ((uint64_t)field << 3) | 2); integer(out, length); append(out, data, length);
}
static void text(bytes *out, unsigned field, const char *value) { blob(out, field, value, strlen(value)); }
static void number(bytes *out, unsigned field, uint64_t value) { integer(out, (uint64_t)field << 3); integer(out, value); }
static bytes frame_for(const bytes *payload) {
    bytes result = {{0}, 5}; uint32_t length = (uint32_t)payload->length;
    result.data[1] = (unsigned char)(length >> 24); result.data[2] = (unsigned char)(length >> 16);
    result.data[3] = (unsigned char)(length >> 8); result.data[4] = (unsigned char)length;
    append(&result, payload->data, payload->length); return result;
}
static bytes endpoint_frame(const bytes *endpoint) {
    bytes payload = {{0}, 0}; blob(&payload, 1, endpoint->data, endpoint->length); return frame_for(&payload);
}
static bytes valid_frame(void) {
    bytes self = {{0}, 0}, endpoint = {{0}, 0};
    text(&self, 1, "company-pc"); text(&self, 2, "company-pc.example.ts.net.");
    text(&self, 4, "100.100.12.34"); text(&self, 4, "fd7a:115c:a1e0::1234");
    number(&self, 5, 1); text(&self, 14, "PRIVATE-HOST-KEY-MUST-NOT-LEAK");
    text(&endpoint, 1, "sb-easy-tailscale"); text(&endpoint, 2, "Running");
    text(&endpoint, 3, "STATE-TEXT-MUST-NOT-LEAK"); text(&endpoint, 4, "https://login.example.test/secret-login");
    text(&endpoint, 5, "example.ts.net"); blob(&endpoint, 7, self.data, self.length);
    bytes users = {{0}, 0}; text(&users, 2, "PRIVATE-ACCOUNT-MUST-NOT-LEAK");
    blob(&endpoint, 8, users.data, users.length); number(&endpoint, 10, 1);
    return endpoint_frame(&endpoint);
}
static bool rejected(const unsigned char *data, size_t length) {
    sbw_error error = {0}; sbj *out = NULL;
    int result = sbw_tailscale_status_decode(data, length, &out, &error);
    bool ok = result != 0 && !out && !strcmp(error.code, "TAILSCALE_STATUS_INVALID");
    sbj_free(out); return ok;
}
static void decoder_tests(void) {
    sbw_error error = {0}; sbj *out = NULL; bytes frame = valid_frame();
    assert(sbw_tailscale_status_decode(frame.data, frame.length, &out, &error) == 0);
    const sbj *endpoints = sbj_get(out, "endpoints"), *endpoint = sbj_arr_at(endpoints, 0);
    assert(sbj_arr_len(endpoints) == 1 && sbj_obj_len(out) == 1 && sbj_obj_len(endpoint) == 4);
    assert(!strcmp(sbj_get_str(endpoint, "tag", ""), "sb-easy-tailscale"));
    assert(!strcmp(sbj_get_str(endpoint, "backend_state", ""), "Running"));
    const sbj *self = sbj_get(endpoint, "self");
    assert(sbj_obj_len(self) == 5 && sbj_get_bool(self, "online", false));
    assert(sbj_arr_len(sbj_get(self, "ips")) == 2);
    char *json = sbj_dump(out, -1);
    assert(json && !strstr(json, "MUST-NOT-LEAK") && !strstr(json, "secret-login") && !strstr(json, "auth"));
    free(json); sbj_free(out); out = NULL;
    for (size_t size = 0; size < frame.length; ++size) assert(rejected(frame.data, size));
    frame.data[0] = 1; assert(rejected(frame.data, frame.length));
    frame.data[0] = 128; assert(rejected(frame.data, frame.length)); frame.data[0] = 0;
    frame.data[1] = 127; assert(rejected(frame.data, frame.length));
    unsigned char empty[] = {0, 0, 0, 0, 0};
    assert(sbw_tailscale_status_decode(empty, sizeof(empty), &out, &error) == 0);
    assert(sbj_arr_len(sbj_get(out, "endpoints")) == 0); sbj_free(out); out = NULL;

    bytes endpoint_data = {{0}, 0}; text(&endpoint_data, 1, "tailnet"); text(&endpoint_data, 2, "NeedsLogin");
    frame = endpoint_frame(&endpoint_data);
    assert(sbw_tailscale_status_decode(frame.data, frame.length, &out, &error) == 0);
    assert(sbj_is_null(sbj_get(sbj_arr_at(sbj_get(out, "endpoints"), 0), "self"))); sbj_free(out); out = NULL;
    text(&endpoint_data, 2, "Running"); frame = endpoint_frame(&endpoint_data);
    assert(rejected(frame.data, frame.length));

    bytes bad_self = {{0}, 0}, bad_endpoint = {{0}, 0};
    text(&bad_self, 4, "https://private.example.test/token"); text(&bad_endpoint, 1, "tailnet");
    blob(&bad_endpoint, 7, bad_self.data, bad_self.length); frame = endpoint_frame(&bad_endpoint);
    assert(rejected(frame.data, frame.length));
    bad_endpoint.length = 0; unsigned char nul[] = {'a', 0, 'b'};
    blob(&bad_endpoint, 1, nul, sizeof(nul)); frame = endpoint_frame(&bad_endpoint);
    assert(rejected(frame.data, frame.length));
    bad_endpoint.length = 0; unsigned char utf8[] = {0xc0, 0xaf};
    blob(&bad_endpoint, 1, utf8, sizeof(utf8)); frame = endpoint_frame(&bad_endpoint);
    assert(rejected(frame.data, frame.length));
    bytes malformed = {{0}, 0}; unsigned char overflow[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2};
    append(&malformed, overflow, sizeof(overflow)); frame = frame_for(&malformed);
    assert(rejected(frame.data, frame.length));
    malformed.length = 0; integer(&malformed, 0); frame = frame_for(&malformed);
    assert(rejected(frame.data, frame.length));
}

typedef struct fake_api {
    SOCKET listener; HANDLE stop, thread; unsigned short port;
    bytes response; bool received, auth_ok; const char *content_type;
} fake_api;
static const char test_secret[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static bool send_bytes(SOCKET connection, const void *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        int count = send(connection, (const char *)data + offset, (int)(length - offset), 0);
        if (count <= 0) return false; offset += (size_t)count;
    }
    return true;
}
static DWORD WINAPI api_thread(void *value) {
    fake_api *api = value; SOCKET peer = INVALID_SOCKET;
    while (WaitForSingleObject(api->stop, 0) == WAIT_TIMEOUT) {
        fd_set readable; FD_ZERO(&readable); FD_SET(api->listener, &readable);
        struct timeval interval = {0, 20000};
        if (select(0, &readable, NULL, NULL, &interval) > 0) { peer = accept(api->listener, NULL, NULL); break; }
    }
    if (peer == INVALID_SOCKET) return 0;
    DWORD timeout = 500; setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    char request[2048] = {0}; size_t used = 0; char *body = NULL;
    while (used < sizeof(request) - 1) {
        int count = recv(peer, request + used, (int)(sizeof(request) - 1 - used), 0);
        if (count <= 0) break;
        used += (size_t)count; request[used] = '\0'; body = strstr(request, "\r\n\r\n");
        if (body && used >= (size_t)(body - request) + 9) break;
    }
    api->received = used != 0;
    char expected[100]; sprintf_s(expected, sizeof(expected), "Authorization: Bearer %s\r\n", test_secret);
    static const char method[] = "POST /daemon.StartedService/SubscribeTailscaleStatus HTTP/1.0\r\n";
    api->auth_ok = body && !strncmp(request, method, sizeof(method) - 1) &&
        strstr(request, expected) && strstr(request, "Content-Length: 5\r\n") &&
        used == (size_t)(body - request) + 9 && !memcmp(body + 4, "\0\0\0\0\0", 5);
    if (api->response.length) {
        char headers[256]; int length = sprintf_s(headers, sizeof(headers),
            "HTTP/1.0 200 OK\r\nContent-Type: %s\r\n\r\n", api->content_type);
        if (length > 0 && send_bytes(peer, headers, (size_t)length)) {
            /* Exercise split frame header/payload and a server which keeps
             * this subscription open after delivering its first snapshot. */
            (void)send_bytes(peer, api->response.data, 3);
            Sleep(10); (void)send_bytes(peer, api->response.data + 3, api->response.length - 3);
        }
    }
    (void)WaitForSingleObject(api->stop, 3000);
    shutdown(peer, SD_BOTH); closesocket(peer); return 0;
}
static void start_api(fake_api *api, const bytes *response) {
    memset(api, 0, sizeof(*api)); api->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(api->listener != INVALID_SOCKET); api->response = *response; api->content_type = "application/grpc-web";
    BOOL exclusive = TRUE; struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); int size = sizeof(address);
    assert(!setsockopt(api->listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive)));
    assert(!bind(api->listener, (const struct sockaddr *)&address, sizeof(address)) && !listen(api->listener, 1));
    assert(!getsockname(api->listener, (struct sockaddr *)&address, &size)); api->port = ntohs(address.sin_port);
    api->stop = CreateEventW(NULL, TRUE, FALSE, NULL); assert(api->stop);
    api->thread = CreateThread(NULL, 0, api_thread, api, 0, NULL); assert(api->thread);
}
static void stop_api(fake_api *api) {
    SetEvent(api->stop); assert(WaitForSingleObject(api->thread, 4000) == WAIT_OBJECT_0);
    CloseHandle(api->thread); CloseHandle(api->stop); closesocket(api->listener);
}
static void network_tests(void) {
    WSADATA startup; assert(!WSAStartup(MAKEWORD(2, 2), &startup));
    fake_api api; bytes frame = valid_frame(); start_api(&api, &frame);
    sbw_runtime_config config = {0}; config.tailscale_port = api.port; config.tailscale_secret = (char *)test_secret;
    sbw_error error = {0}; sbj *out = NULL; ULONGLONG started = GetTickCount64();
    assert(!sbw_tailscale_status_get(&config, GetCurrentProcessId(), NULL, &out, &error));
    assert(GetTickCount64() - started < 1500 && api.auth_ok);
    assert(sbj_arr_len(sbj_get(out, "endpoints")) == 1); sbj_free(out); out = NULL; stop_api(&api);

    start_api(&api, &frame); config.tailscale_port = api.port;
    assert(sbw_tailscale_status_get(&config, 4, NULL, &out, &error) != 0 && !out);
    stop_api(&api); assert(!api.received);
    start_api(&api, &frame); config.tailscale_port = api.port; SetEvent(api.stop);
    assert(sbw_tailscale_status_get(&config, GetCurrentProcessId(), api.stop, &out, &error) != 0 && !out);
    assert(!strcmp(error.code, "CORE_CANCELLED")); stop_api(&api); assert(!api.received);

    bytes no_response = {{0}, 0}; start_api(&api, &no_response); config.tailscale_port = api.port;
    started = GetTickCount64();
    assert(sbw_tailscale_status_get(&config, GetCurrentProcessId(), NULL, &out, &error) != 0 && !out);
    assert(!strcmp(error.code, "TAILSCALE_STATUS_TIMEOUT") && GetTickCount64() - started < 2700);
    stop_api(&api); WSACleanup();
}
int main(void) {
    decoder_tests(); network_tests(); puts("Tailscale bounded decoder and owned-core status transport passed"); return 0;
}
