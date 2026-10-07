#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/control_plane.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static const char test_code[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char test_token[] = "test-device-token-never-in-errors";

static void require_at(bool condition, const char *message, int line) {
    if (!condition) { fprintf(stderr, "Line %d: %s\n", line, message); exit(1); }
}
#define REQUIRE(condition, message) require_at((condition), (message), __LINE__)

static void expect_error(int result, const sbw_error *error, const char *expected) {
    if (result != -1 || strcmp(error->code, expected)) {
        fprintf(stderr, "Expected %s, received %s (%d)\n", expected, error->code, result);
        exit(1);
    }
    REQUIRE(!strstr(error->message, test_code) && !strstr(error->message, test_token) &&
        !strstr(error->message, "sbeasy://") && !strstr(error->message, "http://") &&
        !strstr(error->message, "secret-response"), "Error exposed untrusted or secret data");
}
static char *repeat(char c, size_t size) {
    char *value = sb_xmalloc(size + 1); memset(value, c, size); value[size] = 0; return value;
}

typedef struct http_reply {
    const char *status, *headers, *body;
    DWORD delay_headers, drip_delay;
    bool omit_length;
} http_reply;

typedef struct loopback_server {
    SOCKET listener;
    HANDLE stop, thread;
    CRITICAL_SECTION mutex;
    http_reply reply;
    char *origin, *request;
    LONG requests, failed;
} loopback_server;

static bool stopped(loopback_server *server) { return WaitForSingleObject(server->stop, 0) == WAIT_OBJECT_0; }
static bool pause_server(loopback_server *server, DWORD milliseconds) {
    return WaitForSingleObject(server->stop, milliseconds) == WAIT_OBJECT_0;
}
static bool write_socket(loopback_server *server, SOCKET socket_value, const char *data, size_t length) {
    while (length && !stopped(server)) {
        int sent = send(socket_value, data, (int)length, 0);
        if (sent <= 0) return false;
        data += sent; length -= (size_t)sent;
    }
    return !length;
}
static void serve(loopback_server *server, SOCKET connection) {
    DWORD timeout = 100;
    setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    ULONGLONG deadline = GetTickCount64() + 3000;
    sb_buf request = {0};
    size_t required = SIZE_MAX;
    while (!stopped(server) && GetTickCount64() < deadline) {
        char buffer[4096];
        int count = recv(connection, buffer, sizeof(buffer), 0);
        if (!count) goto done;
        if (count < 0) { if (WSAGetLastError() == WSAETIMEDOUT) continue; goto done; }
        sb_buf_append(&request, buffer, (size_t)count);
        if (request.len > 65536) { InterlockedExchange(&server->failed, 1); goto done; }
        char *end = strstr(request.p, "\r\n\r\n");
        if (end && required == SIZE_MAX) {
            required = (size_t)(end - request.p) + 4;
            char *headers = sb_strndup(request.p, required);
            for (char *p = headers; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p += 'a' - 'A';
            char *length = strstr(headers, "\r\ncontent-length:");
            if (length) required += (size_t)strtoul(length + 17, NULL, 10);
            free(headers);
        }
        if (required != SIZE_MAX && request.len >= required) break;
    }
    if (stopped(server)) goto done;
    if (required == SIZE_MAX || request.len < required) { InterlockedExchange(&server->failed, 1); goto done; }
    EnterCriticalSection(&server->mutex);
    free(server->request); server->request = sb_strdup(request.p);
    InterlockedIncrement(&server->requests);
    LeaveCriticalSection(&server->mutex);
    if (pause_server(server, server->reply.delay_headers)) goto done;
    const char *body = server->reply.body ? server->reply.body : "";
    sb_buf head = {0};
    sb_buf_printf(&head, "HTTP/1.1 %s\r\nConnection: close\r\n", server->reply.status ? server->reply.status : "200 OK");
    if (!server->reply.omit_length) sb_buf_printf(&head, "Content-Length: %zu\r\n", strlen(body));
    sb_buf_puts(&head, server->reply.headers ? server->reply.headers : ""); sb_buf_puts(&head, "\r\n");
    bool wrote = write_socket(server, connection, head.p, head.len);
    sb_buf_free(&head);
    if (!wrote) goto done;
    if (!server->reply.drip_delay) { (void)write_socket(server, connection, body, strlen(body)); goto done; }
    for (; *body; ++body)
        if (pause_server(server, server->reply.drip_delay) || !write_socket(server, connection, body, 1)) break;
done:
    sb_buf_free(&request);
}
static DWORD WINAPI server_thread(void *context) {
    loopback_server *server = context;
    while (!stopped(server)) {
        fd_set readable;
        FD_ZERO(&readable); FD_SET(server->listener, &readable);
        struct timeval wait = {0, 50000};
        if (select(0, &readable, NULL, NULL, &wait) <= 0) continue;
        SOCKET connection = accept(server->listener, NULL, NULL);
        if (connection == INVALID_SOCKET) continue;
        serve(server, connection);
        shutdown(connection, SD_BOTH); closesocket(connection);
    }
    return 0;
}
static void server_init(loopback_server *server) {
    memset(server, 0, sizeof(*server));
    InitializeCriticalSection(&server->mutex);
    server->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    REQUIRE(server->stop != NULL, "CreateEvent failed");
    server->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(server->listener != INVALID_SOCKET, "socket failed");
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
    REQUIRE(bind(server->listener, (const struct sockaddr *)&address, sizeof(address)) == 0, "loopback bind failed");
    REQUIRE(listen(server->listener, 4) == 0, "listen failed");
    int size = sizeof(address);
    REQUIRE(getsockname(server->listener, (struct sockaddr *)&address, &size) == 0, "getsockname failed");
    server->origin = sb_asprintf("http://127.0.0.1:%u", (unsigned)ntohs(address.sin_port));
}
static void server_start(loopback_server *server, http_reply reply) {
    server->reply = reply;
    server->thread = CreateThread(NULL, 0, server_thread, server, 0, NULL);
    REQUIRE(server->thread != NULL, "CreateThread failed");
}
static void server_free(loopback_server *server) {
    SetEvent(server->stop);
    if (server->thread) { REQUIRE(WaitForSingleObject(server->thread, 4000) == WAIT_OBJECT_0, "Fixture did not stop"); CloseHandle(server->thread); }
    closesocket(server->listener); CloseHandle(server->stop);
    REQUIRE(!server->failed, "Loopback fixture received an invalid request");
    DeleteCriticalSection(&server->mutex);
    free(server->origin); free(server->request);
}
static char *server_request(loopback_server *server) {
    EnterCriticalSection(&server->mutex);
    char *request = sb_strdup(server->request ? server->request : "");
    LeaveCriticalSection(&server->mutex);
    return request;
}

static sbj *identity(const char *server) {
    sbj *value = sbj_object();
    sbj_set_str(value, "server", server); sbj_set_str(value, "host_id", "device-1");
    sbj_set_str(value, "host_name", "Windows test device"); sbj_set_str(value, "agent_token", test_token);
    sbj_set_str(value, "profile_id", "profile-1"); sbj_set_str(value, "profile_name", "Default");
    return value;
}
static char *enrollment_response(const char *server) {
    sbj *value = sbj_object(), *profile = sbj_object();
    sbj_set_str(value, "server", server); sbj_set_str(value, "host_id", "device-1");
    sbj_set_str(value, "host_name", "Windows 测试设备"); sbj_set_str(value, "agent_token", test_token);
    sbj_set_str(profile, "id", "profile-1"); sbj_set_str(profile, "name", "默认配置"); sbj_set(value, "profile", profile);
    char *output = sbj_dump(value, -1); sbj_free(value); return output;
}
static int fetch(const sbj *device, const char *etag, DWORD timeout, HANDLE cancel, sbj **out, sbw_error *error) {
    sbw_control_plane *client = sbw_winhttp_new(timeout, error);
    REQUIRE(client != NULL, "Client creation failed");
    int result = client->fetch_config(client->context, device, etag, cancel, out, error);
    sbw_control_plane_free(client); return result;
}
static int enroll_call(const char *server, HANDLE cancel, sbj **out, sbw_error *error) {
    sbw_control_plane *client = sbw_winhttp_new(25000, error);
    REQUIRE(client != NULL, "Client creation failed");
    sbw_enrollment_target target = {(char *)server, (char *)test_code};
    int result = client->enroll(client->context, &target, cancel, out, error);
    sbw_control_plane_free(client); return result;
}
static bool field_is(const sbj *value, const char *name, const char *expected) {
    return sbj_string_is(sbj_get(value, name), expected);
}
static char *uri(const char *server) { return sb_asprintf("sbeasy://enroll?server=%s&code=%s", server, test_code); }
static void invalid_uri(const char *value) {
    sbw_enrollment_target target; sbw_error error = {0};
    expect_error(sbw_parse_enrollment_uri(value, &target, &error), &error, "invalid_enrollment_uri");
    REQUIRE(!target.server && !target.code, "Invalid URI returned partial credentials");
}

static void parser_tests(void) {
    sbw_enrollment_target target; sbw_error error = {0};
    invalid_uri(NULL);
    const char *wrapped = "  \"URL:SBEASY://ENROLL?server=HTTPS%3A%2F%2FPANEL.example%3A443%2Fsb-easy%2F&code=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"  ";
    REQUIRE(sbw_parse_enrollment_uri(wrapped, &target, &error) == 0, "Wrapper URI failed");
    REQUIRE(!strcmp(target.server, "https://panel.example/sb-easy") && !strcmp(target.code, test_code), "Normalization failed");
    sbw_enrollment_target_free(&target);
    const char *valid_servers[] = {"http://localhost:80/", "https://[::1]:443/panel", "https://panel.example/中文"};
    const char *normalized[] = {"http://localhost", "https://[::1]/panel", "https://panel.example/%E4%B8%AD%E6%96%87"};
    for (size_t i = 0; i < 3; ++i) {
        char *value = uri(valid_servers[i]);
        REQUIRE(sbw_parse_enrollment_uri(value, &target, &error) == 0 && !strcmp(target.server, normalized[i]), "Server normalization failed");
        free(value); sbw_enrollment_target_free(&target);
    }
    const char *invalid[] = {"", "https://example.com/", "sbeasy://enroll/", "sbeasy://evil?server=x", "sbeasy://user@enroll?server=x",
        "sbeasy://enroll/path?server=x", "sbeasy://enroll?server=x", "sbeasy://enroll?server=x&code=short"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) invalid_uri(invalid[i]);
    char *valid = uri("https://panel.example/prefix");
    const char *tails[] = {"&code=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "&server=https://other.example",
        "&%73erver=https://other.example", "&unknown=x", "#fragment", "&", "\r\nInjected: secret", "\xFF"};
    for (size_t i = 0; i < sizeof(tails) / sizeof(*tails); ++i) {
        char *bad = sb_asprintf("%s%s", valid, tails[i]); invalid_uri(bad); free(bad);
    }
    free(valid);
    const char *bad_servers[] = {"https://user:password@panel.example", "https://panel.example?x=y", "https://panel.example%23fragment",
        "https://panel.example%0d%0aX:bad", "https://panel.example/%250d", "https://panel.example/%252f", "https://panel.example/%00",
        "https://panel.example/a/../b", "https://panel.example/%252e%252e", "https://panel.example//path", "https://panel.example:0",
        "https://panel.example:65536", "https://panel.example:", "https://panel.example\\evil", "https://panel.example/%FF",
        "https://panel.example/%C0%AF", "https://panel.example/%ED%A0%80", "https://panel.example/%", "https://panel.example/%ZZ",
        "ftp://panel.example", "https://[invalid]", "https://-invalid.example"};
    for (size_t i = 0; i < sizeof(bad_servers) / sizeof(*bad_servers); ++i) { char *bad = uri(bad_servers[i]); invalid_uri(bad); free(bad); }
    char *long_uri = repeat('x', 8193); invalid_uri(long_uri); free(long_uri);
}

static void enrollment_tests(void) {
    sbw_error error = {0}; sbj *output = NULL;
    loopback_server server; server_init(&server);
    char *server_url = sb_asprintf("%s/prefix", server.origin), *body = enrollment_response(server_url);
    server_start(&server, (http_reply){"200 OK", "Content-Type: application/json\r\n", body, 0, 0, false});
    REQUIRE(enroll_call(server_url, NULL, &output, &error) == 0, "Enrollment failed");
    REQUIRE(field_is(output, "server", server_url) && field_is(output, "host_id", "device-1") && field_is(output, "agent_token", test_token) &&
        field_is(output, "host_name", "Windows 测试设备") && field_is(output, "profile_name", "默认配置"), "Enrollment response mismatch");
    char *request = server_request(&server);
    REQUIRE(strstr(request, "POST /prefix/api/devices/enroll HTTP/1.1\r\n") == request, "Enrollment lost base path");
    REQUIRE(!strstr(request, "Authorization:"), "Enrollment unexpectedly authenticated");
    sbj *payload = sbj_parse_cstr(strstr(request, "\r\n\r\n") + 4), *device = sbj_get(payload, "device");
    REQUIRE(field_is(payload, "code", test_code) && field_is(device, "platform", "windows") && field_is(device, "architecture", "x86_64"), "Enrollment contract mismatch");
    REQUIRE(sbj_get_bool(device, "interactive_client", false) && !sbj_get_bool(device, "supports_proxy_selection", true) &&
        !sbj_get_bool(device, "supports_local_route_stats", true) && !sbj_get_bool(device, "supports_diagnostic_upload", true), "Unsupported capability advertised");
    REQUIRE(server.requests == 1, "Enrollment retried");
    server_free(&server); free(server_url); free(body); free(request); sbj_free(payload); sbj_free(output);

    char *mismatch = enrollment_response("https://other.example"), *oversized = repeat('x', 65537);
    const char *bodies[] = {mismatch, "{secret-response", oversized};
    const char *errors[] = {"server_mismatch", "invalid_response", "response_too_large"};
    for (size_t i = 0; i < 3; ++i) {
        server_init(&server); server_start(&server, (http_reply){"200 OK", "", bodies[i], 0, 0, false});
        output = NULL; expect_error(enroll_call(server.origin, NULL, &output, &error), &error, errors[i]);
        REQUIRE(!output, "Failed enrollment returned identity"); server_free(&server);
    }
    free(mismatch); free(oversized);
}

static void config_tests(void) {
    sbw_error error = {0}; sbj *output = NULL;
    loopback_server server; server_init(&server);
    server_start(&server, (http_reply){"200 OK", "ETag: \"next\"\r\nX-SB-Easy-Rule-Source: managed\r\nX-SB-Easy-Profile-Id: profile-2\r\nX-SB-Easy-Profile-Name: 更新配置\r\n", "{\"route\":{}}", 0, 0, false});
    char *server_url = sb_asprintf("%s/prefix", server.origin); sbj *device = identity(server_url);
    REQUIRE(fetch(device, "\"previous\"", 25000, NULL, &output, &error) == 0, "Config fetch failed");
    REQUIRE(!sbj_get_bool(output, "not_modified", true) && field_is(output, "content", "{\"route\":{}}") && field_is(output, "etag", "\"next\"") &&
        field_is(output, "rule_source", "managed") && field_is(output, "profile_id", "profile-2") && field_is(output, "profile_name", "更新配置"), "Config response mismatch");
    char *request = server_request(&server), *authorization = sb_asprintf("Authorization: Bearer %s", test_token);
    REQUIRE(strstr(request, "GET /prefix/api/agent/config HTTP/1.1\r\n") == request && strstr(request, authorization) &&
        strstr(request, "If-None-Match: \"previous\""), "Missing base path/authentication/ETag");
    server_free(&server); free(server_url); free(request); free(authorization); sbj_free(device); sbj_free(output);
    const char *headers[] = {"", "ETag: \"updated\"\r\n"};
    const char *etags[] = {"\"previous\"", "\"updated\""};
    for (size_t i = 0; i < 2; ++i) {
        server_init(&server); server_start(&server, (http_reply){"304 Not Modified", headers[i], "", 0, 0, false});
        device = identity(server.origin); output = NULL;
        REQUIRE(fetch(device, "\"previous\"", 25000, NULL, &output, &error) == 0, "304 failed");
        REQUIRE(sbj_get_bool(output, "not_modified", false) && field_is(output, "content", "") && field_is(output, "etag", etags[i]) &&
            field_is(output, "rule_source", "profile") && field_is(output, "profile_id", "profile-1"), "304 metadata mismatch");
        server_free(&server); sbj_free(device); sbj_free(output);
    }
    unsigned exact_names = 0;
    const char *names[] = {"中", "🚀", "café", "中 🚀 café 配置"};
    for (size_t i = 0; i < 4; ++i) {
        char *response_headers = sb_asprintf("ETag: \"v\"\r\nX-SB-Easy-Profile-Name: %s\r\n", names[i]);
        server_init(&server); server_start(&server, (http_reply){"200 OK", response_headers, "{}", 0, 0, false});
        device = identity(server.origin); output = NULL;
        REQUIRE(fetch(device, "", 25000, NULL, &output, &error) == 0, "Unicode header fetch failed");
        REQUIRE(field_is(output, "profile_name", names[i]) || field_is(output, "profile_name", "Default"), "Profile name corrupted");
        if (field_is(output, "profile_name", names[i])) ++exact_names;
        int size = MultiByteToWideChar(CP_ACP, 0, names[i], (int)strlen(names[i]), NULL, 0);
        REQUIRE(size > 0, "Legacy header conversion failed");
        wchar_t *legacy = sb_xcalloc((size_t)size + 1, sizeof(wchar_t));
        REQUIRE(MultiByteToWideChar(CP_ACP, 0, names[i], (int)strlen(names[i]), legacy, size) == size, "Legacy header conversion failed");
        char *decoded = NULL;
        REQUIRE(sbw_decode_legacy_header(legacy, (size_t)size, true, &decoded, &error) == 0 &&
            (!*decoded || !strcmp(decoded, names[i])), "Legacy fallback returned mojibake");
        server_free(&server); free(response_headers); free(legacy); free(decoded); sbj_free(device); sbj_free(output);
    }
    printf("Unicode profile headers preserved exactly: %u/4\n", exact_names);
    char *decoded = NULL;
    REQUIRE(sbw_decode_legacy_header(L"\xFFFD", 1, true, &decoded, &error) == 0 && !*decoded, "Lossy legacy name retained"); free(decoded);
    expect_error(sbw_decode_legacy_header(L"\xFFFD", 1, false, &decoded, &error), &error, "invalid_response");
    expect_error(sbw_decode_legacy_header(L"\xFFFD\r\n", 3, true, &decoded, &error), &error, "invalid_response");
    wchar_t oversized[1025]; for (size_t i = 0; i < 1025; ++i) oversized[i] = L'x';
    expect_error(sbw_decode_legacy_header(oversized, 1025, true, &decoded, &error), &error, "response_too_large");
    server_init(&server); server_start(&server, (http_reply){"200 OK", "ETag: \"v\"\r\nX-SB-Easy-Profile-Id: profile-2\r\n", "{}", 0, 0, false});
    device = identity(server.origin); output = NULL;
    REQUIRE(fetch(device, "", 25000, NULL, &output, &error) == 0 && field_is(output, "profile_name", "profile-2"), "Old name attached to new profile ID");
    server_free(&server); sbj_free(device); sbj_free(output);
}

static void rejected_response_tests(void) {
    char *large_etag = repeat('a', 1025), *large_name = repeat('x', 1025), *large_body = repeat('x', 4U * 1024U * 1024U + 1);
    char *etag_headers = sb_asprintf("ETag: %s\r\n", large_etag), *name_headers = sb_asprintf("ETag: \"v\"\r\nX-SB-Easy-Profile-Name: %s\r\n", large_name);
    char *opening = repeat('[', 40), *closing = repeat(']', 40), *deep = sb_asprintf("{\"v\":%s0%s}", opening, closing);
    struct test_case { http_reply reply; const char *error; } cases[] = {
        {{"200 OK", "", "{}", 0, 0, false}, "invalid_response"},
        {{"200 OK", "ETag: \"v\"\r\n", "[]", 0, 0, false}, "invalid_response"},
        {{"200 OK", "ETag: \"v\"\r\n", "{bad-secret-response", 0, 0, false}, "invalid_response"},
        {{"200 OK", "ETag: \"v\"\r\n", "{\"v\":\"\xFF\"}", 0, 0, false}, "invalid_response"},
        {{"200 OK", "ETag: \"v\"\r\n", deep, 0, 0, false}, "invalid_response"},
        {{"200 OK", etag_headers, "{}", 0, 0, false}, "response_too_large"},
        {{"200 OK", "ETag: \"one\"\r\nETag: \"two\"\r\n", "{}", 0, 0, false}, "invalid_response"},
        {{"200 OK", "ETag: \"v\"\r\nX-SB-Easy-Profile-Name: one\r\nX-SB-Easy-Profile-Name: two\r\n", "{}", 0, 0, false}, "invalid_response"},
        {{"200 OK", name_headers, "{}", 0, 0, false}, "response_too_large"},
        {{"200 OK", "ETag: \"v\"\r\n", large_body, 0, 0, false}, "response_too_large"},
        {{"200 OK", "ETag: \"v\"\r\n", large_body, 0, 0, true}, "response_too_large"},
        {{"200 OK", "Content-Length: 5000000\r\nETag: \"v\"\r\n", "", 0, 0, true}, "response_too_large"},
        {{"401 Unauthorized", "WWW-Authenticate: Negotiate\r\n", "secret-response", 0, 0, false}, "http_error"},
        {{"500 Internal Server Error", "", "secret-response", 0, 0, false}, "http_error"},
        {{"201 Created", "ETag: \"v\"\r\n", "{}", 0, 0, false}, "http_error"}
    };
    sbw_error error = {0};
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        loopback_server server; server_init(&server); server_start(&server, cases[i].reply);
        sbj *device = identity(server.origin), *output = NULL;
        expect_error(fetch(device, "", 25000, NULL, &output, &error), &error, cases[i].error);
        REQUIRE(!output && server.requests == 1, "Failure returned config or retried authentication");
        server_free(&server); sbj_free(device);
    }
    free(large_etag); free(large_name); free(large_body); free(etag_headers); free(name_headers); free(opening); free(closing); free(deep);
    loopback_server destination, redirect;
    server_init(&destination); server_start(&destination, (http_reply){"200 OK", "ETag: \"v\"\r\n", "{}", 0, 0, false});
    char *location = sb_asprintf("Location: %s/token-sink\r\n", destination.origin);
    server_init(&redirect); server_start(&redirect, (http_reply){"302 Found", location, "", 0, 0, false});
    sbj *device = identity(redirect.origin), *output = NULL;
    expect_error(fetch(device, "", 25000, NULL, &output, &error), &error, "redirect_rejected");
    REQUIRE(!destination.requests, "Bearer token followed redirect");
    server_free(&destination); server_free(&redirect); free(location); sbj_free(device);
    loopback_server unused; server_init(&unused); server_start(&unused, (http_reply){0});
    device = identity(unused.origin); sbj_set_str(device, "agent_token", "bad\r\nX-Injected: bad");
    expect_error(fetch(device, "", 25000, NULL, &output, &error), &error, "invalid_identity");
    sbj_set_str(device, "agent_token", test_token);
    expect_error(fetch(device, "\"v\"\r\nX: bad", 25000, NULL, &output, &error), &error, "invalid_identity");
    char *oversized = repeat('x', 1025);
    expect_error(fetch(device, oversized, 25000, NULL, &output, &error), &error, "invalid_identity");
    REQUIRE(!unused.requests, "Invalid header reached network");
    server_free(&unused); free(oversized); sbj_free(device);
}

typedef struct cancellation { HANDLE event; DWORD delay; } cancellation;
static DWORD WINAPI signal_cancel(void *context) {
    cancellation *cancel = context; Sleep(cancel->delay); SetEvent(cancel->event); return 0;
}
static void cancellation_tests(void) {
    sbw_error error = {0};
    for (unsigned drip = 0; drip < 2; ++drip) {
        loopback_server server; server_init(&server);
        server_start(&server, (http_reply){"200 OK", "ETag: \"v\"\r\n", "{\"value\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", drip ? 0 : 5000, drip ? 20 : 0, false});
        sbj *device = identity(server.origin), *output = NULL;
        ULONGLONG before = GetTickCount64();
        expect_error(fetch(device, "", 180, NULL, &output, &error), &error, "timeout");
        REQUIRE(GetTickCount64() - before < 1500, "Request ignored total deadline");
        server_free(&server); sbj_free(device);
    }
    loopback_server blocked; server_init(&blocked);
    server_start(&blocked, (http_reply){"200 OK", "ETag: \"v\"\r\n", "{}", 5000, 0, false});
    cancellation cancel = {CreateEventW(NULL, TRUE, FALSE, NULL), 80};
    REQUIRE(cancel.event != NULL, "CreateEvent failed");
    HANDLE thread = CreateThread(NULL, 0, signal_cancel, &cancel, 0, NULL); REQUIRE(thread != NULL, "CreateThread failed");
    sbj *device = identity(blocked.origin), *output = NULL;
    ULONGLONG before = GetTickCount64();
    expect_error(fetch(device, "", 25000, cancel.event, &output, &error), &error, "cancelled");
    REQUIRE(GetTickCount64() - before < 1500, "Request ignored cancellation");
    WaitForSingleObject(thread, INFINITE); CloseHandle(thread); server_free(&blocked); sbj_free(device);
    loopback_server unused; server_init(&unused); server_start(&unused, (http_reply){0}); device = identity(unused.origin);
    expect_error(fetch(device, "", 25000, cancel.event, &output, &error), &error, "cancelled");
    REQUIRE(!unused.requests, "Pre-cancelled request reached network");
    server_free(&unused); sbj_free(device); CloseHandle(cancel.event);
    loopback_server fast; server_init(&fast); server_start(&fast, (http_reply){"200 OK", "ETag: \"v\"\r\n", "{}", 0, 0, false});
    device = identity(fast.origin);
    for (unsigned i = 0; i < 20; ++i) {
        cancellation racing = {CreateEventW(NULL, TRUE, FALSE, NULL), 1};
        REQUIRE(racing.event != NULL, "CreateEvent failed");
        thread = CreateThread(NULL, 0, signal_cancel, &racing, 0, NULL); REQUIRE(thread != NULL, "CreateThread failed");
        output = NULL;
        int result = fetch(device, "", 25000, racing.event, &output, &error);
        if (result) expect_error(result, &error, "cancelled");
        sbj_free(output); WaitForSingleObject(thread, INFINITE); CloseHandle(thread); CloseHandle(racing.event);
    }
    server_free(&fast); sbj_free(device);
}

int main(void) {
    WSADATA winsock;
    REQUIRE(WSAStartup(MAKEWORD(2, 2), &winsock) == 0, "WSAStartup failed");
    puts("URI parser tests"); parser_tests();
    puts("Enrollment tests"); enrollment_tests();
    puts("Config tests"); config_tests();
    puts("Rejected response tests"); rejected_response_tests();
    puts("Cancellation tests"); cancellation_tests();
    WSACleanup();
    puts("C11 control-plane parser and loopback transport tests passed.");
    return 0;
}
