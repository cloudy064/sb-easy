#include <winsock2.h>
#include <ws2tcpip.h>
#include "../ui-host/local_web.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static volatile LONG callback_count;
static HANDLE callback_entered;
static HANDLE callback_release;

static char *rpc(const char *request, size_t length, void *user) {
    assert(user == &callback_count);
    assert(length == strlen(request));
    assert(!strcmp(request, "{\"method\":\"status.get\"}"));
    InterlockedIncrement(&callback_count);
    if (callback_entered) {
        SetEvent(callback_entered);
        assert(WaitForSingleObject(callback_release, 5000) == WAIT_OBJECT_0);
    }
    return _strdup("{\"ok\":true,\"result\":{}}");
}

static DWORD WINAPI stop_server(void *server) {
    sbw_local_web_stop((sbw_local_web *)server);
    return 0;
}

static SOCKET connect_local(unsigned short port) {
    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(socket_handle != INVALID_SOCKET);
    DWORD timeout = 3000;
    assert(!setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    assert(!connect(socket_handle, (const struct sockaddr *)&address, sizeof(address)));
    return socket_handle;
}

static char *request(unsigned short port, const char *wire) {
    SOCKET socket_handle = connect_local(port);
    size_t length = strlen(wire), sent = 0;
    while (sent < length) {
        int count = send(socket_handle, wire + sent, (int)(length - sent), 0);
        assert(count > 0);
        sent += (size_t)count;
    }
    char *response = (char *)calloc(32768, 1);
    assert(response);
    size_t used = 0;
    for (;;) {
        int count = recv(socket_handle, response + used, (int)(32767 - used), 0);
        assert(count >= 0);
        if (!count) break;
        used += (size_t)count;
        assert(used < 32767);
    }
    closesocket(socket_handle);
    return response;
}

static void status_is(const char *response, int status) {
    char expected[32];
    snprintf(expected, sizeof(expected), "HTTP/1.1 %d ", status);
    if (strncmp(response, expected, strlen(expected))) {
        fprintf(stderr, "Unexpected HTTP status (wanted %d): %.30s\n", status, response);
        abort();
    }
}

static void write_file(const wchar_t *root, const wchar_t *name, const char *contents) {
    wchar_t path[MAX_PATH];
    assert(swprintf(path, MAX_PATH, L"%ls\\%ls", root, name) > 0);
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    assert(WriteFile(file, contents, (DWORD)strlen(contents), &written, NULL));
    assert(written == strlen(contents));
    CloseHandle(file);
}

static void remove_file(const wchar_t *root, const wchar_t *name) {
    wchar_t path[MAX_PATH];
    assert(swprintf(path, MAX_PATH, L"%ls\\%ls", root, name) > 0);
    assert(DeleteFileW(path));
}

int main(void) {
    WSADATA data;
    assert(!WSAStartup(MAKEWORD(2, 2), &data));
    wchar_t temporary[MAX_PATH], root[MAX_PATH], assets[MAX_PATH], extension_dir[MAX_PATH], plugin[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, temporary));
    assert(GetTempFileNameW(temporary, L"sbw", 0, root));
    assert(DeleteFileW(root));
    assert(CreateDirectoryW(root, NULL));
    assert(swprintf(assets, MAX_PATH, L"%ls\\assets", root) > 0);
    assert(CreateDirectoryW(assets, NULL));
    assert(swprintf(extension_dir, MAX_PATH, L"%ls\\extensions", root) > 0);
    assert(CreateDirectoryW(extension_dir, NULL));
    assert(swprintf(plugin, MAX_PATH, L"%ls\\test-plugin", extension_dir) > 0);
    assert(CreateDirectoryW(plugin, NULL));
    write_file(root, L"index.html", "<!doctype html><title>Local UI</title>");
    write_file(root, L"plugin-frame.html", "<!doctype html><title>Plugin</title>");
    write_file(root, L"plugin-frame.js", "// isolated wrapper");
    write_file(root, L"private.json", "must not be served");
    write_file(assets, L"app.js", "console.log('local');");
    write_file(assets, L"app.js.map", "must not be served");
    write_file(plugin, L"view.js", "export function mount() {}");
    sbw_error error = {0};
    sbw_local_web *server = sbw_local_web_start(root, rpc, (void *)&callback_count, &error);
    assert(server);
    unsigned short port = sbw_local_web_port(server);
    assert(port);
    const char *token = sbw_local_web_token(server);
    assert(token && strlen(token) == 64 && strspn(token, "0123456789abcdef") == 64);
    char wire[4096];
    snprintf(wire, sizeof(wire), "GET / HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", (unsigned)port);
    char *response = request(port, wire);
    status_is(response, 200);
    assert(strstr(response, "Local UI"));
    assert(strstr(response, "frame-ancestors 'none'"));
    assert(strstr(response, "Cache-Control: no-store"));
    assert(strstr(response, "X-Content-Type-Options: nosniff"));
    assert(strstr(response, "Referrer-Policy: no-referrer"));
    assert(!strstr(response, "Access-Control-Allow-Origin"));
    free(response);

    const char *safe_paths[] = {"/assets/app.js", "/extensions/test-plugin/view.js", "/plugin-frame.js"};
    for (size_t i = 0; i < sizeof(safe_paths) / sizeof(safe_paths[0]); ++i) {
        snprintf(wire, sizeof(wire), "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: null\r\n\r\n", safe_paths[i], (unsigned)port);
        response = request(port, wire);
        status_is(response, 200);
        assert(strstr(response, "Access-Control-Allow-Origin: null"));
        free(response);
    }
    snprintf(wire, sizeof(wire), "GET /plugin-frame.html HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", (unsigned)port);
    response = request(port, wire);
    status_is(response, 200);
    assert(strstr(response, "frame-ancestors 'self'"));
    assert(strstr(response, "connect-src 'none'"));
    assert(!strstr(response, "X-Frame-Options: DENY"));
    free(response);

    const char *bad_paths[] = {"/private.json", "/assets/app.js.map", "/../index.html", "/assets/../index.html",
        "/assets/%2e%2e/index.html", "/assets/..\\index.html", "/assets/app.js:secret", "/extensions/test-plugin/private.json"};
    for (size_t i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); ++i) {
        snprintf(wire, sizeof(wire), "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", bad_paths[i], (unsigned)port);
        response = request(port, wire);
        status_is(response, 404);
        assert(!strstr(response, "must not be served"));
        free(response);
    }
    snprintf(wire, sizeof(wire), "GET / HTTP/1.1\r\nHost: attacker.invalid:%u\r\n\r\n", (unsigned)port);
    response = request(port, wire); status_is(response, 403); free(response);
    static const char body[] = "{\"method\":\"status.get\"}";
    char wrong_token[65];
    memcpy(wrong_token, token, sizeof(wrong_token));
    wrong_token[63] = token[63] == '0' ? '1' : '0';
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: http://127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, (unsigned)port, wrong_token, sizeof(body) - 1, body);
    response = request(port, wire); status_is(response, 403); free(response);
    snprintf(wire, sizeof(wire), "OPTIONS /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: https://attacker.invalid\r\n\r\n", (unsigned)port);
    response = request(port, wire); status_is(response, 405); assert(!strstr(response, "Access-Control-Allow-Origin")); free(response);
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, (unsigned)port, sizeof(body) - 1, body);
    response = request(port, wire); status_is(response, 403); free(response);
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: https://attacker.invalid\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, token, sizeof(body) - 1, body);
    response = request(port, wire); status_is(response, 403); free(response);
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: null\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, token, sizeof(body) - 1, body);
    response = request(port, wire); status_is(response, 403); free(response);
    assert(callback_count == 0);
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: http://127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, (unsigned)port, token, sizeof(body) - 1, body);
    response = request(port, wire); status_is(response, 200); assert(strstr(response, "\"ok\":true")); assert(!strstr(response, "Access-Control-Allow-Origin")); free(response);
    assert(callback_count == 1);
    const char *malformed[] = {"Content-Length: 2\r\nContent-Length: 2\r\n", "Transfer-Encoding: chunked\r\n", "Content-Length: 1048577\r\n"};
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: http://127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%s\r\n", (unsigned)port, (unsigned)port, token, malformed[i]);
        response = request(port, wire); status_is(response, i == 2 ? 413 : 400); free(response);
    }
    assert(callback_count == 1);

    /* Reject reparse points even when their targets are otherwise safe. The
     * unprivileged symlink flag requires Developer Mode; skip if unavailable. */
    wchar_t link[MAX_PATH], target[MAX_PATH];
    assert(swprintf(link, MAX_PATH, L"%ls\\linked.js", assets) > 0);
    assert(swprintf(target, MAX_PATH, L"%ls\\app.js", assets) > 0);
    if (CreateSymbolicLinkW(link, target, 2)) {
        snprintf(wire, sizeof(wire), "GET /assets/linked.js HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", (unsigned)port);
        response = request(port, wire); status_is(response, 404); free(response);
        assert(DeleteFileW(link));
    }
    /* Stop interrupts waiting network clients, but must join an RPC callback
     * before freeing its context. The tray supplies its pipe cancellation. */
    callback_entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    callback_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    assert(callback_entered && callback_release);
    SOCKET calling = connect_local(port);
    snprintf(wire, sizeof(wire), "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nOrigin: http://127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", (unsigned)port, (unsigned)port, token, sizeof(body) - 1, body);
    assert(send(calling, wire, (int)strlen(wire), 0) == (int)strlen(wire));
    assert(WaitForSingleObject(callback_entered, 3000) == WAIT_OBJECT_0);
    SOCKET idle[3];
    for (size_t i = 0; i < 3; ++i) {
        idle[i] = connect_local(port);
        assert(send(idle[i], "GET / HTTP/1.1\r\n", 16, 0) == 16);
    }
    ULONGLONG started = GetTickCount64();
    HANDLE stopping_thread = CreateThread(NULL, 0, stop_server, server, 0, NULL);
    assert(stopping_thread);
    assert(WaitForSingleObject(stopping_thread, 100) == WAIT_TIMEOUT);
    SetEvent(callback_release);
    assert(WaitForSingleObject(stopping_thread, 5000) == WAIT_OBJECT_0);
    assert(GetTickCount64() - started < 5000);
    CloseHandle(stopping_thread);
    CloseHandle(callback_entered);
    CloseHandle(callback_release);
    closesocket(calling);
    for (size_t i = 0; i < 3; ++i) closesocket(idle[i]);
    remove_file(root, L"index.html");
    remove_file(root, L"plugin-frame.html");
    remove_file(root, L"plugin-frame.js");
    remove_file(root, L"private.json");
    remove_file(assets, L"app.js");
    remove_file(assets, L"app.js.map");
    remove_file(plugin, L"view.js");
    assert(RemoveDirectoryW(plugin));
    assert(RemoveDirectoryW(extension_dir));
    assert(RemoveDirectoryW(assets));
    assert(RemoveDirectoryW(root));
    WSACleanup();
    puts("local web transport tests passed");
    return 0;
}
