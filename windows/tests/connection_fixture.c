#include <winsock2.h>
#include <ws2tcpip.h>
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Test-only core: no proxy, TUN, DNS or routing behavior. It implements only
 * the exact process-owned loopback health endpoint requested by the adapter. */
static HANDLE stop_event;
static BOOL WINAPI control_event(DWORD event) {
    if (event != CTRL_BREAK_EVENT) return FALSE;
    SetEvent(stop_event); return TRUE;
}

static sbj *read_config(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    DWORD size = GetFileSize(file, NULL), read = 0;
    if (size == INVALID_FILE_SIZE || size > 8U * 1024U * 1024U) { CloseHandle(file); return NULL; }
    char *text = sb_xcalloc((size_t)size + 1, 1);
    bool ok = ReadFile(file, text, size, &read, NULL) && read == size;
    CloseHandle(file);
    sbj *config = ok ? sbw_json_parse(text, size, 40, NULL) : NULL;
    sbw_secret_free(text); return config;
}

static bool send_all(SOCKET client, const char *text) {
    size_t size = strlen(text), sent = 0;
    while (sent < size) {
        int count = send(client, text + sent, (int)(size - sent), 0);
        if (count <= 0) return false;
        sent += (size_t)count;
    }
    return true;
}

static bool serve_client(SOCKET client, const char *secret, bool unhealthy) {
    char request[4096] = {0}, authorization[128];
    size_t used = 0;
    DWORD timeout = 500;
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    while (used < sizeof(request) - 1 && !strstr(request, "\r\n\r\n")) {
        int count = recv(client, request + used, (int)(sizeof(request) - 1 - used), 0);
        if (count <= 0) break;
        used += (size_t)count; request[used] = '\0';
    }
    (void)sprintf_s(authorization, sizeof(authorization), "\r\nAuthorization: Bearer %s\r\n", secret);
    bool authorized = !strncmp(request, "GET /version HTTP/1.", 20) && strstr(request, authorization) &&
        strstr(request, "\r\n\r\n") && strlen(request) == used;
    const char *body = authorized && !unhealthy ? "{\"version\":\"sing-box 1.13.12\"}" :
        "{\"error\":\"CONNECTION_FIXTURE_SECRET_NEVER_RETURN_THIS\"}";
    const char *status = !authorized ? "401 Unauthorized" : unhealthy ? "503 Unavailable" : "200 OK";
    char response[512];
    (void)sprintf_s(response, sizeof(response), "HTTP/1.0 %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        status, strlen(body), body);
    bool ok = send_all(client, response);
    SecureZeroMemory(request, sizeof(request)); SecureZeroMemory(authorization, sizeof(authorization));
    return ok && authorized && !unhealthy;
}

static int run_core(const sbj *config) {
    const sbj *api = sbj_get(sbj_get(config, "experimental"), "clash_api");
    const char *controller = sbj_get_str(api, "external_controller", ""), *secret = sbj_get_str(api, "secret", "");
    const char *mode = sbj_get_str(config, "mode", "good");
    if (strncmp(controller, "127.0.0.1:", 10) || strlen(secret) != 64) return 73;
    char *end = NULL; unsigned long port = strtoul(controller + 10, &end, 10);
    if (!end || *end || !port || port > 65535) return 73;
    const sbj *inbounds = sbj_get(config, "inbounds");
    for (size_t i = 0; i < sbj_arr_len(inbounds); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(inbounds, i), "type"), "tun")) return 74;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event || !SetConsoleCtrlHandler(control_event, TRUE)) return 75;
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) { CloseHandle(stop_event); return 76; }
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL exclusive = TRUE;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons((unsigned short)port);
    int result = 77;
    if (listener == INVALID_SOCKET || setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        (const char *)&exclusive, sizeof(exclusive)) || bind(listener, (const struct sockaddr *)&address, sizeof(address))) goto done;
    int64_t delay = sbj_get_int(config, "health_delay_ms", 0);
    if (delay < 0 || delay > 1500) goto done;
    if (delay && WaitForSingleObject(stop_event, (DWORD)delay) == WAIT_OBJECT_0) { result = 0; goto done; }
    const char *gate_name = sbj_get_str(config, "health_event", "");
    if (*gate_name) {
        wchar_t *wide = sbw_wide(gate_name, NULL);
        HANDLE gate = wide ? OpenEventW(SYNCHRONIZE, FALSE, wide) : NULL; free(wide);
        if (!gate) goto done;
        HANDLE gates[] = {stop_event, gate};
        DWORD waited = WaitForMultipleObjects(2, gates, FALSE, 5000); CloseHandle(gate);
        if (waited == WAIT_OBJECT_0) { result = 0; goto done; }
        if (waited != WAIT_OBJECT_0 + 1) goto done;
    }
    if (listen(listener, 4)) goto done;
    ULONGLONG crash_at = 0;
    for (;;) {
        if (WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) { result = 0; break; }
        if (crash_at && GetTickCount64() >= crash_at) { result = 23; break; }
        fd_set read; FD_ZERO(&read); FD_SET(listener, &read);
        struct timeval interval = {0, 50000};
        int ready = select(0, &read, NULL, NULL, &interval);
        if (ready == SOCKET_ERROR) break;
        if (!ready) continue;
        SOCKET client = accept(listener, NULL, NULL);
        if (client == INVALID_SOCKET) break;
        bool healthy = serve_client(client, secret, !strcmp(mode, "health_fail"));
        shutdown(client, SD_BOTH); closesocket(client);
        if (healthy && !strcmp(mode, "crash") && !crash_at) crash_at = GetTickCount64() + 1500;
    }
done:
    if (listener != INVALID_SOCKET) closesocket(listener);
    WSACleanup(); SetConsoleCtrlHandler(control_event, FALSE); CloseHandle(stop_event); stop_event = NULL;
    return result;
}

int wmain(int argc, wchar_t **argv) {
    BOOL in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job) return 70;
    if (argc != 5 || (wcscmp(argv[1], L"check") && wcscmp(argv[1], L"run")) ||
        wcscmp(argv[2], L"-c") || wcscmp(argv[4], L"--disable-color")) return 71;
    sbj *config = read_config(argv[3]);
    if (!sbj_is_object(config)) { sbj_free(config); return 72; }
    int result;
    if (!wcscmp(argv[1], L"check")) {
        result = sbj_string_is(sbj_get(config, "mode"), "check_fail") ? 17 : 0;
        if (result) fputs("CONNECTION_FIXTURE_SECRET_NEVER_RETURN_THIS\n", stderr);
    } else result = run_core(config);
    sbj_free(config); return result;
}
