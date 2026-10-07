#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/runtime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s (%s)\n", __FILE__, __LINE__, #condition, error.code); goto done; \
} } while (0)

typedef struct fake_api {
    SOCKET listener;
    HANDLE stop;
    HANDLE thread;
    HANDLE received;
    unsigned short port;
    const char *secret;
    const char *response;
    bool auth_ok;
} fake_api;

static DWORD WINAPI api_thread(void *value) {
    fake_api *api = value;
    SOCKET peer = INVALID_SOCKET;
    while (WaitForSingleObject(api->stop, 0) == WAIT_TIMEOUT) {
        fd_set readable;
        FD_ZERO(&readable); FD_SET(api->listener, &readable);
        struct timeval interval = {0, 20000};
        if (select(0, &readable, NULL, NULL, &interval) > 0) {
            peer = accept(api->listener, NULL, NULL);
            break;
        }
    }
    if (peer == INVALID_SOCKET) return 0;
    DWORD timeout = 500;
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    char request[2048] = {0};
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        int size = recv(peer, request + used, (int)(sizeof(request) - 1 - used), 0);
        if (size <= 0) break;
        used += (size_t)size;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n")) break;
    }
    char expected[100];
    (void)sprintf_s(expected, sizeof(expected), "Authorization: Bearer %s\r\n", api->secret);
    api->auth_ok = !strncmp(request, "GET /version HTTP/1.0\r\n", 23) && strstr(request, expected) != NULL;
    SetEvent(api->received);
    if (api->response) {
        size_t sent = 0, length = strlen(api->response);
        while (sent < length) {
            int size = send(peer, api->response + sent, (int)(length - sent), 0);
            if (size <= 0) break;
            sent += (size_t)size;
        }
    } else (void)WaitForSingleObject(api->stop, 3000);
    shutdown(peer, SD_BOTH); closesocket(peer);
    return 0;
}

static bool api_start(fake_api *api, const char *secret, const char *response) {
    memset(api, 0, sizeof(*api));
    api->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    api->secret = secret; api->response = response;
    if (api->listener == INVALID_SOCKET) return false;
    BOOL exclusive = TRUE;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int length = sizeof(address);
    if (setsockopt(api->listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive)) ||
        bind(api->listener, (const struct sockaddr *)&address, sizeof(address)) || listen(api->listener, 1) ||
        getsockname(api->listener, (struct sockaddr *)&address, &length)) return false;
    api->port = ntohs(address.sin_port);
    api->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    api->received = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!api->stop || !api->received) return false;
    api->thread = CreateThread(NULL, 0, api_thread, api, 0, NULL);
    return api->thread != NULL;
}

static void api_stop(fake_api *api) {
    if (api->stop) SetEvent(api->stop);
    if (api->thread) { (void)WaitForSingleObject(api->thread, 4000); CloseHandle(api->thread); }
    if (api->stop) CloseHandle(api->stop);
    if (api->received) CloseHandle(api->received);
    if (api->listener != INVALID_SOCKET) closesocket(api->listener);
    memset(api, 0, sizeof(*api)); api->listener = INVALID_SOCKET;
}

static DWORD WINAPI cancel_after_request(void *value) {
    fake_api *api = value;
    if (WaitForSingleObject(api->received, 2000) == WAIT_OBJECT_0) SetEvent(api->stop);
    return 0;
}

static bool rejected(const char *text, const char *code) {
    sbw_runtime_config config = {0};
    sbw_error error = {0};
    bool ok = sbw_runtime_config_prepare(text, strlen(text), "https://control.example/prefix", &config, &error) != 0 &&
        !strcmp(error.code, code) && !config.json && !config.secret;
    sbw_runtime_config_free(&config);
    return ok;
}

static HANDLE independent_process(DWORD *pid) {
    wchar_t path[32768];
    DWORD size = GetModuleFileNameW(NULL, path, (DWORD)(sizeof(path) / sizeof(*path)));
    if (!size || size >= sizeof(path) / sizeof(*path)) return NULL;
    size_t capacity = wcslen(path) + 20;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    (void)_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --wait", path);
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0}; startup.cb = sizeof(startup);
    bool started = CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process) != FALSE;
    free(command);
    if (!started) return NULL;
    CloseHandle(process.hThread); *pid = process.dwProcessId;
    return process.hProcess;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && !wcscmp(argv[1], L"--wait")) { Sleep(INFINITE); return 0; }
    sbw_error error = {0};
    sbw_runtime_config config = {0}, other = {0};
    sbj *value = NULL;
    fake_api api = {0}; api.listener = INVALID_SOCKET;
    HANDLE cancel = NULL, canceller = NULL, unrelated = NULL;
    char *large_response = NULL;
    WSADATA startup;
    bool sockets = WSAStartup(MAKEWORD(2, 2), &startup) == 0;
    int result = 1;
    CHECK(sockets);
    const char candidate[] = "{\"mode\":\"fixture\",\"inbounds\":[{\"type\":\"tun\",\"address\":[\"172.30.0.1/30\"],\"auto_route\":false,\"strict_route\":true,\"auto_redirect\":true,\"include_uid\":[1000]}],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\",\"bind_interface\":\"eth0\"}],\"route\":{\"default_interface\":\"eth0\",\"rules\":[{\"outbound\":\"direct\"}]},\"log\":{\"output\":\"C:/sensitive/log\"},\"ntp\":{\"enabled\":true},\"experimental\":{\"cache_file\":{\"enabled\":true,\"path\":\"C:/sensitive/db\"},\"debug\":{},\"clash_api\":{\"external_controller\":\"0.0.0.0:9090\",\"secret\":\"old-secret\",\"external_ui\":\"C:/sensitive/ui\",\"external_ui_download_url\":\"https://bad.example/ui.zip\"}}}";
    CHECK(sbw_runtime_config_prepare(candidate, strlen(candidate), "https://control.example/prefix", &config, &error) == 0);
    CHECK(config.has_tun && !config.auto_route && !wcscmp(config.interface_name, L"sb-easy"));
    CHECK(strlen(config.secret) == 64 && config.port && strstr(candidate, "old-secret"));
    value = sbw_json_parse(config.json, strlen(config.json), 40, NULL);
    CHECK(sbj_is_object(value) && !strcmp(sbj_get_str(value, "mode", ""), "fixture"));
    CHECK(!strstr(config.json, "sensitive") && !strstr(config.json, "old-secret") && !strstr(config.json, "bad.example"));
    sbj *tun = sbj_arr_at(sbj_get(value, "inbounds"), 0);
    CHECK(!sbj_get_bool(tun, "auto_route", true) && sbj_get_bool(tun, "strict_route", false));
    CHECK(!sbj_has(tun, "auto_redirect") && !sbj_has(tun, "include_uid"));
    sbj *route = sbj_get(value, "route"), *rules = sbj_get(route, "rules");
    CHECK(sbj_get_bool(route, "auto_detect_interface", false) && !sbj_has(route, "default_interface"));
    CHECK(sbj_arr_len(rules) == 3 && sbj_has(sbj_arr_at(rules, 0), "process_name"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(rules, 1), "domain"), 0), "control.example"));
    CHECK(sbj_get_bool(sbj_get(value, "log"), "disabled", false) && !sbj_has(value, "ntp"));
    sbj_free(value); value = NULL;
    CHECK(sbw_runtime_config_prepare("{}", 2, "http://[::1]:8080/", &other, &error) == 0);
    CHECK(!other.has_tun && !other.auto_route && !other.interface_name && strcmp(config.secret, other.secret));
    CHECK(strstr(other.json, "::1/128"));
    sbw_runtime_config_free(&other);
    const char isolated[] = "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"sb-easy-test_42\",\"auto_route\":true}]}";
    CHECK(sbw_runtime_config_prepare(isolated, strlen(isolated), "https://192.0.2.1/", &other, &error) == 0);
    CHECK(other.has_tun && other.auto_route && !wcscmp(other.interface_name, L"sb-easy-test_42") && strstr(other.json, "192.0.2.1/32"));
    sbw_runtime_config_free(&other);
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\"},{\"type\":\"tun\"}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"platform\":{}}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"bad/name\"}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"auto_route\":\"false\"}]}", "RUNTIME_CONFIG_INVALID"));
    CHECK(rejected("{\"route\":{\"rule_set\":[{\"type\":\"local\",\"path\":\"private.txt\"}]}}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"outbounds\":[{\"type\":\"shadowsocks\",\"plugin\":\"cmd.exe\"}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"outbounds\":[{\"type\":\"trojan\",\"tls\":{\"certificate_path\":\"private.txt\"}}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"outbounds\":[{\"type\":\"trojan\",\"tls\":{\"ech\":{\"config_path\":\"private.txt\"}}}]}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"dns\":{\"servers\":[{\"type\":\"hosts\",\"path\":\"private.txt\"}]}}", "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"log\\u0000extra\":{}}", "RUNTIME_CONFIG_INVALID"));

    const char healthy[] = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"sing-box 1.13.12\",\"meta\":true}";
    CHECK(api_start(&api, config.secret, healthy)); config.port = api.port;
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 2000, &error) == 0);
    CHECK(api.auth_ok); api_stop(&api);
    CHECK(api_start(&api, config.secret, "HTTP/1.0 302 Found\r\nLocation: https://unrelated.invalid/\r\n\r\n")); config.port = api.port;
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 1000, &error) != 0 && !strcmp(error.code, "CORE_HEALTH_FAILED"));
    api_stop(&api);
    CHECK(api_start(&api, config.secret, "HTTP/1.0 200 OK\r\n\r\n{\"version\":\"SECRET_BODY_DO_NOT_EXPOSE\"}")); config.port = api.port;
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 1000, &error) != 0 && !strstr(error.message, "SECRET_BODY"));
    api_stop(&api);
    large_response = sb_xcalloc(20001, 1); memset(large_response, 'x', 20000);
    CHECK(api_start(&api, config.secret, large_response)); config.port = api.port;
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 1000, &error) != 0);
    api_stop(&api);
    CHECK(api_start(&api, config.secret, NULL)); config.port = api.port;
    ULONGLONG before = GetTickCount64();
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 100, &error) != 0 && !strcmp(error.code, "CORE_HEALTH_TIMEOUT"));
    CHECK(GetTickCount64() - before < 500); api_stop(&api);
    CHECK(api_start(&api, config.secret, NULL)); config.port = api.port;
    canceller = CreateThread(NULL, 0, cancel_after_request, &api, 0, NULL); CHECK(canceller);
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), api.stop, 2000, &error) != 0 && !strcmp(error.code, "CORE_CANCELLED"));
    CHECK(WaitForSingleObject(canceller, 2000) == WAIT_OBJECT_0); CloseHandle(canceller); canceller = NULL; api_stop(&api);
    cancel = CreateEventW(NULL, TRUE, TRUE, NULL); CHECK(cancel);
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), cancel, 1000, &error) != 0 && !strcmp(error.code, "CORE_CANCELLED"));
    DWORD unrelated_pid = 0;
    unrelated = independent_process(&unrelated_pid); CHECK(unrelated);
    CHECK(api_start(&api, config.secret, healthy)); config.port = api.port;
    CHECK(sbw_runtime_config_health(&config, unrelated_pid, NULL, 1000, &error) != 0 && !strcmp(error.code, "CORE_HEALTH_IDENTITY"));
    CHECK(WaitForSingleObject(api.received, 0) == WAIT_TIMEOUT); api_stop(&api);
    before = GetTickCount64();
    CHECK(sbw_runtime_config_health(&config, GetCurrentProcessId(), NULL, 100, &error) != 0 && !strcmp(error.code, "CORE_HEALTH_TIMEOUT"));
    CHECK(GetTickCount64() - before < 500);
    result = 0;
    puts("runtime_config_test: passed (fake loopback only; no TUN or routes)");
done:
    if (canceller) { if (api.received) SetEvent(api.received); (void)WaitForSingleObject(canceller, 2500); CloseHandle(canceller); }
    api_stop(&api);
    if (cancel) CloseHandle(cancel);
    if (unrelated) { TerminateProcess(unrelated, 0); (void)WaitForSingleObject(unrelated, 2000); CloseHandle(unrelated); }
    free(large_response); sbj_free(value);
    sbw_runtime_config_free(&config); sbw_runtime_config_free(&other);
    if (sockets) WSACleanup();
    return result;
}
