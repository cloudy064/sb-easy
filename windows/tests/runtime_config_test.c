#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/runtime_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (%s)\n", __FILE__, __LINE__, #condition, s->error.code);    \
            return false;                                                                          \
        }                                                                                          \
    } while (0)

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
        FD_ZERO(&readable);
        FD_SET(api->listener, &readable);
        struct timeval interval = {0, 20000};
        if (select(0, &readable, NULL, NULL, &interval) > 0) {
            peer = accept(api->listener, NULL, NULL);
            break;
        }
    }
    if (peer == INVALID_SOCKET)
        return 0;
    DWORD timeout = 500;
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    char request[2048] = {0};
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        int size = recv(peer, request + used, (int)(sizeof(request) - 1 - used), 0);
        if (size <= 0)
            break;
        used += (size_t)size;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            break;
    }
    char expected[100];
    (void)sprintf_s(expected, sizeof(expected), "Authorization: Bearer %s\r\n", api->secret);
    api->auth_ok =
        !strncmp(request, "GET /version HTTP/1.0\r\n", 23) && strstr(request, expected) != NULL;
    SetEvent(api->received);
    if (api->response) {
        size_t sent = 0, length = strlen(api->response);
        while (sent < length) {
            int size = send(peer, api->response + sent, (int)(length - sent), 0);
            if (size <= 0)
                break;
            sent += (size_t)size;
        }
    } else
        (void)WaitForSingleObject(api->stop, 3000);
    shutdown(peer, SD_BOTH);
    closesocket(peer);
    return 0;
}

static bool api_start(fake_api *api, const char *secret, const char *response) {
    memset(api, 0, sizeof(*api));
    api->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    api->secret = secret;
    api->response = response;
    if (api->listener == INVALID_SOCKET)
        return false;
    BOOL exclusive = TRUE;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int length = sizeof(address);
    if (setsockopt(api->listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive,
                   sizeof(exclusive)) ||
        bind(api->listener, (const struct sockaddr *)&address, sizeof(address)) ||
        listen(api->listener, 1) ||
        getsockname(api->listener, (struct sockaddr *)&address, &length))
        return false;
    api->port = ntohs(address.sin_port);
    api->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    api->received = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!api->stop || !api->received)
        return false;
    api->thread = CreateThread(NULL, 0, api_thread, api, 0, NULL);
    return api->thread != NULL;
}

static void api_stop(fake_api *api) {
    if (api->stop)
        SetEvent(api->stop);
    if (api->thread) {
        (void)WaitForSingleObject(api->thread, 4000);
        CloseHandle(api->thread);
    }
    if (api->stop)
        CloseHandle(api->stop);
    if (api->received)
        CloseHandle(api->received);
    if (api->listener != INVALID_SOCKET)
        closesocket(api->listener);
    memset(api, 0, sizeof(*api));
    api->listener = INVALID_SOCKET;
}

static DWORD WINAPI cancel_after_request(void *value) {
    fake_api *api = value;
    if (WaitForSingleObject(api->received, 2000) == WAIT_OBJECT_0)
        SetEvent(api->stop);
    return 0;
}

static bool rejected(const char *text, const char *code) {
    sbw_runtime_config config = {0};
    sbw_error error = {0};
    bool ok = sbw_runtime_config_prepare(text, strlen(text), "https://control.example/prefix",
                                         &config, &error) != 0 &&
              !strcmp(error.code, code) && !config.json && !config.secret;
    sbw_runtime_config_free(&config);
    return ok;
}

static HANDLE independent_process(DWORD *pid) {
    wchar_t path[32768];
    DWORD size = GetModuleFileNameW(NULL, path, (DWORD)(sizeof(path) / sizeof(*path)));
    if (!size || size >= sizeof(path) / sizeof(*path))
        return NULL;
    size_t capacity = wcslen(path) + 20;
    wchar_t *command = sb_xcalloc(capacity, sizeof(*command));
    (void)_snwprintf_s(command, capacity, _TRUNCATE, L"\"%ls\" --wait", path);
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    bool started = CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                                  &startup, &process) != FALSE;
    free(command);
    if (!started)
        return NULL;
    CloseHandle(process.hThread);
    *pid = process.dwProcessId;
    return process.hProcess;
}

typedef struct test_state {
    sbw_error error;
    sbw_runtime_config config, other;
    sbj *value;
    fake_api api;
    HANDLE cancel, canceller, unrelated;
    char *large_response;
} test_state;

static bool scenario_ipv6_and_dual_stack(test_state *s) {
    s->value = sbw_runtime_ipv6_status(&s->other, false);
    CHECK(sbj_is_bool(sbj_get(s->value, "checked")) && !sbj_get_bool(s->value, "tun_route", true));
    CHECK(sbj_string_is(sbj_get(s->value, "node_support"), "untested"));
    sbj_free(s->value);
    s->value = NULL;
    const char dual[] =
        "{\"inbounds\":[{\"type\":\"tun\",\"address\":[\"172.19.0.1/30\",\"fd71:5be:a5e::1/"
        "126\"],\"auto_route\":true,\"strict_route\":true}],\"dns\":{\"strategy\":\"prefer_ipv4\"}"
        "}";
    CHECK(sbw_runtime_config_prepare(dual, strlen(dual), "https://control.example", &s->other,
                                     &s->error) == 0);
    CHECK(s->other.has_tun && s->other.auto_route && strstr(s->other.json, "fd71:5be:a5e::1/126"));
    CHECK(strstr(s->other.json, "prefer_ipv4") && strstr(dual, "fd71:5be:a5e::1/126"));
    sbw_runtime_config_free(&s->other);
    return true;
}

static bool scenario_wireguard_endpoint(test_state *s) {
    const char wg[] = "{\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"network\",\"system\":true,"
                      "\"name\":\"wg0\",\"address\":[\"10.59.32.3/"
                      "32\"],\"private_key\":\"fixture-key\",\"peers\":[{\"address\":\"vpn.example."
                      "test\",\"allowed_ips\":[\"10.59.32.0/"
                      "24\"],\"public_key\":\"fixture-public\"}]}],\"route\":{\"rules\":[{\"ip_"
                      "cidr\":[\"10.59.32.0/24\"],\"outbound\":\"network\"}]}}";
    CHECK(sbw_runtime_config_prepare(wg, strlen(wg), "https://panel.example.test", &s->other,
                                     &s->error) == 0);
    s->value = sbj_parse_cstr(s->other.json);
    const sbj *endpoint = sbj_arr_at(sbj_get(s->value, "endpoints"), 0);
    CHECK(!sbj_get_bool(endpoint, "system", true) && !sbj_has(endpoint, "name"));
    CHECK(sb_streq(sbj_get_str(endpoint, "private_key", ""), "fixture-key"));
    CHECK(sb_streq(sbj_as_str(sbj_arr_at(sbj_get(endpoint, "address"), 0), ""), "10.59.32.3/32"));
    CHECK(sb_streq(
        sbj_get_str(sbj_arr_at(sbj_get(sbj_get(s->value, "route"), "rules"), 2), "outbound", ""),
        "network"));
    sbj_free(s->value);
    s->value = NULL;
    sbw_runtime_config_free(&s->other);
    return true;
}

static bool scenario_candidate_sanitising(test_state *s) {
    const char candidate[] =
        "{\"mode\":\"fixture\",\"inbounds\":[{\"type\":\"tun\",\"address\":[\"172.30.0.1/"
        "30\"],\"auto_route\":false,\"strict_route\":true,\"auto_redirect\":true,\"include_uid\":["
        "1000]}],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\",\"bind_interface\":"
        "\"eth0\"}],\"route\":{\"default_interface\":\"eth0\",\"rules\":[{\"outbound\":\"direct\"}]"
        "},\"log\":{\"output\":\"C:/sensitive/"
        "log\"},\"ntp\":{\"enabled\":true},\"experimental\":{\"cache_file\":{\"enabled\":true,"
        "\"path\":\"C:/sensitive/"
        "db\"},\"debug\":{},\"clash_api\":{\"external_controller\":\"0.0.0.0:9090\",\"secret\":"
        "\"old-secret\",\"external_ui\":\"C:/sensitive/ui\",\"external_ui_download_url\":\"https://"
        "bad.example/ui.zip\"}}}";
    CHECK(sbw_runtime_config_prepare(candidate, strlen(candidate), "https://control.example/prefix",
                                     &s->config, &s->error) == 0);
    CHECK(s->config.has_tun && !s->config.auto_route &&
          !wcscmp(s->config.interface_name, L"sb-easy"));
    CHECK(strlen(s->config.secret) == 64 && s->config.port && strstr(candidate, "old-secret"));
    s->value = sbw_json_parse(s->config.json, strlen(s->config.json), 40, NULL);
    CHECK(sbj_is_object(s->value) && !strcmp(sbj_get_str(s->value, "mode", ""), "fixture"));
    CHECK(!strstr(s->config.json, "sensitive") && !strstr(s->config.json, "old-secret") &&
          !strstr(s->config.json, "bad.example"));
    sbj *tun = sbj_arr_at(sbj_get(s->value, "inbounds"), 0);
    CHECK(!sbj_get_bool(tun, "auto_route", true) && sbj_get_bool(tun, "strict_route", false));
    CHECK(!sbj_has(tun, "auto_redirect") && !sbj_has(tun, "include_uid"));
    sbj *route = sbj_get(s->value, "route"), *rules = sbj_get(route, "rules");
    CHECK(sbj_get_bool(route, "auto_detect_interface", false) &&
          !sbj_has(route, "default_interface"));
    CHECK(sbj_arr_len(rules) == 3 &&
          sbj_string_is(sbj_get(sbj_arr_at(rules, 0), "type"), "logical"));
    const sbj *guard = sbj_get(sbj_arr_at(rules, 0), "rules");
    CHECK(sbj_has(sbj_arr_at(guard, 0), "process_name"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(guard, 1), "inbound"), SBW_PROBE_INBOUND) &&
          sbj_get_bool(sbj_arr_at(guard, 1), "invert", false));
    CHECK(s->config.probe_port && s->config.probe_port != s->config.port &&
          strlen(s->config.probe_secret) == 64 && strcmp(s->config.secret, s->config.probe_secret));
    const sbj *diagnostic = sbj_arr_at(sbj_get(s->value, "inbounds"), 1);
    CHECK(sbj_string_is(sbj_get(diagnostic, "listen"), "127.0.0.1") &&
          sbj_string_is(sbj_get(diagnostic, "tag"), SBW_PROBE_INBOUND));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(diagnostic, "users"), 0), "password"),
                        s->config.probe_secret));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(rules, 1), "domain"), 0), "control.example"));
    CHECK(sbj_string_is(sbj_get(sbj_get(s->value, "log"), "level"), "debug") &&
          !sbj_has(sbj_get(s->value, "log"), "output") && !sbj_has(s->value, "ntp"));
    sbj_free(s->value);
    s->value = NULL;
    return true;
}

static bool scenario_prepare_variants(test_state *s) {
    CHECK(sbw_runtime_config_prepare("{}", 2, "http://[::1]:8080/", &s->other, &s->error) == 0);
    CHECK(!s->other.has_tun && !s->other.auto_route && !s->other.interface_name &&
          strcmp(s->config.secret, s->other.secret));
    CHECK(strstr(s->other.json, "::1/128"));
    sbw_runtime_config_free(&s->other);
    const char remote_rules[] =
        "{\"route\":{\"rule_set\":[{\"type\":\"remote\",\"tag\":\"test\",\"format\":\"source\","
        "\"url\":\"https://example.invalid/rules\"}]}}";
    CHECK(sbw_runtime_config_prepare(remote_rules, strlen(remote_rules), "https://control.example/",
                                     &s->other, &s->error) == 0);
    CHECK(s->other.remote_rule_sets && strstr(s->other.json, "rule-set-cache.db"));
    sbw_runtime_config_free(&s->other);
    const char isolated[] = "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"sb-easy-test_"
                            "42\",\"auto_route\":true}]}";
    CHECK(sbw_runtime_config_prepare(isolated, strlen(isolated), "https://192.0.2.1/", &s->other,
                                     &s->error) == 0);
    CHECK(s->other.has_tun && s->other.auto_route &&
          !wcscmp(s->other.interface_name, L"sb-easy-test_42") &&
          strstr(s->other.json, "192.0.2.1/32"));
    sbw_runtime_config_free(&s->other);
    return true;
}

static bool scenario_rejected_configs(test_state *s) {
    CHECK(rejected("{\"inbounds\":[{\"type\":\"http\",\"tag\":\"sb-easy-diagnostic\"}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\"},{\"type\":\"tun\"}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"platform\":{}}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"bad/name\"}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"inbounds\":[{\"type\":\"tun\",\"auto_route\":\"false\"}]}",
                   "RUNTIME_CONFIG_INVALID"));
    CHECK(rejected("{\"route\":{\"rule_set\":[{\"type\":\"local\",\"path\":\"private.txt\"}]}}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"outbounds\":[{\"type\":\"shadowsocks\",\"plugin\":\"cmd.exe\"}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected(
        "{\"outbounds\":[{\"type\":\"trojan\",\"tls\":{\"certificate_path\":\"private.txt\"}}]}",
        "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"outbounds\":[{\"type\":\"trojan\",\"tls\":{\"ech\":{\"config_path\":"
                   "\"private.txt\"}}}]}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"dns\":{\"servers\":[{\"type\":\"hosts\",\"path\":\"private.txt\"}]}}",
                   "RUNTIME_CONFIG_UNSUPPORTED"));
    CHECK(rejected("{\"log\\u0000extra\":{}}", "RUNTIME_CONFIG_INVALID"));
    return true;
}

static const char healthy_response[] =
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"sing-box "
    "1.13.12\",\"meta\":true}";

static bool scenario_health_responses(test_state *s) {
    CHECK(api_start(&s->api, s->config.secret, healthy_response));
    s->config.port = s->api.port;
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 2000, &s->error) == 0);
    CHECK(s->api.auth_ok);
    api_stop(&s->api);
    CHECK(api_start(&s->api, s->config.secret,
                    "HTTP/1.0 302 Found\r\nLocation: https://unrelated.invalid/\r\n\r\n"));
    s->config.port = s->api.port;
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 1000, &s->error) !=
              0 &&
          !strcmp(s->error.code, "CORE_HEALTH_FAILED"));
    api_stop(&s->api);
    CHECK(api_start(&s->api, s->config.secret,
                    "HTTP/1.0 200 OK\r\n\r\n{\"version\":\"SECRET_BODY_DO_NOT_EXPOSE\"}"));
    s->config.port = s->api.port;
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 1000, &s->error) !=
              0 &&
          !strstr(s->error.message, "SECRET_BODY"));
    api_stop(&s->api);
    s->large_response = sb_xcalloc(20001, 1);
    memset(s->large_response, 'x', 20000);
    CHECK(api_start(&s->api, s->config.secret, s->large_response));
    s->config.port = s->api.port;
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 1000, &s->error) != 0);
    api_stop(&s->api);
    return true;
}

static bool scenario_health_timeout_and_cancel(test_state *s) {
    CHECK(api_start(&s->api, s->config.secret, NULL));
    s->config.port = s->api.port;
    ULONGLONG before = GetTickCount64();
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 100, &s->error) != 0 &&
          !strcmp(s->error.code, "CORE_HEALTH_TIMEOUT"));
    CHECK(GetTickCount64() - before < 500);
    api_stop(&s->api);
    CHECK(api_start(&s->api, s->config.secret, NULL));
    s->config.port = s->api.port;
    s->canceller = CreateThread(NULL, 0, cancel_after_request, &s->api, 0, NULL);
    CHECK(s->canceller);
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), s->api.stop, 2000,
                                    &s->error) != 0 &&
          !strcmp(s->error.code, "CORE_CANCELLED"));
    CHECK(WaitForSingleObject(s->canceller, 2000) == WAIT_OBJECT_0);
    CloseHandle(s->canceller);
    s->canceller = NULL;
    api_stop(&s->api);
    s->cancel = CreateEventW(NULL, TRUE, TRUE, NULL);
    CHECK(s->cancel);
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), s->cancel, 1000,
                                    &s->error) != 0 &&
          !strcmp(s->error.code, "CORE_CANCELLED"));
    return true;
}

static bool scenario_health_identity(test_state *s) {
    DWORD unrelated_pid = 0;
    s->unrelated = independent_process(&unrelated_pid);
    CHECK(s->unrelated);
    CHECK(api_start(&s->api, s->config.secret, healthy_response));
    s->config.port = s->api.port;
    CHECK(sbw_runtime_config_health(&s->config, unrelated_pid, NULL, 1000, &s->error) != 0 &&
          !strcmp(s->error.code, "CORE_HEALTH_IDENTITY"));
    CHECK(WaitForSingleObject(s->api.received, 0) == WAIT_TIMEOUT);
    api_stop(&s->api);
    ULONGLONG before = GetTickCount64();
    CHECK(sbw_runtime_config_health(&s->config, GetCurrentProcessId(), NULL, 100, &s->error) != 0 &&
          !strcmp(s->error.code, "CORE_HEALTH_TIMEOUT"));
    CHECK(GetTickCount64() - before < 500);
    return true;
}

static const struct {
    const char *name;
    bool (*run)(test_state *);
} scenarios[] = {
    {"ipv6_and_dual_stack", scenario_ipv6_and_dual_stack},
    {"wireguard_endpoint", scenario_wireguard_endpoint},
    {"candidate_sanitising", scenario_candidate_sanitising},
    {"prepare_variants", scenario_prepare_variants},
    {"rejected_configs", scenario_rejected_configs},
    {"health_responses", scenario_health_responses},
    {"health_timeout_and_cancel", scenario_health_timeout_and_cancel},
    {"health_identity", scenario_health_identity},
};

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && !wcscmp(argv[1], L"--wait")) {
        Sleep(INFINITE);
        return 0;
    }
    test_state state = {0};
    test_state *s = &state;
    s->api.listener = INVALID_SOCKET;
    WSADATA startup;
    bool sockets = WSAStartup(MAKEWORD(2, 2), &startup) == 0;
    int result = 1;
    if (!sockets) {
        fprintf(stderr, "WSAStartup failed\n");
        goto done;
    }
    for (size_t i = 0; i < sizeof scenarios / sizeof *scenarios; ++i)
        if (!scenarios[i].run(s)) {
            fprintf(stderr, "scenario %s failed\n", scenarios[i].name);
            goto done;
        }
    result = 0;
    puts("runtime_config_test: passed (fake loopback only; no TUN or routes)");
done:
    if (s->canceller) {
        if (s->api.received)
            SetEvent(s->api.received);
        (void)WaitForSingleObject(s->canceller, 2500);
        CloseHandle(s->canceller);
    }
    api_stop(&s->api);
    if (s->cancel)
        CloseHandle(s->cancel);
    if (s->unrelated) {
        TerminateProcess(s->unrelated, 0);
        (void)WaitForSingleObject(s->unrelated, 2000);
        CloseHandle(s->unrelated);
    }
    free(s->large_response);
    sbj_free(s->value);
    sbw_runtime_config_free(&s->config);
    sbw_runtime_config_free(&s->other);
    if (sockets)
        WSACleanup();
    return result;
}
