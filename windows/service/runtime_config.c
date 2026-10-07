#include <winsock2.h>
#include <ws2tcpip.h>
#include "runtime_config.h"

#include <bcrypt.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(sbw_error *error, const char *code) {
    const char *message = "The local core health check failed.";
    if (!strcmp(code, "RUNTIME_CONFIG_INVALID")) message = "The candidate cannot be adapted to a Windows runtime configuration.";
    else if (!strcmp(code, "RUNTIME_CONFIG_UNSUPPORTED")) message = "The candidate contains an unsupported Windows runtime option.";
    else if (!strcmp(code, "RUNTIME_RESOURCE_ERROR")) message = "Private local core resources could not be allocated.";
    else if (!strcmp(code, "CORE_HEALTH_TIMEOUT")) message = "The core did not become ready before its deadline.";
    else if (!strcmp(code, "CORE_CANCELLED")) message = "The core operation was cancelled.";
    else if (!strcmp(code, "CORE_HEALTH_IDENTITY")) message = "The local health endpoint does not belong to the core process.";
    else if (!strcmp(code, "CORE_HEALTH_EXITED")) message = "The core process exited before becoming ready.";
    return sbw_fail(error, code, message);
}

static bool safe_strings(const sbj *value) {
    if (sbj_is_string(value)) return value->v.str.len == strlen(value->v.str.ptr);
    if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value); ++i) if (!safe_strings(sbj_arr_at(value, i))) return false;
    } else if (sbj_is_object(value)) {
        for (size_t i = 0; i < sbj_obj_len(value); ++i)
            if (value->v.obj.key_lens[i] != strlen(sbj_obj_key(value, i)) || !safe_strings(sbj_obj_val(value, i))) return false;
    }
    return true;
}

static bool unsafe_files(const sbj *value) {
    static const char *keys[] = {"certificate_path", "key_path", "client_certificate_path", "client_key_path",
        "certificate_directory_path", "private_key_path", "known_hosts_path", "config_path", "acme", "plugin", "plugin_opts"};
    if (sbj_is_object(value)) {
        for (size_t i = 0; i < sizeof(keys) / sizeof(*keys); ++i) if (sbj_has(value, keys[i])) return true;
        for (size_t i = 0; i < sbj_obj_len(value); ++i) if (unsafe_files(sbj_obj_val(value, i))) return true;
    } else if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value); ++i) if (unsafe_files(sbj_arr_at(value, i))) return true;
    }
    return false;
}

static void erase_keys(sbj *object, const char *const *keys, size_t count) {
    for (size_t i = 0; i < count; ++i) sbj_del(object, keys[i]);
}

static void adapt_dialers(sbj *value) {
    /* These platform/device bindings may also appear in DNS server and nested
     * handshake dialers. All outbound sockets use Windows interface detection. */
    static const char *keys[] = {"bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port",
        "routing_mark", "netns", "network_namespace", "protect_path"};
    if (sbj_is_object(value)) {
        erase_keys(value, keys, sizeof(keys) / sizeof(*keys));
        for (size_t i = 0; i < sbj_obj_len(value); ++i) adapt_dialers(sbj_obj_val(value, i));
    } else if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value); ++i) adapt_dialers(sbj_arr_at(value, i));
    }
}

static char *server_host(const char *server) {
    wchar_t *wide = sbw_wide(server, NULL);
    if (!wide) return NULL;
    URL_COMPONENTS parts = {0};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = (DWORD)-1;
    parts.dwUserNameLength = (DWORD)-1;
    parts.dwPasswordLength = (DWORD)-1;
    bool valid = WinHttpCrackUrl(wide, 0, 0, &parts) && parts.dwHostNameLength > 0 &&
        parts.dwHostNameLength <= 253 && !parts.dwUserNameLength && !parts.dwPasswordLength &&
        (parts.nScheme == INTERNET_SCHEME_HTTP || parts.nScheme == INTERNET_SCHEME_HTTPS);
    char *host = NULL;
    if (valid) {
        wchar_t *name = sb_xcalloc((size_t)parts.dwHostNameLength + 1, sizeof(*name));
        memcpy(name, parts.lpszHostName, parts.dwHostNameLength * sizeof(*name));
        host = sbw_utf8(name, NULL);
        free(name);
    }
    free(wide);
    if (host && host[0] == '[') {
        size_t size = strlen(host);
        if (size > 2 && host[size - 1] == ']') { memmove(host, host + 1, size - 2); host[size - 2] = '\0'; }
    }
    return host;
}

static int choose_local_api(sbw_runtime_config *out, sbw_error *error) {
    BYTE entropy[32];
    if (BCryptGenRandom(NULL, entropy, sizeof(entropy), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return fail(error, "RUNTIME_RESOURCE_ERROR");
    out->secret = sb_xcalloc(65, 1);
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(entropy); ++i) {
        out->secret[2 * i] = hex[entropy[i] >> 4]; out->secret[2 * i + 1] = hex[entropy[i] & 15];
    }
    SecureZeroMemory(entropy, sizeof(entropy));
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) return fail(error, "RUNTIME_RESOURCE_ERROR");
    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL exclusive = TRUE;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int size = sizeof(address);
    bool ok = socket_handle != INVALID_SOCKET &&
        setsockopt(socket_handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive)) == 0 &&
        bind(socket_handle, (const struct sockaddr *)&address, sizeof(address)) == 0 &&
        getsockname(socket_handle, (struct sockaddr *)&address, &size) == 0;
    if (ok) out->port = ntohs(address.sin_port);
    if (socket_handle != INVALID_SOCKET) closesocket(socket_handle);
    WSACleanup();
    return ok && out->port ? 0 : fail(error, "RUNTIME_RESOURCE_ERROR");
}

static int adapt_inbounds(sbj *candidate, sbw_runtime_config *out, sbw_error *error) {
    sbj *inbounds = sbj_get(candidate, "inbounds");
    if (inbounds && !sbj_is_array(inbounds)) return fail(error, "RUNTIME_CONFIG_INVALID");
    static const char *linux_keys[] = {"iproute2_table_index", "iproute2_rule_index", "auto_redirect",
        "auto_redirect_input_mark", "auto_redirect_output_mark", "auto_redirect_reset_mark", "auto_redirect_nfqueue",
        "auto_redirect_iproute2_fallback_rule_index", "exclude_mptcp", "loopback_address", "include_interface",
        "exclude_interface", "include_uid", "include_uid_range", "exclude_uid", "exclude_uid_range",
        "include_android_user", "include_package", "exclude_package", "gso"};
    for (size_t i = 0; i < sbj_arr_len(inbounds); ++i) {
        sbj *inbound = sbj_arr_at(inbounds, i);
        if (!sbj_is_object(inbound)) return fail(error, "RUNTIME_CONFIG_INVALID");
        const char *type = sbj_get_str(inbound, "type", "");
        if (!strcmp(type, "tun")) {
            if (out->has_tun || sbj_has(inbound, "platform")) return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
            sbj *auto_route = sbj_get(inbound, "auto_route");
            if (auto_route && !sbj_is_bool(auto_route)) return fail(error, "RUNTIME_CONFIG_INVALID");
            out->has_tun = true; out->auto_route = sbj_as_bool(auto_route, false);
            const sbj *provided = sbj_get(inbound, "interface_name");
            if (provided && !sbw_json_string(provided, 48, false)) return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
            const char *name = sbj_as_str(provided, "sb-easy");
            for (const char *p = name; *p; ++p)
                if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
                      *p == '-' || *p == '_')) return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
            out->interface_name = sbw_wide(name, NULL);
            if (!provided) sbj_set_str(inbound, "interface_name", name);
            erase_keys(inbound, linux_keys, sizeof(linux_keys) / sizeof(*linux_keys));
        } else if (!strcmp(type, "mixed") || !strcmp(type, "http") || !strcmp(type, "socks")) {
            sbj_set_str(inbound, "listen", "127.0.0.1");
            sbj_del(inbound, "set_system_proxy");
        } else return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
    }
    return 0;
}

static int adapt_routes(sbj *candidate, const char *host, sbw_error *error) {
    const char *direct_tag = "sb-easy-control-direct";
    sbj *outbounds = sbj_get(candidate, "outbounds");
    if (!outbounds) { outbounds = sbj_array(); sbj_set(candidate, "outbounds", outbounds); }
    if (!sbj_is_array(outbounds)) return fail(error, "RUNTIME_CONFIG_INVALID");
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        sbj *outbound = sbj_arr_at(outbounds, i);
        if (!sbj_is_object(outbound)) return fail(error, "RUNTIME_CONFIG_INVALID");
        if (!strcmp(sbj_get_str(outbound, "tag", ""), direct_tag)) return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
        sbj_del(outbound, "bind_interface"); sbj_del(outbound, "routing_mark");
        sbj_del(outbound, "netns"); sbj_del(outbound, "network_namespace");
    }
    sbj *direct = sbj_object();
    sbj_set_str(direct, "type", "direct"); sbj_set_str(direct, "tag", direct_tag);
    sbj_arr_push(outbounds, direct);
    sbj *route = sbj_get(candidate, "route");
    if (!route) { route = sbj_object(); sbj_set(candidate, "route", route); }
    if (!sbj_is_object(route)) return fail(error, "RUNTIME_CONFIG_INVALID");
    if (sbj_has(route, "geoip") || sbj_has(route, "geosite")) return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
    sbj *sets = sbj_get(route, "rule_set");
    if (sets && !sbj_is_array(sets)) return fail(error, "RUNTIME_CONFIG_INVALID");
    for (size_t i = 0; i < sbj_arr_len(sets); ++i) {
        sbj *set = sbj_arr_at(sets, i);
        if (!sbj_is_object(set) || sbj_has(set, "path") || !strcmp(sbj_get_str(set, "type", ""), "local"))
            return fail(error, "RUNTIME_CONFIG_UNSUPPORTED");
    }
    sbj_del(route, "default_interface"); sbj_del(route, "default_mark"); sbj_del(route, "override_android_vpn");
    sbj_set_bool(route, "auto_detect_interface", true); sbj_set_bool(route, "find_process", true);
    sbj *rules = sbj_get(route, "rules");
    if (!rules) { rules = sbj_array(); sbj_set(route, "rules", rules); }
    if (!sbj_is_array(rules)) return fail(error, "RUNTIME_CONFIG_INVALID");
    sbj *process_rule = sbj_object(), *processes = sbj_array();
    sbj_arr_push(processes, sbj_str("sb-easy-service.exe")); sbj_arr_push(processes, sbj_str("sb-easy.exe"));
    sbj_arr_push(processes, sbj_str("sing-box.exe"));
    sbj_set(process_rule, "process_name", processes);
    sbj_set_str(process_rule, "action", "route"); sbj_set_str(process_rule, "outbound", direct_tag);
    sbj *control_rule = sbj_object(), *hosts = sbj_array();
    BYTE ip[16];
    if (InetPtonA(AF_INET, host, ip) == 1 || InetPtonA(AF_INET6, host, ip) == 1) {
        char cidr[300];
        (void)sprintf_s(cidr, sizeof(cidr), "%s/%d", host, strchr(host, ':') ? 128 : 32);
        sbj_arr_push(hosts, sbj_str(cidr)); sbj_set(control_rule, "ip_cidr", hosts);
    } else { sbj_arr_push(hosts, sbj_str(host)); sbj_set(control_rule, "domain", hosts); }
    sbj_set_str(control_rule, "action", "route"); sbj_set_str(control_rule, "outbound", direct_tag);
    sbj_arr_insert(rules, 0, control_rule); sbj_arr_insert(rules, 0, process_rule);
    return 0;
}

int sbw_runtime_config_prepare(const char *json, size_t length, const char *server,
                               sbw_runtime_config *out, sbw_error *error) {
    if (!out || !json || !length || length > 8U * 1024U * 1024U || !server) return fail(error, "RUNTIME_CONFIG_INVALID");
    memset(out, 0, sizeof(*out));
    sbj *candidate = sbw_json_parse(json, length, 40, NULL);
    char *host = server_host(server);
    int result = -1;
    if (!sbj_is_object(candidate) || !safe_strings(candidate) || !host) { fail(error, "RUNTIME_CONFIG_INVALID"); goto done; }
    if (unsafe_files(candidate) || sbj_size(sbj_get(candidate, "services")) || sbj_size(sbj_get(candidate, "endpoints")) ||
        sbj_has(candidate, "certificate")) { fail(error, "RUNTIME_CONFIG_UNSUPPORTED"); goto done; }
    sbj *dns_servers = sbj_get(sbj_get(candidate, "dns"), "servers");
    for (size_t i = 0; i < sbj_arr_len(dns_servers); ++i) {
        sbj *dns_server = sbj_arr_at(dns_servers, i);
        if (!strcmp(sbj_get_str(dns_server, "type", ""), "hosts") && sbj_has(dns_server, "path")) {
            fail(error, "RUNTIME_CONFIG_UNSUPPORTED"); goto done;
        }
    }
    adapt_dialers(sbj_get(candidate, "outbounds"));
    adapt_dialers(sbj_get(candidate, "dns"));
    sbj_del(candidate, "ntp");
    sbj *log = sbj_object(); sbj_set_bool(log, "disabled", true); sbj_set(candidate, "log", log);
    if (adapt_inbounds(candidate, out, error) != 0 || adapt_routes(candidate, host, error) != 0 ||
        choose_local_api(out, error) != 0) goto done;
    char controller[32];
    (void)sprintf_s(controller, sizeof(controller), "127.0.0.1:%u", out->port);
    sbj *experimental = sbj_object(), *clash = sbj_object(), *origins = sbj_array();
    const char *mode = sbj_get_str(sbj_get(sbj_get(candidate, "experimental"), "clash_api"), "default_mode", "Rule");
    sbj_set_str(clash, "default_mode", mode);
    sbj_set_str(clash, "external_controller", controller); sbj_set_str(clash, "secret", out->secret);
    sbj_arr_push(origins, sbj_str("http://127.0.0.1")); sbj_set(clash, "access_control_allow_origin", origins);
    sbj_set_bool(clash, "access_control_allow_private_network", false);
    sbj_set(experimental, "clash_api", clash); sbj_set(candidate, "experimental", experimental);
    out->json = sbj_dump(candidate, -1);
    result = out->json ? 0 : fail(error, "RUNTIME_RESOURCE_ERROR");
done:
    free(host); sbj_free(candidate);
    if (result != 0) sbw_runtime_config_free(out);
    return result;
}

void sbw_runtime_config_free(sbw_runtime_config *config) {
    if (!config) return;
    sbw_secret_free(config->json); sbw_secret_free(config->secret); free(config->interface_name);
    memset(config, 0, sizeof(*config));
}

static int listener_owner(unsigned short port, DWORD expected_pid) {
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER || !size || size > 4U * 1024U * 1024U) return -1;
    MIB_TCPTABLE_OWNER_PID *table = sb_xmalloc(size);
    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    int owner = 0;
    if (result != NO_ERROR) owner = -1;
    else for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];
        if (ntohs((u_short)row->dwLocalPort) != port) continue;
        if (row->dwLocalAddr != htonl(INADDR_LOOPBACK) && row->dwLocalAddr != htonl(INADDR_ANY)) continue;
        if (row->dwLocalAddr != htonl(INADDR_LOOPBACK) || row->dwOwningPid != expected_pid) { owner = -1; break; }
        owner = 1;
    }
    free(table);
    return owner;
}

static int interrupted(HANDLE cancel, HANDLE process, ULONGLONG deadline, sbw_error *error) {
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return fail(error, "CORE_CANCELLED");
    if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return fail(error, "CORE_HEALTH_EXITED");
    if (GetTickCount64() >= deadline) return fail(error, "CORE_HEALTH_TIMEOUT");
    return 0;
}

static int wait_socket(SOCKET socket_handle, bool writing, HANDLE cancel, HANDLE process,
                        ULONGLONG deadline, sbw_error *error) {
    for (;;) {
        if (interrupted(cancel, process, deadline, error) != 0) return -1;
        fd_set ready, exception;
        FD_ZERO(&ready); FD_SET(socket_handle, &ready); FD_ZERO(&exception); FD_SET(socket_handle, &exception);
        ULONGLONG now = GetTickCount64();
        DWORD left = now < deadline ? (DWORD)(deadline - now) : 0;
        struct timeval interval = {0, (long)(left < 20 ? left * 1000 : 20000)};
        int result = select(0, writing ? NULL : &ready, writing ? &ready : NULL, &exception, &interval);
        if (result == SOCKET_ERROR || FD_ISSET(socket_handle, &exception)) return fail(error, "CORE_HEALTH_FAILED");
        if (result > 0) return 0;
    }
}

static int probe(const sbw_runtime_config *config, DWORD pid, HANDLE cancel, HANDLE process,
                  ULONGLONG deadline, const char *path, size_t capacity, sbj **out, sbw_error *error) {
    char *response = sb_xcalloc(capacity + 1, 1);
    SOCKET connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) { free(response); return fail(error, "CORE_HEALTH_FAILED"); }
    int result = -1;
    u_long nonblocking = 1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(config->port);
    if (ioctlsocket(connection, FIONBIO, &nonblocking) != 0) { fail(error, "CORE_HEALTH_FAILED"); goto done; }
    if (connect(connection, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) { fail(error, "CORE_HEALTH_FAILED"); goto done; }
        if (wait_socket(connection, true, cancel, process, deadline, error) != 0) goto done;
        int socket_error = 0, size = sizeof(socket_error);
        if (getsockopt(connection, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &size) != 0 || socket_error) {
            fail(error, "CORE_HEALTH_FAILED"); goto done;
        }
    }
    if (listener_owner(config->port, pid) != 1) { fail(error, "CORE_HEALTH_IDENTITY"); goto done; }
    char request[384];
    int request_size = sprintf_s(request, sizeof(request),
        "GET %s HTTP/1.0\r\nHost: 127.0.0.1:%u\r\nAuthorization: Bearer %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, config->port, config->secret);
    int sent = 0;
    while (sent < request_size) {
        if (wait_socket(connection, true, cancel, process, deadline, error) != 0) { SecureZeroMemory(request, sizeof(request)); goto done; }
        int count = send(connection, request + sent, request_size - sent, 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (count <= 0) { SecureZeroMemory(request, sizeof(request)); fail(error, "CORE_HEALTH_FAILED"); goto done; }
        sent += count;
    }
    SecureZeroMemory(request, sizeof(request));
    size_t used = 0;
    for (;;) {
        if (wait_socket(connection, false, cancel, process, deadline, error) != 0) goto done;
        int count = recv(connection, response + used, (int)(capacity - used), 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (count < 0) { fail(error, "CORE_HEALTH_FAILED"); goto done; }
        if (!count) break;
        used += (size_t)count;
        if (used >= capacity) { fail(error, "CORE_HEALTH_FAILED"); goto done; }
    }
    response[used] = '\0';
    char *body = strstr(response, "\r\n\r\n");
    if (!body || strlen(response) != used || body - response > 8192 ||
        (strncmp(response, "HTTP/1.0 200 ", 13) && strncmp(response, "HTTP/1.1 200 ", 13))) {
        fail(error, "CORE_HEALTH_FAILED"); goto done;
    }
    body += 4;
    sbj *value = sbw_json_parse(body, used - (size_t)(body - response), out ? 24 : 8, NULL);
    const sbj *version = sbj_get(value, "version");
    bool healthy = sbw_json_string(version, 128, false) && version->v.str.len > 9 &&
        !strncmp(sbj_as_str(version, ""), "sing-box ", 9);
    if (out) healthy = sbj_is_object(value);
    result = healthy ? interrupted(cancel, process, deadline, error) : fail(error, "CORE_HEALTH_FAILED");
    if (result == 0 && out) { *out = value; value = NULL; }
    sbj_free(value);
done:
    free(response); closesocket(connection);
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) result = fail(error, "CORE_CANCELLED");
    return result;
}

int sbw_runtime_config_health(const sbw_runtime_config *config, DWORD expected_pid,
                              HANDLE cancel, DWORD timeout_ms, sbw_error *error) {
    if (!config || !config->port || !expected_pid || !config->secret || strlen(config->secret) != 64)
        return fail(error, "CORE_HEALTH_FAILED");
    for (const char *p = config->secret; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return fail(error, "CORE_HEALTH_FAILED");
    if (!timeout_ms) timeout_ms = 10000;
    if (timeout_ms > 60000) timeout_ms = 60000;
    ULONGLONG deadline = GetTickCount64() + timeout_ms;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, expected_pid);
    if (!process) return fail(error, "CORE_HEALTH_EXITED");
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) { CloseHandle(process); return fail(error, "CORE_HEALTH_FAILED"); }
    int result = -1;
    for (;;) {
        if (interrupted(cancel, process, deadline, error) != 0) break;
        int owner = listener_owner(config->port, expected_pid);
        if (owner < 0) { fail(error, "CORE_HEALTH_IDENTITY"); break; }
        if (owner > 0) { result = probe(config, expected_pid, cancel, process, deadline, "/version", 16384, NULL, error); break; }
        ULONGLONG now = GetTickCount64();
        DWORD left = now < deadline ? (DWORD)(deadline - now) : 0;
        DWORD pause = left < 20 ? left : 20;
        if (cancel) (void)WaitForSingleObject(cancel, pause); else Sleep(pause);
    }
    WSACleanup(); CloseHandle(process);
    return result;
}

int sbw_runtime_config_get(const sbw_runtime_config *config, DWORD expected_pid,
                           HANDLE cancel, const char *path, sbj **out, sbw_error *error) {
    if (out) *out = NULL;
    if (!out || !path || (strcmp(path, "/connections") && strcmp(path, "/proxies")) ||
        !config || !config->port || !expected_pid || !config->secret || strlen(config->secret) != 64)
        return fail(error, "CORE_HEALTH_FAILED");
    for (const char *p = config->secret; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return fail(error, "CORE_HEALTH_FAILED");
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, expected_pid);
    if (!process) return fail(error, "CORE_HEALTH_EXITED");
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) { CloseHandle(process); return fail(error, "CORE_HEALTH_FAILED"); }
    int result = listener_owner(config->port, expected_pid) == 1
        ? probe(config, expected_pid, cancel, process, GetTickCount64() + 1500, path, 256U * 1024U, out, error)
        : fail(error, "CORE_HEALTH_IDENTITY");
    if (result != 0) { sbj_free(*out); *out = NULL; }
    WSACleanup(); CloseHandle(process); return result;
}
