#include <winsock2.h>
#include <ws2tcpip.h>
#include "route_probe.h"
#include "diagnostics.h"
#include <winhttp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct probe_url {
    wchar_t *wide, *host, *path;
    char *display, *host_utf8;
    INTERNET_PORT port;
    bool tls;
} probe_url;

static void url_free(probe_url *url) {
    free(url->wide);
    free(url->host);
    free(url->path);
    free(url->display);
    free(url->host_utf8);
    memset(url, 0, sizeof(*url));
}
static bool parse_url(const sbj *value, probe_url *url, sbw_error *error) {
    if (!sbw_json_string(value, 2048, false))
        goto invalid;
    const char *text = sbj_as_str(value, "");
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p <= 32 || *p == 127 || *p == '\\')
            goto invalid;
    const char *authority = NULL;
    if (!_strnicmp(text, "https://", 8)) {
        authority = text + 8;
        url->tls = true;
        url->port = 443;
    } else if (!_strnicmp(text, "http://", 7)) {
        authority = text + 7;
        url->port = 80;
    } else
        goto invalid;
    const char *end = authority + strcspn(authority, "/?#"), *host = authority, *host_end = end, *port = NULL;
    if (host == end || memchr(host, '@', (size_t)(end - host)) || memchr(host, '%', (size_t)(end - host)))
        goto invalid;
    if (*host == '[') {
        ++host;
        host_end = memchr(host, ']', (size_t)(end - host));
        if (!host_end || host_end == host)
            goto invalid;
        if (host_end + 1 < end) {
            if (host_end[1] != ':')
                goto invalid;
            port = host_end + 2;
        }
        char *literal = sb_strndup(host, (size_t)(host_end - host));
        BYTE ip[16];
        bool valid = InetPtonA(AF_INET6, literal, ip) == 1;
        free(literal);
        if (!valid)
            goto invalid;
    } else {
        const char *colon = memchr(host, ':', (size_t)(end - host));
        if (colon) {
            host_end = colon;
            port = colon + 1;
        }
    }
    if (host_end == host || host_end - host > 253)
        goto invalid;
    if (port) {
        unsigned number = 0;
        if (port == end)
            goto invalid;
        for (const char *p = port; p < end; ++p) {
            if (*p < '0' || *p > '9')
                goto invalid;
            number = number * 10U + (unsigned)(*p - '0');
            if (number > 65535)
                goto invalid;
        }
        if (!number)
            goto invalid;
        url->port = (INTERNET_PORT)number;
    }
    url->host_utf8 = sb_strndup(host, (size_t)(host_end - host));
    url->host = sbw_wide(url->host_utf8, error);
    if (!url->host)
        goto invalid;
    const char *fragment = strchr(end, '#'), *path_end = fragment ? fragment : text + strlen(text);
    char *path = *end == '/' ? sb_strndup(end, (size_t)(path_end - end))
                             : sb_asprintf("/%.*s", (int)(path_end - end), end);
    url->path = sbw_wide(path, error);
    free(path);
    if (!url->path)
        goto invalid;
    url->wide = sbw_wide(text, error);
    if (!url->wide)
        goto invalid;
    url->display = sb_strdup(text);
    char *private_part = strpbrk(url->display, "?#");
    if (private_part)
        *private_part = 0;
    return true;
invalid:
    url_free(url);
    sbw_fail(error, "INVALID_REQUEST",
             "Provide one HTTP or HTTPS URL without credentials (maximum 2048 bytes).");
    return false;
}

static DWORD timeout_value(const sbj *params, DWORD fallback, DWORD maximum) {
    const sbj *v = sbj_get(params, "timeout_ms");
    if (!v)
        return fallback;
    int64_t n = sbj_get_int(params, "timeout_ms", 0);
    return sbj_is_integer(v) && n >= 1000 && n <= maximum ? (DWORD)n : 0;
}
static bool keys_valid(const sbj *params, bool delay) {
    if (!sbj_is_object(params))
        return false;
    for (size_t i = 0; i < sbj_obj_len(params); ++i) {
        const char *key = sbj_obj_key(params, i);
        if (strcmp(key, "url") && strcmp(key, "timeout_ms") && !(delay && !strcmp(key, "target")))
            return false;
    }
    return true;
}
sbj *sbw_route_delay(const sbw_runtime_config *config, DWORD pid, HANDLE cancel, const sbj *params,
                     sbw_error *error) {
    DWORD timeout = timeout_value(params, 5000, 10000);
    probe_url url = {0};
    if (!keys_valid(params, true) || !timeout || !sbw_json_string(sbj_get(params, "target"), 512, false)) {
        sbw_fail(error, "INVALID_REQUEST", "Choose a node or group and a timeout between 1000 and 10000 ms.");
        return NULL;
    }
    sbj *default_url = sbj_str("https://www.gstatic.com/generate_204");
    bool valid = parse_url(sbj_get(params, "url") ? sbj_get(params, "url") : default_url, &url, error);
    sbj_free(default_url);
    if (!valid)
        return NULL;
    sbj *response = NULL;
    const char *target = sbj_get_str(params, "target", "");
    char *request_url = sbw_utf8(url.wide, error);
    int rc = request_url
                 ? sbw_runtime_delay(config, pid, cancel, target, request_url, timeout, &response, error)
                 : -1;
    sbw_secret_free(request_url);
    if (rc) {
        url_free(&url);
        return NULL;
    }
    sbj *result = sbj_object();
    sbj_set_str(result, "target", target);
    sbj_set_str(result, "url", url.display);
    sbj_set_int(result, "delay_ms", sbj_get_int(response, "delay", 0));
    sbj_set_bool(result, "success", true);
    sbj_free(response);
    url_free(&url);
    return result;
}

/* Each asynchronous request owns a reference until HANDLE_CLOSING. The caller
 * can cancel without waiting for a stalled OS callback or freeing its context. */
typedef struct request_state {
    volatile LONG references;
    HANDLE event;
    volatile LONG stage, win_error;
} request_state;
static void request_release(request_state *state) {
    if (InterlockedDecrement(&state->references) == 0) {
        CloseHandle(state->event);
        free(state);
    }
}
static void CALLBACK request_callback(HINTERNET handle, DWORD_PTR context, DWORD status, void *info,
                                      DWORD length) {
    (void)handle;
    request_state *state = (request_state *)context;
    if (!state)
        return;
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
        request_release(state);
        return;
    }
    if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
        DWORD code = length >= sizeof(WINHTTP_ASYNC_RESULT) ? ((WINHTTP_ASYNC_RESULT *)info)->dwError
                                                            : ERROR_WINHTTP_INTERNAL_ERROR;
        InterlockedExchange(&state->win_error, (LONG)code);
        InterlockedExchange(&state->stage, -1);
    } else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE)
        InterlockedExchange(&state->stage, 1);
    else if (status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE)
        InterlockedExchange(&state->stage, 2);
    else
        return;
    SetEvent(state->event);
}
static const char *transport_error(DWORD code) {
    if (code == ERROR_WINHTTP_TIMEOUT || code == WAIT_TIMEOUT)
        return "PROBE_TIMEOUT";
    if (code == ERROR_WINHTTP_SECURE_FAILURE || code == ERROR_WINHTTP_SECURE_CERT_DATE_INVALID ||
        code == ERROR_WINHTTP_SECURE_INVALID_CA || code == ERROR_WINHTTP_SECURE_CERT_CN_INVALID)
        return "PROBE_TLS_FAILED";
    if (code == ERROR_WINHTTP_NAME_NOT_RESOLVED)
        return "PROBE_DNS_FAILED";
    if (code == ERROR_WINHTTP_OPERATION_CANCELLED)
        return "PROBE_CANCELLED";
    return "PROBE_NETWORK_FAILED";
}
static void safe_field(sbj *out, const char *key, const sbj *from, const sbj *private_config) {
    const sbj *value = sbj_get(from, key);
    if (!sbw_json_string(value, 1024, true))
        return;
    char *safe = sbw_diagnostics_redact(sbj_as_str(value, ""), private_config);
    sbj_set_str(out, key, safe);
    sbw_secret_free(safe);
}
static bool known_connection(const sbj *baseline, const sbj *connection) {
    const char *id = sbj_get_str(connection, "id", "");
    const sbj *items = sbj_get(baseline, "connections");
    if (!*id)
        return true;
    for (size_t i = 0; i < sbj_arr_len(items); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(items, i), "id"), id))
            return true;
    return false;
}
static sbj *connection_evidence(const sbj *snapshot, const sbj *baseline, const probe_url *url,
                                unsigned short source_port, const sbj *private_config) {
    const sbj *connections = sbj_get(snapshot, "connections");
    for (size_t i = 0; i < sbj_arr_len(connections); ++i) {
        const sbj *connection = sbj_arr_at(connections, i), *m = sbj_get(connection, "metadata");
        if (known_connection(baseline, connection))
            continue;
        const char *type = sbj_get_str(m, "type", "");
        if (strcmp(type, "http/" SBW_PROBE_INBOUND) || _stricmp(sbj_get_str(m, "host", ""), url->host_utf8))
            continue;
        char port[16];
        sprintf_s(port, sizeof(port), "%u", url->port);
        if (!sbj_string_is(sbj_get(m, "destinationPort"), port))
            continue;
        if (source_port) {
            sprintf_s(port, sizeof(port), "%u", source_port);
            if (!sbj_string_is(sbj_get(m, "sourcePort"), port))
                continue;
        }
        sbj *out = sbj_object(), *metadata = sbj_object(), *chain = sbj_array();
        safe_field(out, "id", connection, private_config);
        safe_field(out, "rule", connection, private_config);
        const char *keys[] = {"host",        "sourceIP", "sourcePort", "destinationIP", "destinationPort",
                              "processPath", "type",     "network",    "dnsMode"};
        for (size_t k = 0; k < sizeof(keys) / sizeof(*keys); ++k)
            safe_field(metadata, keys[k], m, private_config);
        const sbj *chains = sbj_get(connection, "chains");
        for (size_t k = 0; k < sbj_arr_len(chains) && k < 32; ++k)
            if (sbw_json_string(sbj_arr_at(chains, k), 512, false)) {
                char *safe = sbw_diagnostics_redact(sbj_as_str(sbj_arr_at(chains, k), ""), private_config);
                sbj_arr_push(chain, sbj_str(safe));
                sbw_secret_free(safe);
            }
        sbj_set(out, "metadata", metadata);
        sbj_set(out, "chains", chain);
        return out;
    }
    return NULL;
}
static unsigned short request_source(HINTERNET request) {
    WINHTTP_CONNECTION_INFO info = {0};
    info.cbSize = sizeof(info);
    DWORD size = sizeof(info);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_CONNECTION_INFO, &info, &size))
        return 0;
    if (info.LocalAddress.ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)&info.LocalAddress)->sin_port);
    return 0;
}
static bool prior_line(const sbj *before, const char *line) {
    const sbj *lines = sbj_get(before, "lines");
    for (size_t i = 0; i < sbj_arr_len(lines); ++i)
        if (sbj_string_is(sbj_arr_at(lines, i), line))
            return true;
    return false;
}
static sbj *related_logs(sbw_core *core, const sbj *before, unsigned short source_port,
                         const sbj *private_config) {
    sbj *output = sbj_array();
    if (!core || !source_port)
        return output;
    sbj *after = sbw_core_logs(core);
    const sbj *lines = sbj_get(after, "lines");
    char address[64], correlation[64] = "";
    sprintf_s(address, sizeof(address), "inbound connection from 127.0.0.1:%u", source_port);
    for (size_t i = 0; i < sbj_arr_len(lines); ++i) {
        const char *line = sbj_as_str(sbj_arr_at(lines, i), "");
        if (prior_line(before, line) || !strstr(line, "inbound/http[" SBW_PROBE_INBOUND "]") ||
            !strstr(line, address))
            continue;
        const char *p = line;
        while ((p = strchr(p, '[')) != NULL) {
            ++p;
            const char *q = p;
            while (*q >= '0' && *q <= '9')
                ++q;
            if (q > p && *q == ' ' && (size_t)(q - p) < sizeof(correlation) - 3) {
                sprintf_s(correlation, sizeof(correlation), "[%.*s ", (int)(q - p), p);
                break;
            }
        }
    }
    if (*correlation)
        for (size_t i = 0; i < sbj_arr_len(lines) && sbj_arr_len(output) < 32; ++i) {
            const char *line = sbj_as_str(sbj_arr_at(lines, i), "");
            if (!prior_line(before, line) && strstr(line, correlation)) {
                char *safe = sbw_diagnostics_redact(line, private_config);
                sbj_arr_push(output, sbj_str(safe));
                sbw_secret_free(safe);
            }
        }
    sbj_free(after);
    return output;
}
sbj *sbw_route_probe(const sbw_runtime_config *config, sbw_core *core, DWORD pid, HANDLE cancel,
                     const sbj *params, sbw_error *error) {
    DWORD timeout = timeout_value(params, 10000, 15000);
    probe_url url = {0};
    if (!keys_valid(params, false) || !timeout) {
        sbw_fail(error, "INVALID_REQUEST", "Use a URL and a timeout between 1000 and 15000 ms.");
        return NULL;
    }
    if (!parse_url(sbj_get(params, "url"), &url, error))
        return NULL;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
        url_free(&url);
        sbw_fail(error, "CORE_CANCELLED", "The probe was cancelled.");
        return NULL;
    }
    if (sbw_runtime_probe_owner(config, pid, error)) {
        url_free(&url);
        return NULL;
    }
    HINTERNET session = NULL, connection = NULL, request = NULL;
    request_state *state = NULL;
    sbj *result = NULL, *observed = NULL, *baseline = NULL,
        *before = core ? sbw_core_logs(core) : sbj_object();
    sbj *private_config = sbj_parse_cstr(config->json ? config->json : "{}");
    DWORD win_error = 0, status = 0;
    unsigned short source_port = 0;
    bool callback_owned = false;
    ULONGLONG started = GetTickCount64(), deadline = started + timeout;
    if (sbw_runtime_config_get(config, pid, cancel, "/connections", &baseline, error))
        goto done;
    wchar_t proxy[64];
    swprintf_s(proxy, 64, L"127.0.0.1:%u", config->probe_port);
    session = WinHttpOpen(L"sb-easy route diagnostic", WINHTTP_ACCESS_TYPE_NAMED_PROXY, proxy,
                          WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    if (!session)
        goto failed;
    if (!WinHttpSetTimeouts(session, (int)timeout, (int)timeout, (int)timeout, (int)timeout))
        goto failed;
    connection = WinHttpConnect(session, url.host, url.port, 0);
    if (!connection)
        goto failed;
    request = WinHttpOpenRequest(connection, L"GET", url.path, NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, url.tls ? WINHTTP_FLAG_SECURE : 0);
    if (!request)
        goto failed;
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER, disabled = WINHTTP_DISABLE_COOKIES,
          autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)) ||
        !WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
        !WinHttpSetOption(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon, sizeof(autologon)))
        goto failed;
    wchar_t *password = sbw_wide(config->probe_secret, error);
    if (!password)
        goto failed;
    bool credentials = WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC,
                                             L"sb-easy-probe", password, NULL) != FALSE;
    SecureZeroMemory(password, (wcslen(password) + 1) * sizeof(wchar_t));
    free(password);
    if (!credentials)
        goto failed;
    state = sb_xcalloc(1, sizeof(*state));
    state->references = 1;
    state->event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!state->event)
        goto failed;
    DWORD_PTR context = (DWORD_PTR)state;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context)))
        goto failed;
    if (WinHttpSetStatusCallback(request, request_callback,
                                 WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE |
                                     WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE |
                                     WINHTTP_CALLBACK_FLAG_REQUEST_ERROR | WINHTTP_CALLBACK_FLAG_HANDLES,
                                 0) == WINHTTP_INVALID_STATUS_CALLBACK)
        goto failed;
    InterlockedIncrement(&state->references);
    callback_owned = true;
    /* Recheck just before the first authenticated request. WinHTTP never uses
     * system proxy discovery or a direct fallback for this request. */
    if (sbw_runtime_probe_owner(config, pid, error))
        goto done;
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0,
                            context) &&
        GetLastError() != ERROR_IO_PENDING)
        goto failed;
    bool receiving = false;
    ULONGLONG next_snapshot = 0;
    for (;;) {
        if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
            sbw_fail(error, "CORE_CANCELLED", "The probe was cancelled.");
            goto done;
        }
        if (GetTickCount64() >= deadline) {
            win_error = ERROR_WINHTTP_TIMEOUT;
            break;
        }
        LONG stage = InterlockedCompareExchange(&state->stage, 0, 0);
        if (stage < 0) {
            win_error = (DWORD)InterlockedCompareExchange(&state->win_error, 0, 0);
            break;
        }
        if (stage >= 1 && !receiving) {
            source_port = request_source(request);
            receiving = true;
            if (!WinHttpReceiveResponse(request, NULL) && GetLastError() != ERROR_IO_PENDING)
                goto failed;
        }
        if (receiving) {
            unsigned short current_source = request_source(request);
            if (current_source)
                source_port = current_source;
        }
        if (!observed && (stage >= 1 || GetTickCount64() >= next_snapshot)) {
            sbj *snapshot = NULL;
            sbw_error ignored = {0};
            if (!sbw_runtime_config_get(config, pid, cancel, "/connections", &snapshot, &ignored))
                observed = connection_evidence(snapshot, baseline, &url, source_port, private_config);
            sbj_free(snapshot);
            next_snapshot = GetTickCount64() + 150;
        }
        if (stage >= 2) {
            DWORD size = sizeof(status);
            if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX))
                goto failed;
            unsigned short current_source = request_source(request);
            if (current_source)
                source_port = current_source;
            break;
        }
        (void)WaitForSingleObject(state->event, 25);
    }
    goto response;
failed:
    win_error = GetLastError();
    if (!win_error)
        win_error = ERROR_WINHTTP_INTERNAL_ERROR;
response:
    result = sbj_object();
    sbj_set_str(result, "url", url.display);
    sbj_set_str(result, "host", url.host_utf8);
    sbj_set_int(result, "port", url.port);
    sbj_set_bool(result, "success", !win_error && status >= 200 && status < 400);
    sbj_set_int(result, "http_status", status);
    sbj_set_int(result, "elapsed_ms", (int64_t)(GetTickCount64() - started));
    sbj_set_str(result, "error_code",
                win_error       ? transport_error(win_error)
                : status >= 400 ? "PROBE_HTTP_STATUS"
                                : "");
    sbj *evidence = sbj_object();
    sbj_set_bool(evidence, "observed", observed != NULL);
    if (observed) {
        sbj_set(evidence, "connection", observed);
        observed = NULL;
    }
    sbj *logs = related_logs(core, before, source_port, private_config);
    bool dns_observed = false;
    for (size_t i = 0; i < sbj_arr_len(logs); ++i)
        if (strstr(sbj_as_str(sbj_arr_at(logs, i), ""), "dns:"))
            dns_observed = true;
    sbj_set(evidence, "logs", logs);
    sbj_set_str(evidence, "dns", dns_observed ? "correlated_logs" : "unobserved");
    sbj_set_str(evidence, "public_exit_ip", "unobserved");
    sbj_set_str(evidence, "process_scope", "diagnostic-service-request");
    sbj_set(result, "evidence", evidence);
done:
    if (request)
        WinHttpCloseHandle(request);
    if (connection)
        WinHttpCloseHandle(connection);
    if (session)
        WinHttpCloseHandle(session);
    if (state) {
        if (!callback_owned && !state->event) {
            free(state);
        } else
            request_release(state);
    }
    sbj_free(observed);
    sbj_free(baseline);
    sbj_free(before);
    sbj_free(private_config);
    url_free(&url);
    return result;
}
