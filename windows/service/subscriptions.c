#include "subscriptions.h"
#include <winhttp.h>
#include <objbase.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SUB_MAX_BYTES (256U * 1024U)
#define JS_MAX_INTEGER INT64_C(9007199254740991)
static bool plain_string(const sbj *value, size_t max, bool empty) {
    if (!sbw_json_string(value, max, empty))
        return false;
    for (const unsigned char *p = (const unsigned char *)sbj_as_str(value, ""); *p; ++p)
        if (*p < 32 || *p == 127)
            return false;
    return true;
}
static bool forbidden_option(const sbj *value, unsigned depth) {
    if (depth > 32)
        return true;
    const char *keys[] = {"plugin",
                          "plugin_opts",
                          "detour",
                          "bind_interface",
                          "routing_mark",
                          "netns",
                          "network_namespace",
                          "certificate_path",
                          "key_path",
                          "client_certificate_path",
                          "client_key_path",
                          "certificate_directory_path",
                          "private_key_path",
                          "known_hosts_path",
                          "config_path",
                          "protect_path",
                          "acme",
                          "ech"};
    if (sbj_is_object(value))
        for (size_t i = 0; i < sbj_obj_len(value); ++i) {
            const char *key = sbj_obj_key(value, i);
            for (size_t j = 0; j < sizeof(keys) / sizeof(*keys); ++j)
                if (!strcmp(key, keys[j]))
                    return true;
            if (forbidden_option(sbj_obj_val(value, i), depth + 1))
                return true;
        }
    else if (sbj_is_array(value))
        for (size_t i = 0; i < sbj_arr_len(value); ++i)
            if (forbidden_option(sbj_arr_at(value, i), depth + 1))
                return true;
    return false;
}
bool sbw_subscription_node_valid(const sbj *node) {
    const char *type = sbj_get_str(node, "type", "");
    const char *types[] = {"shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "http", "socks"};
    bool supported = false;
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i)
        if (!strcmp(type, types[i]))
            supported = true;
    if (!supported || !plain_string(sbj_get(node, "tag"), 80, false) ||
        !plain_string(sbj_get(node, "server"), 253, false) || !sbj_is_integer(sbj_get(node, "server_port")) ||
        sbj_get_int(node, "server_port", 0) < 1 || sbj_get_int(node, "server_port", 0) > 65535 ||
        forbidden_option(node, 0))
        return false;
    if ((!strcmp(type, "vmess") || !strcmp(type, "vless") || !strcmp(type, "tuic")) &&
        !plain_string(sbj_get(node, "uuid"), 128, false))
        return false;
    if ((!strcmp(type, "shadowsocks") || !strcmp(type, "trojan") || !strcmp(type, "hysteria2") ||
         !strcmp(type, "tuic")) &&
        !sbw_json_string(sbj_get(node, "password"), 4096, false))
        return false;
    if (!strcmp(type, "shadowsocks") && !plain_string(sbj_get(node, "method"), 128, false))
        return false;
    return true;
}
static bool valid_id(const sbj *value) {
    if (!sbw_json_string(value, 36, false))
        return false;
    const char *id = sbj_as_str(value, "");
    return strlen(id) == 36 && strspn(id, "0123456789abcdef-") == 36;
}
static const sbj *find_subscription(const sbj *identity, const char *id) {
    const sbj *subs = sbj_get(identity, "local_subscriptions");
    for (size_t i = 0; i < sbj_arr_len(subs); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(subs, i), "id"), id))
            return sbj_arr_at(subs, i);
    return NULL;
}
static bool valid_url(const sbj *value, bool allow_empty) {
    if (!plain_string(value, 8192, allow_empty))
        return false;
    const char *url = sbj_as_str(value, "");
    if (!*url)
        return allow_empty;
    const char *authority = !strncmp(url, "https://", 8)  ? url + 8
                            : !strncmp(url, "http://", 7) ? url + 7
                                                          : NULL;
    if (!authority || !*authority || strchr(url, '#') || strchr(url, '\\') || strchr(url, ' '))
        return false;
    size_t host_length = strcspn(authority, "/?");
    return host_length > 0 && !memchr(authority, '@', host_length);
}
int sbw_subscriptions_merge(sbj *config, const sbj *identity, sbw_error *error) {
    sbj *out = sbj_get(config, "outbounds");
    const sbj *subs = sbj_get(identity, "local_subscriptions");
    if (!subs)
        return 0;
    if (!sbj_is_array(subs) || sbj_arr_len(subs) > 16)
        return sbw_fail(error, "SUBSCRIPTION_INVALID", "The saved subscription list is invalid.");
    if (!sbj_arr_len(subs))
        return 0;
    if (!sbj_is_array(out))
        return sbw_fail(error, "SUBSCRIPTION_INVALID", "The base configuration has no outbounds.");
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj *sub = sbj_arr_at(subs, i), *nodes = sbj_get(sub, "nodes");
        if (!valid_id(sbj_get(sub, "id")) || !sbj_is_array(nodes) || !sbj_arr_len(nodes) ||
            sbj_arr_len(nodes) > 256)
            return sbw_fail(error, "SUBSCRIPTION_INVALID", "A saved subscription is invalid.");
        for (size_t j = 0; j < sbj_arr_len(nodes); ++j) {
            const sbj *node = sbj_arr_at(nodes, j);
            if (!sbw_subscription_node_valid(node))
                return sbw_fail(error, "SUBSCRIPTION_INVALID", "A saved subscription node is invalid.");
            char tag[128];
            sprintf_s(tag, sizeof(tag), "local-%s/%s", sbj_get_str(sub, "id", ""),
                      sbj_get_str(node, "tag", ""));
            for (size_t k = 0; k < sbj_arr_len(out); ++k)
                if (sbj_string_is(sbj_get(sbj_arr_at(out, k), "tag"), tag))
                    return sbw_fail(error, "SUBSCRIPTION_CONFLICT",
                                    "A local node name conflicts with another node.");
            sbj *copy = sbj_clone(node);
            sbj_set_str(copy, "tag", tag);
            sbj_arr_push(out, copy);
        }
    }
    if (sbj_arr_len(out) > 1024)
        return sbw_fail(error, "SUBSCRIPTION_LIMIT", "At most 1024 combined nodes are supported.");
    return 0;
}
sbj *sbw_subscriptions_summary(const sbj *source, const sbj *identity) {
    sbj *result = sbj_object(), *list = sbj_array(), *sources = sbj_get(source, "subscription_sources");
    sbj_set(result, "managed", sbj_is_array(sources) ? sbj_clone(sources) : sbj_array());
    sbj_set_bool(result, "sources_available", sbj_is_array(sources));
    const sbj *subs = sbj_get(identity, "local_subscriptions");
    for (size_t i = 0; i < sbj_arr_len(subs) && i < 16; ++i) {
        const sbj *sub = sbj_arr_at(subs, i), *nodes = sbj_get(sub, "nodes");
        if (!valid_id(sbj_get(sub, "id")))
            continue;
        sbj *item = sbj_object(), *tags = sbj_array();
        sbj_set_str(item, "id", sbj_get_str(sub, "id", ""));
        sbj_set_str(item, "name", sbj_get_str(sub, "name", ""));
        for (size_t j = 0; j < sbj_arr_len(nodes) && j < 256; ++j)
            if (plain_string(sbj_get(sbj_arr_at(nodes, j), "tag"), 80, false)) {
                char tag[128];
                sprintf_s(tag, sizeof(tag), "local-%s/%s", sbj_get_str(sub, "id", ""),
                          sbj_get_str(sbj_arr_at(nodes, j), "tag", ""));
                sbj_arr_push(tags, sbj_str(tag));
            }
        sbj_set(item, "tags", tags);
        sbj_set_int(item, "node_count", (int64_t)sbj_arr_len(nodes));
        sbj_set_bool(item, "remote", *sbj_get_str(sub, "url", "") != 0);
        const char *fields[] = {"refresh_interval_minutes", "last_attempt_at", "last_success_at",
                                "next_refresh_at"};
        for (size_t j = 0; j < sizeof(fields) / sizeof(*fields); ++j)
            sbj_set_int(item, fields[j], sbj_get_int(sub, fields[j], 0));
        sbj_set_str(item, "last_error", sbj_get_str(sub, "last_error", ""));
        sbj *metadata = sbj_is_object(sbj_get(sub, "metadata"))
                            ? sbj_clone(sbj_get(sub, "metadata"))
                            : sbw_subscription_metadata(NULL, (uint64_t)time(NULL));
        if (sbj_is_integer(sbj_get(metadata, "expires_at"))) {
            int64_t expiry = sbj_get_int(metadata, "expires_at", 0);
            sbj_set_bool(metadata, "expired", expiry > 0 && expiry <= (int64_t)time(NULL));
        }
        sbj_set(item, "metadata", metadata);
        sbj_set(item, "report",
                sbj_is_object(sbj_get(sub, "report")) ? sbj_clone(sbj_get(sub, "report")) : sbj_object());
        sbj_arr_push(list, item);
    }
    sbj_set(result, "local", list);
    return result;
}
static int64_t refresh_minutes(const sbj *params, const sbj *existing, bool remote) {
    const sbj *provided = sbj_get(params, "refresh_interval_minutes");
    int64_t value = provided ? sbj_as_int(provided, -1)
                             : sbj_get_int(existing, "refresh_interval_minutes", remote ? 360 : 0);
    if ((provided && !sbj_is_integer(provided)) || (value != 0 && (value < 15 || value > 10080)))
        return -1;
    return remote ? value : 0;
}
sbj *sbw_subscriptions_change(const sbj *identity, const sbj *params, bool remove, sbw_error *error) {
    if (!sbj_is_object(identity)) {
        sbw_fail(error, "NOT_CONFIGURED", "Set up a local or managed profile first.");
        return NULL;
    }
    if (!sbj_is_object(params))
        goto invalid;
    const char *id = sbj_get_str(params, "id", "");
    const sbj *old = sbj_get(identity, "local_subscriptions"), *nodes = sbj_get(params, "nodes");
    if ((old && !sbj_is_array(old)) || strlen(id) > 36 || (*id && !valid_id(sbj_get(params, "id"))))
        goto invalid;
    const sbj *existing = *id ? find_subscription(identity, id) : NULL;
    if ((*id && !existing) || (remove && (!existing || sbj_obj_len(params) != 1)) ||
        (!*id && sbj_arr_len(old) >= 16))
        goto invalid;
    sbj *updated = NULL;
    if (!remove) {
        const sbj *url = sbj_get(params, "url");
        if (!url && existing)
            url = sbj_get(existing, "url");
        bool remote = url && *sbj_as_str(url, "");
        int64_t minutes = refresh_minutes(params, existing, remote);
        if (!plain_string(sbj_get(params, "name"), 100, false) || !sbj_is_array(nodes) ||
            !sbj_arr_len(nodes) || sbj_arr_len(nodes) > 256 || (url && !valid_url(url, true)) || minutes < 0)
            goto invalid;
        for (size_t i = 0; i < sbj_arr_len(nodes); ++i) {
            if (!sbw_subscription_node_valid(sbj_arr_at(nodes, i)))
                goto invalid;
            for (size_t j = 0; j < i; ++j)
                if (sbj_equal(sbj_get(sbj_arr_at(nodes, i), "tag"), sbj_get(sbj_arr_at(nodes, j), "tag")))
                    goto invalid;
        }
        char generated[37];
        GUID guid;
        if (!*id) {
            if (FAILED(CoCreateGuid(&guid)))
                goto invalid;
            sprintf_s(generated, sizeof(generated), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2],
                      guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
            id = generated;
        }
        updated = existing ? sbj_clone(existing) : sbj_object();
        sbj_set_str(updated, "id", id);
        sbj_set_str(updated, "name", sbj_get_str(params, "name", ""));
        sbj_set_str(updated, "url", sbj_as_str(url, ""));
        sbj_set(updated, "nodes", sbj_clone(nodes));
        sbj_set_int(updated, "refresh_interval_minutes", minutes);
        if (!existing)
            sbj_set_int(updated, "next_refresh_at", minutes ? (int64_t)time(NULL) + minutes * 60 : 0);
    }
    sbj *copy = sbj_clone(identity), *list = sbj_array();
    for (size_t i = 0; i < sbj_arr_len(old); ++i) {
        const sbj *entry = sbj_arr_at(old, i);
        if (entry == existing) {
            if (updated) {
                sbj_arr_push(list, updated);
                updated = NULL;
            }
        } else
            sbj_arr_push(list, sbj_clone(entry));
    }
    if (updated)
        sbj_arr_push(list, updated);
    sbj_set(copy, "local_subscriptions", list);
    return copy;
invalid:
    sbw_fail(error, "SUBSCRIPTION_INVALID",
             "Check the subscription name, address, refresh interval and node parameters.");
    return NULL;
}
sbj *sbw_subscription_metadata(const char *header, uint64_t now) {
    sbj *result = sbj_object();
    sbj_set_bool(result, "available", false);
    sbj_set_bool(result, "header_present", header && *header);
    if (!header || !*header)
        return result;
    if (strlen(header) > 4096)
        goto invalid;
    const char *names[] = {"upload", "download", "total", "expire"},
               *fields[] = {"upload_bytes", "download_bytes", "total_bytes", "expires_at"};
    uint64_t values[4] = {0};
    unsigned seen = 0;
    const char *cursor = header;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ';')
            ++cursor;
        if (!*cursor)
            break;
        const char *end = strchr(cursor, ';');
        if (!end)
            end = cursor + strlen(cursor);
        const char *equal = memchr(cursor, '=', (size_t)(end - cursor));
        if (!equal)
            goto invalid;
        const char *key_end = equal;
        while (key_end > cursor && (key_end[-1] == ' ' || key_end[-1] == '\t'))
            --key_end;
        int field = -1;
        for (size_t i = 0; i < 4; ++i)
            if ((size_t)(key_end - cursor) == strlen(names[i]) && !memcmp(cursor, names[i], strlen(names[i])))
                field = (int)i;
        if (field >= 0) {
            if (seen & (1U << (unsigned)field))
                goto invalid;
            seen |= 1U << (unsigned)field;
            const char *number = equal + 1;
            while (number < end && (*number == ' ' || *number == '\t'))
                ++number;
            const char *number_end = end;
            while (number_end > number && (number_end[-1] == ' ' || number_end[-1] == '\t'))
                --number_end;
            if (number == number_end)
                goto invalid;
            for (const char *p = number; p < number_end; ++p) {
                if (*p < '0' || *p > '9')
                    goto invalid;
                unsigned digit = (unsigned)(*p - '0');
                if (values[field] > ((uint64_t)JS_MAX_INTEGER - digit) / 10U)
                    goto invalid;
                values[field] = values[field] * 10U + digit;
            }
            if (field == 3 && values[3] > UINT64_C(253402300799))
                goto invalid;
        }
        cursor = *end ? end + 1 : end;
    }
    if (!seen)
        goto invalid;
    for (size_t i = 0; i < 4; ++i)
        if (seen & (1U << (unsigned)i))
            sbj_set_int(result, fields[i], (int64_t)values[i]);
    if ((seen & 3U) == 3U) {
        if (values[0] > (uint64_t)JS_MAX_INTEGER - values[1])
            goto invalid;
        uint64_t used = values[0] + values[1];
        sbj_set_int(result, "used_bytes", (int64_t)used);
        if ((seen & 4U) && values[2]) {
            sbj_set_int(result, "remaining_bytes", (int64_t)(used < values[2] ? values[2] - used : 0));
            sbj_set_bool(result, "quota_exhausted", used >= values[2]);
        }
    }
    if (seen & 8U)
        sbj_set_bool(result, "expired", values[3] != 0 && values[3] <= now);
    sbj_set_bool(result, "available", true);
    return result;
invalid:
    sbj_free(result);
    result = sbj_object();
    sbj_set_bool(result, "available", false);
    sbj_set_bool(result, "header_present", true);
    sbj_set_str(result, "warning", "invalid_subscription_userinfo");
    return result;
}
static char *response_header(HINTERNET request, const wchar_t *name) {
    DWORD size = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, NULL, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size > 8192 || !size)
        return NULL;
    wchar_t *buffer = sb_xcalloc((size_t)size / sizeof(wchar_t) + 1, sizeof(wchar_t));
    char *result = NULL;
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, buffer, &size, WINHTTP_NO_HEADER_INDEX))
        result = sbw_utf8(buffer, NULL);
    free(buffer);
    return result;
}
/* The callback retains the buffer and event until HANDLE_CLOSING, allowing
 * cancellation to return even while the networking stack is still unwinding. */
typedef struct fetch_state {
    volatile LONG references, stage, read_length;
    HANDLE event;
    char bytes[8192];
} fetch_state;
static void fetch_release(fetch_state *state) {
    if (InterlockedDecrement(&state->references) == 0) {
        CloseHandle(state->event);
        SecureZeroMemory(state->bytes, sizeof(state->bytes));
        free(state);
    }
}
static void CALLBACK fetch_callback(HINTERNET handle, DWORD_PTR context, DWORD status, void *info,
                                    DWORD length) {
    (void)handle;
    (void)info;
    fetch_state *state = (fetch_state *)context;
    if (!state)
        return;
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
        fetch_release(state);
        return;
    }
    LONG stage = 0;
    if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE)
        stage = 1;
    else if (status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE)
        stage = 2;
    else if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
        InterlockedExchange(&state->read_length, (LONG)length);
        stage = 3;
    } else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR)
        stage = -1;
    else
        return;
    InterlockedExchange(&state->stage, stage);
    SetEvent(state->event);
}
static bool fetch_wait(fetch_state *state, LONG expected, HANDLE cancel, ULONGLONG deadline) {
    for (;;) {
        if ((cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) || GetTickCount64() >= deadline)
            return false;
        LONG stage = InterlockedCompareExchange(&state->stage, 0, 0);
        if (stage < 0)
            return false;
        if (stage == expected)
            return true;
        (void)WaitForSingleObject(state->event, 25);
    }
}
static sbj *fetch_run(const char *url, HANDLE cancel, sbw_error *error) {
    wchar_t *wide = NULL, *host = NULL, *path = NULL;
    HINTERNET session = NULL, connection = NULL, request = NULL;
    sbj *result = NULL;
    sb_buf body = {0};
    fetch_state *state = NULL;
    ULONGLONG deadline = GetTickCount64() + 30000;
    sbj *url_value = sbj_str(url);
    bool valid = valid_url(url_value, false);
    sbj_free(url_value);
    if (!valid)
        goto done;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
        goto done;
    wide = sbw_wide(url, error);
    if (!wide)
        goto done;
    URL_COMPONENTS parts = {0};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = parts.dwUserNameLength =
        parts.dwPasswordLength = (DWORD)-1;
    if (!WinHttpCrackUrl(wide, 0, 0, &parts) ||
        (parts.nScheme != INTERNET_SCHEME_HTTPS && parts.nScheme != INTERNET_SCHEME_HTTP) ||
        !parts.dwHostNameLength || parts.dwUserNameLength || parts.dwPasswordLength)
        goto done;
    host = sb_xcalloc((size_t)parts.dwHostNameLength + 1, sizeof(wchar_t));
    wmemcpy(host, parts.lpszHostName, parts.dwHostNameLength);
    size_t length = (size_t)parts.dwUrlPathLength + parts.dwExtraInfoLength;
    path = sb_xcalloc(length + 2, sizeof(wchar_t));
    if (parts.dwUrlPathLength)
        wmemcpy(path, parts.lpszUrlPath, parts.dwUrlPathLength);
    else
        path[0] = L'/';
    if (parts.dwExtraInfoLength)
        wcsncat_s(path, length + 2, parts.lpszExtraInfo, parts.dwExtraInfoLength);
    session = WinHttpOpen(L"sb-easy subscription", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    if (!session)
        goto done;
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);
    connection = WinHttpConnect(session, host, parts.nPort, 0);
    if (!connection)
        goto done;
    request =
        WinHttpOpenRequest(connection, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                           parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!request)
        goto done;
    DWORD disabled = WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES,
          autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
          policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
        !WinHttpSetOption(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon, sizeof(autologon)) ||
        !WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)))
        goto done;
    state = sb_xcalloc(1, sizeof(*state));
    state->references = 1;
    state->event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!state->event)
        goto done;
    DWORD_PTR context = (DWORD_PTR)state;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context)) ||
        WinHttpSetStatusCallback(request, fetch_callback,
                                 WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES,
                                 0) == WINHTTP_INVALID_STATUS_CALLBACK)
        goto done;
    InterlockedIncrement(&state->references);
    if ((!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0,
                             context) &&
         GetLastError() != ERROR_IO_PENDING) ||
        !fetch_wait(state, 1, cancel, deadline))
        goto done;
    if ((!WinHttpReceiveResponse(request, NULL) && GetLastError() != ERROR_IO_PENDING) ||
        !fetch_wait(state, 2, cancel, deadline))
        goto done;
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) ||
        status != 200)
        goto done;
    for (;;) {
        InterlockedExchange(&state->stage, 0);
        if ((!WinHttpReadData(request, state->bytes, sizeof(state->bytes), NULL) &&
             GetLastError() != ERROR_IO_PENDING) ||
            !fetch_wait(state, 3, cancel, deadline))
            goto done;
        LONG read = InterlockedCompareExchange(&state->read_length, 0, 0);
        if (!read)
            break;
        if (read < 0 || read > (LONG)sizeof(state->bytes) || body.len + (size_t)read > SUB_MAX_BYTES)
            goto done;
        sb_buf_append(&body, state->bytes, (size_t)read);
    }
    if (!body.len || memchr(body.p, 0, body.len) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.p, (int)body.len, NULL, 0))
        goto done;
    if ((cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) || GetTickCount64() >= deadline)
        goto done;
    char *userinfo = response_header(request, L"Subscription-Userinfo");
    result = sbj_object();
    sbj_set(result, "body", sbj_strn(body.p, body.len));
    sbj_set(result, "metadata", sbw_subscription_metadata(userinfo, (uint64_t)time(NULL)));
    free(userinfo);
    sbj_set_int(result, "fetched_at", (int64_t)time(NULL));
done:
    if (request)
        WinHttpCloseHandle(request);
    if (connection)
        WinHttpCloseHandle(connection);
    if (session)
        WinHttpCloseHandle(session);
    if (state)
        fetch_release(state);
    free(wide);
    free(host);
    free(path);
    if (body.p)
        SecureZeroMemory(body.p, body.len);
    sb_buf_free(&body);
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
        sbj_free(result);
        result = NULL;
    }
    if (!result)
        sbw_fail(error,
                 cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0 ? "SUBSCRIPTION_CANCELLED"
                                                                           : "SUBSCRIPTION_FETCH_FAILED",
                 "Unable to download the HTTP(S) subscription within 30 seconds (maximum 256 KB).");
    return result;
}
/* Some WinHTTP providers can synchronously perform proxy discovery or socket
 * work even for an async session. Isolate them from the service mutation lane;
 * the worker owns every object and a private cancellation event until it exits. */
typedef struct fetch_job {
    volatile LONG references;
    HANDLE cancel, complete;
    char *url;
    sbj *result;
    sbw_error error;
} fetch_job;
static void fetch_job_release(fetch_job *job) {
    if (InterlockedDecrement(&job->references) == 0) {
        CloseHandle(job->cancel);
        CloseHandle(job->complete);
        sbw_secret_free(job->url);
        sbj_free(job->result);
        free(job);
    }
}
static DWORD WINAPI fetch_worker(void *argument) {
    fetch_job *job = argument;
    job->result = fetch_run(job->url, job->cancel, &job->error);
    SetEvent(job->complete);
    fetch_job_release(job);
    return 0;
}
sbj *sbw_subscription_fetch(const char *url, HANDLE cancel, sbw_error *error) {
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
        sbw_fail(error, "SUBSCRIPTION_CANCELLED", "The subscription download was cancelled.");
        return NULL;
    }
    fetch_job *job = sb_xcalloc(1, sizeof(*job));
    job->references = 1;
    job->url = sb_strdup(url);
    job->cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    job->complete = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!job->cancel || !job->complete) {
        fetch_job_release(job);
        sbw_fail(error, "SUBSCRIPTION_FETCH_FAILED", "Unable to initialize the subscription download.");
        return NULL;
    }
    InterlockedIncrement(&job->references);
    HANDLE thread = CreateThread(NULL, 0, fetch_worker, job, 0, NULL);
    if (!thread) {
        fetch_job_release(job);
        fetch_job_release(job);
        sbw_fail(error, "SUBSCRIPTION_FETCH_FAILED", "Unable to start the subscription download.");
        return NULL;
    }
    CloseHandle(thread);
    HANDLE events[2] = {job->complete, cancel};
    DWORD waited = WaitForMultipleObjects(cancel ? 2 : 1, events, FALSE, 30000);
    bool cancelled = cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0;
    sbj *result = NULL;
    if (waited == WAIT_OBJECT_0 && !cancelled) {
        result = job->result;
        job->result = NULL;
        if (!result && error)
            *error = job->error;
    } else {
        SetEvent(job->cancel);
        sbw_fail(error, cancelled ? "SUBSCRIPTION_CANCELLED" : "SUBSCRIPTION_FETCH_FAILED",
                 cancelled ? "The subscription download was cancelled."
                           : "The subscription download exceeded its 30-second deadline.");
    }
    fetch_job_release(job);
    return result;
}
static sbj *import_content(const sbj *identity, const sbj *params, const sbj *download, sbw_error *error) {
    const sbj *body = download ? sbj_get(download, "body") : sbj_get(params, "body");
    if (!sbw_json_string(body, SUB_MAX_BYTES, false)) {
        sbw_fail(error, "SUBSCRIPTION_INVALID", "Provide a subscription body or address.");
        return NULL;
    }
    sbj *parsed = sbw_subscription_parse(body->v.str.ptr, body->v.str.len, error);
    if (!parsed)
        return NULL;
    sbj *change = sbj_clone(params);
    sbj_del(change, "body");
    sbj_set(change, "nodes", sbj_clone(sbj_get(parsed, "nodes")));
    sbj *updated = sbw_subscriptions_change(identity, change, false, error);
    sbj_free(change);
    if (updated) {
        sbj *items = sbj_get(updated, "local_subscriptions"), *saved = NULL;
        const char *requested = sbj_get_str(params, "id", "");
        for (size_t i = 0; i < sbj_arr_len(items); ++i) {
            sbj *item = sbj_arr_at(items, i);
            const char *id = sbj_get_str(item, "id", "");
            if ((*requested && !strcmp(id, requested)) || (!*requested && !find_subscription(identity, id))) {
                saved = item;
                break;
            }
        }
        if (saved) {
            int64_t now = (int64_t)time(NULL), minutes = sbj_get_int(saved, "refresh_interval_minutes", 0);
            sbj_set(saved, "report", sbj_clone(sbj_get(parsed, "report")));
            sbj_set(saved, "metadata",
                    download ? sbj_clone(sbj_get(download, "metadata"))
                             : sbw_subscription_metadata(NULL, (uint64_t)now));
            sbj_set_int(saved, "last_attempt_at", now);
            sbj_set_int(saved, "last_success_at", now);
            sbj_set_int(saved, "next_refresh_at", minutes ? now + minutes * 60 : 0);
            sbj_set_int(saved, "failure_count", 0);
            sbj_set_str(saved, "last_error", "");
        }
    }
    sbj_free(parsed);
    return updated;
}
sbj *sbw_subscriptions_import(const sbj *identity, const sbj *params, HANDLE cancel, sbw_error *error) {
    if (!sbj_is_object(params))
        goto invalid;
    const char *allowed[] = {"id", "name", "url", "body", "refresh_interval_minutes"};
    for (size_t i = 0; i < sbj_obj_len(params); ++i) {
        bool known = false;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(*allowed); ++j)
            if (!strcmp(sbj_obj_key(params, i), allowed[j]))
                known = true;
        if (!known)
            goto invalid;
    }
    if (sbj_get(params, "body"))
        return import_content(identity, params, NULL, error);
    const sbj *url = sbj_get(params, "url");
    if (!valid_url(url, false))
        goto invalid;
    sbj *download = sbw_subscription_fetch(sbj_as_str(url, ""), cancel, error);
    if (!download)
        return NULL;
    sbj *updated = import_content(identity, params, download, error);
    sbj_free(download);
    return updated;
invalid:
    sbw_fail(error, "SUBSCRIPTION_INVALID",
             "Provide a name, a subscription address or body, and an optional refresh interval.");
    return NULL;
}
sbj *sbw_subscriptions_refresh(const sbj *identity, const char *id, HANDLE cancel, sbw_error *error) {
    const sbj *existing = id ? find_subscription(identity, id) : NULL;
    if (!existing || !valid_url(sbj_get(existing, "url"), false)) {
        sbw_fail(error, "SUBSCRIPTION_NOT_REMOTE", "This subscription has no saved remote address.");
        return NULL;
    }
    sbj *params = sbj_object();
    sbj_set_str(params, "id", id);
    sbj_set_str(params, "name", sbj_get_str(existing, "name", ""));
    sbj_set_str(params, "url", sbj_get_str(existing, "url", ""));
    sbj *updated = sbw_subscriptions_import(identity, params, cancel, error);
    sbj_free(params);
    return updated;
}
sbj *sbw_subscriptions_failure(const sbj *identity, const char *id, const char *code, uint64_t now) {
    sbj *updated = sbj_clone(identity);
    sbj *item = (sbj *)find_subscription(updated, id);
    if (!item)
        return updated;
    int64_t failures = sbj_get_int(item, "failure_count", 0) + 1;
    if (failures < 1 || failures > 16)
        failures = 16;
    uint64_t delay = 60U << (unsigned)(failures > 6 ? 6 : failures - 1);
    if (delay > 3600)
        delay = 3600;
    const char *safe =
        code && (!strcmp(code, "SUBSCRIPTION_CANCELLED") || !strcmp(code, "SUBSCRIPTION_INVALID") ||
                 !strcmp(code, "SUBSCRIPTION_FETCH_FAILED") || !strcmp(code, "ROUTING_NODE_UNAVAILABLE"))
            ? code
            : "SUBSCRIPTION_REFRESH_FAILED";
    sbj_set_int(item, "last_attempt_at", (int64_t)now);
    sbj_set_int(item, "failure_count", failures);
    sbj_set_str(item, "last_error", safe);
    sbj_set_int(item, "next_refresh_at",
                sbj_get_int(item, "refresh_interval_minutes", 0) > 0 ? (int64_t)(now + delay) : 0);
    return updated;
}
const char *sbw_subscriptions_due(const sbj *identity, uint64_t now) {
    const sbj *subs = sbj_get(identity, "local_subscriptions");
    const char *selected = NULL;
    uint64_t earliest = UINT64_MAX;
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj *sub = sbj_arr_at(subs, i);
        int64_t minutes = sbj_get_int(sub, "refresh_interval_minutes", 360),
                at = sbj_get_int(sub, "next_refresh_at", 0);
        if (!valid_id(sbj_get(sub, "id")) || !valid_url(sbj_get(sub, "url"), false) || minutes <= 0 || at < 0)
            continue;
        if ((uint64_t)at <= now && (uint64_t)at < earliest) {
            earliest = (uint64_t)at;
            selected = sbj_get_str(sub, "id", NULL);
        }
    }
    return selected;
}
