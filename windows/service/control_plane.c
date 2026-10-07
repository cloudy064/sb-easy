#include <winsock2.h>
#include <ws2tcpip.h>
#include "control_plane.h"
#include <winhttp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "0.1.0-dev"
#endif

#define MAX_URI 8192U
#define MAX_HEADER 1024U
#define MAX_HEADERS (16U * 1024U)
#define MAX_ENROLLMENT_BODY (64U * 1024U)
#define MAX_CONFIG_BODY (4U * 1024U * 1024U)

static int failure(sbw_error *error, const char *code) {
    const char *message = "The control-plane request failed.";
    if (!strcmp(code, "invalid_enrollment_uri")) message = "The enrollment link is invalid.";
    else if (!strcmp(code, "invalid_server")) message = "The control-plane server address is invalid.";
    else if (!strcmp(code, "invalid_identity")) message = "The stored device identity is invalid.";
    else if (!strcmp(code, "cancelled")) message = "The control-plane request was cancelled.";
    else if (!strcmp(code, "timeout")) message = "The control-plane request timed out.";
    else if (!strcmp(code, "tls_error")) message = "The secure connection could not be verified.";
    else if (!strcmp(code, "http_error")) message = "The control-plane server rejected the request.";
    else if (!strcmp(code, "invalid_response")) message = "The control-plane server returned an invalid response.";
    else if (!strcmp(code, "response_too_large")) message = "The control-plane response exceeds the supported limit.";
    else if (!strcmp(code, "redirect_rejected")) message = "Control-plane redirects are not permitted.";
    else if (!strcmp(code, "server_mismatch")) message = "The enrollment response names a different server.";
    return sbw_fail(error, code, message);
}

static bool is_control(unsigned char c) { return c < 32 || c == 127; }
static bool ascii_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static void lower_ascii(char *value) {
    for (; *value; ++value) if (*value >= 'A' && *value <= 'Z') *value += 'a' - 'A';
}
static int clean_text(const char *value, size_t length, size_t limit, const char *code, sbw_error *error) {
    if (!value || length > limit || length > INT_MAX) return failure(error, code);
    for (size_t i = 0; i < length; ++i) if (is_control((unsigned char)value[i])) return failure(error, code);
    if (length && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, (int)length, NULL, 0))
        return failure(error, code);
    return 0;
}
static char *trim_spaces(char *value) {
    while (*value == ' ') ++value;
    size_t size = strlen(value);
    while (size && value[size - 1] == ' ') value[--size] = 0;
    return value;
}
static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static char *percent_decode(const char *value, bool query, const char *code, sbw_error *error) {
    size_t length = strlen(value), count = 0;
    char *result = sb_xmalloc(length + 1);
    for (size_t i = 0; i < length; ++i) {
        if (value[i] == '%') {
            if (i + 2 >= length || hex(value[i + 1]) < 0 || hex(value[i + 2]) < 0) goto invalid;
            result[count++] = (char)((hex(value[i + 1]) << 4) | hex(value[i + 2]));
            i += 2;
        } else result[count++] = query && value[i] == '+' ? ' ' : value[i];
    }
    result[count] = 0;
    if (clean_text(result, count, MAX_URI, code, error) < 0) { free(result); return NULL; }
    return result;
invalid:
    free(result);
    failure(error, code);
    return NULL;
}

typedef struct server_address {
    char *normalized;
    wchar_t *host;
    wchar_t *prefix;
    INTERNET_PORT port;
    bool secure;
} server_address;

static void server_free(server_address *server) {
    free(server->normalized); free(server->host); free(server->prefix);
    memset(server, 0, sizeof(*server));
}

static bool decimal(const char *text, uint64_t *value) {
    *value = 0;
    if (!*text) return false;
    for (; *text; ++text) {
        unsigned char c = (unsigned char)*text;
        if (c < '0' || c > '9' || *value > (UINT64_MAX - (c - '0')) / 10) return false;
        *value = *value * 10 + (c - '0');
    }
    return true;
}

static int parse_server(const char *input, server_address *out, sbw_error *error) {
    memset(out, 0, sizeof(*out));
    if (!input) return failure(error, "invalid_server");
    if (clean_text(input, strlen(input), MAX_URI, "invalid_server", error) < 0) return -1;
    int result = -1;
    char *storage = sb_strdup(input), *raw = trim_spaces(storage), *path_storage = NULL;
    char *host = NULL;
    sb_buf origin = {0}, canonical = {0};
    wchar_t *wide = NULL;
    if (!*raw || strpbrk(raw, "\\?# \"<>")) goto invalid;
    char *separator = strstr(raw, "://");
    if (!separator) goto invalid;
    *separator = 0;
    lower_ascii(raw);
    if (strcmp(raw, "http") && strcmp(raw, "https")) goto invalid;
    out->secure = !strcmp(raw, "https");
    char *authority = separator + 3;
    char *slash = strchr(authority, '/');
    path_storage = sb_strdup(slash ? slash : "");
    if (slash) *slash = 0;
    if (!*authority || strchr(authority, '@')) goto invalid;
    char *port = NULL;
    if (*authority == '[') {
        char *end = strchr(authority, ']');
        if (!end) goto invalid;
        *end = 0;
        wide = sbw_wide(authority + 1, error);
        IN6_ADDR address;
        wchar_t formatted[INET6_ADDRSTRLEN];
        if (!wide || InetPtonW(AF_INET6, wide, &address) != 1 ||
            !InetNtopW(AF_INET6, &address, formatted, INET6_ADDRSTRLEN)) goto invalid;
        host = sbw_utf8(formatted, error);
        if (!host) goto invalid;
        if (end[1]) { if (end[1] != ':') goto invalid; port = end + 2; }
        sb_buf_printf(&origin, "%s://[%s]", raw, host);
    } else {
        char *colon = strchr(authority, ':');
        if (colon) { *colon = 0; port = colon + 1; }
        host = sb_strdup(authority);
        lower_ascii(host);
        size_t length = strlen(host);
        if (!length || length > 253 || host[0] == '.' || host[length - 1] == '.') goto invalid;
        size_t start = 0;
        for (size_t i = 0; i <= length; ++i) {
            if (host[i] && !ascii_alnum((unsigned char)host[i]) && host[i] != '-' && host[i] != '.') goto invalid;
            if (!host[i] || host[i] == '.') {
                if (i == start || i - start > 63 || host[start] == '-' || host[i - 1] == '-') goto invalid;
                start = i + 1;
            }
        }
        sb_buf_printf(&origin, "%s://%s", raw, host);
    }
    uint64_t parsed_port = out->secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    if (port) {
        if (!decimal(port, &parsed_port) || !parsed_port || parsed_port > 65535) goto invalid;
        if (parsed_port != (uint64_t)(out->secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT))
            sb_buf_printf(&origin, ":%u", (unsigned)parsed_port);
    }
    out->port = (INTERNET_PORT)parsed_port;
    out->host = sbw_wide(host, error);
    if (!out->host) goto invalid;
    size_t path_length = strlen(path_storage);
    while (path_length && path_storage[path_length - 1] == '/') path_storage[--path_length] = 0;
    char *path = path_storage;
    while (*path) {
        if (*path++ != '/') goto invalid;
        char *next = strchr(path, '/');
        if (next) *next = 0;
        char *segment = percent_decode(path, false, "invalid_server", error);
        if (!segment) goto done;
        if (!*segment || !strcmp(segment, ".") || !strcmp(segment, "..") || strpbrk(segment, "/\\%?#")) {
            free(segment); goto invalid;
        }
        sb_buf_putc(&canonical, '/');
        static const char digits[] = "0123456789ABCDEF";
        for (const unsigned char *c = (const unsigned char *)segment; *c; ++c) {
            if (ascii_alnum(*c) || strchr("-_.~:@!$&'()*+,;=", *c)) sb_buf_putc(&canonical, (char)*c);
            else { sb_buf_putc(&canonical, '%'); sb_buf_putc(&canonical, digits[*c >> 4]); sb_buf_putc(&canonical, digits[*c & 15]); }
        }
        free(segment);
        if (!next) break;
        *next = '/'; path = next;
    }
    out->prefix = sbw_wide(canonical.p ? canonical.p : "", error);
    if (!out->prefix) goto invalid;
    sb_buf_puts(&origin, canonical.p ? canonical.p : "");
    out->normalized = sb_buf_detach(&origin);
    result = 0;
    goto done;
invalid:
    failure(error, "invalid_server");
done:
    free(storage); free(path_storage); free(host); free(wide);
    sb_buf_free(&origin); sb_buf_free(&canonical);
    if (result) server_free(out);
    return result;
}

static int normalize_code(const char *input, char **out, sbw_error *error) {
    if (!input || strlen(input) != 64) return failure(error, "invalid_enrollment_uri");
    for (size_t i = 0; i < 64; ++i) if (hex(input[i]) < 0) return failure(error, "invalid_enrollment_uri");
    *out = sb_strdup(input); lower_ascii(*out); return 0;
}

void sbw_enrollment_target_free(sbw_enrollment_target *target) {
    if (!target) return;
    free(target->server);
    if (target->code) { SecureZeroMemory(target->code, strlen(target->code)); free(target->code); }
    memset(target, 0, sizeof(*target));
}

int sbw_parse_enrollment_uri(const char *input, sbw_enrollment_target *out, sbw_error *error) {
    memset(out, 0, sizeof(*out));
    if (!input) return failure(error, "invalid_enrollment_uri");
    if (clean_text(input, strlen(input), MAX_URI, "invalid_enrollment_uri", error) < 0) return -1;
    int result = -1;
    char *storage = sb_strdup(input), *raw = trim_spaces(storage), *server = NULL, *code = NULL;
    server_address address = {0};
    size_t length = strlen(raw);
    if (length >= 2 && ((raw[0] == '"' && raw[length - 1] == '"') || (raw[0] == '\'' && raw[length - 1] == '\''))) {
        raw[length - 1] = 0; raw = trim_spaces(raw + 1);
    }
    if (!_strnicmp(raw, "URL:", 4)) raw = trim_spaces(raw + 4);
    if (_strnicmp(raw, "sbeasy://enroll?", 16) || strchr(raw, '#')) goto done;
    raw += 16;
    while (*raw) {
        char *ampersand = strchr(raw, '&');
        if (ampersand) *ampersand = 0;
        char *equals = strchr(raw, '=');
        if (!equals) goto done;
        *equals = 0;
        char *key = percent_decode(raw, true, "invalid_enrollment_uri", error);
        char *value = percent_decode(equals + 1, true, "invalid_enrollment_uri", error);
        if (!key || !value) { free(key); free(value); goto done; }
        if (!strcmp(key, "server") && !server) server = value;
        else if (!strcmp(key, "code") && !code) code = value;
        else { free(key); free(value); goto done; }
        free(key);
        if (!ampersand) break;
        raw = ampersand + 1;
        if (!*raw) goto done;
    }
    if (!server || !code || parse_server(server, &address, error) < 0 || normalize_code(code, &out->code, error) < 0) goto done;
    out->server = address.normalized; address.normalized = NULL;
    result = 0;
done:
    SecureZeroMemory(storage, strlen(input)); free(storage);
    free(server);
    if (code) { SecureZeroMemory(code, strlen(code)); free(code); }
    server_free(&address);
    if (result) { sbw_enrollment_target_free(out); failure(error, "invalid_enrollment_uri"); }
    return result;
}

static int check_cancel(HANDLE cancel, sbw_error *error) {
    if (!cancel) return 0;
    DWORD status = WaitForSingleObject(cancel, 0);
    if (status == WAIT_OBJECT_0) return failure(error, "cancelled");
    if (status == WAIT_FAILED) return failure(error, "network_error");
    return 0;
}
static int transport_error(DWORD error_code, sbw_error *error) {
    if (error_code == ERROR_WINHTTP_TIMEOUT) return failure(error, "timeout");
    if (error_code == ERROR_WINHTTP_SECURE_FAILURE || error_code == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED)
        return failure(error, "tls_error");
    if (error_code == ERROR_WINHTTP_HEADER_SIZE_OVERFLOW) return failure(error, "response_too_large");
    return failure(error, "network_error");
}

typedef struct async_state {
    LONG references;
    HINTERNET session, connection;
    HANDLE completion;
    CRITICAL_SECTION mutex;
    DWORD status, bytes, error;
    char buffer[16 * 1024];
    char *payload;
    wchar_t *headers;
} async_state;

static void state_release(async_state *state) {
    if (!state || InterlockedDecrement(&state->references)) return;
    if (state->connection) WinHttpCloseHandle(state->connection);
    if (state->session) WinHttpCloseHandle(state->session);
    if (state->completion) CloseHandle(state->completion);
    if (state->payload) { SecureZeroMemory(state->payload, strlen(state->payload)); free(state->payload); }
    if (state->headers) { SecureZeroMemory(state->headers, wcslen(state->headers) * sizeof(wchar_t)); free(state->headers); }
    DeleteCriticalSection(&state->mutex);
    free(state);
}

/* Registration owns a reference until HANDLE_CLOSING, the documented last
 * callback. Each callback also takes a reference until it returns. All buffers
 * touched by WinHTTP live here; cancel never leaves stack memory in flight. */
static void CALLBACK status_callback(HINTERNET handle, DWORD_PTR context, DWORD status, void *info, DWORD bytes) {
    (void)handle;
    if (!context) return;
    async_state *state = (async_state *)context;
    InterlockedIncrement(&state->references);
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
        state_release(state); /* callback registration */
    } else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE ||
        status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE || status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE ||
        status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
        EnterCriticalSection(&state->mutex);
        state->status = status;
        state->bytes = status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE ? bytes : 0;
        if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR)
            state->error = info && bytes == sizeof(WINHTTP_ASYNC_RESULT)
                ? ((WINHTTP_ASYNC_RESULT *)info)->dwError : ERROR_WINHTTP_INTERNAL_ERROR;
        SetEvent(state->completion);
        LeaveCriticalSection(&state->mutex);
    }
    state_release(state);
}

typedef struct pending_request {
    async_state *state;
    HINTERNET handle;
    HANDLE cancel;
    ULONGLONG deadline;
} pending_request;

static void request_free(pending_request *request) {
    if (request->handle) WinHttpCloseHandle(request->handle);
    state_release(request->state);
    memset(request, 0, sizeof(*request));
}
static int option(HINTERNET handle, DWORD name, DWORD value, sbw_error *error) {
    return WinHttpSetOption(handle, name, &value, sizeof(value)) ? 0 : failure(error, "network_error");
}
static int request_init(pending_request *request, const server_address *server, const wchar_t *method,
    const wchar_t *endpoint, HANDLE cancel, DWORD timeout, sbw_error *error) {
    memset(request, 0, sizeof(*request));
    request->cancel = cancel;
    request->deadline = GetTickCount64() + timeout;
    if (check_cancel(cancel, error) < 0) return -1;
    async_state *state = sb_xcalloc(1, sizeof(*state));
    request->state = state;
    state->references = 1;
    InitializeCriticalSection(&state->mutex);
    state->completion = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!state->completion) goto invalid;
    wchar_t *agent = sbw_wide("sb-easy-windows/" SB_EASY_VERSION, error);
    state->session = WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    free(agent);
    if (!state->session || !WinHttpSetTimeouts(state->session, (int)timeout, (int)timeout, (int)timeout, (int)timeout)) goto invalid;
    state->connection = WinHttpConnect(state->session, server->host, server->port, 0);
    if (!state->connection) goto invalid;
    size_t path_size = wcslen(server->prefix) + wcslen(endpoint) + 1;
    wchar_t *path = sb_xcalloc(path_size, sizeof(wchar_t));
    wcscpy_s(path, path_size, server->prefix); wcscat_s(path, path_size, endpoint);
    const wchar_t *accepts[] = {L"application/json", NULL};
    request->handle = WinHttpOpenRequest(state->connection, method, path, NULL, WINHTTP_NO_REFERER,
        accepts, server->secure ? WINHTTP_FLAG_SECURE : 0);
    free(path);
    if (!request->handle) goto invalid;
    if (option(request->handle, WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES, error) < 0 ||
        option(request->handle, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH, error) < 0 ||
        option(request->handle, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, MAX_HEADERS, error) < 0) goto invalid;
    DWORD_PTR context = (DWORD_PTR)state;
    if (!WinHttpSetOption(request->handle, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) goto invalid;
    if (WinHttpSetStatusCallback(request->handle, status_callback,
        WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES, 0) == WINHTTP_INVALID_STATUS_CALLBACK) goto invalid;
    InterlockedIncrement(&state->references); /* released by HANDLE_CLOSING */
    return 0;
invalid:
    request_free(request);
    return failure(error, "network_error");
}
static int request_prepare(pending_request *request, sbw_error *error) {
    if (check_cancel(request->cancel, error) < 0) return -1;
    if (GetTickCount64() >= request->deadline) return failure(error, "timeout");
    EnterCriticalSection(&request->state->mutex);
    request->state->status = request->state->bytes = request->state->error = 0;
    ResetEvent(request->state->completion);
    LeaveCriticalSection(&request->state->mutex);
    return 0;
}
static int request_await(pending_request *request, BOOL started, DWORD expected, DWORD *bytes, sbw_error *error) {
    if (!started) { DWORD status = GetLastError(); if (status != ERROR_IO_PENDING) return transport_error(status, error); }
    if (check_cancel(request->cancel, error) < 0) return -1;
    ULONGLONG now = GetTickCount64();
    if (now >= request->deadline) return failure(error, "timeout");
    HANDLE events[] = {request->state->completion, request->cancel};
    DWORD waited = WaitForMultipleObjects(request->cancel ? 2 : 1, events, FALSE, (DWORD)(request->deadline - now));
    if (check_cancel(request->cancel, error) < 0) return -1;
    if (waited == WAIT_TIMEOUT || GetTickCount64() >= request->deadline) return failure(error, "timeout");
    if (waited != WAIT_OBJECT_0) return failure(error, "network_error");
    EnterCriticalSection(&request->state->mutex);
    DWORD status = request->state->status, failure_code = request->state->error;
    if (bytes) *bytes = request->state->bytes;
    LeaveCriticalSection(&request->state->mutex);
    if (failure_code) return transport_error(failure_code, error);
    return status == expected ? 0 : failure(error, "network_error");
}

static int legacy_fallback(size_t size, UINT codepage, bool advisory, char **out, sbw_error *error) {
    if (!advisory) return failure(error, "invalid_response");
    CPINFO info;
    if (!GetCPInfo(codepage, &info)) return failure(error, "invalid_response");
    if (size * info.MaxCharSize > MAX_HEADER) return failure(error, "response_too_large");
    *out = sb_strdup(""); return 0;
}

int sbw_decode_legacy_header(const wchar_t *value, size_t size, bool advisory, char **out, sbw_error *error) {
    *out = NULL;
    if (size > MAX_HEADER) return failure(error, "response_too_large");
    bool replacement_character = false;
    for (size_t i = 0; i < size; ++i) {
        if (value[i] < 32 || value[i] == 127) return failure(error, "invalid_response");
        if (value[i] == 0xfffd) replacement_character = true;
    }
    UINT codepage = GetACP();
    DWORD flags = codepage == CP_UTF8 ? WC_ERR_INVALID_CHARS : WC_NO_BEST_FIT_CHARS;
    BOOL replaced = FALSE, *replacement = codepage == CP_UTF8 ? NULL : &replaced;
    int wire_size = WideCharToMultiByte(codepage, flags, value, (int)size, NULL, 0, NULL, replacement);
    if ((size && wire_size <= 0) || replaced || replacement_character)
        return legacy_fallback(size, codepage, advisory, out, error);
    if (wire_size > MAX_HEADER) return failure(error, "response_too_large");
    char *result = sb_xcalloc((size_t)wire_size + 1, 1);
    if (wire_size && WideCharToMultiByte(codepage, flags, value, (int)size, result, wire_size, NULL, replacement) != wire_size) replaced = TRUE;
    if (replaced) { free(result); return legacy_fallback(size, codepage, advisory, out, error); }
    for (int i = 0; i < wire_size; ++i) if (is_control((unsigned char)result[i])) { free(result); return failure(error, "invalid_response"); }
    if (wire_size && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, result, wire_size, NULL, 0)) {
        free(result); return legacy_fallback(size, codepage, advisory, out, error);
    }
    *out = result; return 0;
}

static int reject_duplicate(pending_request *request, const wchar_t *name, DWORD flags, DWORD index, sbw_error *error) {
    DWORD bytes = 0;
    if (WinHttpQueryHeaders(request->handle, WINHTTP_QUERY_CUSTOM | flags, name, NULL, &bytes, &index) ||
        GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND) return failure(error, "invalid_response");
    return 0;
}
static int header(pending_request *request, const wchar_t *name, bool advisory, char **out, sbw_error *error) {
    *out = NULL;
    char wire[MAX_HEADER + 1];
    DWORD bytes = sizeof(wire), index = 0;
    if (WinHttpQueryHeaders(request->handle, WINHTTP_QUERY_CUSTOM | WINHTTP_QUERY_FLAG_WIRE_ENCODING,
        name, wire, &bytes, &index)) {
        if (bytes > MAX_HEADER) return failure(error, "response_too_large");
        if (reject_duplicate(request, name, WINHTTP_QUERY_FLAG_WIRE_ENCODING, index, error) < 0 ||
            clean_text(wire, bytes, MAX_HEADER, "invalid_response", error) < 0) return -1;
        *out = sb_strndup(wire, bytes); return 0;
    }
    DWORD status = GetLastError();
    if (status == ERROR_WINHTTP_HEADER_NOT_FOUND) { *out = sb_strdup(""); return 0; }
    if (status == ERROR_INSUFFICIENT_BUFFER) return failure(error, "response_too_large");
    if (status != ERROR_INVALID_PARAMETER && status != ERROR_WINHTTP_INVALID_OPTION) return failure(error, "invalid_response");
    wchar_t legacy[MAX_HEADER + 1];
    bytes = sizeof(legacy); index = 0;
    if (!WinHttpQueryHeaders(request->handle, WINHTTP_QUERY_CUSTOM, name, legacy, &bytes, &index)) {
        status = GetLastError();
        if (status == ERROR_WINHTTP_HEADER_NOT_FOUND) { *out = sb_strdup(""); return 0; }
        return failure(error, status == ERROR_INSUFFICIENT_BUFFER ? "response_too_large" : "invalid_response");
    }
    if (reject_duplicate(request, name, 0, index, error) < 0) return -1;
    return sbw_decode_legacy_header(legacy, bytes / sizeof(wchar_t), advisory, out, error);
}

static int validate_headers(pending_request *request, sbw_error *error) {
    DWORD bytes = 0;
    if (WinHttpQueryHeaders(request->handle, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        NULL, &bytes, WINHTTP_NO_HEADER_INDEX) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return failure(error, "invalid_response");
    if (bytes > (MAX_HEADERS + 1) * sizeof(wchar_t)) return failure(error, "response_too_large");
    wchar_t *buffer = sb_xcalloc(bytes / sizeof(wchar_t) + 1, sizeof(wchar_t));
    if (!WinHttpQueryHeaders(request->handle, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        buffer, &bytes, WINHTTP_NO_HEADER_INDEX)) { free(buffer); return failure(error, "invalid_response"); }
    int result = 0;
    for (wchar_t *line = buffer; *line;) {
        wchar_t *end = wcsstr(line, L"\r\n");
        if (end) *end = 0;
        size_t length = wcslen(line);
        wchar_t *colon = wcschr(line, L':');
        if (length > MAX_HEADER + 128 || (colon && wcslen(colon + 1) > MAX_HEADER + 1)) {
            result = failure(error, "response_too_large"); break;
        }
        if (!end) break;
        line = end + 2;
    }
    free(buffer); return result;
}

typedef struct http_response {
    DWORD status;
    sb_buf body;
    char *etag, *rule_source, *profile_id, *profile_name;
} http_response;
static void response_free(http_response *response) {
    sb_buf_free(&response->body);
    free(response->etag); free(response->rule_source); free(response->profile_id); free(response->profile_name);
    memset(response, 0, sizeof(*response));
}

static int send_request(const server_address *server, const wchar_t *method, const wchar_t *endpoint,
    const char *payload, const char *token, const char *etag, size_t body_limit, HANDLE cancel,
    DWORD timeout, http_response *response, sbw_error *error) {
    memset(response, 0, sizeof(*response));
    if (!token) token = "";
    if (!etag) etag = "";
    if (clean_text(token, strlen(token), MAX_HEADER, "invalid_identity", error) < 0 ||
        clean_text(etag, strlen(etag), MAX_HEADER, "invalid_identity", error) < 0) return -1;
    for (const unsigned char *c = (const unsigned char *)token; *c; ++c)
        if (*c <= 32 || *c >= 127) return failure(error, "invalid_identity");
    for (const unsigned char *c = (const unsigned char *)etag; *c; ++c)
        if (*c >= 127) return failure(error, "invalid_identity");
    pending_request request;
    if (request_init(&request, server, method, endpoint, cancel, timeout, error) < 0) return -1;
    int result = -1;
    char *content_length = NULL;
    sb_buf headers = {0};
    request.state->payload = sb_strdup(payload ? payload : "");
    sb_buf_puts(&headers, "Accept: application/json\r\n");
    if (*token) sb_buf_printf(&headers, "Authorization: Bearer %s\r\n", token);
    if (*etag) sb_buf_printf(&headers, "If-None-Match: %s\r\n", etag);
    if (payload && *payload) sb_buf_puts(&headers, "Content-Type: application/json; charset=utf-8\r\n");
    request.state->headers = sbw_wide(headers.p, error);
    if (!request.state->headers) { failure(error, "invalid_identity"); goto done; }
    if (request_prepare(&request, error) < 0) goto done;
    DWORD payload_size = (DWORD)strlen(request.state->payload);
    if (request_await(&request, WinHttpSendRequest(request.handle, request.state->headers,
        (DWORD)wcslen(request.state->headers), payload_size ? request.state->payload : WINHTTP_NO_REQUEST_DATA,
        payload_size, payload_size, (DWORD_PTR)request.state), WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE, NULL, error) < 0) goto done;
    if (request_prepare(&request, error) < 0 || request_await(&request, WinHttpReceiveResponse(request.handle, NULL),
        WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE, NULL, error) < 0) goto done;
    DWORD bytes = sizeof(response->status);
    if (!WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &response->status, &bytes, WINHTTP_NO_HEADER_INDEX)) {
        failure(error, "invalid_response"); goto done;
    }
    if (response->status >= 300 && response->status < 400 && response->status != 304) {
        failure(error, "redirect_rejected"); goto done;
    }
    if (response->status != 304 && (response->status < 200 || response->status >= 300)) {
        failure(error, "http_error"); goto done;
    }
    if (validate_headers(&request, error) < 0 || header(&request, L"ETag", false, &response->etag, error) < 0 ||
        header(&request, L"X-SB-Easy-Rule-Source", false, &response->rule_source, error) < 0 ||
        header(&request, L"X-SB-Easy-Profile-Id", false, &response->profile_id, error) < 0 ||
        header(&request, L"X-SB-Easy-Profile-Name", true, &response->profile_name, error) < 0 ||
        header(&request, L"Content-Length", false, &content_length, error) < 0) goto done;
    for (const unsigned char *c = (const unsigned char *)response->etag; *c; ++c)
        if (*c >= 127) { failure(error, "invalid_response"); goto done; }
    if (*content_length) {
        uint64_t length;
        if (!decimal(content_length, &length)) { failure(error, "invalid_response"); goto done; }
        if (length > body_limit && response->status != 304) { failure(error, "response_too_large"); goto done; }
    }
    if (response->status != 304) for (;;) {
        if (request_prepare(&request, error) < 0 || request_await(&request,
            WinHttpReadData(request.handle, request.state->buffer, sizeof(request.state->buffer), NULL),
            WINHTTP_CALLBACK_STATUS_READ_COMPLETE, &bytes, error) < 0) goto done;
        if (!bytes) break;
        if (bytes > body_limit - response->body.len) { failure(error, "response_too_large"); goto done; }
        sb_buf_append(&response->body, request.state->buffer, bytes);
    }
    result = 0;
done:
    free(content_length);
    if (headers.p) SecureZeroMemory(headers.p, headers.len);
    sb_buf_free(&headers);
    request_free(&request);
    if (result) response_free(response);
    return result;
}

static sbj *response_json(const sb_buf *body, sbw_error *error) {
    sbj *parsed = sbw_json_parse(body->p ? body->p : "", body->len, 32, error);
    if (!sbj_is_object(parsed)) { sbj_free(parsed); failure(error, "invalid_response"); return NULL; }
    return parsed;
}
static const char *required_field(const sbj *object, const char *name, sbw_error *error) {
    const sbj *found = sbj_get(object, name);
    if (!sbj_is_string(found) || !found->v.str.len ||
        clean_text(found->v.str.ptr, found->v.str.len, MAX_HEADER, "invalid_response", error) < 0) {
        failure(error, "invalid_response"); return NULL;
    }
    return found->v.str.ptr;
}

typedef struct winhttp_client { DWORD timeout; } winhttp_client;

static int enroll(void *context, const sbw_enrollment_target *target, HANDLE cancel, sbj **identity, sbw_error *error) {
    *identity = NULL;
    if (!target) return failure(error, "invalid_enrollment_uri");
    winhttp_client *client = context;
    server_address server = {0}, returned_server = {0};
    http_response response = {0};
    sbj *body = NULL, *request = NULL, *output = NULL;
    char *code = NULL, *payload = NULL;
    int result = -1;
    if (parse_server(target->server, &server, error) < 0 || normalize_code(target->code, &code, error) < 0) goto done;
    sbj *device = sbj_object();
    sbj_set_str(device, "platform", "windows"); sbj_set_str(device, "architecture", "x86_64");
    sbj_set_str(device, "os", "Windows"); sbj_set_str(device, "agent_version", SB_EASY_VERSION);
    sbj_set_bool(device, "interactive_client", true);
    sbj_set_bool(device, "supports_proxy_selection", false);
    sbj_set_bool(device, "supports_local_route_stats", false);
    sbj_set_bool(device, "supports_diagnostic_upload", false);
    request = sbj_object(); sbj_set_str(request, "code", code); sbj_set(request, "device", device);
    payload = sbj_dump(request, -1);
    if (send_request(&server, L"POST", L"/api/devices/enroll", payload, "", "", MAX_ENROLLMENT_BODY,
        cancel, client->timeout, &response, error) < 0) goto done;
    if (response.status < 200 || response.status >= 300) { failure(error, "http_error"); goto done; }
    body = response_json(&response.body, error);
    if (!body) goto done;
    if (sbj_has(body, "server")) {
        const char *address = required_field(body, "server", error);
        if (!address || parse_server(address, &returned_server, error) < 0) { failure(error, "invalid_response"); goto done; }
        if (strcmp(returned_server.normalized, server.normalized)) { failure(error, "server_mismatch"); goto done; }
    }
    const char *host_id = required_field(body, "host_id", error);
    const char *host_name = required_field(body, "host_name", error);
    const char *token = required_field(body, "agent_token", error);
    const sbj *profile = sbj_get(body, "profile");
    const char *profile_id = required_field(profile, "id", error);
    const char *profile_name = required_field(profile, "name", error);
    if (!host_id || !host_name || !token || !profile_id || !profile_name) goto done;
    for (const unsigned char *c = (const unsigned char *)token; *c; ++c)
        if (*c <= 32 || *c >= 127) { failure(error, "invalid_response"); goto done; }
    output = sbj_object();
    sbj_set_str(output, "server", server.normalized); sbj_set_str(output, "host_id", host_id);
    sbj_set_str(output, "host_name", host_name); sbj_set_str(output, "agent_token", token);
    sbj_set_str(output, "profile_id", profile_id); sbj_set_str(output, "profile_name", profile_name);
    *identity = output; output = NULL; result = 0;
done:
    if (code) { SecureZeroMemory(code, strlen(code)); free(code); }
    if (payload) { SecureZeroMemory(payload, strlen(payload)); free(payload); }
    server_free(&server); server_free(&returned_server); response_free(&response);
    sbj_free(body); sbj_free(request); sbj_free(output);
    return result;
}

static int fetch_config(void *context, const sbj *identity, const char *etag, HANDLE cancel, sbj **download, sbw_error *error) {
    *download = NULL;
    winhttp_client *client = context;
    server_address server = {0};
    http_response response = {0};
    sbj *parsed = NULL;
    int result = -1;
    const char *address = required_field(identity, "server", error);
    const char *token = required_field(identity, "agent_token", error);
    const char *stored_id = required_field(identity, "profile_id", error);
    const char *stored_name = required_field(identity, "profile_name", error);
    if (!address || !token || !stored_id || !stored_name) return failure(error, "invalid_identity");
    if (parse_server(address, &server, error) < 0) goto done;
    if (send_request(&server, L"GET", L"/api/agent/config", "", token, etag, MAX_CONFIG_BODY,
        cancel, client->timeout, &response, error) < 0) goto done;
    if (response.status != 200 && response.status != 304) { failure(error, "http_error"); goto done; }
    bool not_modified = response.status == 304;
    const char *response_etag = !*response.etag && not_modified ? (etag ? etag : "") : response.etag;
    if (!*response_etag) { failure(error, "invalid_response"); goto done; }
    if (!not_modified) { parsed = response_json(&response.body, error); if (!parsed) goto done; }
    const char *profile_id = *response.profile_id ? response.profile_id : stored_id;
    const char *profile_name = *response.profile_name ? response.profile_name :
        (!strcmp(profile_id, stored_id) ? stored_name : profile_id);
    sbj *output = sbj_object();
    sbj_set_bool(output, "not_modified", not_modified);
    sbj_set_str(output, "content", not_modified ? "" : (response.body.p ? response.body.p : ""));
    sbj_set_str(output, "etag", response_etag);
    sbj_set_str(output, "rule_source", *response.rule_source ? response.rule_source : "profile");
    sbj_set_str(output, "profile_id", profile_id); sbj_set_str(output, "profile_name", profile_name);
    *download = output; result = 0;
done:
    server_free(&server); response_free(&response); sbj_free(parsed);
    return result;
}

sbw_control_plane *sbw_winhttp_new(DWORD timeout, sbw_error *error) {
    if (!timeout || timeout > 60000) { failure(error, "invalid_server"); return NULL; }
    sbw_control_plane *api = sb_xcalloc(1, sizeof(*api));
    winhttp_client *client = sb_xcalloc(1, sizeof(*client));
    client->timeout = timeout;
    api->context = client; api->enroll = enroll; api->fetch_config = fetch_config; api->destroy = free;
    return api;
}
void sbw_control_plane_free(sbw_control_plane *client) {
    if (!client) return;
    if (client->destroy) client->destroy(client->context);
    free(client);
}
