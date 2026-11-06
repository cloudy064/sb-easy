#include <winsock2.h>
#include <ws2tcpip.h>
#include "local_web.h"
#include <bcrypt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define WEB_WORKERS 4
#define WEB_HEADER_LIMIT 16384
#define WEB_BODY_LIMIT (1024 * 1024)
#define WEB_FILE_LIMIT (16 * 1024 * 1024)
#define WEB_IO_TIMEOUT 2000
#define WEB_REQUEST_TIMEOUT 10000

typedef struct web_worker {
    struct sbw_local_web *server;
    HANDLE thread;
    SOCKET active;
} web_worker;

struct sbw_local_web {
    SOCKET listener;
    HANDLE root_handle;
    wchar_t *root;
    unsigned short port;
    char token[65];
    char authority[48];
    char origin[64];
    sbw_local_web_rpc callback;
    void *user;
    volatile LONG stopping;
    CRITICAL_SECTION lock;
    web_worker workers[WEB_WORKERS];
};

typedef struct web_request {
    char *method;
    char *path;
    char *host;
    char *origin;
    char *authorization;
    char *content_type;
    size_t content_length;
    int has_length;
} web_request;

static int stopped(sbw_local_web *server) {
    return InterlockedCompareExchange(&server->stopping, 0, 0) != 0;
}

static int send_all(SOCKET socket, const char *bytes, size_t length) {
    ULONGLONG deadline = GetTickCount64() + WEB_REQUEST_TIMEOUT;
    while (length) {
        if (GetTickCount64() > deadline) return -1;
        int count = send(socket, bytes, (int)(length > INT_MAX ? INT_MAX : length), 0);
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

static int headers(sbw_local_web *server, SOCKET socket, int status,
    const char *type, size_t length, int frame, int public_asset) {
    const char *reason = status == 200 ? "OK" : status == 400 ? "Bad Request" :
        status == 403 ? "Forbidden" : status == 404 ? "Not Found" :
        status == 405 ? "Method Not Allowed" : status == 413 ? "Content Too Large" :
        status == 431 ? "Request Header Fields Too Large" : "Internal Server Error";
    char policy[1024];
    if (frame) {
        snprintf(policy, sizeof(policy), "default-src 'none'; script-src %s; "
            "style-src %s 'unsafe-inline'; img-src %s data:; font-src %s data:; "
            "connect-src 'none'; frame-src 'none'; frame-ancestors 'self'; "
            "base-uri 'none'; form-action 'none'; object-src 'none'",
            server->origin, server->origin, server->origin, server->origin);
    } else {
        snprintf(policy, sizeof(policy), "default-src 'none'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
            "connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'; object-src 'none'");
    }
    char buffer[2048];
    int count = snprintf(buffer, sizeof(buffer),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Connection: close\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: %s\r\n%s%s\r\n",
        status, reason, type, length, policy,
        public_asset ? "Access-Control-Allow-Origin: null\r\nCross-Origin-Resource-Policy: cross-origin\r\n" :
            "Cross-Origin-Resource-Policy: same-origin\r\n",
        frame ? "" : "X-Frame-Options: DENY\r\n");
    if (count < 0 || (size_t)count >= sizeof(buffer)) return -1;
    return send_all(socket, buffer, (size_t)count);
}

static void reject(sbw_local_web *server, SOCKET socket, int status) {
    static const char body[] = "{\"error\":\"Local request rejected\"}";
    if (headers(server, socket, status, "application/json; charset=utf-8", sizeof(body) - 1, 0, 0) == 0)
        (void)send_all(socket, body, sizeof(body) - 1);
}

static int token_matches(const char *authorization, const char *token) {
    if (!authorization || strlen(authorization) != 71 || memcmp(authorization, "Bearer ", 7)) return 0;
    unsigned difference = 0;
    for (size_t i = 0; i < 64; ++i) difference |= (unsigned char)authorization[i + 7] ^ (unsigned char)token[i];
    return difference == 0;
}

static int header_name(const char *name) {
    if (!*name) return 0;
    for (; *name; ++name) {
        unsigned char c = (unsigned char)*name;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_`|~", c))) return 0;
    }
    return 1;
}

static int parse_headers(char *buffer, web_request *request) {
    char *line_end = strstr(buffer, "\r\n");
    if (!line_end) return 400;
    *line_end = 0;
    char *space = strchr(buffer, ' ');
    if (!space) return 400;
    *space++ = 0;
    request->method = buffer;
    request->path = space;
    char *version = strchr(space, ' ');
    if (!version || version == space) return 400;
    *version++ = 0;
    if (strcmp(version, "HTTP/1.1") || strlen(request->path) > 2048 || request->path[0] != '/') return 400;
    char *line = line_end + 2;
    while (*line) {
        line_end = strstr(line, "\r\n");
        if (!line_end || line_end == line) break;
        *line_end = 0;
        char *colon = strchr(line, ':');
        if (!colon) return 400;
        *colon++ = 0;
        if (!header_name(line)) return 400;
        while (*colon == ' ' || *colon == '\t') ++colon;
        char *last = colon + strlen(colon);
        while (last > colon && (last[-1] == ' ' || last[-1] == '\t')) *--last = 0;
        for (char *p = colon; *p; ++p)
            if (((unsigned char)*p < 32 && *p != '\t') || (unsigned char)*p == 127) return 400;
        char **field = NULL;
        if (!_stricmp(line, "Host")) field = &request->host;
        else if (!_stricmp(line, "Origin")) field = &request->origin;
        else if (!_stricmp(line, "Authorization")) field = &request->authorization;
        else if (!_stricmp(line, "Content-Type")) field = &request->content_type;
        else if (!_stricmp(line, "Transfer-Encoding") || !_stricmp(line, "Expect")) return 400;
        else if (!_stricmp(line, "Content-Length")) {
            if (request->has_length || !*colon) return 400;
            request->has_length = 1;
            for (const char *p = colon; *p; ++p) {
                if (*p < '0' || *p > '9') return 400;
                if (request->content_length > WEB_BODY_LIMIT / 10) return 413;
                request->content_length = request->content_length * 10 + (size_t)(*p - '0');
                if (request->content_length > WEB_BODY_LIMIT) return 413;
            }
        }
        if (field) {
            if (*field) return 400;
            *field = colon;
        }
        line = line_end + 2;
    }
    return 0;
}

static int json_content_type(const char *value) {
    if (!value || _strnicmp(value, "application/json", 16)) return 0;
    value += 16;
    while (*value == ' ' || *value == '\t') ++value;
    if (!*value) return 1;
    if (*value++ != ';') return 0;
    while (*value == ' ' || *value == '\t') ++value;
    return !_stricmp(value, "charset=utf-8") || !_stricmp(value, "charset=\"utf-8\"");
}

static const char *static_type(const char *path, int *frame, int *asset) {
    *frame = *asset = 0;
    if (!strcmp(path, "/")) return "text/html; charset=utf-8";
    if (!strcmp(path, "/plugin-frame.html")) { *frame = 1; return "text/html; charset=utf-8"; }
    if (!strcmp(path, "/plugin-frame.js")) { *asset = 1; return "text/javascript; charset=utf-8"; }
    if (!strncmp(path, "/extensions/", 12)) {
        const char *id = path + 12, *slash = strchr(id, '/');
        if (!slash || slash == id || slash - id > 64) return NULL;
        for (const char *p = id; p < slash; ++p)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-')) return NULL;
        *asset = 1;
        if (!strcmp(slash, "/view.js")) return "text/javascript; charset=utf-8";
        if (!strcmp(slash, "/view.css")) return "text/css; charset=utf-8";
        return NULL;
    }
    if (strncmp(path, "/assets/", 8)) return NULL;
    *asset = 1;
    const char *ext = strrchr(path, '.');
    if (!ext) return NULL;
    if (!strcmp(ext, ".js")) return "text/javascript; charset=utf-8";
    if (!strcmp(ext, ".css")) return "text/css; charset=utf-8";
    if (!strcmp(ext, ".svg")) return "image/svg+xml";
    if (!strcmp(ext, ".png")) return "image/png";
    if (!strcmp(ext, ".ico")) return "image/x-icon";
    if (!strcmp(ext, ".webp")) return "image/webp";
    if (!strcmp(ext, ".woff2")) return "font/woff2";
    if (!strcmp(ext, ".woff")) return "font/woff";
    return NULL;
}

/* All path components are conservative ASCII names. Open each directory while
 * denying rename/delete, so a directory cannot be swapped for a junction
 * between the reparse check and opening its child. The root is already pinned
 * by its canonical physical path, independently of the caller's spelling. */
static HANDLE open_static(sbw_local_web *server, const char *url) {
    const char *relative = !strcmp(url, "/") ? "index.html" : url + 1;
    size_t root_length = wcslen(server->root), length = strlen(relative);
    if (!length || length > 2048) return INVALID_HANDLE_VALUE;
    wchar_t *path = (wchar_t *)calloc(root_length + length + 2, sizeof(wchar_t));
    if (!path) return INVALID_HANDLE_VALUE;
    memcpy(path, server->root, root_length * sizeof(wchar_t));
    path[root_length++] = L'\\';
    HANDLE directories[64];
    size_t directory_count = 0, component_start = 0;
    HANDLE result = INVALID_HANDLE_VALUE;
    for (size_t i = 0; i <= length; ++i) {
        unsigned char c = (unsigned char)relative[i];
        if (c && c != '/' && !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) goto done;
        if (c != '/' && c) { path[root_length + i] = (wchar_t)c; continue; }
        if (i == component_start || relative[component_start] == '.' || relative[i - 1] == '.') goto done;
        path[root_length + i] = 0;
        HANDLE entry = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (entry == INVALID_HANDLE_VALUE) goto done;
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(entry, &information) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            !!(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != !!c) {
            CloseHandle(entry); goto done;
        }
        if (!c) { result = entry; goto done; }
        if (directory_count == sizeof(directories) / sizeof(directories[0])) { CloseHandle(entry); goto done; }
        directories[directory_count++] = entry;
        path[root_length + i] = L'\\';
        component_start = i + 1;
    }
done:
    while (directory_count) CloseHandle(directories[--directory_count]);
    free(path);
    return result;
}

static void serve_static(sbw_local_web *server, SOCKET socket, const char *path) {
    int frame = 0, asset = 0;
    const char *type = static_type(path, &frame, &asset);
    if (!type) { reject(server, socket, 404); return; }
    HANDLE file = open_static(server, path);
    if (file == INVALID_HANDLE_VALUE) { reject(server, socket, 404); return; }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > WEB_FILE_LIMIT) {
        CloseHandle(file); reject(server, socket, 404); return;
    }
    if (headers(server, socket, 200, type, (size_t)size.QuadPart, frame, asset) == 0) {
        char buffer[16384];
        LONGLONG remaining = size.QuadPart;
        ULONGLONG deadline = GetTickCount64() + WEB_REQUEST_TIMEOUT;
        while (remaining > 0 && !stopped(server) && GetTickCount64() <= deadline) {
            DWORD count = 0, wanted = remaining > (LONGLONG)sizeof(buffer) ? (DWORD)sizeof(buffer) : (DWORD)remaining;
            if (!ReadFile(file, buffer, wanted, &count, NULL) || !count || send_all(socket, buffer, count)) break;
            remaining -= count;
        }
    }
    CloseHandle(file);
}

static void serve_connection(sbw_local_web *server, SOCKET socket) {
    char header[WEB_HEADER_LIMIT + 1];
    size_t received = 0, header_length = 0;
    ULONGLONG deadline = GetTickCount64() + WEB_REQUEST_TIMEOUT;
    while (received < WEB_HEADER_LIMIT && !stopped(server) && GetTickCount64() <= deadline) {
        int count = recv(socket, header + received, (int)(WEB_HEADER_LIMIT - received), 0);
        if (count <= 0) return;
        if (memchr(header + received, 0, (size_t)count)) { reject(server, socket, 400); return; }
        received += (size_t)count;
        header[received] = 0;
        char *end = strstr(header, "\r\n\r\n");
        if (end) { header_length = (size_t)(end - header) + 4; break; }
    }
    if (!header_length) { reject(server, socket, 431); return; }
    web_request request = {0};
    int status = parse_headers(header, &request);
    if (status) { reject(server, socket, status); return; }
    if (!request.host || strcmp(request.host, server->authority)) { reject(server, socket, 403); return; }
    if (!strcmp(request.method, "GET")) {
        int frame = 0, asset = 0;
        (void)static_type(request.path, &frame, &asset);
        if (request.content_length || received != header_length) { reject(server, socket, 400); return; }
        if (request.origin && strcmp(request.origin, server->origin) && !(asset && !strcmp(request.origin, "null"))) {
            reject(server, socket, 403); return;
        }
        serve_static(server, socket, request.path);
        return;
    }
    if (strcmp(request.method, "POST") || strcmp(request.path, "/api/rpc")) { reject(server, socket, 405); return; }
    if (!request.origin || strcmp(request.origin, server->origin) || !token_matches(request.authorization, server->token)) {
        reject(server, socket, 403); return;
    }
    if (!request.has_length || !request.content_length || !json_content_type(request.content_type)) { reject(server, socket, 400); return; }
    size_t body_received = received - header_length;
    if (body_received > request.content_length) { reject(server, socket, 400); return; }
    char *body = (char *)malloc(request.content_length + 1);
    if (!body) { reject(server, socket, 500); return; }
    memcpy(body, header + header_length, body_received);
    while (body_received < request.content_length && !stopped(server) && GetTickCount64() <= deadline) {
        int count = recv(socket, body + body_received, (int)(request.content_length - body_received), 0);
        if (count <= 0) break;
        body_received += (size_t)count;
    }
    if (body_received != request.content_length || memchr(body, 0, request.content_length) || stopped(server)) {
        SecureZeroMemory(body, request.content_length); free(body); reject(server, socket, 400); return;
    }
    body[request.content_length] = 0;
    char *response = server->callback(body, request.content_length, server->user);
    SecureZeroMemory(body, request.content_length);
    free(body);
    if (!response) { reject(server, socket, 500); return; }
    size_t response_length = strnlen(response, WEB_BODY_LIMIT + 1);
    if (response_length > WEB_BODY_LIMIT) reject(server, socket, 500);
    else if (headers(server, socket, 200, "application/json; charset=utf-8", response_length, 0, 0) == 0)
        (void)send_all(socket, response, response_length);
    SecureZeroMemory(response, response_length);
    free(response);
}

static DWORD WINAPI worker_main(void *context) {
    web_worker *worker = (web_worker *)context;
    sbw_local_web *server = worker->server;
    while (!stopped(server)) {
        SOCKET client = accept(server->listener, NULL, NULL);
        if (client == INVALID_SOCKET) break;
        EnterCriticalSection(&server->lock);
        worker->active = client;
        int stopping = stopped(server);
        LeaveCriticalSection(&server->lock);
        if (!stopping) {
            DWORD timeout = WEB_IO_TIMEOUT;
            (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
            (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
            serve_connection(server, client);
        }
        EnterCriticalSection(&server->lock);
        worker->active = INVALID_SOCKET;
        closesocket(client);
        LeaveCriticalSection(&server->lock);
    }
    return 0;
}

void sbw_local_web_stop(sbw_local_web *server) {
    if (!server) return;
    InterlockedExchange(&server->stopping, 1);
    if (server->listener != INVALID_SOCKET) closesocket(server->listener);
    EnterCriticalSection(&server->lock);
    for (size_t i = 0; i < WEB_WORKERS; ++i)
        if (server->workers[i].active != INVALID_SOCKET) shutdown(server->workers[i].active, SD_BOTH);
    LeaveCriticalSection(&server->lock);
    for (size_t i = 0; i < WEB_WORKERS; ++i) {
        if (server->workers[i].thread) {
            WaitForSingleObject(server->workers[i].thread, INFINITE);
            CloseHandle(server->workers[i].thread);
        }
    }
    if (server->root_handle != INVALID_HANDLE_VALUE) CloseHandle(server->root_handle);
    DeleteCriticalSection(&server->lock);
    free(server->root);
    SecureZeroMemory(server->token, sizeof(server->token));
    free(server);
    WSACleanup();
}

sbw_local_web *sbw_local_web_start(const wchar_t *static_root,
    sbw_local_web_rpc callback, void *user, sbw_error *error) {
    WSADATA data;
    if (!static_root || !*static_root || !callback || WSAStartup(MAKEWORD(2, 2), &data)) {
        sbw_fail(error, "local_web_start", "Cannot initialize local web transport"); return NULL;
    }
    sbw_local_web *server = (sbw_local_web *)calloc(1, sizeof(*server));
    if (!server) { WSACleanup(); sbw_fail(error, "out_of_memory", "Cannot allocate local web transport"); return NULL; }
    server->listener = INVALID_SOCKET;
    server->root_handle = INVALID_HANDLE_VALUE;
    for (size_t i = 0; i < WEB_WORKERS; ++i) server->workers[i].active = INVALID_SOCKET;
    InitializeCriticalSection(&server->lock);
    server->callback = callback;
    server->user = user;
    server->root_handle = CreateFileW(static_root, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (server->root_handle == INVALID_HANDLE_VALUE) goto failed;
    BY_HANDLE_FILE_INFORMATION information;
    if (!GetFileInformationByHandle(server->root_handle, &information) ||
        !(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) goto failed;
    DWORD root_length = GetFinalPathNameByHandleW(server->root_handle, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!root_length || root_length > 32760) goto failed;
    server->root = (wchar_t *)calloc((size_t)root_length + 1, sizeof(wchar_t));
    if (!server->root || !GetFinalPathNameByHandleW(server->root_handle, server->root, root_length + 1, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)) goto failed;
    size_t root_size = wcslen(server->root);
    if (root_size && server->root[root_size - 1] == L'\\') server->root[root_size - 1] = 0;
    HANDLE index = open_static(server, "/");
    if (index == INVALID_HANDLE_VALUE) goto failed;
    CloseHandle(index);
    unsigned char random[32];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) goto failed;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) {
        server->token[i * 2] = hex[random[i] >> 4];
        server->token[i * 2 + 1] = hex[random[i] & 15];
    }
    SecureZeroMemory(random, sizeof(random));
    server->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server->listener == INVALID_SOCKET) goto failed;
    BOOL exclusive = TRUE;
    if (setsockopt(server->listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive))) goto failed;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server->listener, (const struct sockaddr *)&address, sizeof(address))) goto failed;
    int address_length = sizeof(address);
    if (getsockname(server->listener, (struct sockaddr *)&address, &address_length) || listen(server->listener, 16)) goto failed;
    server->port = ntohs(address.sin_port);
    snprintf(server->authority, sizeof(server->authority), "127.0.0.1:%u", (unsigned)server->port);
    snprintf(server->origin, sizeof(server->origin), "http://%s", server->authority);
    for (size_t i = 0; i < WEB_WORKERS; ++i) {
        server->workers[i].server = server;
        server->workers[i].thread = CreateThread(NULL, 0, worker_main, &server->workers[i], 0, NULL);
        if (!server->workers[i].thread) goto failed;
    }
    return server;
failed:
    sbw_local_web_stop(server);
    sbw_fail(error, "local_web_start", "Cannot start local web transport or open packaged web assets");
    return NULL;
}

unsigned short sbw_local_web_port(const sbw_local_web *server) { return server ? server->port : 0; }
const char *sbw_local_web_token(const sbw_local_web *server) { return server ? server->token : NULL; }
