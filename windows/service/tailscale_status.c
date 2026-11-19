#include <winsock2.h>
#include <ws2tcpip.h>
#include "tailscale_status.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* sing-box 1.14.3 daemon/started_service.proto, projected as C JSON. Unknown
 * protobuf fields are skipped, never copied to the local management client. */
typedef struct pb_reader { const unsigned char *data; size_t length, position; } pb_reader;
typedef struct pb_field { unsigned number, wire; uint64_t integer; const unsigned char *data; size_t length; } pb_field;

static int unavailable(sbw_error *error) {
    return sbw_fail(error, "TAILSCALE_STATUS_UNAVAILABLE", "Tailscale status could not be read from the running core.");
}
static int invalid(sbw_error *error) {
    return sbw_fail(error, "TAILSCALE_STATUS_INVALID", "The core returned an invalid Tailscale status response.");
}
static bool varint(pb_reader *reader, uint64_t *value) {
    *value = 0;
    for (unsigned index = 0; index < 10; ++index) {
        if (reader->position == reader->length) return false;
        unsigned byte = reader->data[reader->position++];
        if (index == 9 && byte > 1) return false;
        *value |= (uint64_t)(byte & 127U) << (index * 7U);
        if (!(byte & 128U)) return true;
    }
    return false;
}
static bool next_field(pb_reader *reader, pb_field *field) {
    uint64_t key = 0, length = 0;
    memset(field, 0, sizeof(*field));
    if (!varint(reader, &key) || key < 8 || key >> 3 > UINT32_C(0x1fffffff)) return false;
    field->number = (unsigned)(key >> 3); field->wire = (unsigned)(key & 7U);
    if (field->wire == 0) return varint(reader, &field->integer);
    if (field->wire == 1) length = 8;
    else if (field->wire == 5) length = 4;
    else if (field->wire != 2 || !varint(reader, &length)) return false;
    if (length > reader->length - reader->position) return false;
    field->data = reader->data + reader->position; field->length = (size_t)length;
    reader->position += field->length;
    return true;
}
static char *field_text(const pb_field *field, size_t maximum) {
    if (field->wire != 2 || field->length > maximum) return NULL;
    for (size_t i = 0; i < field->length; ++i)
        if (field->data[i] < 32 || field->data[i] == 127) return NULL;
    if (field->length && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        (const char *)field->data, (int)field->length, NULL, 0)) return NULL;
    return sb_strndup((const char *)field->data, field->length);
}
static bool set_text(sbj *target, const char *name, const pb_field *field, size_t maximum) {
    char *value = field_text(field, maximum);
    if (!value) return false;
    sbj_set_str(target, name, value); free(value); return true;
}
static sbj *decode_self(const pb_field *parent) {
    if (parent->wire != 2) return NULL;
    pb_reader reader = {parent->data, parent->length, 0};
    sbj *self = sbj_object(), *ips = sbj_array();
    sbj_set_str(self, "hostname", ""); sbj_set_str(self, "dns_name", "");
    sbj_set_bool(self, "online", false); sbj_set_bool(self, "expired", false);
    sbj_set(self, "ips", ips);
    unsigned seen = 0;
    while (reader.position < reader.length) {
        pb_field field;
        if (!next_field(&reader, &field)) goto fail;
        unsigned bit = field.number == 1 ? 1U : field.number == 2 ? 2U :
            field.number == 5 ? 4U : field.number == 13 ? 8U : 0;
        if (bit && (seen & bit)) goto fail;
        seen |= bit;
        if (field.number == 1 || field.number == 2) {
            if (!set_text(self, field.number == 1 ? "hostname" : "dns_name", &field, 253)) goto fail;
        } else if (field.number == 4) {
            char *ip = field_text(&field, 45);
            IN_ADDR address4; IN6_ADDR address6;
            if (!ip) goto fail;
            bool valid = InetPtonA(AF_INET, ip, &address4) == 1 || InetPtonA(AF_INET6, ip, &address6) == 1;
            if (!valid || sbj_arr_len(ips) >= 8) { free(ip); goto fail; }
            sbj_arr_push(ips, sbj_str(ip)); free(ip);
        } else if (field.number == 5 || field.number == 13) {
            if (field.wire != 0 || field.integer > 1) goto fail;
            sbj_set_bool(self, field.number == 5 ? "online" : "expired", field.integer != 0);
        }
    }
    return self;
fail:
    sbj_free(self); return NULL;
}
static sbj *decode_endpoint(const pb_field *parent) {
    if (parent->wire != 2) return NULL;
    pb_reader reader = {parent->data, parent->length, 0};
    sbj *endpoint = sbj_object();
    sbj_set_str(endpoint, "tag", ""); sbj_set_str(endpoint, "backend_state", "");
    sbj_set_str(endpoint, "network_name", ""); sbj_set(endpoint, "self", sbj_null());
    unsigned seen = 0;
    while (reader.position < reader.length) {
        pb_field field;
        if (!next_field(&reader, &field)) goto fail;
        unsigned bit = field.number == 1 ? 1U : field.number == 2 ? 2U :
            field.number == 5 ? 4U : field.number == 7 ? 8U : 0;
        if (bit && (seen & bit)) goto fail;
        seen |= bit;
        if (field.number == 1 || field.number == 2 || field.number == 5) {
            const char *name = field.number == 1 ? "tag" : field.number == 2 ? "backend_state" : "network_name";
            size_t maximum = field.number == 1 ? 512 : field.number == 2 ? 64 : 253;
            if (!set_text(endpoint, name, &field, maximum)) goto fail;
        } else if (field.number == 7) {
            sbj *self = decode_self(&field);
            if (!self) goto fail;
            sbj_set(endpoint, "self", self);
        }
    }
    if (!*sbj_get_str(endpoint, "tag", "")) goto fail;
    return endpoint;
fail:
    sbj_free(endpoint); return NULL;
}
int sbw_tailscale_status_decode(const unsigned char *frame, size_t length, sbj **out, sbw_error *error) {
    if (out) *out = NULL;
    if (!out || !frame || length < 5 || length > SBW_TAILSCALE_STATUS_LIMIT + 5U || frame[0]) return invalid(error);
    uint32_t payload = ((uint32_t)frame[1] << 24) | ((uint32_t)frame[2] << 16) | ((uint32_t)frame[3] << 8) | frame[4];
    if ((size_t)payload != length - 5) return invalid(error);
    pb_reader reader = {frame + 5, length - 5, 0};
    sbj *result = sbj_object(), *endpoints = sbj_array();
    sbj_set(result, "endpoints", endpoints);
    while (reader.position < reader.length) {
        pb_field field;
        if (!next_field(&reader, &field)) goto fail;
        if (field.number == 1) {
            if (sbj_arr_len(endpoints) >= 16) goto fail;
            sbj *endpoint = decode_endpoint(&field);
            if (!endpoint) goto fail;
            for (size_t i = 0; i < sbj_arr_len(endpoints); ++i) {
                if (!strcmp(sbj_get_str(endpoint, "tag", ""), sbj_get_str(sbj_arr_at(endpoints, i), "tag", ""))) {
                    sbj_free(endpoint); goto fail;
                }
            }
            sbj_arr_push(endpoints, endpoint);
        }
    }
    *out = result; return 0;
fail:
    sbj_free(result); return invalid(error);
}

static int interrupted(HANDLE cancel, HANDLE process, ULONGLONG deadline, sbw_error *error) {
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
        return sbw_fail(error, "CORE_CANCELLED", "The Tailscale status request was cancelled.");
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) return unavailable(error);
    if (GetTickCount64() >= deadline)
        return sbw_fail(error, "TAILSCALE_STATUS_TIMEOUT", "The Tailscale status request timed out.");
    return 0;
}
static int wait_socket(SOCKET connection, bool writing, HANDLE cancel, HANDLE process,
                       ULONGLONG deadline, sbw_error *error) {
    for (;;) {
        if (interrupted(cancel, process, deadline, error)) return -1;
        fd_set ready, exception;
        FD_ZERO(&ready); FD_SET(connection, &ready); FD_ZERO(&exception); FD_SET(connection, &exception);
        struct timeval interval = {0, 20000};
        int result = select(0, writing ? NULL : &ready, writing ? &ready : NULL, &exception, &interval);
        if (result == SOCKET_ERROR || FD_ISSET(connection, &exception)) return unavailable(error);
        if (result > 0) return 0;
    }
}
static bool headers_valid(char *headers) {
    if (strncmp(headers, "HTTP/1.0 200 ", 13) && strncmp(headers, "HTTP/1.1 200 ", 13)) return false;
    char *line = strstr(headers, "\r\n");
    bool content_type = false;
    while (line && *(line += 2)) {
        char *end = strstr(line, "\r\n");
        if (!end) return false;
        if (end == line) break;
        *end = '\0';
        char *colon = strchr(line, ':');
        if (!colon) return false;
        *colon++ = '\0'; while (*colon == ' ' || *colon == '\t') ++colon;
        if (!_stricmp(line, "Content-Type")) {
            if (content_type || (strcmp(colon, "application/grpc-web") && strcmp(colon, "application/grpc-web+proto"))) return false;
            content_type = true;
        } else if (!_stricmp(line, "Transfer-Encoding")) return false;
        else if (!_stricmp(line, "Grpc-Status") && strcmp(colon, "0")) return false;
        line = end;
    }
    return content_type;
}
int sbw_tailscale_status_get(const sbw_runtime_config *config, DWORD expected_pid,
                            HANDLE cancel, sbj **out, sbw_error *error) {
    if (out) *out = NULL;
    if (!out || !config || !config->tailscale_port || !expected_pid || !config->tailscale_secret ||
        strlen(config->tailscale_secret) != 64) return unavailable(error);
    for (const char *p = config->tailscale_secret; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return unavailable(error);
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, expected_pid);
    if (!process) return unavailable(error);
    WSADATA startup;
    if (WSAStartup(MAKEWORD(2, 2), &startup)) { CloseHandle(process); return unavailable(error); }
    int result = -1;
    SOCKET connection = INVALID_SOCKET;
    unsigned char *response = NULL;
    const size_t header_limit = 16384, capacity = header_limit + SBW_TAILSCALE_STATUS_LIMIT + 5U;
    ULONGLONG deadline = GetTickCount64() + 2000;
    if (interrupted(cancel, process, deadline, error) ||
        sbw_runtime_loopback_owner(config->tailscale_port, expected_pid, error)) goto done;
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) { unavailable(error); goto done; }
    u_long nonblocking = 1;
    if (ioctlsocket(connection, FIONBIO, &nonblocking)) { unavailable(error); goto done; }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(config->tailscale_port);
    if (connect(connection, (const struct sockaddr *)&address, sizeof(address))) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) { unavailable(error); goto done; }
        if (wait_socket(connection, true, cancel, process, deadline, error)) goto done;
        int socket_error = 0, socket_error_size = sizeof(socket_error);
        if (getsockopt(connection, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &socket_error_size) || socket_error) {
            unavailable(error); goto done;
        }
    }
    if (sbw_runtime_loopback_owner(config->tailscale_port, expected_pid, error)) goto done;
    /* HTTP/1.0 keeps the streaming body unchunked. The bundled API's gRPC-Web
     * bridge accepts it and translates it to gRPC internally. Stop after the
     * first data frame; do not wait for this subscription to close. */
    char request[1024];
    int header_size = sprintf_s(request, sizeof(request),
        "POST /daemon.StartedService/SubscribeTailscaleStatus HTTP/1.0\r\nHost: 127.0.0.1:%u\r\n"
        "Authorization: Bearer %s\r\nContent-Type: application/grpc-web\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        config->tailscale_port, config->tailscale_secret);
    if (header_size <= 0 || (size_t)header_size + 5 > sizeof(request)) {
        SecureZeroMemory(request, sizeof(request)); unavailable(error); goto done;
    }
    memset(request + header_size, 0, 5);
    int sent = 0, request_size = header_size + 5;
    while (sent < request_size) {
        if (wait_socket(connection, true, cancel, process, deadline, error)) {
            SecureZeroMemory(request, sizeof(request)); goto done;
        }
        int count = send(connection, request + sent, request_size - sent, 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (count <= 0) { SecureZeroMemory(request, sizeof(request)); unavailable(error); goto done; }
        sent += count;
    }
    SecureZeroMemory(request, sizeof(request));
    response = sb_xcalloc(capacity + 1, 1);
    size_t used = 0, body_offset = 0;
    for (;;) {
        if (wait_socket(connection, false, cancel, process, deadline, error)) goto done;
        size_t limit = body_offset ? capacity : header_limit;
        if (used == limit) { invalid(error); goto done; }
        int count = recv(connection, (char *)response + used, (int)(limit - used), 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (count <= 0) { unavailable(error); goto done; }
        used += (size_t)count;
        if (!body_offset) {
            for (size_t i = 0; i + 3 < used; ++i) {
                if (!memcmp(response + i, "\r\n\r\n", 4)) { body_offset = i + 4; break; }
                if (!response[i]) { invalid(error); goto done; }
            }
            if (!body_offset) continue;
            char saved = (char)response[body_offset]; response[body_offset] = 0;
            bool valid = headers_valid((char *)response); response[body_offset] = (unsigned char)saved;
            if (!valid) { unavailable(error); goto done; }
        }
        size_t body_length = used - body_offset;
        if (body_length < 5) continue;
        const unsigned char *frame = response + body_offset;
        uint32_t payload = ((uint32_t)frame[1] << 24) | ((uint32_t)frame[2] << 16) | ((uint32_t)frame[3] << 8) | frame[4];
        if (frame[0] || payload > SBW_TAILSCALE_STATUS_LIMIT) { invalid(error); goto done; }
        if (body_length < (size_t)payload + 5) continue;
        if (interrupted(cancel, process, deadline, error)) goto done;
        result = sbw_tailscale_status_decode(frame, (size_t)payload + 5, out, error);
        goto done;
    }
done:
    if (response) { SecureZeroMemory(response, capacity + 1); free(response); }
    if (connection != INVALID_SOCKET) closesocket(connection);
    WSACleanup(); CloseHandle(process);
    return result;
}
