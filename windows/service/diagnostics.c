#include "diagnostics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_LIMIT (4U * 1024U * 1024U)
#define LINE_LIMIT 16384
struct sbw_diagnostics { SRWLOCK lock; wchar_t *paths[4]; HANDLE file; DWORD size; char *recent[200]; size_t next, count; };
struct sbw_log_stream { sbw_diagnostics *log; HANDLE reader, thread, stop; sbj *config; };

static bool private_key(const char *key) {
    char lower[128]; size_t n = strlen(key);
    if (n >= sizeof lower) return true;
    for (size_t i = 0; i <= n; ++i) lower[i] = key[i] >= 'A' && key[i] <= 'Z' ? (char)(key[i] + ('a' - 'A')) : key[i];
    return strstr(lower, "password") || strstr(lower, "secret") || strstr(lower, "token") ||
        strstr(lower, "key") || strstr(lower, "authorization") || strstr(lower, "cookie") ||
        !strcmp(lower, "uuid") || !strcmp(lower, "username") || !strcmp(lower, "headers");
}
static void mask(char *line, const char *value) {
    size_t length = strlen(value);
    if (!length) return;
    char *found = line;
    while ((found = strstr(found, value)) != NULL) { memset(found, '*', length); found += length; }
}
static void redact_values(char *line, const sbj *value, bool sensitive) {
    if (sbj_is_object(value)) {
        for (size_t i = 0; i < sbj_obj_len(value); ++i)
            redact_values(line, sbj_obj_val(value, i), sensitive || private_key(sbj_obj_key(value, i)));
    } else if (sbj_is_array(value)) {
        for (size_t i = 0; i < sbj_arr_len(value); ++i) redact_values(line, sbj_arr_at(value, i), sensitive);
    } else if (sensitive && sbj_is_string(value)) {
        mask(line, sbj_as_str(value, ""));
        char *encoded = sbj_dump(value, -1);
        if (encoded) { mask(line, encoded); sbw_secret_free(encoded); }
    }
}
char *sbw_diagnostics_redact(const char *line, const sbj *config) {
    if (!line || strlen(line) >= LINE_LIMIT) return sb_strdup("[oversized core line omitted]");
    char *out = sb_strdup(line);
    /* Drop header/config-like messages entirely, including unknown credentials.
     * Domain, DNS, outbound tag, process and error messages remain useful. */
    char lower[LINE_LIMIT]; size_t length = strlen(out);
    for (size_t i = 0; i <= length; ++i) lower[i] = out[i] >= 'A' && out[i] <= 'Z' ? (char)(out[i] + ('a' - 'A')) : out[i];
    if (strstr(lower, "authorization") || strstr(lower, "bearer ") || strstr(lower, "basic ") ||
        strstr(lower, "password") || strstr(lower, "secret") || strstr(lower, "private_key") || strstr(lower, "cookie:") ||
        strstr(lower, "token=") || (strstr(lower, "://") && strchr(lower, '@'))) {
        sbw_secret_free(out); return sb_strdup("[credential-bearing core line omitted]");
    }
    redact_values(out, config, false);
    char *query = strchr(out, '?'); if (query) strcpy_s(query, strlen(query) + 1, "?");
    for (char *p = out; *p; ++p) if ((unsigned char)*p < 32 && *p != '\t') *p = ' ';
    return out;
}
static void open_log(sbw_diagnostics *log) {
    log->file = CreateFileW(log->paths[0], GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (log->file == INVALID_HANDLE_VALUE) return;
    FILE_ATTRIBUTE_TAG_INFO info; LARGE_INTEGER size;
    if (!GetFileInformationByHandleEx(log->file, FileAttributeTagInfo, &info, sizeof info) ||
        (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(log->file, &size)) { CloseHandle(log->file); log->file = INVALID_HANDLE_VALUE; return; }
    log->size = size.QuadPart >= LOG_LIMIT ? LOG_LIMIT : (DWORD)size.QuadPart;
    SetFilePointer(log->file, 0, NULL, FILE_END);
}
static void write_line(sbw_diagnostics *log, const char *kind, const char *line) {
    if (!log) return;
    SYSTEMTIME now; GetSystemTime(&now);
    sb_buf buffer = {0};
    sb_buf_printf(&buffer, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu %s %s\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
        GetCurrentProcessId(), kind, line);
    AcquireSRWLockExclusive(&log->lock);
    free(log->recent[log->next]);
    log->recent[log->next] = sb_strdup(buffer.len <= 1024 ? buffer.p : "[long log line: see exported diagnostics]");
    log->next = (log->next + 1) % 200;
    if (log->count < 200) ++log->count;
    if (log->file != INVALID_HANDLE_VALUE && log->size + buffer.len > LOG_LIMIT) {
        CloseHandle(log->file); log->file = INVALID_HANDLE_VALUE;
        DeleteFileW(log->paths[3]);
        for (int i = 2; i >= 0; --i) MoveFileExW(log->paths[i], log->paths[i + 1], MOVEFILE_REPLACE_EXISTING);
        open_log(log);
    }
    if (log->file != INVALID_HANDLE_VALUE && log->size + buffer.len <= LOG_LIMIT) {
        DWORD written = 0;
        if (WriteFile(log->file, buffer.p, (DWORD)buffer.len, &written, NULL)) log->size += written;
    }
    ReleaseSRWLockExclusive(&log->lock); sb_buf_free(&buffer);
}
sbw_diagnostics *sbw_diagnostics_new(const wchar_t *directory) {
    sbw_diagnostics *log = sb_xcalloc(1, sizeof *log); InitializeSRWLock(&log->lock);
    for (int i = 0; i < 4; ++i) {
        wchar_t name[40]; swprintf_s(name, 40, L"diagnostic-%d.log", i); log->paths[i] = sbw_path_join(directory, name);
    }
    open_log(log);
    if (log->file == INVALID_HANDLE_VALUE) { sbw_diagnostics_free(log); return NULL; }
    sbw_diagnostics_event(log, "service", "logger-ready version=" SB_EASY_VERSION); return log;
}
void sbw_diagnostics_free(sbw_diagnostics *log) {
    if (!log) return;
    if (log->file != INVALID_HANDLE_VALUE) CloseHandle(log->file);
    for (int i = 0; i < 4; ++i) free(log->paths[i]);
    for (size_t i = 0; i < 200; ++i) free(log->recent[i]); free(log);
}
void sbw_diagnostics_event(sbw_diagnostics *log, const char *event, const char *result) {
    sb_buf message = {0}; sb_buf_printf(&message, "%s %s", event, result ? result : "");
    write_line(log, "service", message.p); sb_buf_free(&message);
}
static DWORD WINAPI capture_thread(void *argument) {
    sbw_log_stream *stream = argument;
    char line[LINE_LIMIT]; size_t used = 0; bool oversized = false;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(stream->reader, NULL, 0, NULL, &available, NULL)) break;
        if (!available) { if (WaitForSingleObject(stream->stop, 20) == WAIT_OBJECT_0) break; continue; }
        char bytes[4096]; DWORD count = 0;
        if (!ReadFile(stream->reader, bytes, available < sizeof bytes ? available : sizeof bytes, &count, NULL) || !count) break;
        for (DWORD i = 0; i < count; ++i) {
            if (bytes[i] == '\n') {
                line[used] = '\0';
                char *safe = sbw_diagnostics_redact(oversized ? NULL : line, stream->config);
                write_line(stream->log, "core", safe); sbw_secret_free(safe); used = 0; oversized = false;
            } else if (used + 1 < sizeof line) line[used++] = bytes[i]; else oversized = true;
        }
    }
    if (used || oversized) {
        line[used] = '\0'; char *safe = sbw_diagnostics_redact(oversized ? NULL : line, stream->config);
        write_line(stream->log, "core", safe); sbw_secret_free(safe);
    }
    SecureZeroMemory(line, sizeof line); return 0;
}
sbw_log_stream *sbw_diagnostics_capture(sbw_diagnostics *log, HANDLE reader, const char *config) {
    sbw_log_stream *stream = sb_xcalloc(1, sizeof *stream);
    stream->log = log; stream->reader = reader;
    stream->config = config ? sbw_json_parse(config, strlen(config), 40, NULL) : NULL;
    if (!sbj_is_object(stream->config)) { sbw_diagnostics_finish(stream); return NULL; }
    stream->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stream->stop) stream->thread = CreateThread(NULL, 0, capture_thread, stream, 0, NULL);
    if (!stream->thread) { sbw_diagnostics_finish(stream); return NULL; }
    return stream;
}
void sbw_diagnostics_finish(sbw_log_stream *stream) {
    if (!stream) return;
    if (stream->thread) { SetEvent(stream->stop); WaitForSingleObject(stream->thread, INFINITE); CloseHandle(stream->thread); }
    if (stream->stop) CloseHandle(stream->stop);
    CloseHandle(stream->reader); sbj_free(stream->config); free(stream);
}

sbj *sbw_diagnostics_snapshot(sbw_diagnostics *log) {
    sbj *result = sbj_object(), *lines = sbj_array();
    if (log) {
        AcquireSRWLockShared(&log->lock);
        for (size_t i = 0; i < log->count; ++i)
            sbj_arr_push(lines, sbj_str(log->recent[(log->next + 200 - log->count + i) % 200]));
        ReleaseSRWLockShared(&log->lock);
    }
    sbj_set(result, "lines", lines); return result;
}
