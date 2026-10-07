#include "common.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Windows adapter for the portable sbj library's utility boundary. No POSIX
 * runtime, OpenSSL or alternative JSON implementation is linked here. */
int sb_fail(sb_err *error, sb_code code, const char *format, ...) {
    if (error) {
        va_list args;
        error->code = code;
        va_start(args, format);
        vsnprintf(error->msg, sizeof error->msg, format, args);
        va_end(args);
    }
    return -1;
}
void sb_err_clear(sb_err *error) { if (error) memset(error, 0, sizeof *error); }
void *sb_xmalloc(size_t size) {
    void *p = malloc(size ? size : 1);
    if (!p) abort();
    return p;
}
void *sb_xcalloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) abort();
    void *p = calloc(count ? count : 1, size ? size : 1);
    if (!p) abort();
    return p;
}
void *sb_xrealloc(void *old, size_t size) {
    void *p = realloc(old, size ? size : 1);
    if (!p) abort();
    return p;
}
char *sb_strndup(const char *text, size_t length) {
    if (!text) return NULL;
    if (length == SIZE_MAX) abort();
    char *copy = sb_xmalloc(length + 1);
    memcpy(copy, text, length);
    copy[length] = '\0';
    return copy;
}
char *sb_strdup(const char *text) { return text ? sb_strndup(text, strlen(text)) : NULL; }
bool sb_strn_eq(const char *text, size_t length, const char *literal) {
    return text && literal && length == strlen(literal) && memcmp(text, literal, length) == 0;
}
bool sb_streq(const char *a, const char *b) { return a && b ? strcmp(a, b) == 0 : a == b; }
bool sb_str_empty(const char *text) { return !text || !*text; }
void sb_str_setn(char **slot, const char *text, size_t length) {
    char *copy = sb_strndup(text, length);
    free(*slot); *slot = copy;
}
void sb_str_set(char **slot, const char *text) { sb_str_setn(slot, text, text ? strlen(text) : 0); }
char *sb_vasprintf(const char *format, va_list args) {
    va_list copy;
    va_copy(copy, args);
    int size = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (size < 0) return sb_strdup("");
    char *text = sb_xmalloc((size_t)size + 1);
    vsnprintf(text, (size_t)size + 1, format, args);
    return text;
}
char *sb_asprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *text = sb_vasprintf(format, args);
    va_end(args);
    return text;
}
void sb_buf_append(sb_buf *buffer, const void *data, size_t length) {
    if (length >= SIZE_MAX - buffer->len) abort();
    size_t needed = buffer->len + length + 1;
    if (needed > buffer->cap) {
        size_t capacity = buffer->cap ? buffer->cap : 128;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
            capacity *= 2;
        }
        buffer->p = sb_xrealloc(buffer->p, capacity);
        buffer->cap = capacity;
    }
    if (length) memcpy(buffer->p + buffer->len, data, length);
    buffer->len += length; buffer->p[buffer->len] = '\0';
}
void sb_buf_puts(sb_buf *buffer, const char *text) { sb_buf_append(buffer, text, strlen(text)); }
void sb_buf_putc(sb_buf *buffer, char c) { sb_buf_append(buffer, &c, 1); }
void sb_buf_printf(sb_buf *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *text = sb_vasprintf(format, args);
    va_end(args);
    sb_buf_puts(buffer, text); free(text);
}
char *sb_buf_detach(sb_buf *buffer) {
    char *text = buffer->p ? buffer->p : sb_strdup("");
    memset(buffer, 0, sizeof *buffer); return text;
}
void sb_buf_free(sb_buf *buffer) { free(buffer->p); memset(buffer, 0, sizeof *buffer); }
void sb_buf_reset(sb_buf *buffer) { buffer->len = 0; if (buffer->p) buffer->p[0] = '\0'; }

int sbw_fail(sbw_error *error, const char *code, const char *message) {
    if (error) {
        snprintf(error->code, sizeof error->code, "%s", code ? code : "INTERNAL_ERROR");
        snprintf(error->message, sizeof error->message, "%s", message ? message : "The operation failed.");
    }
    return -1;
}
sbj *sbw_json_parse(const char *text, size_t length, unsigned max_depth, sbw_error *error) {
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    if (!text || !length || length > 16U * 1024U * 1024U || !max_depth) goto invalid;
    /* Bound recursion before entering the production parser. The parser validates
     * matching delimiters, escapes, numbers and UTF-8; this scan only limits depth. */
    for (size_t i = 0; i < length; ++i) {
        char c = text[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '{' || c == '[') { if (++depth > max_depth) goto invalid; }
        else if (c == '}' || c == ']') { if (!depth) goto invalid; --depth; }
    }
    if (quoted || depth) goto invalid;
    sbj *value = sbj_parse(text, length, NULL, 0);
    if (!value) goto invalid;
    if (sbj_validate_utf8(value, NULL) != 0) { sbj_free(value); goto invalid; }
    return value;
invalid:
    sbw_fail(error, "INVALID_JSON", "JSON is malformed, invalid UTF-8 or exceeds the supported limits.");
    return NULL;
}
bool sbw_json_string(const sbj *value, size_t limit, bool empty_allowed) {
    return sbj_is_string(value) && value->v.str.len <= limit &&
        (empty_allowed || value->v.str.len > 0) && strlen(value->v.str.ptr) == value->v.str.len;
}
wchar_t *sbw_wide(const char *text, sbw_error *error) {
    if (!text || strlen(text) > INT_MAX) goto invalid;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (!count) goto invalid;
    wchar_t *result = sb_xmalloc((size_t)count * sizeof *result);
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, result, count) != count) {
        free(result); goto invalid;
    }
    return result;
invalid:
    sbw_fail(error, "INVALID_TEXT", "Text is not valid UTF-8."); return NULL;
}
char *sbw_utf8(const wchar_t *text, sbw_error *error) {
    if (!text || wcslen(text) > INT_MAX) goto invalid;
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, NULL, 0, NULL, NULL);
    if (!count) goto invalid;
    char *result = sb_xmalloc((size_t)count);
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, result, count, NULL, NULL) != count) {
        free(result); goto invalid;
    }
    return result;
invalid:
    sbw_fail(error, "INVALID_TEXT", "Text is not valid Unicode."); return NULL;
}
wchar_t *sbw_path_join(const wchar_t *directory, const wchar_t *name) {
    size_t a = wcslen(directory), b = wcslen(name);
    if (a > 32767 || b > 32767 || a + b + 2 > 32768) return NULL;
    bool separator = a && directory[a - 1] != L'\\' && directory[a - 1] != L'/';
    wchar_t *result = sb_xmalloc((a + b + 2) * sizeof *result);
    memcpy(result, directory, a * sizeof *result);
    if (separator) result[a++] = L'\\';
    memcpy(result + a, name, (b + 1) * sizeof *result);
    return result;
}
wchar_t *sbw_executable_directory(sbw_error *error) {
    wchar_t *path = sb_xcalloc(32768, sizeof *path);
    DWORD length = GetModuleFileNameW(NULL, path, 32768);
    if (!length || length >= 32768) goto invalid;
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash) goto invalid;
    *slash = L'\0'; return path;
invalid:
    free(path); sbw_fail(error, "PATH_ERROR", "The executable location is unavailable."); return NULL;
}
void sbw_secret_free(char *text) {
    if (text) { SecureZeroMemory(text, strlen(text)); free(text); }
}
