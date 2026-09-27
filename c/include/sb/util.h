/* Shared C utilities: error reporting, growable buffers, string vectors,
 * encodings, hashing, randomness, files and logging. */
#ifndef SB_UTIL_H
#define SB_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define SB_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#define SB_NODISCARD __attribute__((warn_unused_result))
#else
#define SB_PRINTF(fmt, args)
#define SB_NODISCARD
#endif

/* ---- errors ---------------------------------------------------------- */
/* The error kinds mirror the C++ exception hierarchy so HTTP handlers can map
 * them to the same status codes (NotFoundError -> 404, ValidationError -> 400,
 * ConflictError -> 409, ScriptError -> 422 (per handler), others -> 500). */
typedef enum {
    SB_OK = 0,
    SB_ERR_GENERIC,    /* std::runtime_error */
    SB_ERR_NOT_FOUND,  /* NotFoundError */
    SB_ERR_VALIDATION, /* ValidationError / std::invalid_argument */
    SB_ERR_CONFLICT,   /* ConflictError */
    SB_ERR_SCRIPT,     /* ScriptError */
    SB_ERR_IO,         /* filesystem / process failures */
    SB_ERR_UPSTREAM,   /* remote HTTP / Clash / subscription failures */
    SB_ERR_AUTH,       /* authentication failures -> HTTP 401 (UnauthorizedError) */
    SB_ERR_FORBIDDEN,  /* ForbiddenError -> HTTP 403 */
    SB_ERR_UNAVAILABLE,/* ServiceUnavailableError -> HTTP 503 */
    SB_ERR_BAD_JSON,   /* nlohmann json::exception -> HTTP 400 "Invalid JSON request: ..." */
} sb_code;

typedef struct {
    sb_code code;
    char msg[1024];
} sb_err;

/* Records an error (if e != NULL) and returns -1, so callers can write
 * `return sb_fail(err, SB_ERR_VALIDATION, "bad %s", x);`. */
int sb_fail(sb_err *e, sb_code code, const char *fmt, ...) SB_PRINTF(3, 4);
void sb_err_clear(sb_err *e);
static inline bool sb_err_is(const sb_err *e, sb_code c) { return e && e->code == c; }

/* ---- memory / strings ------------------------------------------------ */
void *sb_xmalloc(size_t n);          /* aborts on OOM */
void *sb_xcalloc(size_t n, size_t sz);
void *sb_xrealloc(void *p, size_t n);
char *sb_strdup(const char *s);      /* NULL -> NULL */
char *sb_strndup(const char *s, size_t n);
char *sb_asprintf(const char *fmt, ...) SB_PRINTF(1, 2);
char *sb_vasprintf(const char *fmt, va_list ap);
bool sb_streq(const char *a, const char *b); /* NULL-safe */
bool sb_starts_with(const char *s, const char *prefix);
bool sb_ends_with(const char *s, const char *suffix);
bool sb_str_empty(const char *s); /* NULL or "" */
char *sb_trim_dup(const char *s); /* ASCII whitespace trimmed copy */
char *sb_lower_dup(const char *s);
/* Replace *slot with a copy of value (frees the old one). */
void sb_str_set(char **slot, const char *value);
void sb_str_setn(char **slot, const char *value, size_t len);

/* ---- growable byte buffer ------------------------------------------- */
typedef struct {
    char *p; /* always NUL-terminated when non-NULL */
    size_t len, cap;
} sb_buf;

void sb_buf_append(sb_buf *b, const void *data, size_t n);
void sb_buf_puts(sb_buf *b, const char *s);
void sb_buf_putc(sb_buf *b, char c);
void sb_buf_printf(sb_buf *b, const char *fmt, ...) SB_PRINTF(2, 3);
char *sb_buf_detach(sb_buf *b); /* returns malloc'd string ("" if empty) */
void sb_buf_free(sb_buf *b);
void sb_buf_reset(sb_buf *b);

/* ---- string vector --------------------------------------------------- */
typedef struct {
    char **items;
    size_t len, cap;
} sb_strvec;

void sb_strvec_push(sb_strvec *v, const char *s); /* copies */
void sb_strvec_push_take(sb_strvec *v, char *s);
bool sb_strvec_contains(const sb_strvec *v, const char *s);
void sb_strvec_free(sb_strvec *v);
/* Splits on a single delimiter character; keeps empty fields. */
sb_strvec sb_split(const char *s, char delimiter);
char *sb_join(const sb_strvec *v, const char *separator);

/* ---- encodings ------------------------------------------------------- */
/* Standard (RFC 4648 §4) base64 with padding. */
char *sb_base64_encode(const unsigned char *data, size_t len);
/* URL-safe alphabet without padding (JWT). */
char *sb_base64url_encode(const unsigned char *data, size_t len);
/* Lenient decoder: accepts standard or URL-safe alphabets, optional padding
 * and ignores ASCII whitespace. Returns NULL on invalid input. The output is
 * NUL-terminated for convenience; *out_len excludes the terminator. */
unsigned char *sb_base64_decode(const char *text, size_t text_len, size_t *out_len);
/* Strict variants: exactly one alphabet, padding rules enforced. */
unsigned char *sb_base64_decode_strict(const char *text, size_t text_len, size_t *out_len);
unsigned char *sb_base64url_decode_strict(const char *text, size_t text_len, size_t *out_len);
char *sb_hex_encode(const unsigned char *data, size_t len); /* lowercase */
char *sb_url_decode(const char *s, bool plus_as_space);
char *sb_url_encode(const char *s); /* RFC 3986 unreserved kept */

/* ---- hashing / randomness (OpenSSL) ---------------------------------- */
void sb_sha256(const void *data, size_t len, unsigned char out[32]);
char *sb_sha256_hex(const void *data, size_t len);
void sb_hmac_sha256(const void *key, size_t key_len, const void *data, size_t len,
                    unsigned char out[32]);
int sb_random_bytes(unsigned char *out, size_t len); /* 0 on success */
char *sb_uuid_v4(void);                               /* lowercase hyphenated */
char *sb_random_hex(size_t bytes);                    /* 2*bytes hex chars */
bool sb_consttime_eq(const void *a, const void *b, size_t len);
bool sb_consttime_streq(const char *a, const char *b);

/* ---- time ------------------------------------------------------------ */
int64_t sb_unix_now(void);
int64_t sb_monotonic_ms(void);
/* UTC "YYYY-MM-DD HH:MM:SS" (SQLite datetime('now') format). */
char *sb_sqlite_datetime(int64_t unix_seconds);
/* UTC RFC 3339 "YYYY-MM-DDTHH:MM:SSZ". */
char *sb_rfc3339(int64_t unix_seconds);
/* Parses "YYYY-MM-DD HH:MM:SS", "YYYY-MM-DDTHH:MM:SS[.fff][Z|±hh:mm]" or a date.
 * Returns 0 on success. */
int sb_parse_datetime(const char *text, int64_t *unix_seconds);
void sb_sleep_ms(int64_t ms);

/* ---- files ----------------------------------------------------------- */
/* Reads a whole file (NUL-terminated). Returns NULL and sets errno on failure. */
char *sb_read_file(const char *path, size_t *len);
int sb_write_file(const char *path, const void *data, size_t len);
bool sb_file_exists(const char *path);
bool sb_is_directory(const char *path);
int sb_mkdirs(const char *path, unsigned mode); /* mkdir -p */
char *sb_path_join(const char *a, const char *b);
char *sb_dirname_dup(const char *path);
const char *sb_getenv_or(const char *name, const char *fallback);

/* ---- logging --------------------------------------------------------- */
typedef enum { SB_LOG_TRACE, SB_LOG_DEBUG, SB_LOG_INFO, SB_LOG_WARN, SB_LOG_ERROR } sb_log_level;
void sb_log_set_level(sb_log_level level);
sb_log_level sb_log_parse_level(const char *name);
void sb_log(sb_log_level level, const char *fmt, ...) SB_PRINTF(2, 3);
/* Optional sink (e.g. the panel's in-memory log ring). Called with the fully
 * formatted line (no trailing newline) after it is written to stderr. */
typedef void (*sb_log_sink)(sb_log_level level, const char *line, void *user);
void sb_log_set_sink(sb_log_sink sink, void *user);
#define SB_TRACE(...) sb_log(SB_LOG_TRACE, __VA_ARGS__)
#define SB_DEBUG(...) sb_log(SB_LOG_DEBUG, __VA_ARGS__)
#define SB_INFO(...) sb_log(SB_LOG_INFO, __VA_ARGS__)
#define SB_WARN(...) sb_log(SB_LOG_WARN, __VA_ARGS__)
#define SB_ERROR(...) sb_log(SB_LOG_ERROR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
