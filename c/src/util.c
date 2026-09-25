#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sb/util.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ---- errors ---------------------------------------------------------- */

int sb_fail(sb_err *e, sb_code code, const char *fmt, ...) {
    if (e) {
        e->code = code;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->msg, sizeof e->msg, fmt, ap);
        va_end(ap);
    }
    return -1;
}

void sb_err_clear(sb_err *e) {
    if (e) {
        e->code = SB_OK;
        e->msg[0] = '\0';
    }
}

/* ---- memory / strings ------------------------------------------------ */

static void oom(void) {
    fputs("sb-easy: out of memory\n", stderr);
    abort();
}

void *sb_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) oom();
    return p;
}

void *sb_xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) oom();
    return p;
}

void *sb_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) oom();
    return q;
}

char *sb_strdup(const char *s) {
    if (!s) return NULL;
    return sb_strndup(s, strlen(s));
}

char *sb_strndup(const char *s, size_t n) {
    if (!s) return NULL;
    char *d = sb_xmalloc(n + 1);
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

char *sb_vasprintf(const char *fmt, va_list ap) {
    va_list cp;
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0) return sb_strdup("");
    char *s = sb_xmalloc((size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    return s;
}

char *sb_asprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = sb_vasprintf(fmt, ap);
    va_end(ap);
    return s;
}

bool sb_streq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    return strcmp(a, b) == 0;
}

bool sb_starts_with(const char *s, const char *prefix) {
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

bool sb_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return false;
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

bool sb_str_empty(const char *s) { return !s || !*s; }

char *sb_trim_dup(const char *s) {
    if (!s) return sb_strdup("");
    while (*s && isspace((unsigned char)*s)) ++s;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) --n;
    return sb_strndup(s, n);
}

char *sb_lower_dup(const char *s) {
    char *d = sb_strdup(s ? s : "");
    for (char *p = d; *p; ++p) *p = (char)tolower((unsigned char)*p);
    return d;
}

void sb_str_set(char **slot, const char *value) {
    char *copy = sb_strdup(value);
    free(*slot);
    *slot = copy;
}

/* ---- buffer ---------------------------------------------------------- */

void sb_buf_append(sb_buf *b, const void *data, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 128;
        while (cap < b->len + n + 1) cap *= 2;
        b->p = sb_xrealloc(b->p, cap);
        b->cap = cap;
    }
    if (n) memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
}

void sb_buf_puts(sb_buf *b, const char *s) { sb_buf_append(b, s, strlen(s)); }
void sb_buf_putc(sb_buf *b, char c) { sb_buf_append(b, &c, 1); }

void sb_buf_printf(sb_buf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = sb_vasprintf(fmt, ap);
    va_end(ap);
    sb_buf_puts(b, s);
    free(s);
}

char *sb_buf_detach(sb_buf *b) {
    char *p = b->p ? b->p : sb_strdup("");
    b->p = NULL;
    b->len = b->cap = 0;
    return p;
}

void sb_buf_free(sb_buf *b) {
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

void sb_buf_reset(sb_buf *b) {
    b->len = 0;
    if (b->p) b->p[0] = '\0';
}

/* ---- string vector --------------------------------------------------- */

void sb_strvec_push_take(sb_strvec *v, char *s) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof(char *));
    }
    v->items[v->len++] = s;
}

void sb_strvec_push(sb_strvec *v, const char *s) { sb_strvec_push_take(v, sb_strdup(s ? s : "")); }

bool sb_strvec_contains(const sb_strvec *v, const char *s) {
    for (size_t i = 0; i < v->len; ++i)
        if (sb_streq(v->items[i], s)) return true;
    return false;
}

void sb_strvec_free(sb_strvec *v) {
    for (size_t i = 0; i < v->len; ++i) free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->len = v->cap = 0;
}

sb_strvec sb_split(const char *s, char delimiter) {
    sb_strvec v = {0};
    if (!s) return v;
    const char *start = s;
    for (const char *p = s;; ++p) {
        if (*p == delimiter || *p == '\0') {
            sb_strvec_push_take(&v, sb_strndup(start, (size_t)(p - start)));
            if (!*p) break;
            start = p + 1;
        }
    }
    return v;
}

char *sb_join(const sb_strvec *v, const char *sep) {
    sb_buf b = {0};
    for (size_t i = 0; i < v->len; ++i) {
        if (i) sb_buf_puts(&b, sep);
        sb_buf_puts(&b, v->items[i]);
    }
    return sb_buf_detach(&b);
}

/* ---- encodings ------------------------------------------------------- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64_encode(const unsigned char *d, size_t n, const char *alpha, bool pad) {
    sb_buf b = {0};
    sb_buf_append(&b, "", 0);
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)d[i] << 16;
        if (i + 1 < n) v |= (unsigned)d[i + 1] << 8;
        if (i + 2 < n) v |= d[i + 2];
        sb_buf_putc(&b, alpha[(v >> 18) & 63]);
        sb_buf_putc(&b, alpha[(v >> 12) & 63]);
        if (i + 1 < n) sb_buf_putc(&b, alpha[(v >> 6) & 63]);
        else if (pad) sb_buf_putc(&b, '=');
        if (i + 2 < n) sb_buf_putc(&b, alpha[v & 63]);
        else if (pad) sb_buf_putc(&b, '=');
    }
    return sb_buf_detach(&b);
}

char *sb_base64_encode(const unsigned char *d, size_t n) { return b64_encode(d, n, B64, true); }
char *sb_base64url_encode(const unsigned char *d, size_t n) { return b64_encode(d, n, B64URL, false); }

static int b64_value(char c, int mode) {
    /* mode: 0 lenient, 1 standard, 2 url */
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' && mode != 2) return 62;
    if (c == '/' && mode != 2) return 63;
    if (c == '-' && mode != 1) return 62;
    if (c == '_' && mode != 1) return 63;
    return -1;
}

static unsigned char *b64_decode(const char *t, size_t n, size_t *out_len, int mode) {
    sb_buf b = {0};
    sb_buf_append(&b, "", 0);
    unsigned acc = 0;
    int bits = 0;
    size_t count = 0, pads = 0;
    for (size_t i = 0; i < n; ++i) {
        char c = t[i];
        if (mode == 0 && isspace((unsigned char)c)) continue;
        if (c == '=') {
            ++pads;
            continue;
        }
        if (pads) goto bad; /* data after padding */
        int v = b64_value(c, mode);
        if (v < 0) goto bad;
        ++count;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            sb_buf_putc(&b, (char)((acc >> bits) & 0xFF));
        }
    }
    if (count % 4 == 1) goto bad;
    if (mode == 1) {
        if ((count + pads) % 4 != 0 || pads > 2) goto bad;
    } else if (mode == 2) {
        if (pads) goto bad;
    } else if (pads > 2) {
        goto bad;
    }
    /* Reject non-zero trailing bits in strict modes (canonical encoding). */
    if (mode != 0 && bits > 0 && (acc & ((1u << bits) - 1u)) != 0) goto bad;
    if (out_len) *out_len = b.len;
    return (unsigned char *)sb_buf_detach(&b);
bad:
    sb_buf_free(&b);
    return NULL;
}

unsigned char *sb_base64_decode(const char *t, size_t n, size_t *o) { return b64_decode(t, n, o, 0); }
unsigned char *sb_base64_decode_strict(const char *t, size_t n, size_t *o) { return b64_decode(t, n, o, 1); }
unsigned char *sb_base64url_decode_strict(const char *t, size_t n, size_t *o) { return b64_decode(t, n, o, 2); }

char *sb_hex_encode(const unsigned char *d, size_t n) {
    static const char H[] = "0123456789abcdef";
    char *s = sb_xmalloc(n * 2 + 1);
    for (size_t i = 0; i < n; ++i) {
        s[2 * i] = H[d[i] >> 4];
        s[2 * i + 1] = H[d[i] & 15];
    }
    s[n * 2] = '\0';
    return s;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char *sb_url_decode(const char *s, bool plus_as_space) {
    sb_buf b = {0};
    sb_buf_append(&b, "", 0);
    for (const char *p = s ? s : ""; *p; ++p) {
        if (*p == '%' && hexval(p[1]) >= 0 && hexval(p[2]) >= 0) {
            sb_buf_putc(&b, (char)(hexval(p[1]) * 16 + hexval(p[2])));
            p += 2;
        } else if (*p == '+' && plus_as_space) {
            sb_buf_putc(&b, ' ');
        } else {
            sb_buf_putc(&b, *p);
        }
    }
    return sb_buf_detach(&b);
}

char *sb_url_encode(const char *s) {
    sb_buf b = {0};
    sb_buf_append(&b, "", 0);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; ++p) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') sb_buf_putc(&b, (char)*p);
        else sb_buf_printf(&b, "%%%02X", *p);
    }
    return sb_buf_detach(&b);
}

/* ---- hashing / randomness -------------------------------------------- */

void sb_sha256(const void *data, size_t len, unsigned char out[32]) {
    unsigned int n = 0;
    EVP_Digest(data, len, out, &n, EVP_sha256(), NULL);
}

char *sb_sha256_hex(const void *data, size_t len) {
    unsigned char d[32];
    sb_sha256(data, len, d);
    return sb_hex_encode(d, 32);
}

void sb_hmac_sha256(const void *key, size_t key_len, const void *data, size_t len, unsigned char out[32]) {
    unsigned int n = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, len, out, &n);
}

int sb_random_bytes(unsigned char *out, size_t len) {
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

char *sb_uuid_v4(void) {
    unsigned char b[16];
    if (sb_random_bytes(b, sizeof b) != 0) abort();
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    return sb_asprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1], b[2],
                       b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

char *sb_random_hex(size_t bytes) {
    unsigned char *b = sb_xmalloc(bytes);
    if (sb_random_bytes(b, bytes) != 0) abort();
    char *s = sb_hex_encode(b, bytes);
    free(b);
    return s;
}

bool sb_consttime_eq(const void *a, const void *b, size_t len) { return CRYPTO_memcmp(a, b, len) == 0; }

bool sb_consttime_streq(const char *a, const char *b) {
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    return CRYPTO_memcmp(a, b, la) == 0;
}

/* ---- time ------------------------------------------------------------ */

int64_t sb_unix_now(void) { return (int64_t)time(NULL); }

int64_t sb_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *fmt_utc(int64_t t, const char *fmt) {
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);
    char buf[64];
    strftime(buf, sizeof buf, fmt, &tm);
    return sb_strdup(buf);
}

char *sb_sqlite_datetime(int64_t t) { return fmt_utc(t, "%Y-%m-%d %H:%M:%S"); }
char *sb_rfc3339(int64_t t) { return fmt_utc(t, "%Y-%m-%dT%H:%M:%SZ"); }

int sb_parse_datetime(const char *text, int64_t *out) {
    if (!text) return -1;
    int Y, M, D, h = 0, m = 0, s = 0;
    int consumed = 0;
    if (sscanf(text, "%4d-%2d-%2d%n", &Y, &M, &D, &consumed) != 3) return -1;
    const char *p = text + consumed;
    if (*p == 'T' || *p == ' ') {
        int c2 = 0;
        if (sscanf(p + 1, "%2d:%2d:%2d%n", &h, &m, &s, &c2) != 3) return -1;
        p += 1 + c2;
        if (*p == '.')
            while (*++p >= '0' && *p <= '9') {
            }
    }
    long offset = 0;
    if (*p == 'Z' || *p == 'z') {
        ++p;
    } else if (*p == '+' || *p == '-') {
        int oh = 0, om = 0;
        int sign = *p == '-' ? -1 : 1;
        if (sscanf(p + 1, "%2d:%2d", &oh, &om) < 1) return -1;
        offset = sign * (oh * 3600L + om * 60L);
        p = "";
    }
    if (*p) return -1;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || s > 60) return -1;
    struct tm tm = {0};
    tm.tm_year = Y - 1900;
    tm.tm_mon = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min = m;
    tm.tm_sec = s;
    *out = (int64_t)timegm(&tm) - offset;
    return 0;
}

void sb_sleep_ms(int64_t ms) {
    if (ms <= 0) return;
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* ---- files ----------------------------------------------------------- */

char *sb_read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    sb_buf b = {0};
    sb_buf_append(&b, "", 0);
    char chunk[65536];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) sb_buf_append(&b, chunk, n);
    int failed = ferror(f);
    fclose(f);
    if (failed) {
        sb_buf_free(&b);
        errno = EIO;
        return NULL;
    }
    if (len) *len = b.len;
    return sb_buf_detach(&b);
}

int sb_write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = len ? fwrite(data, 1, len, f) : 0;
    int rc = (w == len && fflush(f) == 0) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

bool sb_file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

bool sb_is_directory(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int sb_mkdirs(const char *path, unsigned mode) {
    if (sb_str_empty(path)) return 0;
    char *p = sb_strdup(path);
    for (char *c = p + 1; *c; ++c) {
        if (*c == '/') {
            *c = '\0';
            if (mkdir(p, (mode_t)mode) != 0 && errno != EEXIST) {
                free(p);
                return -1;
            }
            *c = '/';
        }
    }
    int rc = (mkdir(p, (mode_t)mode) != 0 && errno != EEXIST) ? -1 : 0;
    free(p);
    return rc;
}

char *sb_path_join(const char *a, const char *b) {
    if (sb_str_empty(a)) return sb_strdup(b ? b : "");
    if (b && b[0] == '/') return sb_strdup(b);
    return sb_asprintf("%s%s%s", a, sb_ends_with(a, "/") ? "" : "/", b ? b : "");
}

char *sb_dirname_dup(const char *path) {
    if (!path) return sb_strdup(".");
    const char *slash = strrchr(path, '/');
    if (!slash) return sb_strdup(".");
    if (slash == path) return sb_strdup("/");
    return sb_strndup(path, (size_t)(slash - path));
}

const char *sb_getenv_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

/* ---- logging --------------------------------------------------------- */

static sb_log_level g_level = SB_LOG_INFO;
static sb_log_sink g_sink;
static void *g_sink_user;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void sb_log_set_level(sb_log_level level) { g_level = level; }

sb_log_level sb_log_parse_level(const char *name) {
    if (!name) return SB_LOG_INFO;
    if (strcasecmp(name, "trace") == 0) return SB_LOG_TRACE;
    if (strcasecmp(name, "debug") == 0) return SB_LOG_DEBUG;
    if (strcasecmp(name, "warn") == 0 || strcasecmp(name, "warning") == 0) return SB_LOG_WARN;
    if (strcasecmp(name, "error") == 0) return SB_LOG_ERROR;
    return SB_LOG_INFO;
}

void sb_log_set_sink(sb_log_sink sink, void *user) {
    pthread_mutex_lock(&g_log_mutex);
    g_sink = sink;
    g_sink_user = user;
    pthread_mutex_unlock(&g_log_mutex);
}

void sb_log(sb_log_level level, const char *fmt, ...) {
    if (level < g_level) return;
    static const char *names[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
    va_list ap;
    va_start(ap, fmt);
    char *msg = sb_vasprintf(fmt, ap);
    va_end(ap);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char stamp[40];
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &tm);
    char *line = sb_asprintf("%s.%03ldZ %5s %s", stamp, ts.tv_nsec / 1000000L, names[level], msg);
    pthread_mutex_lock(&g_log_mutex);
    fprintf(stderr, "%s\n", line);
    if (g_sink) g_sink(level, line, g_sink_user);
    pthread_mutex_unlock(&g_log_mutex);
    free(line);
    free(msg);
}
