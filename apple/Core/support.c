/* Small portable utility boundary for the authoritative C parser. */
#include "sb/util.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (!p)
        oom();
    return p;
}

void *sb_xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        oom();
    return p;
}

void *sb_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q)
        oom();
    return q;
}

char *sb_strdup(const char *s) {
    if (!s)
        return NULL;
    return sb_strndup(s, strlen(s));
}

char *sb_strndup(const char *s, size_t n) {
    if (!s)
        return NULL;
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
    if (n < 0)
        return sb_strdup("");
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

bool sb_strn_eq(const char *a, size_t len, const char *literal) {
    return a && literal && len == strlen(literal) && memcmp(a, literal, len) == 0;
}

bool sb_streq(const char *a, const char *b) {
    if (!a || !b)
        return a == b;
    return strcmp(a, b) == 0;
}

bool sb_starts_with(const char *s, const char *prefix) {
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

bool sb_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix)
        return false;
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

bool sb_str_empty(const char *s) { return !s || !*s; }

char *sb_trim_dup(const char *s) {
    if (!s)
        return sb_strdup("");
    while (*s && isspace((unsigned char)*s))
        ++s;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        --n;
    return sb_strndup(s, n);
}

char *sb_lower_dup(const char *s) {
    char *d = sb_strdup(s ? s : "");
    for (char *p = d; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    return d;
}

void sb_str_set(char **slot, const char *value) { sb_str_setn(slot, value, value ? strlen(value) : 0); }

void sb_str_setn(char **slot, const char *value, size_t len) {
    char *copy = sb_strndup(value, len);
    free(*slot);
    *slot = copy;
}

/* ---- buffer ---------------------------------------------------------- */

void sb_buf_append(sb_buf *b, const void *data, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 128;
        while (cap < b->len + n + 1)
            cap *= 2;
        b->p = sb_xrealloc(b->p, cap);
        b->cap = cap;
    }
    if (n)
        memcpy(b->p + b->len, data, n);
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
    if (b->p)
        b->p[0] = '\0';
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
        if (sb_streq(v->items[i], s))
            return true;
    return false;
}

void sb_strvec_free(sb_strvec *v) {
    for (size_t i = 0; i < v->len; ++i)
        free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->len = v->cap = 0;
}

sb_strvec sb_split(const char *s, char delimiter) {
    sb_strvec v = {0};
    if (!s)
        return v;
    const char *start = s;
    for (const char *p = s;; ++p) {
        if (*p == delimiter || *p == '\0') {
            sb_strvec_push_take(&v, sb_strndup(start, (size_t)(p - start)));
            if (!*p)
                break;
            start = p + 1;
        }
    }
    return v;
}

char *sb_join(const sb_strvec *v, const char *sep) {
    sb_buf b = {0};
    for (size_t i = 0; i < v->len; ++i) {
        if (i)
            sb_buf_puts(&b, sep);
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
        if (i + 1 < n)
            v |= (unsigned)d[i + 1] << 8;
        if (i + 2 < n)
            v |= d[i + 2];
        sb_buf_putc(&b, alpha[(v >> 18) & 63]);
        sb_buf_putc(&b, alpha[(v >> 12) & 63]);
        if (i + 1 < n)
            sb_buf_putc(&b, alpha[(v >> 6) & 63]);
        else if (pad)
            sb_buf_putc(&b, '=');
        if (i + 2 < n)
            sb_buf_putc(&b, alpha[v & 63]);
        else if (pad)
            sb_buf_putc(&b, '=');
    }
    return sb_buf_detach(&b);
}

char *sb_base64_encode(const unsigned char *d, size_t n) { return b64_encode(d, n, B64, true); }
char *sb_base64url_encode(const unsigned char *d, size_t n) { return b64_encode(d, n, B64URL, false); }

static int b64_value(char c, int mode) {
    /* mode: 0 lenient, 1 standard, 2 url */
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' && mode != 2)
        return 62;
    if (c == '/' && mode != 2)
        return 63;
    if (c == '-' && mode != 1)
        return 62;
    if (c == '_' && mode != 1)
        return 63;
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
        if (mode == 0 && isspace((unsigned char)c))
            continue;
        if (c == '=') {
            ++pads;
            continue;
        }
        if (pads)
            goto bad; /* data after padding */
        int v = b64_value(c, mode);
        if (v < 0)
            goto bad;
        ++count;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            sb_buf_putc(&b, (char)((acc >> bits) & 0xFF));
        }
    }
    if (count % 4 == 1)
        goto bad;
    if (mode == 1) {
        if ((count + pads) % 4 != 0 || pads > 2)
            goto bad;
    } else if (mode == 2) {
        if (pads)
            goto bad;
    } else if (pads > 2) {
        goto bad;
    }
    /* Reject non-zero trailing bits in strict modes (canonical encoding). */
    if (mode != 0 && bits > 0 && (acc & ((1u << bits) - 1u)) != 0)
        goto bad;
    if (out_len)
        *out_len = b.len;
    return (unsigned char *)sb_buf_detach(&b);
bad:
    sb_buf_free(&b);
    return NULL;
}

unsigned char *sb_base64_decode(const char *t, size_t n, size_t *o) { return b64_decode(t, n, o, 0); }
unsigned char *sb_base64_decode_strict(const char *t, size_t n, size_t *o) { return b64_decode(t, n, o, 1); }
unsigned char *sb_base64url_decode_strict(const char *t, size_t n, size_t *o) {
    return b64_decode(t, n, o, 2);
}

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
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
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
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~')
            sb_buf_putc(&b, (char)*p);
        else
            sb_buf_printf(&b, "%%%02X", *p);
    }
    return sb_buf_detach(&b);
}

void sba_free(void *memory) { free(memory); }

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
char *sb_sha256_hex(const void *data, size_t length) {
    unsigned char digest[32];
#if defined(__APPLE__)
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    const unsigned char *cursor = data;
    while (length) {
        CC_LONG part = length > UINT32_MAX ? UINT32_MAX : (CC_LONG)length;
        CC_SHA256_Update(&context, cursor, part);
        cursor += part;
        length -= part;
    }
    CC_SHA256_Final(digest, &context);
#else
    SHA256(data, length, digest);
#endif
    static const char digits[] = "0123456789abcdef";
    char *hex = sb_xmalloc(65);
    for (size_t i = 0; i < 32; ++i) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = 0;
    return hex;
}
