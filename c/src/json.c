#include "sb/json.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------- */
/* allocation                                                              */

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fputs("sbj: out of memory\n", stderr);
        abort();
    }
    return q;
}

static sbj *new_value(sbj_type type) {
    sbj *v = xrealloc(NULL, sizeof *v);
    memset(v, 0, sizeof *v);
    v->type = type;
    return v;
}

sbj *sbj_null(void) { return new_value(SBJ_NULL); }

sbj *sbj_bool(bool value) {
    sbj *v = new_value(SBJ_BOOL);
    v->v.b = value;
    return v;
}

sbj *sbj_int(int64_t value) {
    sbj *v = new_value(SBJ_INT);
    v->v.i = value;
    return v;
}

sbj *sbj_uint(uint64_t value) {
    if (value <= (uint64_t)INT64_MAX) return sbj_int((int64_t)value);
    sbj *v = new_value(SBJ_UINT);
    v->v.u = value;
    return v;
}

sbj *sbj_float(double value) {
    sbj *v = new_value(SBJ_FLOAT);
    v->v.f = value;
    return v;
}

sbj *sbj_strn(const char *value, size_t len) {
    sbj *v = new_value(SBJ_STRING);
    v->v.str.ptr = xrealloc(NULL, len + 1);
    if (len) memcpy(v->v.str.ptr, value, len);
    v->v.str.ptr[len] = '\0';
    v->v.str.len = len;
    return v;
}

sbj *sbj_str(const char *value) {
    if (!value) return sbj_null();
    return sbj_strn(value, strlen(value));
}

sbj *sbj_str_take(char *value) {
    if (!value) return sbj_null();
    sbj *v = new_value(SBJ_STRING);
    v->v.str.ptr = value;
    v->v.str.len = strlen(value);
    return v;
}

sbj *sbj_array(void) { return new_value(SBJ_ARRAY); }
sbj *sbj_object(void) { return new_value(SBJ_OBJECT); }

static char *dup_str(const char *s) {
    size_t n = strlen(s);
    char *d = xrealloc(NULL, n + 1);
    memcpy(d, s, n + 1);
    return d;
}

void sbj_free(sbj *v) {
    if (!v) return;
    switch (v->type) {
    case SBJ_STRING:
        free(v->v.str.ptr);
        break;
    case SBJ_ARRAY:
        for (size_t i = 0; i < v->v.arr.len; ++i) sbj_free(v->v.arr.items[i]);
        free(v->v.arr.items);
        break;
    case SBJ_OBJECT:
        for (size_t i = 0; i < v->v.obj.len; ++i) {
            free(v->v.obj.keys[i]);
            sbj_free(v->v.obj.vals[i]);
        }
        free(v->v.obj.keys);
        free(v->v.obj.vals);
        break;
    default:
        break;
    }
    free(v);
}

sbj *sbj_clone(const sbj *v) {
    if (!v) return NULL;
    switch (v->type) {
    case SBJ_NULL: return sbj_null();
    case SBJ_BOOL: return sbj_bool(v->v.b);
    case SBJ_INT: return sbj_int(v->v.i);
    case SBJ_UINT: return sbj_uint(v->v.u);
    case SBJ_FLOAT: return sbj_float(v->v.f);
    case SBJ_STRING: return sbj_strn(v->v.str.ptr, v->v.str.len);
    case SBJ_ARRAY: {
        sbj *a = sbj_array();
        for (size_t i = 0; i < v->v.arr.len; ++i) sbj_arr_push(a, sbj_clone(v->v.arr.items[i]));
        return a;
    }
    case SBJ_OBJECT: {
        sbj *o = sbj_object();
        o->v.obj.cap = v->v.obj.len;
        o->v.obj.keys = xrealloc(NULL, o->v.obj.cap * sizeof(char *));
        o->v.obj.vals = xrealloc(NULL, o->v.obj.cap * sizeof(sbj *));
        for (size_t i = 0; i < v->v.obj.len; ++i) {
            o->v.obj.keys[i] = dup_str(v->v.obj.keys[i]);
            o->v.obj.vals[i] = sbj_clone(v->v.obj.vals[i]);
        }
        o->v.obj.len = v->v.obj.len;
        return o;
    }
    }
    return sbj_null();
}

/* ---------------------------------------------------------------------- */
/* inspection                                                              */

const char *sbj_type_name(const sbj *v) {
    if (!v) return "null";
    switch (v->type) {
    case SBJ_NULL: return "null";
    case SBJ_BOOL: return "boolean";
    case SBJ_INT:
    case SBJ_UINT:
    case SBJ_FLOAT: return "number";
    case SBJ_STRING: return "string";
    case SBJ_ARRAY: return "array";
    case SBJ_OBJECT: return "object";
    }
    return "null";
}

size_t sbj_size(const sbj *v) {
    if (!v || v->type == SBJ_NULL) return 0;
    if (v->type == SBJ_ARRAY) return v->v.arr.len;
    if (v->type == SBJ_OBJECT) return v->v.obj.len;
    return 1;
}

static int num_cmp_equal(const sbj *a, const sbj *b) {
    /* nlohmann compares numbers across integer/unsigned/float kinds. */
    if (a->type == SBJ_FLOAT || b->type == SBJ_FLOAT) {
        double x = a->type == SBJ_FLOAT ? a->v.f : a->type == SBJ_INT ? (double)a->v.i : (double)a->v.u;
        double y = b->type == SBJ_FLOAT ? b->v.f : b->type == SBJ_INT ? (double)b->v.i : (double)b->v.u;
        return x == y;
    }
    if (a->type == b->type) return a->type == SBJ_INT ? a->v.i == b->v.i : a->v.u == b->v.u;
    return 0; /* INT vs UINT: UINT is always > INT64_MAX */
}

bool sbj_equal(const sbj *a, const sbj *b) {
    if (!a || !b) return sbj_is_null(a) && sbj_is_null(b);
    if (sbj_is_number(a) && sbj_is_number(b)) return num_cmp_equal(a, b);
    if (a->type != b->type) return false;
    switch (a->type) {
    case SBJ_NULL: return true;
    case SBJ_BOOL: return a->v.b == b->v.b;
    case SBJ_STRING:
        return a->v.str.len == b->v.str.len && memcmp(a->v.str.ptr, b->v.str.ptr, a->v.str.len) == 0;
    case SBJ_ARRAY:
        if (a->v.arr.len != b->v.arr.len) return false;
        for (size_t i = 0; i < a->v.arr.len; ++i)
            if (!sbj_equal(a->v.arr.items[i], b->v.arr.items[i])) return false;
        return true;
    case SBJ_OBJECT:
        if (a->v.obj.len != b->v.obj.len) return false;
        for (size_t i = 0; i < a->v.obj.len; ++i) {
            if (strcmp(a->v.obj.keys[i], b->v.obj.keys[i]) != 0) return false;
            if (!sbj_equal(a->v.obj.vals[i], b->v.obj.vals[i])) return false;
        }
        return true;
    default: return false;
    }
}

const char *sbj_as_str(const sbj *v, const char *fallback) {
    return (v && v->type == SBJ_STRING) ? v->v.str.ptr : fallback;
}

int64_t sbj_as_int(const sbj *v, int64_t fallback) {
    if (!v) return fallback;
    if (v->type == SBJ_INT) return v->v.i;
    if (v->type == SBJ_UINT) return (int64_t)v->v.u;
    if (v->type == SBJ_FLOAT && isfinite(v->v.f)) return (int64_t)v->v.f;
    return fallback;
}

double sbj_as_double(const sbj *v, double fallback) {
    if (!v) return fallback;
    if (v->type == SBJ_FLOAT) return v->v.f;
    if (v->type == SBJ_INT) return (double)v->v.i;
    if (v->type == SBJ_UINT) return (double)v->v.u;
    return fallback;
}

bool sbj_as_bool(const sbj *v, bool fallback) {
    return (v && v->type == SBJ_BOOL) ? v->v.b : fallback;
}

/* ---------------------------------------------------------------------- */
/* arrays                                                                  */

size_t sbj_arr_len(const sbj *a) { return sbj_is_array(a) ? a->v.arr.len : 0; }

sbj *sbj_arr_at(const sbj *a, size_t i) {
    return (sbj_is_array(a) && i < a->v.arr.len) ? a->v.arr.items[i] : NULL;
}

static void arr_reserve(sbj *a, size_t need) {
    if (need <= a->v.arr.cap) return;
    size_t cap = a->v.arr.cap ? a->v.arr.cap * 2 : 4;
    while (cap < need) cap *= 2;
    a->v.arr.items = xrealloc(a->v.arr.items, cap * sizeof(sbj *));
    a->v.arr.cap = cap;
}

void sbj_arr_push(sbj *a, sbj *value) {
    if (!sbj_is_array(a)) {
        sbj_free(value);
        return;
    }
    if (!value) value = sbj_null();
    arr_reserve(a, a->v.arr.len + 1);
    a->v.arr.items[a->v.arr.len++] = value;
}

void sbj_arr_insert(sbj *a, size_t index, sbj *value) {
    if (!sbj_is_array(a)) {
        sbj_free(value);
        return;
    }
    if (!value) value = sbj_null();
    if (index > a->v.arr.len) index = a->v.arr.len;
    arr_reserve(a, a->v.arr.len + 1);
    memmove(a->v.arr.items + index + 1, a->v.arr.items + index,
            (a->v.arr.len - index) * sizeof(sbj *));
    a->v.arr.items[index] = value;
    a->v.arr.len++;
}

sbj *sbj_arr_take(sbj *a, size_t index) {
    if (!sbj_is_array(a) || index >= a->v.arr.len) return NULL;
    sbj *v = a->v.arr.items[index];
    memmove(a->v.arr.items + index, a->v.arr.items + index + 1,
            (a->v.arr.len - index - 1) * sizeof(sbj *));
    a->v.arr.len--;
    return v;
}

void sbj_arr_remove(sbj *a, size_t index) { sbj_free(sbj_arr_take(a, index)); }

void sbj_arr_clear(sbj *a) {
    if (!sbj_is_array(a)) return;
    for (size_t i = 0; i < a->v.arr.len; ++i) sbj_free(a->v.arr.items[i]);
    a->v.arr.len = 0;
}

/* ---------------------------------------------------------------------- */
/* objects                                                                 */

size_t sbj_obj_len(const sbj *o) { return sbj_is_object(o) ? o->v.obj.len : 0; }

/* Binary search; returns index of key or insertion point with *found = 0. */
static size_t obj_find(const sbj *o, const char *key, int *found) {
    size_t lo = 0, hi = o->v.obj.len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(o->v.obj.keys[mid], key);
        if (c == 0) {
            *found = 1;
            return mid;
        }
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    *found = 0;
    return lo;
}

sbj *sbj_get(const sbj *o, const char *key) {
    if (!sbj_is_object(o) || !key) return NULL;
    int found;
    size_t i = obj_find(o, key, &found);
    return found ? o->v.obj.vals[i] : NULL;
}

bool sbj_has(const sbj *o, const char *key) { return sbj_get(o, key) != NULL; }

void sbj_set(sbj *o, const char *key, sbj *value) {
    if (!sbj_is_object(o) || !key) {
        sbj_free(value);
        return;
    }
    if (!value) value = sbj_null();
    int found;
    size_t i = obj_find(o, key, &found);
    if (found) {
        sbj_free(o->v.obj.vals[i]);
        o->v.obj.vals[i] = value;
        return;
    }
    if (o->v.obj.len == o->v.obj.cap) {
        size_t cap = o->v.obj.cap ? o->v.obj.cap * 2 : 4;
        o->v.obj.keys = xrealloc(o->v.obj.keys, cap * sizeof(char *));
        o->v.obj.vals = xrealloc(o->v.obj.vals, cap * sizeof(sbj *));
        o->v.obj.cap = cap;
    }
    size_t tail = o->v.obj.len - i;
    memmove(o->v.obj.keys + i + 1, o->v.obj.keys + i, tail * sizeof(char *));
    memmove(o->v.obj.vals + i + 1, o->v.obj.vals + i, tail * sizeof(sbj *));
    o->v.obj.keys[i] = dup_str(key);
    o->v.obj.vals[i] = value;
    o->v.obj.len++;
}

sbj *sbj_take(sbj *o, const char *key) {
    if (!sbj_is_object(o) || !key) return NULL;
    int found;
    size_t i = obj_find(o, key, &found);
    if (!found) return NULL;
    sbj *v = o->v.obj.vals[i];
    free(o->v.obj.keys[i]);
    size_t tail = o->v.obj.len - i - 1;
    memmove(o->v.obj.keys + i, o->v.obj.keys + i + 1, tail * sizeof(char *));
    memmove(o->v.obj.vals + i, o->v.obj.vals + i + 1, tail * sizeof(sbj *));
    o->v.obj.len--;
    return v;
}

bool sbj_del(sbj *o, const char *key) {
    sbj *v = sbj_take(o, key);
    if (!v) return false;
    sbj_free(v);
    return true;
}

const char *sbj_obj_key(const sbj *o, size_t i) {
    return (sbj_is_object(o) && i < o->v.obj.len) ? o->v.obj.keys[i] : NULL;
}

sbj *sbj_obj_val(const sbj *o, size_t i) {
    return (sbj_is_object(o) && i < o->v.obj.len) ? o->v.obj.vals[i] : NULL;
}

sbj *sbj_get_or_object(sbj *o, const char *key) {
    sbj *v = sbj_get(o, key);
    if (v && v->type != SBJ_NULL) return v;
    v = sbj_object();
    sbj_set(o, key, v);
    return v;
}

sbj *sbj_get_or_array(sbj *o, const char *key) {
    sbj *v = sbj_get(o, key);
    if (v && v->type != SBJ_NULL) return v;
    v = sbj_array();
    sbj_set(o, key, v);
    return v;
}

void sbj_set_str(sbj *o, const char *k, const char *v) { sbj_set(o, k, sbj_str(v)); }
void sbj_set_int(sbj *o, const char *k, int64_t v) { sbj_set(o, k, sbj_int(v)); }
void sbj_set_bool(sbj *o, const char *k, bool v) { sbj_set(o, k, sbj_bool(v)); }
void sbj_set_float(sbj *o, const char *k, double v) { sbj_set(o, k, sbj_float(v)); }
void sbj_set_null(sbj *o, const char *k) { sbj_set(o, k, sbj_null()); }

const char *sbj_get_str(const sbj *o, const char *k, const char *fb) { return sbj_as_str(sbj_get(o, k), fb); }
int64_t sbj_get_int(const sbj *o, const char *k, int64_t fb) { return sbj_as_int(sbj_get(o, k), fb); }
bool sbj_get_bool(const sbj *o, const char *k, bool fb) { return sbj_as_bool(sbj_get(o, k), fb); }
double sbj_get_double(const sbj *o, const char *k, double fb) { return sbj_as_double(sbj_get(o, k), fb); }

void sbj_update(sbj *dst, const sbj *src) {
    /* nlohmann update(): shallow overwrite of top-level members. */
    if (!sbj_is_object(dst) || !sbj_is_object(src)) return;
    for (size_t i = 0; i < src->v.obj.len; ++i)
        sbj_set(dst, src->v.obj.keys[i], sbj_clone(src->v.obj.vals[i]));
}

/* ---------------------------------------------------------------------- */
/* serialisation                                                           */

typedef struct {
    char *p;
    size_t len, cap;
} buf_t;

static void buf_grow(buf_t *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap * 2 : 256;
    while (cap < b->len + extra + 1) cap *= 2;
    b->p = xrealloc(b->p, cap);
    b->cap = cap;
}

static void buf_put(buf_t *b, const char *s, size_t n) {
    buf_grow(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_putc(buf_t *b, char c) { buf_put(b, &c, 1); }
static void buf_puts(buf_t *b, const char *s) { buf_put(b, s, strlen(s)); }

static void buf_spaces(buf_t *b, size_t n) {
    buf_grow(b, n);
    memset(b->p + b->len, ' ', n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void dump_string(buf_t *b, const char *s, size_t n) {
    buf_putc(b, '"');
    size_t run = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char tmp[8];
        switch (c) {
        case '"': esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\b': esc = "\\b"; break;
        case '\f': esc = "\\f"; break;
        case '\n': esc = "\\n"; break;
        case '\r': esc = "\\r"; break;
        case '\t': esc = "\\t"; break;
        default:
            if (c < 0x20) {
                snprintf(tmp, sizeof tmp, "\\u%04x", c);
                esc = tmp;
            }
        }
        if (esc) {
            if (run) buf_put(b, s + i - run, run);
            run = 0;
            buf_puts(b, esc);
        } else {
            ++run;
        }
    }
    if (run) buf_put(b, s + n - run, run);
    buf_putc(b, '"');
}

#include "json_grisu.inc"

static void dump_float(buf_t *b, double x) {
    if (!isfinite(x)) {
        buf_puts(b, "null");
        return;
    }
    if (signbit(x)) {
        buf_putc(b, '-');
        x = -x;
    }
    if (x == 0.0) {
        buf_puts(b, "0.0");
        return;
    }
    char d[32];
    int e;
    int k = grisu2(d, &e, x);
    int n = k + e; /* position of the decimal point relative to digits */
    const int max_exp = 15, min_exp = -4;
    if (k <= n && n <= max_exp) {
        buf_put(b, d, (size_t)k);
        for (int i = 0; i < n - k; ++i) buf_putc(b, '0');
        buf_puts(b, ".0");
    } else if (0 < n && n <= max_exp) {
        buf_put(b, d, (size_t)n);
        buf_putc(b, '.');
        buf_put(b, d + n, (size_t)(k - n));
    } else if (min_exp < n && n <= 0) {
        buf_puts(b, "0.");
        for (int i = 0; i < -n; ++i) buf_putc(b, '0');
        buf_put(b, d, (size_t)k);
    } else {
        buf_putc(b, d[0]);
        if (k > 1) {
            buf_putc(b, '.');
            buf_put(b, d + 1, (size_t)(k - 1));
        }
        buf_putc(b, 'e');
        int ex = n - 1;
        buf_putc(b, ex < 0 ? '-' : '+');
        if (ex < 0) ex = -ex;
        char t[16];
        if (ex < 10) snprintf(t, sizeof t, "0%d", ex);
        else snprintf(t, sizeof t, "%d", ex);
        buf_puts(b, t);
    }
}

static void dump_value(buf_t *b, const sbj *v, int indent, size_t level) {
    char tmp[32];
    if (!v) {
        buf_puts(b, "null");
        return;
    }
    switch (v->type) {
    case SBJ_NULL: buf_puts(b, "null"); return;
    case SBJ_BOOL: buf_puts(b, v->v.b ? "true" : "false"); return;
    case SBJ_INT:
        snprintf(tmp, sizeof tmp, "%lld", (long long)v->v.i);
        buf_puts(b, tmp);
        return;
    case SBJ_UINT:
        snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v->v.u);
        buf_puts(b, tmp);
        return;
    case SBJ_FLOAT: dump_float(b, v->v.f); return;
    case SBJ_STRING: dump_string(b, v->v.str.ptr, v->v.str.len); return;
    case SBJ_ARRAY:
        if (v->v.arr.len == 0) {
            buf_puts(b, "[]");
            return;
        }
        buf_putc(b, '[');
        for (size_t i = 0; i < v->v.arr.len; ++i) {
            if (i) buf_putc(b, ',');
            if (indent >= 0) {
                buf_putc(b, '\n');
                buf_spaces(b, (size_t)indent * (level + 1));
            }
            dump_value(b, v->v.arr.items[i], indent, level + 1);
        }
        if (indent >= 0) {
            buf_putc(b, '\n');
            buf_spaces(b, (size_t)indent * level);
        }
        buf_putc(b, ']');
        return;
    case SBJ_OBJECT:
        if (v->v.obj.len == 0) {
            buf_puts(b, "{}");
            return;
        }
        buf_putc(b, '{');
        for (size_t i = 0; i < v->v.obj.len; ++i) {
            if (i) buf_putc(b, ',');
            if (indent >= 0) {
                buf_putc(b, '\n');
                buf_spaces(b, (size_t)indent * (level + 1));
            }
            dump_string(b, v->v.obj.keys[i], strlen(v->v.obj.keys[i]));
            buf_puts(b, indent >= 0 ? ": " : ":");
            dump_value(b, v->v.obj.vals[i], indent, level + 1);
        }
        if (indent >= 0) {
            buf_putc(b, '\n');
            buf_spaces(b, (size_t)indent * level);
        }
        buf_putc(b, '}');
        return;
    }
}

char *sbj_dump(const sbj *v, int indent) {
    buf_t b = {0};
    buf_grow(&b, 16);
    b.p[0] = '\0';
    dump_value(&b, v, indent, 0);
    return b.p;
}

/* ---------------------------------------------------------------------- */
/* parsing                                                                 */

typedef struct {
    const char *s;
    size_t len, pos;
    char *err;
    size_t err_size;
    int depth;
} parser_t;

#define SBJ_MAX_DEPTH 512

static void perr(parser_t *p, const char *msg) {
    if (p->err && p->err_size && !p->err[0])
        snprintf(p->err, p->err_size, "%s at offset %zu", msg, p->pos);
}

static void skip_ws(parser_t *p) {
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++p->pos;
        else break;
    }
}

static sbj *parse_value(parser_t *p);

static int hex4(parser_t *p, unsigned *out) {
    if (p->pos + 4 > p->len) return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; ++i) {
        char c = p->s[p->pos++];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static void put_utf8(buf_t *b, unsigned cp) {
    char t[4];
    if (cp < 0x80) {
        t[0] = (char)cp;
        buf_put(b, t, 1);
    } else if (cp < 0x800) {
        t[0] = (char)(0xC0 | (cp >> 6));
        t[1] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 2);
    } else if (cp < 0x10000) {
        t[0] = (char)(0xE0 | (cp >> 12));
        t[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        t[2] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 3);
    } else {
        t[0] = (char)(0xF0 | (cp >> 18));
        t[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        t[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        t[3] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 4);
    }
}

/* Validates one UTF-8 sequence starting at s[i]; returns its length or 0. */
static size_t utf8_seq(const unsigned char *s, size_t avail) {
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    size_t n;
    unsigned cp;
    if (c >= 0xC2 && c <= 0xDF) n = 2, cp = c & 0x1F;
    else if (c >= 0xE0 && c <= 0xEF) n = 3, cp = c & 0x0F;
    else if (c >= 0xF0 && c <= 0xF4) n = 4, cp = c & 0x07;
    else return 0;
    if (avail < n) return 0;
    for (size_t i = 1; i < n; ++i) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    if ((n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
        return 0;
    return n;
}

static char *parse_string_raw(parser_t *p, size_t *out_len) {
    /* assumes s[pos] == '"' */
    ++p->pos;
    buf_t b = {0};
    buf_grow(&b, 16);
    b.p[0] = '\0';
    while (p->pos < p->len) {
        unsigned char c = (unsigned char)p->s[p->pos];
        if (c == '"') {
            ++p->pos;
            *out_len = b.len;
            return b.p;
        }
        if (c < 0x20) {
            perr(p, "control character in string");
            goto fail;
        }
        if (c == '\\') {
            if (++p->pos >= p->len) break;
            char e = p->s[p->pos++];
            switch (e) {
            case '"': buf_putc(&b, '"'); break;
            case '\\': buf_putc(&b, '\\'); break;
            case '/': buf_putc(&b, '/'); break;
            case 'b': buf_putc(&b, '\b'); break;
            case 'f': buf_putc(&b, '\f'); break;
            case 'n': buf_putc(&b, '\n'); break;
            case 'r': buf_putc(&b, '\r'); break;
            case 't': buf_putc(&b, '\t'); break;
            case 'u': {
                unsigned cp;
                if (hex4(p, &cp) < 0) {
                    perr(p, "invalid \\u escape");
                    goto fail;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (p->pos + 2 > p->len || p->s[p->pos] != '\\' || p->s[p->pos + 1] != 'u') {
                        perr(p, "unpaired surrogate");
                        goto fail;
                    }
                    p->pos += 2;
                    if (hex4(p, &lo) < 0 || lo < 0xDC00 || lo > 0xDFFF) {
                        perr(p, "invalid surrogate pair");
                        goto fail;
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    perr(p, "unpaired surrogate");
                    goto fail;
                }
                put_utf8(&b, cp);
                break;
            }
            default:
                perr(p, "invalid escape");
                goto fail;
            }
            continue;
        }
        size_t n = utf8_seq((const unsigned char *)p->s + p->pos, p->len - p->pos);
        if (!n) {
            perr(p, "invalid UTF-8");
            goto fail;
        }
        buf_put(&b, p->s + p->pos, n);
        p->pos += n;
    }
    perr(p, "unterminated string");
fail:
    free(b.p);
    return NULL;
}

static sbj *parse_number(parser_t *p) {
    size_t start = p->pos;
    int is_float = 0;
    if (p->pos < p->len && p->s[p->pos] == '-') ++p->pos;
    if (p->pos >= p->len) goto bad;
    if (p->s[p->pos] == '0') {
        ++p->pos;
    } else if (p->s[p->pos] >= '1' && p->s[p->pos] <= '9') {
        while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') ++p->pos;
    } else {
        goto bad;
    }
    if (p->pos < p->len && p->s[p->pos] == '.') {
        is_float = 1;
        ++p->pos;
        if (p->pos >= p->len || p->s[p->pos] < '0' || p->s[p->pos] > '9') goto bad;
        while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') ++p->pos;
    }
    if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
        is_float = 1;
        ++p->pos;
        if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-')) ++p->pos;
        if (p->pos >= p->len || p->s[p->pos] < '0' || p->s[p->pos] > '9') goto bad;
        while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') ++p->pos;
    }
    {
        size_t n = p->pos - start;
        char tmp[512];
        char *num = n < sizeof tmp ? tmp : xrealloc(NULL, n + 1);
        memcpy(num, p->s + start, n);
        num[n] = '\0';
        sbj *out = NULL;
        if (!is_float) {
            errno = 0;
            if (num[0] == '-') {
                long long v = strtoll(num, NULL, 10);
                if (errno == 0) out = sbj_int(v);
            } else {
                unsigned long long v = strtoull(num, NULL, 10);
                if (errno == 0) out = sbj_uint(v);
            }
        }
        if (!out) out = sbj_float(strtod(num, NULL));
        if (num != tmp) free(num);
        return out;
    }
bad:
    perr(p, "invalid number");
    return NULL;
}

static int match_lit(parser_t *p, const char *lit) {
    size_t n = strlen(lit);
    if (p->pos + n > p->len || memcmp(p->s + p->pos, lit, n) != 0) return 0;
    p->pos += n;
    return 1;
}

static sbj *parse_value(parser_t *p) {
    skip_ws(p);
    if (p->pos >= p->len) {
        perr(p, "unexpected end of input");
        return NULL;
    }
    char c = p->s[p->pos];
    if (c == '{') {
        if (++p->depth > SBJ_MAX_DEPTH) {
            perr(p, "nesting too deep");
            return NULL;
        }
        ++p->pos;
        sbj *o = sbj_object();
        skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == '}') {
            ++p->pos;
            --p->depth;
            return o;
        }
        for (;;) {
            skip_ws(p);
            if (p->pos >= p->len || p->s[p->pos] != '"') {
                perr(p, "expected object key");
                goto obj_fail;
            }
            size_t klen;
            char *key = parse_string_raw(p, &klen);
            if (!key) goto obj_fail;
            skip_ws(p);
            if (p->pos >= p->len || p->s[p->pos] != ':') {
                free(key);
                perr(p, "expected ':'");
                goto obj_fail;
            }
            ++p->pos;
            sbj *val = parse_value(p);
            if (!val) {
                free(key);
                goto obj_fail;
            }
            sbj_set(o, key, val);
            free(key);
            skip_ws(p);
            if (p->pos < p->len && p->s[p->pos] == ',') {
                ++p->pos;
                continue;
            }
            if (p->pos < p->len && p->s[p->pos] == '}') {
                ++p->pos;
                --p->depth;
                return o;
            }
            perr(p, "expected ',' or '}'");
            goto obj_fail;
        }
    obj_fail:
        sbj_free(o);
        return NULL;
    }
    if (c == '[') {
        if (++p->depth > SBJ_MAX_DEPTH) {
            perr(p, "nesting too deep");
            return NULL;
        }
        ++p->pos;
        sbj *a = sbj_array();
        skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ']') {
            ++p->pos;
            --p->depth;
            return a;
        }
        for (;;) {
            sbj *val = parse_value(p);
            if (!val) goto arr_fail;
            sbj_arr_push(a, val);
            skip_ws(p);
            if (p->pos < p->len && p->s[p->pos] == ',') {
                ++p->pos;
                continue;
            }
            if (p->pos < p->len && p->s[p->pos] == ']') {
                ++p->pos;
                --p->depth;
                return a;
            }
            perr(p, "expected ',' or ']'");
            goto arr_fail;
        }
    arr_fail:
        sbj_free(a);
        return NULL;
    }
    if (c == '"') {
        size_t n;
        char *s = parse_string_raw(p, &n);
        if (!s) return NULL;
        sbj *v = new_value(SBJ_STRING);
        v->v.str.ptr = s;
        v->v.str.len = n;
        return v;
    }
    if (c == 't' && match_lit(p, "true")) return sbj_bool(true);
    if (c == 'f' && match_lit(p, "false")) return sbj_bool(false);
    if (c == 'n' && match_lit(p, "null")) return sbj_null();
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(p);
    perr(p, "unexpected character");
    return NULL;
}

sbj *sbj_parse(const char *text, size_t len, char *error, size_t error_size) {
    if (error && error_size) error[0] = '\0';
    if (!text) {
        if (error && error_size) snprintf(error, error_size, "null input");
        return NULL;
    }
    parser_t p = {text, len, 0, error, error_size, 0};
    sbj *v = parse_value(&p);
    if (!v) return NULL;
    skip_ws(&p);
    if (p.pos != p.len) {
        perr(&p, "trailing characters");
        sbj_free(v);
        return NULL;
    }
    return v;
}

sbj *sbj_parse_cstr(const char *text) {
    return text ? sbj_parse(text, strlen(text), NULL, 0) : NULL;
}
