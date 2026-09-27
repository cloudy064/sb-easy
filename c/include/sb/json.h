/* sbj — a small JSON value library whose semantics mirror nlohmann::json.
 *
 * Objects keep their keys sorted by byte order (nlohmann's default std::map),
 * so sbj_dump() is byte-for-byte identical to nlohmann's dump()/dump(2). That
 * matters because config ETags and stored JSON columns are hashed/compared as
 * text across the C++ and C implementations.
 *
 * Ownership: every sbj* returned by a constructor, sbj_parse() or sbj_clone()
 * is owned by the caller and released with sbj_free(). Container setters take
 * ownership of the value passed in. Getters return borrowed pointers.
 */
#ifndef SB_JSON_H
#define SB_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SBJ_NULL,
    SBJ_BOOL,
    SBJ_INT,   /* int64 (nlohmann number_integer) */
    SBJ_UINT,  /* uint64 above INT64_MAX (nlohmann number_unsigned) */
    SBJ_FLOAT, /* double (nlohmann number_float) */
    SBJ_STRING,
    SBJ_ARRAY,
    SBJ_OBJECT,
} sbj_type;

typedef struct sbj sbj;

struct sbj {
    sbj_type type;
    union {
        bool b;
        int64_t i;
        uint64_t u;
        double f;
        struct {
            char *ptr; /* NUL-terminated; len excludes the terminator */
            size_t len;
        } str;
        struct {
            sbj **items;
            size_t len, cap;
        } arr;
        struct {
            char **keys; /* sorted, unique */
            size_t *key_lens; /* keys can contain embedded NUL bytes */
            sbj **vals;
            size_t len, cap;
        } obj;
    } v;
};

/* ---- construction ---------------------------------------------------- */
sbj *sbj_null(void);
sbj *sbj_bool(bool value);
sbj *sbj_int(int64_t value);
sbj *sbj_uint(uint64_t value);
sbj *sbj_float(double value);
sbj *sbj_str(const char *value); /* NULL -> JSON null */
sbj *sbj_strn(const char *value, size_t len);
sbj *sbj_str_take(char *value); /* takes ownership of a malloc'd string */
sbj *sbj_array(void);
sbj *sbj_object(void);
sbj *sbj_clone(const sbj *value);
void sbj_free(sbj *value);

/* ---- parsing / serialisation ----------------------------------------- */
/* Parses RFC 8259 JSON. Returns NULL on error and, when error is non-NULL,
 * writes a short message (at most error_size bytes). Duplicate keys: last wins. */
sbj *sbj_parse(const char *text, size_t len, char *error, size_t error_size);
sbj *sbj_parse_cstr(const char *text);
/* indent < 0: compact (nlohmann dump()); indent >= 0: pretty with that many
 * spaces per level (nlohmann dump(indent)). Returns a malloc'd string. */
char *sbj_dump(const sbj *value, int indent);
/* Validate strings and keys before emitting externally sourced JSON.
 * Returns -1 with nlohmann-compatible type_error.316 on invalid UTF-8. */
int sbj_validate_utf8(const sbj *value, sb_err *err);

/* ---- inspection ------------------------------------------------------ */
static inline bool sbj_is_null(const sbj *v) { return !v || v->type == SBJ_NULL; }
static inline bool sbj_is_bool(const sbj *v) { return v && v->type == SBJ_BOOL; }
static inline bool sbj_is_string(const sbj *v) { return v && v->type == SBJ_STRING; }
bool sbj_string_is(const sbj *v, const char *literal);
static inline bool sbj_is_array(const sbj *v) { return v && v->type == SBJ_ARRAY; }
static inline bool sbj_is_object(const sbj *v) { return v && v->type == SBJ_OBJECT; }
static inline bool sbj_is_number(const sbj *v) {
    return v && (v->type == SBJ_INT || v->type == SBJ_UINT || v->type == SBJ_FLOAT);
}
static inline bool sbj_is_integer(const sbj *v) {
    return v && (v->type == SBJ_INT || v->type == SBJ_UINT);
}
const char *sbj_type_name(const sbj *value); /* nlohmann type_name() */
size_t sbj_size(const sbj *value); /* elements/members; 0 for scalars, 1 for... nlohmann: scalars 1, null 0 */
bool sbj_equal(const sbj *a, const sbj *b); /* nlohmann operator== */

/* Scalar accessors. Return fallback when the type does not match. */
const char *sbj_as_str(const sbj *value, const char *fallback);
int64_t sbj_as_int(const sbj *value, int64_t fallback); /* ints, or integral floats */
double sbj_as_double(const sbj *value, double fallback); /* any number */
bool sbj_as_bool(const sbj *value, bool fallback);

/* ---- arrays ---------------------------------------------------------- */
size_t sbj_arr_len(const sbj *array);
sbj *sbj_arr_at(const sbj *array, size_t index);
void sbj_arr_push(sbj *array, sbj *value); /* takes ownership */
void sbj_arr_insert(sbj *array, size_t index, sbj *value);
void sbj_arr_remove(sbj *array, size_t index); /* frees the element */
sbj *sbj_arr_take(sbj *array, size_t index); /* detaches the element */
void sbj_arr_clear(sbj *array);
#define SBJ_ARR_FOREACH(array, idx, item)                                            \
    for (size_t idx = 0; (array) && sbj_is_array(array) && idx < (array)->v.arr.len && \
                         ((item) = (array)->v.arr.items[idx], 1);                     \
         ++idx)

/* ---- objects --------------------------------------------------------- */
size_t sbj_obj_len(const sbj *object);
sbj *sbj_get(const sbj *object, const char *key); /* NULL if absent / not object */
bool sbj_has(const sbj *object, const char *key);
void sbj_set(sbj *object, const char *key, sbj *value); /* replaces; takes ownership */
void sbj_setn(sbj *object, const char *key, size_t key_len, sbj *value);
sbj *sbj_getn(const sbj *object, const char *key, size_t key_len);
bool sbj_del(sbj *object, const char *key);
sbj *sbj_take(sbj *object, const char *key); /* detaches */
const char *sbj_obj_key(const sbj *object, size_t index);
sbj *sbj_obj_val(const sbj *object, size_t index);
/* Returns the member, inserting (and returning) a fresh value of the given kind
 * if the key is missing or null — the nlohmann `obj["k"]` auto-vivify idiom. */
sbj *sbj_get_or_object(sbj *object, const char *key);
sbj *sbj_get_or_array(sbj *object, const char *key);
#define SBJ_OBJ_FOREACH(object, idx, key, val)                                        \
    for (size_t idx = 0; (object) && sbj_is_object(object) && idx < (object)->v.obj.len && \
                         ((key) = (object)->v.obj.keys[idx], (val) = (object)->v.obj.vals[idx], 1); \
         ++idx)

/* Convenience setters. */
void sbj_set_str(sbj *object, const char *key, const char *value);
void sbj_set_int(sbj *object, const char *key, int64_t value);
void sbj_set_bool(sbj *object, const char *key, bool value);
void sbj_set_float(sbj *object, const char *key, double value);
void sbj_set_null(sbj *object, const char *key);

/* Convenience member getters: (object, key, fallback). */
const char *sbj_get_str(const sbj *object, const char *key, const char *fallback);
int64_t sbj_get_int(const sbj *object, const char *key, int64_t fallback);
bool sbj_get_bool(const sbj *object, const char *key, bool fallback);
double sbj_get_double(const sbj *object, const char *key, double fallback);

/* Deep merge-patch helper used by settings: overwrite members of dst by src. */
void sbj_update(sbj *dst, const sbj *src);

#ifdef __cplusplus
}
#endif

#endif
