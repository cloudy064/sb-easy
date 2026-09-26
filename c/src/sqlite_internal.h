/* Statement / transaction helpers shared by database.c and store.c
 * (port of cpp/src/sqlite_utils.hpp). Error messages match the C++ ones. */
#ifndef SB_SQLITE_INTERNAL_H
#define SB_SQLITE_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "sb/util.h"

/* "<operation> failed (<code>): <errmsg>" */
static inline int sbq_fail(sqlite3 *db, const char *operation, int code, sb_err *err) {
    return sb_fail(err, SB_ERR_GENERIC, "%s failed (%d): %s", operation, code, sqlite3_errmsg(db));
}

static inline int sbq_exec(sqlite3 *db, const char *sql, sb_err *err) {
    char *message = NULL;
    int code = sqlite3_exec(db, sql, NULL, NULL, &message);
    if (code != SQLITE_OK) {
        sb_fail(err, SB_ERR_GENERIC, "execute SQL failed (%d): %s", code,
                message ? message : sqlite3_errmsg(db));
        sqlite3_free(message);
        return -1;
    }
    return 0;
}

static inline sqlite3_stmt *sbq_prepare(sqlite3 *db, const char *sql, sb_err *err) {
    sqlite3_stmt *st = NULL;
    int code = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (code != SQLITE_OK) {
        sbq_fail(db, "prepare SQL", code, err);
        sqlite3_finalize(st);
        return NULL;
    }
    return st;
}

/* NULL value binds SQL NULL (std::optional<std::string>). */
static inline void sbq_bind_text(sqlite3_stmt *st, int i, const char *value) {
    if (value)
        sqlite3_bind_text(st, i, value, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, i);
}
static inline void sbq_bind_int(sqlite3_stmt *st, int i, int64_t value) {
    sqlite3_bind_int64(st, i, value);
}
static inline void sbq_bind_bool(sqlite3_stmt *st, int i, bool value) {
    sqlite3_bind_int64(st, i, value ? 1 : 0);
}
/* NULL pointer binds SQL NULL (std::optional<double>). */
static inline void sbq_bind_opt_double(sqlite3_stmt *st, int i, const double *value) {
    if (value)
        sqlite3_bind_double(st, i, *value);
    else
        sqlite3_bind_null(st, i);
}
static inline void sbq_bind_blob(sqlite3_stmt *st, int i, const void *data, size_t len) {
    sqlite3_bind_blob(st, i, data, (int)len, SQLITE_TRANSIENT);
}

/* 1 = row, 0 = done, -1 = error. */
static inline int sbq_step_row(sqlite3_stmt *st, sb_err *err) {
    int code = sqlite3_step(st);
    if (code == SQLITE_ROW) return 1;
    if (code == SQLITE_DONE) return 0;
    return sbq_fail(sqlite3_db_handle(st), "step SQL", code, err);
}

static inline int sbq_step_done(sqlite3_stmt *st, sb_err *err) {
    int code = sqlite3_step(st);
    if (code != SQLITE_DONE) return sbq_fail(sqlite3_db_handle(st), "execute SQL", code, err);
    return 0;
}

/* Column text copy; "" for NULL. */
static inline char *sbq_text(sqlite3_stmt *st, int col) {
    const unsigned char *v = sqlite3_column_text(st, col);
    if (!v) return sb_strdup("");
    return sb_strndup((const char *)v, (size_t)sqlite3_column_bytes(st, col));
}
/* Column text copy; NULL for SQL NULL. */
static inline char *sbq_opt_text(sqlite3_stmt *st, int col) {
    if (sqlite3_column_type(st, col) == SQLITE_NULL) return NULL;
    return sbq_text(st, col);
}
static inline int64_t sbq_int(sqlite3_stmt *st, int col) {
    return sqlite3_column_int64(st, col);
}

static inline int sbq_begin(sqlite3 *db, sb_err *err) { return sbq_exec(db, "BEGIN", err); }
static inline int sbq_commit(sqlite3 *db, sb_err *err) { return sbq_exec(db, "COMMIT", err); }
static inline void sbq_rollback(sqlite3 *db) { sbq_exec(db, "ROLLBACK", NULL); }

#endif
