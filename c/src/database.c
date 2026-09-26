/* Port of cpp/src/database.cpp. */
#include "sb/database.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/sha.h>

#include "sqlite_internal.h"

struct sb_database {
    sqlite3 *handle;
    pthread_mutex_t mutex;
};

typedef struct {
    int64_t version;
    char *description;
    char *sql;
    size_t sql_len;
    unsigned char checksum[SHA384_DIGEST_LENGTH];
} migration;

typedef struct {
    migration *items;
    size_t len, cap;
} migration_vec;

static void migration_vec_free(migration_vec *v) {
    for (size_t i = 0; i < v->len; ++i) {
        free(v->items[i].description);
        free(v->items[i].sql);
    }
    free(v->items);
    memset(v, 0, sizeof *v);
}

static int compare_migrations(const void *a, const void *b) {
    int64_t x = ((const migration *)a)->version, y = ((const migration *)b)->version;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* std::regex_match(filename, ^([0-9]+)_(.+)\.sql$) with ECMAScript rules:
 * '.' matches anything except '\n' and '\r'. Returns 1 on a match, 0 when the
 * name does not match and -1 when the version overflows (std::stoll throws). */
static int match_filename(const char *name, int64_t *version, char **description, sb_err *err) {
    size_t n = strlen(name), digits = 0;
    while (name[digits] >= '0' && name[digits] <= '9') ++digits;
    if (digits == 0 || name[digits] != '_') return 0;
    if (n < digits + 1 + 1 + 4 || strcmp(name + n - 4, ".sql") != 0) return 0;
    for (size_t i = digits + 1; i < n - 4; ++i)
        if (name[i] == '\n' || name[i] == '\r') return 0;
    errno = 0;
    long long parsed = strtoll(name, NULL, 10);
    if (errno == ERANGE) return sb_fail(err, SB_ERR_GENERIC, "stoll");
    *version = parsed;
    *description = sb_strndup(name + digits + 1, n - digits - 1 - 4);
    for (char *p = *description; *p; ++p)
        if (*p == '_') *p = ' ';
    return 1;
}

static int load_migrations(const char *directory, migration_vec *out, sb_err *err) {
    if (!sb_is_directory(directory))
        return sb_fail(err, SB_ERR_GENERIC, "migration directory does not exist: %s", directory);
    DIR *dir = opendir(directory);
    if (!dir) return sb_fail(err, SB_ERR_GENERIC, "migration directory does not exist: %s", directory);
    struct dirent *entry;
    int rc = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *path = sb_path_join(directory, entry->d_name);
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            free(path);
            continue;
        }
        int64_t version;
        char *description;
        int matched = match_filename(entry->d_name, &version, &description, err);
        if (matched < 0) {
            rc = -1;
            free(path);
            break;
        }
        if (matched == 0) {
            free(path);
            continue;
        }
        size_t len = 0;
        char *sql = sb_read_file(path, &len);
        if (!sql) {
            rc = sb_fail(err, SB_ERR_GENERIC, "cannot read migration: %s", path);
            free(description);
            free(path);
            break;
        }
        free(path);
        if (out->len == out->cap) {
            out->cap = out->cap ? out->cap * 2 : 16;
            out->items = sb_xrealloc(out->items, out->cap * sizeof *out->items);
        }
        migration *m = &out->items[out->len++];
        m->version = version;
        m->description = description;
        m->sql = sql;
        m->sql_len = len;
        SHA384((const unsigned char *)sql, len, m->checksum);
    }
    closedir(dir);
    if (rc != 0) return rc;
    if (out->len) qsort(out->items, out->len, sizeof *out->items, compare_migrations);
    for (size_t i = 1; i < out->len; ++i)
        if (out->items[i].version == out->items[i - 1].version)
            return sb_fail(err, SB_ERR_GENERIC, "duplicate migration version: %lld",
                           (long long)out->items[i].version);
    return 0;
}

sb_database *sb_database_open(const char *path, sb_err *err) {
    sqlite3 *handle = NULL;
    int code = sqlite3_open_v2(path, &handle,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                               NULL);
    if (code != SQLITE_OK) {
        sb_fail(err, SB_ERR_GENERIC, "open SQLite database failed: %s",
                handle ? sqlite3_errmsg(handle) : "unknown sqlite error");
        if (handle) sqlite3_close(handle);
        return NULL;
    }
    int timeout_code = sqlite3_busy_timeout(handle, 5000);
    if (timeout_code != SQLITE_OK) {
        sbq_fail(handle, "configure SQLite busy timeout", timeout_code, err);
        sqlite3_close(handle);
        return NULL;
    }
    if (sbq_exec(handle, "PRAGMA foreign_keys = ON", err) != 0 ||
        sbq_exec(handle, "PRAGMA journal_mode = WAL", err) != 0) {
        sqlite3_close(handle);
        return NULL;
    }
    sb_database *db = sb_xcalloc(1, sizeof *db);
    db->handle = handle;
    pthread_mutex_init(&db->mutex, NULL);
    return db;
}

void sb_database_free(sb_database *db) {
    if (!db) return;
    if (db->handle) sqlite3_close(db->handle);
    pthread_mutex_destroy(&db->mutex);
    free(db);
}

struct sqlite3 *sb_database_handle(sb_database *db) { return db->handle; }
void sb_database_lock(sb_database *db) { pthread_mutex_lock(&db->mutex); }
void sb_database_unlock(sb_database *db) { pthread_mutex_unlock(&db->mutex); }

int sb_database_execute(sb_database *db, const char *sql, sb_err *err) {
    pthread_mutex_lock(&db->mutex);
    int rc = sbq_exec(db->handle, sql, err);
    pthread_mutex_unlock(&db->mutex);
    return rc;
}

static int64_t elapsed_ns(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)(now.tv_sec - start->tv_sec) * 1000000000LL + (now.tv_nsec - start->tv_nsec);
}

static int migrate_locked(sqlite3 *h, const migration_vec *migrations, sb_err *err) {
    if (sbq_exec(h,
                 "\nCREATE TABLE IF NOT EXISTS _sqlx_migrations (\n"
                 "    version BIGINT PRIMARY KEY,\n"
                 "    description TEXT NOT NULL,\n"
                 "    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n"
                 "    success BOOLEAN NOT NULL,\n"
                 "    checksum BLOB NOT NULL,\n"
                 "    execution_time BIGINT NOT NULL\n"
                 ")\n",
                 err) != 0)
        return -1;

    sqlite3_stmt *st = sbq_prepare(h,
                                   "SELECT version FROM _sqlx_migrations WHERE success = FALSE "
                                   "ORDER BY version LIMIT 1",
                                   err);
    if (!st) return -1;
    int r = sbq_step_row(st, err);
    if (r == 1) sb_fail(err, SB_ERR_GENERIC, "migration %lld is partially applied", (long long)sbq_int(st, 0));
    sqlite3_finalize(st);
    if (r != 0) return -1;

    st = sbq_prepare(h, "SELECT version FROM _sqlx_migrations ORDER BY version", err);
    if (!st) return -1;
    while ((r = sbq_step_row(st, err)) == 1) {
        int64_t version = sbq_int(st, 0);
        bool found = false;
        for (size_t i = 0; i < migrations->len && !found; ++i) found = migrations->items[i].version == version;
        if (!found) {
            sb_fail(err, SB_ERR_GENERIC, "applied migration %lld is missing from the migration directory",
                    (long long)version);
            r = -1;
            break;
        }
    }
    sqlite3_finalize(st);
    if (r != 0) return -1;

    for (size_t i = 0; i < migrations->len; ++i) {
        const migration *m = &migrations->items[i];
        st = sbq_prepare(h, "SELECT checksum FROM _sqlx_migrations WHERE version = ?1", err);
        if (!st) return -1;
        sbq_bind_int(st, 1, m->version);
        r = sbq_step_row(st, err);
        if (r == 1) {
            const void *blob = sqlite3_column_blob(st, 0);
            int n = sqlite3_column_bytes(st, 0);
            bool same = blob && n == SHA384_DIGEST_LENGTH && memcmp(blob, m->checksum, (size_t)n) == 0;
            sqlite3_finalize(st);
            if (!same)
                return sb_fail(err, SB_ERR_GENERIC,
                               "migration %lld checksum differs from the applied sqlx migration",
                               (long long)m->version);
            continue;
        }
        sqlite3_finalize(st);
        if (r < 0) return -1;

        if (sb_starts_with(m->sql, "-- no-transaction"))
            return sb_fail(err, SB_ERR_GENERIC, "non-transactional migrations are not supported");

        struct timespec started;
        clock_gettime(CLOCK_MONOTONIC, &started);
        if (sbq_begin(h, err) != 0) return -1;
        if (sbq_exec(h, m->sql, err) != 0) {
            sbq_rollback(h);
            return -1;
        }
        st = sbq_prepare(h,
                         "INSERT INTO _sqlx_migrations "
                         "(version, description, success, checksum, execution_time) "
                         "VALUES (?1, ?2, TRUE, ?3, -1)",
                         err);
        if (!st) {
            sbq_rollback(h);
            return -1;
        }
        sbq_bind_int(st, 1, m->version);
        sbq_bind_text(st, 2, m->description);
        sbq_bind_blob(st, 3, m->checksum, sizeof m->checksum);
        r = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (r != 0 || sbq_commit(h, err) != 0) {
            sbq_rollback(h);
            return -1;
        }

        st = sbq_prepare(h, "UPDATE _sqlx_migrations SET execution_time = ?1 WHERE version = ?2", err);
        if (!st) return -1;
        sbq_bind_int(st, 1, elapsed_ns(&started));
        sbq_bind_int(st, 2, m->version);
        r = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (r != 0) return -1;
    }
    return 0;
}

int sb_database_migrate(sb_database *db, const char *directory, sb_err *err) {
    migration_vec migrations = {0};
    if (load_migrations(directory, &migrations, err) != 0) {
        migration_vec_free(&migrations);
        return -1;
    }
    pthread_mutex_lock(&db->mutex);
    int rc = migrate_locked(db->handle, &migrations, err);
    pthread_mutex_unlock(&db->mutex);
    migration_vec_free(&migrations);
    return rc;
}

int64_t sb_database_applied_migration_count(sb_database *db, sb_err *err) {
    pthread_mutex_lock(&db->mutex);
    int64_t count = -1;
    sqlite3_stmt *st =
        sbq_prepare(db->handle, "SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE", err);
    if (st) {
        int r = sbq_step_row(st, err);
        count = r == 1 ? sbq_int(st, 0) : r == 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    pthread_mutex_unlock(&db->mutex);
    return count;
}
