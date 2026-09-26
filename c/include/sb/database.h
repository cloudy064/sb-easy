/* A serialized SQLite connection compatible with the existing sqlx database.
 * Port of cpp/include/sbeasy/database.hpp. */
#ifndef SB_DATABASE_H
#define SB_DATABASE_H

#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_database sb_database;
struct sqlite3;

/* Opens (creating if needed) the database with a 5 s busy timeout,
 * foreign_keys = ON and journal_mode = WAL. NULL on failure. */
sb_database *sb_database_open(const char *path, sb_err *err);
void sb_database_free(sb_database *db);

/* Applies `<version>_<description>.sql` files from directory, recording them
 * in `_sqlx_migrations` with SHA-384 checksums exactly like SQLx. Fails on a
 * dirty (success = FALSE) row, an applied version missing from the directory
 * or a checksum mismatch. */
int sb_database_migrate(sb_database *db, const char *directory, sb_err *err);
int sb_database_execute(sb_database *db, const char *sql, sb_err *err);
/* Number of successfully applied migrations, or -1 on error. */
int64_t sb_database_applied_migration_count(sb_database *db, sb_err *err);

/* Low-level access for the store: the raw handle (borrowed) and the mutex
 * that serialises every statement on it. */
struct sqlite3 *sb_database_handle(sb_database *db);
void sb_database_lock(sb_database *db);
void sb_database_unlock(sb_database *db);

#ifdef __cplusplus
}
#endif

#endif
