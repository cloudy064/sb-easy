/* Private helpers shared by the store_*.c files. Not part of the public API. */
#ifndef SB_STORE_INTERNAL_H
#define SB_STORE_INTERNAL_H
#include "sb/store.h"
#include "sqlite_internal.h"
#include <string.h>

struct sb_store {
    sb_database *db;
};

#define S(x) ((x) ? (x) : "")
#define LOCK(s) sb_database_lock((s)->db)
#define UNLOCK(s) sb_database_unlock((s)->db)
#define H(s) sb_database_handle((s)->db)

#define WIREGUARD_PEER_SELECT                                                          \
    "\nSELECT id, name, private_key, public_key, preshared_key, address, dns,\n"       \
    "       enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes,\n"     \
    "       created_at, updated_at, notes, host_id\n"                                  \
    "FROM wireguard_peers\n"

sbj *parse_object_col(sqlite3_stmt *st, int col, const char *description, sb_err *err);
void read_wireguard_peer(sqlite3_stmt *st, sb_wireguard_peer *p);
char *dump_checked(const sbj *value, sb_err *err);
extern const char *const settings_upsert_sql;
int bind_dump(sqlite3_stmt *st, int i, const sbj *value, sb_err *err);
int exec_bound(sqlite3_stmt *st, int bound, sb_err *err);
int restore_peer(sqlite3 *h, const sbj *value, size_t *count, sb_err *err);

int exec_stmt(sqlite3_stmt *st, sb_err *err);

#endif
