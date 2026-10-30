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

#define COMMAND_SELECT "SELECT id, host_id, command, status, result, created_at, acked_at "

#define VEC_APPEND_MOVE(dst, src)                                                      \
    do {                                                                               \
        if ((dst)->len + (src)->len > (dst)->cap) {                                    \
            (dst)->cap = (dst)->len + (src)->len;                                      \
            (dst)->items = sb_xrealloc((dst)->items, (dst)->cap * sizeof *(dst)->items); \
        }                                                                              \
        if ((src)->len)                                                                \
            memcpy((dst)->items + (dst)->len, (src)->items, (src)->len * sizeof *(src)->items); \
        (dst)->len += (src)->len;                                                      \
        free((src)->items);                                                            \
        memset((src), 0, sizeof *(src));                                               \
    } while (0)

#define FINISH_LIST(free_fn, out, rows, r)                                             \
    do {                                                                               \
        if ((r) < 0) {                                                                 \
            free_fn(&(rows));                                                          \
            return -1;                                                                 \
        }                                                                              \
        VEC_APPEND_MOVE((out), &(rows));                                               \
        return 0;                                                                      \
    } while (0)

int host_exists(sqlite3 *db, const char *host_id, sb_err *err);
void read_host_command(sqlite3_stmt *st, sb_host_command *c);

#define SUBSCRIPTION_SELECT                                                            \
    "SELECT id, name, url, enabled, refresh_interval, last_fetched_at, "               \
    "last_fetch_result, created_at, updated_at, usage, last_attempt_at, last_error, "    \
    "next_refresh_at, failure_count "

sbj *strvec_to_json(const sb_strvec *v);
void read_subscription(sqlite3_stmt *st, sb_subscription *s);
int exec_changes(sb_store *s, const char *sql, const char *not_found, sb_err *err, int nbinds, const char *const *binds);
int upsert_one(sqlite3 *h, const sb_parsed_node *node, const char *subscription_id, sb_proxy_upsert_result *result, sb_err *err);

#define HOST_SELECT                                                                    \
    "\nSELECT h.id, h.name, h.agent_token, h.capabilities, h.profile_id,\n"            \
    "       h.wg_address, h.wg_public_key, h.wg_endpoint, h.clash_api,\n"              \
    "       h.clash_secret, h.last_seen, h.singbox_state, h.enabled,\n"                \
    "       h.created_at, h.updated_at,\n"                                             \
    "       (SELECT COUNT(*) FROM host_outbounds o WHERE o.host_id = h.id)\n"          \
    "FROM hosts h\n"

sbj *parse_object_or_empty(const char *text);
void read_host(sqlite3_stmt *st, sb_host *h);
char *new_agent_token(void);

#endif
