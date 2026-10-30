/* Host command queue. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

int sb_store_enqueue_host_command(sb_store *s, const char *host_id, const char *command,
                                  sb_host_command *out, sb_err *err) {
    if (sb_str_empty(command)) return sb_fail(err, SB_ERR_VALIDATION, "Command is required");
    char *id = sb_uuid_v4();
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    const char *hid = S(host_id);
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT INTO host_commands "
                                   "(id, host_id, command, status, created_at) "
                                   "VALUES (?1, ?2, ?3, 'pending', datetime('now'))",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, id, strlen(id), err);
        sbq_stmt_bind_text_n(&q, 2, hid, strlen(hid), err);
        sbq_stmt_bind_text_n(&q, 3, command, strlen(command), err);
        if (q.rc != 0 || sbq_step_done(q.st, err) != 0) goto done;
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h, COMMAND_SELECT "FROM host_commands WHERE id = ?1", err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, id, strlen(id), err);
        r = sbq_stmt_step_row(&q, err);
        if (r == 1) read_host_command(q.st, out);
        if (r == 0) sb_fail(err, SB_ERR_GENERIC, "created host command could not be reloaded");
        rc = r == 1 ? 0 : -1;
    }
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_list_host_commands(sb_store *s, const char *host_id, bool pending_only,
                                sb_host_command_vec *out, sb_err *err) {
    sb_host_command_vec rows = {0};
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) r = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r == 1) {
        const char *sql = pending_only
                              ? COMMAND_SELECT "FROM host_commands WHERE host_id = ?1 AND status = 'pending' "
                                               "ORDER BY created_at"
                              : COMMAND_SELECT "FROM host_commands WHERE host_id = ?1 "
                                               "ORDER BY created_at DESC LIMIT 20";
        SBQ_AUTO q = sbq_stmt_open(h, sql, err);
        const char *hid = S(host_id);
        sbq_stmt_bind_text_n(&q, 1, hid, strlen(hid), err);
        while ((r = sbq_stmt_step_row(&q, err)) == 1)
            read_host_command(q.st, sb_host_command_vec_push(&rows));
    }
    UNLOCK(s);
    FINISH_LIST(sb_host_command_vec_free, out, rows, r);
}

int sb_store_acknowledge_host_command(sb_store *s, const char *host_id, const char *command_id,
                                      const char *status, const char *result, sb_err *err) {
    return sb_store_acknowledge_host_command_n(s, host_id, command_id, status, result,
                                               result ? strlen(result) : 0, err);
}

int sb_store_acknowledge_host_command_n(sb_store *s, const char *host_id, const char *command_id,
                                        const char *status, const char *result, size_t result_len,
                                        sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE host_commands SET status = ?1, result = ?2, "
                                   "acked_at = datetime('now') WHERE id = ?3 AND host_id = ?4",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, S(status));
        int bound = sbq_bind_text_n(st, 2, result, result_len, err);
        sbq_bind_text(st, 3, S(command_id));
        sbq_bind_text(st, 4, S(host_id));
        if (exec_bound(st, bound, err) == 0) rc = sqlite3_changes(h) != 0 ? 1 : 0;
    }
    UNLOCK(s);
    return rc;
}
