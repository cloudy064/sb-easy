/* Packet capture storage. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* PCAP payloads are bounded by HTTP and per-host quotas. Digest is checked by
 * the HTTP layer; the primary key makes uncertain upload retries idempotent. */
int sb_store_save_capture(sb_store *s, const char *host_id, const char *digest,
                          const void *data, size_t len, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        int found = -1;
        {
            SBQ_AUTO q = sbq_stmt_open(h, "SELECT 1 FROM packet_captures WHERE host_id=?1 AND digest=?2", err);
            if (q.rc == 0) {
                sbq_bind_text(q.st, 1, host_id);
                sbq_bind_text(q.st, 2, digest);
                found = sbq_step_row(q.st, err);
            }
        }
        if (found == 1) { rc = sbq_commit(h, err); if (rc != 0) sbq_rollback(h); UNLOCK(s); return rc; }
        if (found < 0) rc = -1;
    }
    if (rc == 0) {
        SBQ_AUTO q = sbq_stmt_open(h, "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM packet_captures WHERE host_id=?1", err);
        if (q.rc != 0) rc = -1;
        else {
            sbq_bind_text(q.st, 1, host_id);
            if (sbq_step_row(q.st, err) != 1) rc = -1;
            else if (sqlite3_column_int64(q.st, 0) >= 1000 || sqlite3_column_int64(q.st, 1) + (int64_t)len > 128*1024*1024)
                rc = sb_fail(err, SB_ERR_CONFLICT, "Capture storage full (128 MiB or 1000 files); delete captures first");
        }
    }
    if (rc == 0) {
        SBQ_AUTO q = sbq_stmt_open(h, "INSERT INTO packet_captures(host_id,digest,payload) VALUES(?1,?2,?3)", err);
        if (q.rc != 0) rc = -1;
        else {
            sbq_bind_text(q.st, 1, host_id);
            sbq_bind_text(q.st, 2, digest);
            sbq_bind_blob(q.st, 3, data, len);
            rc = sbq_step_done(q.st, err);
        }
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}
sbj *sb_store_list_captures(sb_store *s, const char *host_id, sb_err *err) {
    LOCK(s);
    sbj *out = sbj_array();
    int rc;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT digest,length(payload),created_at FROM packet_captures WHERE host_id=?1 ORDER BY created_at DESC,digest LIMIT 1000", err);
        rc = q.rc;
        if (q.rc == 0) {
            sbq_bind_text(q.st, 1, host_id);
            while ((rc = sbq_step_row(q.st, err)) == 1) {
                sbj *item = sbj_object();
                sbj_set_str(item, "digest", (const char *)sqlite3_column_text(q.st, 0));
                sbj_set_int(item, "size", sqlite3_column_int64(q.st, 1));
                sbj_set_str(item, "created_at", (const char *)sqlite3_column_text(q.st, 2));
                sbj_arr_push(out, item);
            }
        }
    }
    UNLOCK(s);
    if (rc < 0) { sbj_free(out); return NULL; }
    return out;
}
char *sb_store_get_capture(sb_store *s, const char *host_id, const char *digest, size_t *len, sb_err *err) {
    LOCK(s);
    char *out = NULL;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT payload FROM packet_captures WHERE host_id=?1 AND digest=?2", err);
        if (q.rc == 0) {
            sbq_bind_text(q.st, 1, host_id);
            sbq_bind_text(q.st, 2, digest);
            int rc = sbq_step_row(q.st, err);
            if (rc == 1) { *len = (size_t)sqlite3_column_bytes(q.st, 0); out = sb_xmalloc(*len); memcpy(out, sqlite3_column_blob(q.st, 0), *len); }
            else if (rc == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Capture not found");
        }
    }
    UNLOCK(s);
    return out;
}
int sb_store_delete_capture(sb_store *s, const char *host_id, const char *digest, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), "DELETE FROM packet_captures WHERE host_id=?1 AND digest=?2", err);
    int rc = -1;
    if (st) { sbq_bind_text(st, 1, host_id); sbq_bind_text(st, 2, digest); rc = exec_stmt(st, err); }
    UNLOCK(s);
    return rc;
}
