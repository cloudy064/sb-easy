/* Subscription storage. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* ======================================================================
 * subscriptions
 * ====================================================================== */

static int find_subscription_locked(sqlite3 *h, const char *id, sb_subscription *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h, SUBSCRIPTION_SELECT "FROM subscriptions WHERE id = ?1", err);
    if (q.rc != 0) return -1;
    const char *sid = S(id);
    sbq_stmt_bind_text_n(&q, 1, sid, strlen(sid), err);
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1) read_subscription(q.st, out);
    return r;
}

static int reload_subscription(sqlite3 *h, const char *id, sb_subscription *out, sb_err *err) {
    int r = find_subscription_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "subscription could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_subscriptions(sb_store *s, sb_subscription_vec *out, sb_err *err) {
    sb_subscription_vec rows = {0};
    LOCK(s);
    int r;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), SUBSCRIPTION_SELECT "FROM subscriptions ORDER BY name", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1)
            read_subscription(q.st, sb_subscription_vec_push(&rows));
    }
    UNLOCK(s);
    FINISH_LIST(sb_subscription_vec_free, out, rows, r);
}

int sb_store_find_subscription(sb_store *s, const char *id, sb_subscription *out, sb_err *err) {
    LOCK(s);
    int r = find_subscription_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err) {
    if (!sub->name_len || !sub->url_len || sub->refresh_interval <= 0)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Subscription name, URL, and positive refresh interval are required");
    char *id = sb_str_empty(sub->id) ? sb_uuid_v4() : sb_strdup(sub->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO subscriptions "
                                   "(id, name, url, enabled, refresh_interval, last_fetched_at, "
                                   "last_fetch_result, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
                                   "datetime('now'), datetime('now'))",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        int bound = sbq_bind_text_n(st, 2, sub->name, sub->name_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 3, sub->url, sub->url_len, err);
        sbq_bind_bool(st, 4, sub->enabled);
        sbq_bind_int(st, 5, sub->refresh_interval);
        sbq_bind_text(st, 6, sub->last_fetched_at);
        sbq_bind_text(st, 7, sub->last_fetch_result);
        if (exec_bound(st, bound, err) == 0) rc = reload_subscription(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err) {
    if (sb_str_empty(sub->id) || !sub->name_len || !sub->url_len ||
        sub->refresh_interval <= 0)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Subscription id, name, URL, and positive refresh interval are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE subscriptions SET name = ?1, url = ?2, enabled = ?3, "
                                   "next_refresh_at = CASE WHEN url != ?2 OR enabled != ?3 OR refresh_interval != ?4 "
                                   "THEN 0 ELSE next_refresh_at END, refresh_interval = ?4, "
                                   "updated_at = datetime('now') WHERE id = ?5",
                                   err);
    if (st) {
        int bound = sbq_bind_text_n(st, 1, sub->name, sub->name_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 2, sub->url, sub->url_len, err);
        sbq_bind_bool(st, 3, sub->enabled);
        sbq_bind_int(st, 4, sub->refresh_interval);
        sbq_bind_text(st, 5, sub->id);
        if (exec_bound(st, bound, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
            else
                rc = reload_subscription(h, sub->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_subscription(sb_store *s, const char *id, sb_err *err) {
    const char *binds[] = {S(id)};
    return exec_changes(s, "DELETE FROM subscriptions WHERE id = ?1", "Subscription not found", err, 1,
                        binds);
}

int sb_store_record_subscription_fetch(sb_store *s, const char *id,
                                       const sb_subscription_fetch_result *result, sb_err *err) {
    sbj *metadata = sbj_object();
    sbj_set(metadata, "added", sbj_uint(result->added));
    sbj_set(metadata, "updated", sbj_uint(result->updated));
    sbj_set(metadata, "skipped", sbj_uint(result->skipped));
    sbj_set(metadata, "total", sbj_uint(result->found));
    sbj_set(metadata, "errors", strvec_to_json(&result->errors));
    char *text = dump_checked(metadata, err);
    sbj_free(metadata);
    if (!text) return -1;
    const char *binds[] = {text, S(id)};
    int rc = exec_changes(s,
                          "UPDATE subscriptions SET last_fetched_at = datetime('now'), "
                          "last_fetch_result = ?1 WHERE id = ?2",
                          "Subscription not found", err, 2, binds);
    free(text);
    return rc;
}

/* Keep the source check, node writes and success marker in one transaction.
 * A slow response from an edited/deleted source must never replace its nodes. */
static int subscription_unchanged(sqlite3 *h, const sb_subscription *expected,
                                  sb_subscription *current, sb_err *err) {
    int r = find_subscription_locked(h, expected->id, current, err);
    if (r == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
    if (r < 0) return -1;
    if (current->url_len != expected->url_len ||
        memcmp(current->url, expected->url, current->url_len) != 0 ||
        current->enabled != expected->enabled)
        return sb_fail(err, SB_ERR_CONFLICT, "Subscription changed during refresh; response discarded");
    return 0;
}

int sb_store_apply_subscription_fetch(sb_store *s, const sb_subscription *expected,
                                      const sb_parsed_node *nodes, size_t count,
                                      sb_subscription_fetch_result *result, int64_t now,
                                      sb_err *err) {
    sb_subscription current;
    sb_subscription_init(&current);
    sb_proxy_upsert_result upsert;
    sb_proxy_upsert_result_init(&upsert);
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) rc = subscription_unchanged(h, expected, &current, err);
    for (size_t i = 0; rc == 0 && i < count; ++i)
        rc = upsert_one(h, &nodes[i], expected->id, &upsert, err);
    if (rc == 0) {
        result->added = upsert.added;
        result->updated = upsert.updated;
        result->found = count;
        sbj *metadata = sbj_object();
        sbj_set(metadata, "added", sbj_uint(result->added));
        sbj_set(metadata, "updated", sbj_uint(result->updated));
        sbj_set(metadata, "skipped", sbj_uint(result->skipped));
        sbj_set(metadata, "total", sbj_uint(result->found));
        sbj_set(metadata, "errors", strvec_to_json(&result->errors));
        sqlite3_stmt *st = sbq_prepare(h,
            "UPDATE subscriptions SET last_fetched_at = datetime(?1, 'unixepoch'), "
            "last_attempt_at = datetime(?1, 'unixepoch'), last_fetch_result = ?2, "
            "usage = ?3, last_error = NULL, failure_count = 0, next_refresh_at = ?4 "
            "WHERE id = ?5", err);
        rc = st ? 0 : -1;
        if (st) {
            sbq_bind_int(st, 1, now);
            int bound = bind_dump(st, 2, metadata, err);
            if (bound == 0) bound = bind_dump(st, 3, result->usage, err);
            int64_t interval = current.refresh_interval < 60 ? 60 : current.refresh_interval;
            sbq_bind_int(st, 4, interval > INT64_MAX - now ? INT64_MAX : now + interval);
            sbq_bind_text(st, 5, expected->id);
            rc = exec_bound(st, bound, err);
        }
        sbj_free(metadata);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    sb_proxy_upsert_result_free(&upsert);
    sb_subscription_free(&current);
    return rc;
}

int sb_store_record_subscription_failure(sb_store *s, const sb_subscription *expected,
                                         const char *message, int64_t now, sb_err *err) {
    sb_subscription current;
    sb_subscription_init(&current);
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = subscription_unchanged(h, expected, &current, err);
    if (rc == 0) {
        int64_t attempts = current.failure_count < 20 ? current.failure_count + 1 : 20;
        int64_t delay = attempts > 6 ? 3600 : (60LL << (attempts - 1));
        sqlite3_stmt *st = sbq_prepare(h,
            "UPDATE subscriptions SET last_attempt_at = datetime(?1, 'unixepoch'), "
            "last_error = ?2, failure_count = ?3, next_refresh_at = ?4 WHERE id = ?5", err);
        rc = st ? 0 : -1;
        if (st) {
            sbq_bind_int(st, 1, now);
            sbq_bind_text(st, 2, message);
            sbq_bind_int(st, 3, attempts);
            sbq_bind_int(st, 4, now > INT64_MAX - delay ? INT64_MAX : now + delay);
            sbq_bind_text(st, 5, expected->id);
            rc = exec_stmt(st, err);
        }
    }
    UNLOCK(s);
    sb_subscription_free(&current);
    return rc;
}
