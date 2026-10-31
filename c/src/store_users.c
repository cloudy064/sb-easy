/* Users, audit log and application settings for the repository facade. */
#include "sb/store.h"

#include <stdlib.h>
#include <string.h>

#include "sb/auth.h"
#include "store_internal.h"

static int find_user_locked(sqlite3 *h, const char *username, size_t username_len, sb_user_account *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h,
                               "SELECT id, username, password_hash, role, created_at "
                               "FROM users WHERE username = ?1 LIMIT 1",
                               err);
    if (q.rc != 0) return -1;
    sbq_stmt_bind_text_n(&q, 1, S(username), username_len, err);
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1) read_user(q.st, out);
    return r;
}

int sb_store_ensure_default_admin(sb_store *s, const char *password, sb_err *err) {
    LOCK(s);
    int r = -1;
    int64_t count = 0;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT COUNT(*) FROM users", err);
        r = sbq_stmt_step_row(&q, err);
        if (r == 1) count = sbq_int(q.st, 0);
    }
    UNLOCK(s);
    if (r < 0) return -1;
    if (r == 1 && count != 0) return 0;
    char *hash = sb_hash_password(password, err);
    if (!hash) return -1;
    sb_user_account created;
    sb_user_account_init(&created);
    int rc = sb_store_create_user(s, "admin", hash, "admin", &created, err);
    sb_user_account_free(&created);
    free(hash);
    return rc;
}

int sb_store_list_users(sb_store *s, sb_user_account_vec *out, sb_err *err) {
    sb_user_account_vec rows = {0};
    LOCK(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s),
                                   "SELECT id, username, password_hash, role, created_at "
                                   "FROM users ORDER BY created_at",
                                   err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1)
            read_user(q.st, sb_user_account_vec_push(&rows));
    }
    UNLOCK(s);
    FINISH_LIST(sb_user_account_vec_free, out, rows, r);
}

int sb_store_find_user_by_username(sb_store *s, const char *username, sb_user_account *out,
                                   sb_err *err) {
    return sb_store_find_user_by_username_n(s, username, strlen(S(username)), out, err);
}

int sb_store_find_user_by_username_n(sb_store *s, const char *username, size_t username_len,
                                    sb_user_account *out, sb_err *err) {
    LOCK(s);
    int r = find_user_locked(H(s), username, username ? username_len : 0, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_user(sb_store *s, const char *username, const char *password_hash,
                         const char *role, sb_user_account *out, sb_err *err) {
    return sb_store_create_user_n(s, username, strlen(S(username)), password_hash, role, out, err);
}

int sb_store_create_user_n(sb_store *s, const char *username, size_t username_len,
                           const char *password_hash, const char *role,
                           sb_user_account *out, sb_err *err) {
    if (!username || username_len == 0 || sb_str_empty(password_hash) ||
        (!sb_streq(role, "admin") && !sb_streq(role, "viewer") && !sb_streq(role, "operator")))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid user");
    char *id = sb_uuid_v4();
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    int r = 0;
    {
        SBQ_AUTO q = sbq_stmt_open(h, "SELECT 1 FROM users WHERE username = ?1", err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, username, username_len, err);
        r = sbq_stmt_step_row(&q, err);
        if (r < 0) goto done;
        if (r == 1) {
            sb_fail(err, SB_ERR_CONFLICT, "Username already exists");
            goto done;
        }
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT INTO users (id, username, password_hash, role) "
                                   "VALUES (?1, ?2, ?3, ?4)",
                                   err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, id);
        sbq_stmt_bind_text_n(&q, 2, username, username_len, err);
        sbq_bind_text(q.st, 3, password_hash);
        sbq_bind_text(q.st, 4, role);
        if (q.rc != 0 || sbq_step_done(q.st, err) != 0) goto done;
    }
    r = find_user_locked(h, username, username_len, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "created user could not be reloaded");
    rc = r == 1 ? 0 : -1;
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_delete_user(sb_store *s, const char *actor_id, const char *user_id, sb_err *err) {
    if (sb_streq(S(actor_id), S(user_id)))
        return sb_fail(err, SB_ERR_VALIDATION, "You cannot delete your own account");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    const char *uid = S(user_id);
    int r = -1;
    bool is_admin = false;
    {
        SBQ_AUTO q = sbq_stmt_open(h, "SELECT role FROM users WHERE id = ?1", err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, uid, strlen(uid), err);
        r = sbq_stmt_step_row(&q, err);
        is_admin = r == 1 && sb_streq((const char *)sqlite3_column_text(q.st, 0), "admin");
    }
    if (r < 0) goto done;
    if (r == 0) {
        rc = 0;
        goto done;
    }
    if (is_admin) {
        int64_t count = 0;
        {
            SBQ_AUTO q = sbq_stmt_open(h, "SELECT COUNT(*) FROM users WHERE role = 'admin'", err);
            if (q.rc != 0) goto done;
            r = sbq_stmt_step_row(&q, err);
            count = r == 1 ? sbq_int(q.st, 0) : 0;
        }
        if (r < 0) goto done;
        if (r == 1 && count <= 1) {
            sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the last admin");
            goto done;
        }
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h, "DELETE FROM users WHERE id = ?1", err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, uid, strlen(uid), err);
        rc = q.rc != 0 ? -1 : sbq_step_done(q.st, err);
    }
done:
    UNLOCK(s);
    return rc;
}

/* Executes a single-statement UPDATE/DELETE with text binds; fails with
 * SB_ERR_NOT_FOUND + not_found message when no row changed (unless NULL). */
int exec_changes(sb_store *s, const char *sql, const char *not_found, sb_err *err,
                        int nbinds, const char *const *binds) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h, sql, err);
    if (st) {
        for (int i = 0; i < nbinds; ++i) sbq_bind_text(st, i + 1, binds[i]);
        rc = exec_stmt(st, err);
        if (rc == 0 && not_found && sqlite3_changes(h) == 0)
            rc = sb_fail(err, SB_ERR_NOT_FOUND, "%s", not_found);
    }
    UNLOCK(s);
    return rc;
}

int sb_store_reset_user_password(sb_store *s, const char *user_id, const char *password_hash,
                                 sb_err *err) {
    const char *binds[] = {S(password_hash), S(user_id)};
    return exec_changes(s, "UPDATE users SET password_hash = ?1 WHERE id = ?2", "User not found",
                        err, 2, binds);
}

int sb_store_record_audit(sb_store *s, const char *actor, const char *action, const char *target,
                          sb_err *err) {
    return sb_store_record_audit_n(s, actor, strlen(S(actor)), action, target, err);
}

int sb_store_record_audit_n(sb_store *s, const char *actor, size_t actor_len,
                            const char *action, const char *target, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s),
        "INSERT INTO audit_log (actor, action, target) VALUES (?1, ?2, ?3)", err);
    int rc = -1;
    if (st) {
        int bound = sbq_bind_text_n(st, 1, S(actor), actor ? actor_len : 0, err);
        sbq_bind_text(st, 2, S(action));
        sbq_bind_text(st, 3, target);
        rc = exec_bound(st, bound, err);
    }
    UNLOCK(s);
    return rc;
}

int sb_store_list_audit(sb_store *s, size_t limit, sb_audit_entry_vec *out, sb_err *err) {
    sb_audit_entry_vec rows = {0};
    size_t bounded = limit < 1 ? 1 : limit > 1000 ? 1000 : limit;
    LOCK(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s),
                                   "SELECT id, ts, actor, action, target FROM audit_log "
                                   "ORDER BY id DESC LIMIT ?1",
                                   err);
        r = q.rc;
        if (q.rc == 0) sbq_bind_int(q.st, 1, (int64_t)bounded);
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
            sb_audit_entry *e = sb_audit_entry_vec_push(&rows);
            sb_audit_entry_free(e);
            e->id = sbq_int(q.st, 0);
            e->timestamp = sbq_text(q.st, 1);
            e->actor = sbq_text(q.st, 2);
            e->actor_len = (size_t)sqlite3_column_bytes(q.st, 2);
            e->action = sbq_text(q.st, 3);
            e->target = sbq_opt_text(q.st, 4);
        }
    }
    UNLOCK(s);
    FINISH_LIST(sb_audit_entry_vec_free, out, rows, r);
}

sbj *sb_store_app_settings(sb_store *s, sb_err *err) {
    LOCK(s);
    sbj *settings = NULL;
    int r = 0;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT key, value FROM app_settings", err);
        if (q.rc == 0) settings = sbj_object();
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
            const char *text = (const char *)sqlite3_column_text(q.st, 1);
            sbj *value = text ? sbj_parse(text, (size_t)sqlite3_column_bytes(q.st, 1), NULL, 0) : NULL;
            const char *key = (const char *)sqlite3_column_text(q.st, 0);
            if (value) sbj_set(settings, key ? key : "", value);
        }
    }
    UNLOCK(s);
    if (r < 0) {
        sbj_free(settings);
        return NULL;
    }
    return settings;
}

int sb_store_update_app_settings(sb_store *s, const sbj *sections, sb_err *err) {
    if (!sbj_is_object(sections)) return sb_fail(err, SB_ERR_VALIDATION, "settings must be a JSON object");
    static const char *const allowed[] = {"wireguard_interface", "singbox_connection", "general"};
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    for (size_t i = 0; rc == 0 && i < 3; ++i) {
        const sbj *found = sbj_get(sections, allowed[i]);
        if (!found) continue;
        sqlite3_stmt *st = sbq_prepare(h, settings_upsert_sql, err);
        if (!st) {
            rc = -1;
            break;
        }
        sbq_bind_text(st, 1, allowed[i]);
        int bound = bind_dump(st, 2, found, err);
        rc = exec_bound(st, bound, err);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

int sb_store_app_setting(sb_store *s, const char *key, sbj **out, sb_err *err) {
    LOCK(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT value FROM app_settings WHERE key = ?1", err);
        if (q.rc == 0) {
            const char *k = S(key);
            sbq_stmt_bind_text_n(&q, 1, k, strlen(k), err);
            r = sbq_stmt_step_row(&q, err);
            if (r == 1) {
                const char *text = (const char *)sqlite3_column_text(q.st, 0);
                sbj *value =
                    text ? sbj_parse(text, (size_t)sqlite3_column_bytes(q.st, 0), NULL, 0) : NULL;
                if (value)
                    *out = value;
                else
                    r = 0;
            }
        }
    }
    UNLOCK(s);
    return r;
}

int sb_store_set_app_setting(sb_store *s, const char *key, const sbj *value, sb_err *err) {
    if (sb_str_empty(key)) return sb_fail(err, SB_ERR_VALIDATION, "setting key is required");
    char *text = dump_checked(value, err);
    if (!text) return -1;
    const char *binds[] = {key, text};
    int rc = exec_changes(s, settings_upsert_sql, NULL, err, 2, binds);
    free(text);
    return rc;
}
