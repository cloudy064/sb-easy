#include "auth_security_internal.h"

static bool json_text(const sbj *value, size_t maximum, bool token) {
    if (!sbj_is_string(value) || !value->v.str.len || value->v.str.len > maximum ||
        memchr(value->v.str.ptr, '\0', value->v.str.len)) return false;
    if (token) return sb_auth_sec_token(value->v.str.ptr, maximum);
    for (size_t i = 0; i < value->v.str.len; ++i)
        if ((unsigned char)value->v.str.ptr[i] < 32 || value->v.str.ptr[i] == 127) return false;
    return sbj_validate_utf8(value, NULL) == 0;
}

static int require_user(sb_auth_security *s, const char *user_id, sb_err *err) {
    int exists = sb_auth_sec_user_exists_locked(s, user_id, err);
    if (!exists) return sb_fail(err, SB_ERR_NOT_FOUND, "User not found");
    return exists < 0 ? -1 : 0;
}

sbj *sb_auth_device_groups(sb_auth_security *s, sb_err *err) {
    if (!s) return NULL;
    sbj *result = sbj_array();
    sb_database_lock(s->database);
    int row = -1;
    {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT g.id,g.name,h.host_id FROM auth_device_groups g LEFT JOIN auth_device_group_hosts h ON h.group_id=g.id ORDER BY g.name,g.id,h.host_id", err);
    sqlite3_stmt *st = q.st;
    if (q.rc == 0) {
        sbj *current = NULL;
        while ((row = sbq_step_row(st, err)) == 1) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            if (!current || !sb_streq(sbj_get_str(current, "id", ""), id)) {
                current = sbj_object(); sbj_set_str(current, "id", id);
                sbj_set_str(current, "name", (const char *)sqlite3_column_text(st, 1));
                sbj_set(current, "host_ids", sbj_array()); sbj_arr_push(result, current);
            }
            if (sqlite3_column_type(st, 2) != SQLITE_NULL)
                sbj_arr_push(sbj_get(current, "host_ids"), sbj_str((const char *)sqlite3_column_text(st, 2)));
        }
    }
    }
    sb_database_unlock(s->database);
    if (row < 0) { sbj_free(result); return NULL; }
    return result;
}

int sb_auth_device_group_save(sb_auth_security *s, const sbj *group, sb_err *err) {
    sbj *id_value = sbj_get(group, "id"), *name = sbj_get(group, "name"), *hosts = sbj_get(group, "host_ids");
    if (!s || !sbj_is_object(group) || !json_text(name, 128, false) ||
        (id_value && !json_text(id_value, 128, true)) || !sbj_is_array(hosts) || sbj_arr_len(hosts) > 2000)
        return sb_fail(err, SB_ERR_VALIDATION, "Device group requires a name and at most 2000 host IDs");
    sb_strvec seen = {0};
    for (size_t i = 0; i < sbj_arr_len(hosts); ++i) {
        sbj *host = sbj_arr_at(hosts, i);
        if (!json_text(host, 256, true) || sb_strvec_contains(&seen, host->v.str.ptr)) {
            sb_strvec_free(&seen); return sb_fail(err, SB_ERR_VALIDATION, "Invalid or duplicate device group host");
        }
        sb_strvec_push(&seen, host->v.str.ptr);
    }
    char *id = id_value ? sb_strdup(id_value->v.str.ptr) : sb_uuid_v4();
    if (!id) { sb_strvec_free(&seen); return sb_fail(err, SB_ERR_GENERIC, "Device group ID generation failed"); }
    sb_database_lock(s->database); int result = -1;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_device_groups(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, id); sbq_bind_text(st, 2, name->v.str.ptr);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) {
        if (sqlite3_errcode(SB_AUTH_DB(s)) == SQLITE_CONSTRAINT)
            sb_fail(err, SB_ERR_CONFLICT, "Device group name already exists");
        goto rollback;
    }
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_device_group_hosts WHERE group_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, id); rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    for (size_t i = 0; i < seen.len; ++i) {
        st = sbq_prepare(SB_AUTH_DB(s), "SELECT 1 FROM hosts WHERE id=?", err);
        if (!st) goto rollback;
        sbq_bind_text(st, 1, seen.items[i]); int row = sbq_step_row(st, err); sqlite3_finalize(st);
        if (row != 1) {
            if (!row) sb_fail(err, SB_ERR_VALIDATION, "Device group references an unknown host");
            goto rollback;
        }
        st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_device_group_hosts(group_id,host_id) VALUES(?,?)", err);
        if (!st) goto rollback;
        sbq_bind_text(st, 1, id); sbq_bind_text(st, 2, seen.items[i]);
        rc = sbq_step_done(st, err); sqlite3_finalize(st);
        if (rc) goto rollback;
    }
    if (sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    result = 0; goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s));
done:
    sb_database_unlock(s->database); free(id); sb_strvec_free(&seen); return result;
}

int sb_auth_device_group_remove(sb_auth_security *s, const char *group_id, sb_err *err) {
    if (!s || !sb_auth_sec_token(group_id, 128)) return sb_fail(err, SB_ERR_VALIDATION, "Invalid device group ID");
    sb_database_lock(s->database);
    int result = -1;
    {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "DELETE FROM auth_device_groups WHERE id=?", err);
    if (q.rc == 0) {
        sbq_bind_text(q.st, 1, group_id); result = sbq_step_done(q.st, err);
        if (!result && !sqlite3_changes(SB_AUTH_DB(s))) result = sb_fail(err, SB_ERR_NOT_FOUND, "Device group not found");
    }
    }
    sb_database_unlock(s->database); return result;
}

sbj *sb_auth_user_scope(sb_auth_security *s, const char *user_id, sb_err *err) {
    if (!s) return NULL;
    sb_database_lock(s->database); sbj *result = NULL;
    if (require_user(s, user_id, err)) goto done;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "SELECT scope FROM auth_user_scope WHERE user_id=?", err);
    if (!st) goto done;
    sbq_bind_text(st, 1, user_id); int row = sbq_step_row(st, err);
    if (row >= 0) {
        result = sbj_object(); sbj_set_str(result, "scope", row ? (const char *)sqlite3_column_text(st, 0) : "groups");
        sbj_set(result, "grants", sbj_array());
    }
    sqlite3_finalize(st);
    if (!result) goto done;
    st = sbq_prepare(SB_AUTH_DB(s), "SELECT group_id,permission FROM auth_device_grants WHERE user_id=? ORDER BY group_id", err);
    row = -1;
    if (st) {
        sbq_bind_text(st, 1, user_id);
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *grant = sbj_object(); sbj_set_str(grant, "group_id", (const char *)sqlite3_column_text(st, 0));
            sbj_set_str(grant, "permission", (const char *)sqlite3_column_text(st, 1));
            sbj_arr_push(sbj_get(result, "grants"), grant);
        }
        sqlite3_finalize(st);
    }
    if (row < 0) { sbj_free(result); result = NULL; }
done:
    sb_database_unlock(s->database); return result;
}

int sb_auth_user_scope_set(sb_auth_security *s, const char *user_id, const sbj *policy, sb_err *err) {
    sbj *scope = sbj_get(policy, "scope"), *grants = sbj_get(policy, "grants");
    if (!s || !sbj_is_object(policy) || (!sbj_string_is(scope, "all") && !sbj_string_is(scope, "groups")) ||
        !sbj_is_array(grants) || sbj_arr_len(grants) > 500 ||
        (sbj_string_is(scope, "all") && sbj_arr_len(grants)))
        return sb_fail(err, SB_ERR_VALIDATION, "Scope requires all or groups and at most 500 group grants");
    sb_strvec seen = {0};
    for (size_t i = 0; i < sbj_arr_len(grants); ++i) {
        sbj *grant = sbj_arr_at(grants, i), *id = sbj_get(grant, "group_id"), *permission = sbj_get(grant, "permission");
        if (!sbj_is_object(grant) || !json_text(id, 128, true) ||
            (!sbj_string_is(permission, "view") && !sbj_string_is(permission, "operate")) ||
            sb_strvec_contains(&seen, id->v.str.ptr)) {
            sb_strvec_free(&seen); return sb_fail(err, SB_ERR_VALIDATION, "Invalid or duplicate device group grant");
        }
        sb_strvec_push(&seen, id->v.str.ptr);
    }
    sb_database_lock(s->database); int result = -1;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    if (require_user(s, user_id, err)) goto rollback;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_user_scope(user_id,scope) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET scope=excluded.scope", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, scope->v.str.ptr);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_device_grants WHERE user_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    for (size_t i = 0; i < seen.len; ++i) {
        st = sbq_prepare(SB_AUTH_DB(s), "SELECT 1 FROM auth_device_groups WHERE id=?", err);
        if (!st) goto rollback;
        sbq_bind_text(st, 1, seen.items[i]); int row = sbq_step_row(st, err); sqlite3_finalize(st);
        if (row != 1) {
            if (!row) sb_fail(err, SB_ERR_VALIDATION, "Scope references an unknown device group");
            goto rollback;
        }
        st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_device_grants(user_id,group_id,permission) VALUES(?,?,?)", err);
        if (!st) goto rollback;
        sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, seen.items[i]);
        sbq_bind_text(st, 3, sbj_get_str(sbj_arr_at(grants, i), "permission", ""));
        rc = sbq_step_done(st, err); sqlite3_finalize(st);
        if (rc) goto rollback;
    }
    if (sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    result = 0; goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s));
done:
    sb_database_unlock(s->database); sb_strvec_free(&seen); return result;
}

bool sb_auth_device_allowed(sb_auth_security *s, const char *user_id, const char *host_id,
                             bool mutate, sb_err *err) {
    if (!s || !sb_auth_sec_token(user_id, 256) || !sb_auth_sec_token(host_id, 256)) {
        sb_fail(err, SB_ERR_FORBIDDEN, "Device access denied"); return false;
    }
    sb_database_lock(s->database);
    bool allowed = false; int row = -1;
    {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s),
        "SELECT u.role='admin' OR ((u.role='operator' OR (u.role='viewer' AND ?=0)) "
        "AND EXISTS(SELECT 1 FROM hosts WHERE id=?) AND EXISTS(SELECT 1 FROM auth_user_scope s "
        "WHERE s.user_id=u.id AND (s.scope='all' OR EXISTS(SELECT 1 FROM auth_device_grants g "
        "JOIN auth_device_group_hosts h ON h.group_id=g.group_id WHERE g.user_id=u.id AND h.host_id=? "
        "AND (?=0 OR g.permission='operate'))))) FROM users u WHERE u.id=?", err);
    sqlite3_stmt *st = q.st;
    if (q.rc == 0) {
        sbq_bind_bool(st, 1, mutate); sbq_bind_text(st, 2, host_id); sbq_bind_text(st, 3, host_id);
        sbq_bind_bool(st, 4, mutate); sbq_bind_text(st, 5, user_id);
        row = sbq_step_row(st, err); allowed = row == 1 && sbq_int(st, 0);
    }
    }
    sb_database_unlock(s->database);
    if (!allowed && row >= 0) sb_fail(err, SB_ERR_FORBIDDEN, "Device access denied");
    return allowed;
}
