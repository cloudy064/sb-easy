/* Config profiles, hosts, diagnostics and host outbounds. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* ======================================================================
 * profiles
 * ====================================================================== */

int find_profile_locked(sqlite3 *h, const char *id, sb_config_profile *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h, PROFILE_SELECT "FROM config_profiles WHERE id = ?1", err);
    if (q.rc != 0) return -1;
    const char *pid = S(id);
    sbq_stmt_bind_text_n(&q, 1, pid, strlen(pid), err);
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1 && read_profile(q.st, out, err) != 0) r = -1;
    return r;
}

static int reload_profile(sqlite3 *h, const char *id, sb_config_profile *out, sb_err *err) {
    int r = find_profile_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "profile could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_profiles(sb_store *s, sb_config_profile_vec *out, sb_err *err) {
    sb_config_profile_vec rows = {0};
    LOCK(s);
    int r;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), PROFILE_SELECT "FROM config_profiles ORDER BY name", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
            sb_config_profile p;
            sb_config_profile_init(&p);
            if (read_profile(q.st, &p, err) != 0) {
                sb_config_profile_free(&p);
                r = -1;
                break;
            }
            sb_config_profile *slot = sb_config_profile_vec_push(&rows);
            sb_config_profile_free(slot);
            *slot = p;
        }
    }
    UNLOCK(s);
    FINISH_LIST(sb_config_profile_vec_free, out, rows, r);
}

int sb_store_find_profile(sb_store *s, const char *id, sb_config_profile *out, sb_err *err) {
    LOCK(s);
    int r = find_profile_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_profile(sb_store *s, const sb_config_profile *profile, sb_config_profile *out,
                            sb_err *err) {
    if (!profile->name || profile->name_len == 0 || !sbj_is_object(profile->profile))
        return sb_fail(err, SB_ERR_VALIDATION, "Profile name and object template are required");
    char *id = sb_str_empty(profile->id) ? sb_uuid_v4() : sb_strdup(profile->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO config_profiles "
                                   "(id, name, template, mode, rule_script, "
                                   "rule_script_enabled, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, "
                                   "datetime('now'), datetime('now'))",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        int bound = sbq_bind_text_n(st, 2, profile->name, profile->name_len, err);
        if (bound == 0) bound = bind_dump(st, 3, profile->profile, err);
        sbq_bind_text(st, 4, sb_profile_mode_name(profile->mode));
        if (bound == 0) bound = sbq_bind_text_n(st, 5, S(profile->rule_script), profile->rule_script_len, err);
        sbq_bind_bool(st, 6, profile->rule_script_enabled);
        if (exec_bound(st, bound, err) == 0) rc = reload_profile(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_profile(sb_store *s, const sb_config_profile *profile, sb_config_profile *out,
                            sb_err *err) {
    if (sb_str_empty(profile->id) || !profile->name || profile->name_len == 0 || !sbj_is_object(profile->profile))
        return sb_fail(err, SB_ERR_VALIDATION, "Profile id, name, and object template are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE config_profiles SET name = ?1, template = ?2, "
                                   "mode = ?3, rule_script = ?4, rule_script_enabled = ?5, "
                                   "updated_at = datetime('now') WHERE id = ?6",
                                   err);
    if (st) {
        int bound = sbq_bind_text_n(st, 1, profile->name, profile->name_len, err);
        if (bound == 0) bound = bind_dump(st, 2, profile->profile, err);
        sbq_bind_text(st, 3, sb_profile_mode_name(profile->mode));
        if (bound == 0) bound = sbq_bind_text_n(st, 4, S(profile->rule_script), profile->rule_script_len, err);
        sbq_bind_bool(st, 5, profile->rule_script_enabled);
        sbq_bind_text(st, 6, profile->id);
        if (exec_bound(st, bound, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Profile not found");
            else
                rc = reload_profile(h, profile->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_profile(sb_store *s, const char *id, sb_err *err) {
    if (sb_streq(id, "default")) return sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the default profile");
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE hosts SET profile_id = 'default', updated_at = datetime('now') "
                                       "WHERE profile_id = ?1",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM config_profiles WHERE id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Profile not found");
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

/* ======================================================================
 * hosts
 * ====================================================================== */

static int find_host_locked(sqlite3 *h, const char *id, sb_host *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h, HOST_SELECT " WHERE h.id = ?1", err);
    if (q.rc != 0) return -1;
    const char *hid = S(id);
    sbq_stmt_bind_text_n(&q, 1, hid, strlen(hid), err);
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1) read_host(q.st, out);
    return r;
}

static int reload_host(sqlite3 *h, const char *id, sb_host *out, sb_err *err) {
    int r = find_host_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "host could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_hosts(sb_store *s, sb_host_vec *out, sb_err *err) {
    sb_host_vec rows = {0};
    LOCK(s);
    int r;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), HOST_SELECT " ORDER BY h.created_at", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1)
            read_host(q.st, sb_host_vec_push(&rows));
    }
    UNLOCK(s);
    FINISH_LIST(sb_host_vec_free, out, rows, r);
}

int sb_store_find_host(sb_store *s, const char *id, sb_host *out, sb_err *err) {
    LOCK(s);
    int r = find_host_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err) {
    if ((!host->name || host->name_len == 0) || !sbj_is_object(host->capabilities))
        return sb_fail(err, SB_ERR_VALIDATION, "Host name and object capabilities are required");
    char *id = sb_str_empty(host->id) ? sb_uuid_v4() : sb_strdup(host->id);
    char *token = sb_str_empty(host->agent_token) ? new_agent_token() : sb_strdup(host->agent_token);
    char *token_hash = sb_sha256_hex(token, strlen(token));
    const char *profile_id = host->profile_id ? host->profile_id : "default";
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO hosts "
                                   "(id, name, agent_token, capabilities, profile_id, wg_address, "
                                   "wg_public_key, wg_endpoint, clash_api, clash_secret, last_seen, "
                                   "singbox_state, enabled, created_at, updated_at, agent_token_hash) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                                   "?13, datetime('now'), datetime('now'), ?14)",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        int bound = sbq_bind_text_n(st, 2, host->name, host->name_len, err);
        sbq_bind_text(st, 3, token);
        if (bound == 0) bound = bind_dump(st, 4, host->capabilities, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 5, profile_id,
            host->profile_id ? host->profile_id_len : strlen("default"), err);
        if (bound == 0) bound = sbq_bind_text_n(st, 6, host->wg_address, host->wg_address_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 7, host->wg_public_key, host->wg_public_key_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 8, host->wg_endpoint, host->wg_endpoint_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 9, host->clash_api, host->clash_api_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 10, host->clash_secret, host->clash_secret_len, err);
        sbq_bind_text(st, 11, host->last_seen);
        sbq_bind_text(st, 12, host->singbox_state);
        sbq_bind_bool(st, 13, host->enabled);
        sbq_bind_text(st, 14, token_hash);
        if (exec_bound(st, bound, err) == 0) rc = reload_host(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    free(token_hash);
    free(token);
    return rc;
}

int sb_store_update_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err) {
    if (sb_str_empty(host->id) || (!host->name || host->name_len == 0) || !sbj_is_object(host->capabilities))
        return sb_fail(err, SB_ERR_VALIDATION, "Host id, name, and object capabilities are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE hosts SET name = ?1, capabilities = ?2, profile_id = ?3, "
                                   "wg_address = ?4, wg_public_key = ?5, wg_endpoint = ?6, "
                                   "clash_api = ?7, clash_secret = ?8, enabled = ?9, "
                                   "updated_at = datetime('now') WHERE id = ?10",
                                   err);
    if (st) {
        int bound = sbq_bind_text_n(st, 1, host->name, host->name_len, err);
        if (bound == 0) bound = bind_dump(st, 2, host->capabilities, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 3, host->profile_id, host->profile_id_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 4, host->wg_address, host->wg_address_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 5, host->wg_public_key, host->wg_public_key_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 6, host->wg_endpoint, host->wg_endpoint_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 7, host->clash_api, host->clash_api_len, err);
        if (bound == 0) bound = sbq_bind_text_n(st, 8, host->clash_secret, host->clash_secret_len, err);
        sbq_bind_bool(st, 9, host->enabled);
        sbq_bind_text(st, 10, host->id);
        if (exec_bound(st, bound, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
            else
                rc = reload_host(h, host->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_host(sb_store *s, const char *id, sb_err *err) {
    if (sb_streq(id, "self")) return sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the built-in self host");
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM host_outbounds WHERE host_id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM hosts WHERE id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

char *sb_store_save_diagnostic_report(sb_store *s, const char *host_id, const sbj *report,
                                      sb_err *err) {
    if (!sbj_is_object(report)) {
        sb_fail(err, SB_ERR_VALIDATION, "Diagnostic report must be a JSON object");
        return NULL;
    }
    const char *reason = NULL, *app_version = NULL, *core_version = NULL;
    if (jv_str(report, "reason", "manual", &reason, err) ||
        jv_str(report, "app_version", "", &app_version, err) ||
        jv_str(report, "core_version", "", &core_version, err))
        return NULL;
    char *id = sb_uuid_v4();
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        int r = host_exists(h, host_id, err);
        if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT INTO diagnostic_reports "
                                       "(id, host_id, reason, app_version, core_version, payload, created_at) "
                                       "VALUES (?1, ?2, ?3, ?4, ?5, ?6, "
                                       "strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                                       err);
        if (st) {
            sbq_bind_text(st, 1, id);
            sbq_bind_text(st, 2, S(host_id));
            int bound = sbq_bind_text_n(st, 3, reason,
                sbj_has(report, "reason") ? sbj_get(report, "reason")->v.str.len : strlen(reason), err);
            if (bound == 0) bound = sbq_bind_text_n(st, 4, app_version,
                sbj_has(report, "app_version") ? sbj_get(report, "app_version")->v.str.len : strlen(app_version), err);
            if (bound == 0) bound = sbq_bind_text_n(st, 5, core_version,
                sbj_has(report, "core_version") ? sbj_get(report, "core_version")->v.str.len : strlen(core_version), err);
            if (bound == 0) bound = bind_dump(st, 6, report, err);
            rc = exec_bound(st, bound, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "DELETE FROM diagnostic_reports WHERE host_id = ?1 AND id NOT IN "
                                       "(SELECT id FROM diagnostic_reports WHERE host_id = ?1 "
                                       "ORDER BY created_at DESC, rowid DESC LIMIT 20)",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    if (rc != 0) {
        free(id);
        return NULL;
    }
    return id;
}

sbj *sb_store_list_diagnostic_reports(sb_store *s, const char *host_id, size_t limit, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    sbj *reports = NULL;
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "SELECT id, reason, app_version, core_version, payload, created_at "
                                   "FROM diagnostic_reports WHERE host_id = ?1 "
                                   "ORDER BY created_at DESC, rowid DESC LIMIT ?2",
                                   err);
        if (q.rc != 0) goto done;
        const char *hid = S(host_id);
        sbq_stmt_bind_text_n(&q, 1, hid, strlen(hid), err);
        if (q.rc == 0) sbq_bind_int(q.st, 2, (int64_t)(limit < 20U ? limit : 20U));
        reports = sbj_array();
        while ((r = sbq_stmt_step_row(&q, err)) == 1) {
            char *payload = sbq_text(q.st, 4);
            sbj *report = sbj_parse(payload, strlen(payload), NULL, 0);
            free(payload);
            if (!sbj_is_object(report)) {
                sbj_free(report);
                report = sbj_object();
                sbj_set(report, "logs", sbj_array());
            }
            sbj_set(report, "report_id", sbj_str_take(sbq_text(q.st, 0)));
            sbj_set(report, "reason", sbj_strn((const char *)sqlite3_column_text(q.st, 1),
                                                        (size_t)sqlite3_column_bytes(q.st, 1)));
            sbj_set(report, "app_version", sbj_strn((const char *)sqlite3_column_text(q.st, 2),
                                                        (size_t)sqlite3_column_bytes(q.st, 2)));
            sbj_set(report, "core_version", sbj_strn((const char *)sqlite3_column_text(q.st, 3),
                                                        (size_t)sqlite3_column_bytes(q.st, 3)));
            sbj_set(report, "created_at", sbj_str_take(sbq_text(q.st, 5)));
            sbj_arr_push(reports, report);
        }
    }
    if (r < 0) {
        sbj_free(reports);
        reports = NULL;
    }
done:
    UNLOCK(s);
    return reports;
}

int sb_store_host_outbounds(sb_store *s, const char *host_id, sb_strvec *out, sb_err *err) {
    sb_strvec rows = {0};
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) r = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r == 1) {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "SELECT node_id FROM host_outbounds WHERE host_id = ?1 "
                                   "ORDER BY node_id",
                                   err);
        const char *hid = S(host_id);
        sbq_stmt_bind_text_n(&q, 1, hid, strlen(hid), err);
        while ((r = sbq_stmt_step_row(&q, err)) == 1)
            sb_strvec_push_take(&rows, sbq_text(q.st, 0));
    }
    UNLOCK(s);
    FINISH_LIST(sb_strvec_free, out, rows, r);
}

int sb_store_set_host_outbounds(sb_store *s, const char *host_id, const sb_strvec *node_ids,
                                sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM host_outbounds WHERE host_id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    for (size_t i = 0; rc == 0 && node_ids && i < node_ids->len; ++i) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT OR IGNORE INTO host_outbounds (host_id, node_id) "
                                       "VALUES (?1, ?2)",
                                       err);
        if (!st) {
            rc = -1;
            break;
        }
        sbq_bind_text(st, 1, S(host_id));
        sbq_bind_text(st, 2, node_ids->items[i]);
        rc = exec_stmt(st, err);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
done:
    UNLOCK(s);
    return rc;
}

char *sb_store_rotate_agent_token(sb_store *s, const char *host_id, sb_err *err) {
    char *token = new_agent_token();
    char *token_hash = sb_sha256_hex(token, strlen(token));
    const char *binds[] = {token, S(host_id), token_hash};
    int changed = exec_changes(s,
                     "UPDATE hosts SET agent_token = ?1, agent_token_hash = ?3, "
                     "updated_at = datetime('now') WHERE id = ?2",
                     "Host not found", err, 3, binds);
    free(token_hash);
    if (changed != 0) {
        free(token);
        return NULL;
    }
    return token;
}
