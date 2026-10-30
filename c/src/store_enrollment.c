/* Agent enrollment and token lookup. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

int sb_store_create_agent_enrollment(sb_store *s, const char *host_id, sb_agent_enrollment *out,
                                     sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int found = sb_store_find_host(s, host_id, &host, err);
    bool usable = found == 1 && !sb_streq(host.id, "self") && host.enabled;
    sb_host_free(&host);
    if (found < 0) return -1;
    if (found == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (!usable) return sb_fail(err, SB_ERR_VALIDATION, "Enrollment requires an enabled remote host");

    char *id = sb_uuid_v4();
    char *code = new_agent_token();
    char *code_hash = sb_sha256_hex(code, strlen(code));
    char *expires_at = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE agent_enrollments SET expires_at = datetime('now') "
                                       "WHERE host_id = ?1 AND redeemed_at IS NULL",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT INTO agent_enrollments "
                                       "(id, host_id, code_hash, expires_at) "
                                       "VALUES (?1, ?2, ?3, datetime('now', '+10 minutes'))",
                                       err);
        if (st) {
            sbq_bind_text(st, 1, id);
            sbq_bind_text(st, 2, S(host_id));
            sbq_bind_text(st, 3, code_hash);
            rc = exec_stmt(st, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) {
        int r = -1;
        {
            SBQ_AUTO q = sbq_stmt_open(h, "SELECT expires_at FROM agent_enrollments WHERE id = ?1", err);
            if (q.rc == 0) {
                sbq_stmt_bind_text_n(&q, 1, id, strlen(id), err);
                r = sbq_stmt_step_row(&q, err);
                if (r == 1) expires_at = sbq_text(q.st, 0);
                if (r == 0) sb_fail(err, SB_ERR_GENERIC, "Created enrollment could not be read");
            }
        }
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    free(code_hash);
    if (rc != 0) {
        free(id);
        free(code);
        free(expires_at);
        return -1;
    }
    sb_agent_enrollment_free(out);
    out->id = id;
    out->host_id = sb_strdup(S(host_id));
    out->code = code;
    out->expires_at = expires_at;
    return 0;
}

int sb_store_redeem_agent_enrollment(sb_store *s, const char *code, const sbj *device,
                                     sb_agent_enrollment_result *out, sb_err *err) {
    if (strlen(S(code)) < 32U || !sbj_is_object(device))
        return sb_fail(err, SB_ERR_VALIDATION, "A valid enrollment code and device are required");
    /* These describe local UI features, never server-owned roles or topology. */
    static const char *const feature_keys[] = {
        "interactive_client", "supports_proxy_selection", "supports_local_route_stats",
        "supports_diagnostic_upload"};
    for (size_t i = 0; i < sizeof feature_keys / sizeof *feature_keys; ++i) {
        const sbj *found = sbj_get(device, feature_keys[i]);
        if (found && !sbj_is_bool(found))
            return sb_fail(err, SB_ERR_VALIDATION, "Device capability '%s' must be a boolean",
                           feature_keys[i]);
    }
    char *code_hash = sb_sha256_hex(code, strlen(code));
    sb_agent_enrollment_result result;
    sb_agent_enrollment_result_init(&result);
    char *enrollment_id = NULL;
    sbj *capabilities = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        int r = -1;
        {
            SBQ_AUTO q = sbq_stmt_open(h,
                                       "SELECT e.id, h.id, h.name, h.agent_token, "
                                       "COALESCE(h.profile_id, 'default'), p.name, h.capabilities "
                                       "FROM agent_enrollments e "
                                       "JOIN hosts h ON h.id = e.host_id "
                                       "JOIN config_profiles p ON p.id = COALESCE(h.profile_id, 'default') "
                                       "WHERE e.code_hash = ?1 AND e.redeemed_at IS NULL "
                                       "AND e.expires_at > datetime('now') AND h.enabled = 1",
                                       err);
            if (q.rc == 0) {
                sbq_stmt_bind_text_n(&q, 1, code_hash, strlen(code_hash), err);
                r = sbq_stmt_step_row(&q, err);
                if (r == 0) sb_fail(err, SB_ERR_VALIDATION, "Enrollment code is invalid or expired");
                if (r == 1) {
                    sb_agent_enrollment_result_free(&result);
                    enrollment_id = sbq_text(q.st, 0);
                    result.host_id = sbq_text(q.st, 1);
                    result.host_name = sbq_text(q.st, 2);
                    result.host_name_len = (size_t)sqlite3_column_bytes(q.st, 2);
                    result.agent_token = sbq_text(q.st, 3);
                    result.profile_id = sbq_text(q.st, 4);
                    result.profile_name = sbq_text(q.st, 5);
                    result.profile_name_len = (size_t)sqlite3_column_bytes(q.st, 5);
                    char *caps = sbq_text(q.st, 6);
                    capabilities = parse_object_or_empty(caps);
                    free(caps);
                }
            }
        }
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) {
        /* Enrollment is shared by every managed device. The enrolling runtime may
         * describe its platform and build, but the server must never infer a
         * device kind from the transport used to redeem the code. */
        static const char *const keys[] = {"platform", "app_version", "agent_version",
                                           "core_version", "install_id", "model",
                                           "hostname", "architecture", "os"};
        for (size_t i = 0; i < sizeof keys / sizeof *keys; ++i) {
            const sbj *found = sbj_get(device, keys[i]);
            if (sbj_is_string(found) && found->v.str.len > 0)
                sbj_set(capabilities, keys[i], sbj_clone(found));
        }
        for (size_t i = 0; i < sizeof feature_keys / sizeof *feature_keys; ++i) {
            const sbj *found = sbj_get(device, feature_keys[i]);
            if (found) sbj_set(capabilities, feature_keys[i], sbj_clone(found));
        }
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE agent_enrollments SET redeemed_at = datetime('now') "
                                       "WHERE id = ?1 AND redeemed_at IS NULL",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, enrollment_id), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) != 1)
            rc = sb_fail(err, SB_ERR_CONFLICT, "Enrollment code was already redeemed");
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE hosts SET capabilities = ?1, last_seen = datetime('now'), "
                                       "updated_at = datetime('now') WHERE id = ?2",
                                       err);
        if (st) {
            int bound = bind_dump(st, 1, capabilities, err);
            sbq_bind_text(st, 2, result.host_id);
            rc = exec_bound(st, bound, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    free(code_hash);
    free(enrollment_id);
    sbj_free(capabilities);
    if (rc != 0) {
        sb_agent_enrollment_result_free(&result);
        return -1;
    }
    sb_agent_enrollment_result_free(out);
    *out = result;
    return 0;
}

int sb_store_find_enabled_host_by_token(sb_store *s, const char *token, sb_host *out, sb_err *err) {
    if (sb_str_empty(token)) return 0;
    /* Hash first; plaintext remains a fallback until startup backfill completes. */
    char *token_hash = sb_sha256_hex(token, strlen(token));
    LOCK(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s),
                                   HOST_SELECT " WHERE ((h.agent_token_hash = ?1 AND h.agent_token_hash != '') "
                                               "OR (h.agent_token = ?2 AND h.agent_token != '')) "
                                               "AND h.enabled = 1",
                                   err);
        if (q.rc == 0) {
            sbq_stmt_bind_text_n(&q, 1, token_hash, strlen(token_hash), err);
            sbq_stmt_bind_text_n(&q, 2, token, strlen(token), err);
            r = sbq_stmt_step_row(&q, err);
            if (r == 1) read_host(q.st, out);
        }
    }
    UNLOCK(s);
    free(token_hash);
    return r;
}

int sb_store_touch_host(sb_store *s, const char *host_id, sb_err *err) {
    const char *binds[] = {S(host_id)};
    return exec_changes(s, "UPDATE hosts SET last_seen = datetime('now') WHERE id = ?1",
                        "Host not found", err, 1, binds);
}

int sb_store_update_agent_status(sb_store *s, const char *host_id, const sbj *state, sb_err *err) {
    if (!sbj_is_object(state)) return sb_fail(err, SB_ERR_VALIDATION, "Agent state must be a JSON object");
    char *text = dump_checked(state, err);
    if (!text) return -1;
    const char *binds[] = {text, S(host_id)};
    int rc = exec_changes(s,
                          "UPDATE hosts SET last_seen = datetime('now'), singbox_state = ?1 "
                          "WHERE id = ?2",
                          "Host not found", err, 2, binds);
    free(text);
    return rc;
}
