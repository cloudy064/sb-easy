#include "sb/proxy_users.h"
#include "sqlite_internal.h"
#include "proxy_clock_internal.h"
#include <arpa/inet.h>
#include <ctype.h>

#define SAFE_INTEGER INT64_C(9007199254740991)
#define GRANT_CHUNK INT64_C(67108864)
#define LEASE_SECONDS 60
#define METHOD "2022-blake3-aes-128-gcm"
#define RUNTIME_FRESH_SECONDS 180

static bool text_ok(const sbj *v, size_t limit, bool identifier) {
    if (!sbj_is_string(v) || !v->v.str.len || v->v.str.len > limit || sbj_validate_utf8(v, NULL))
        return false;
    for (size_t i = 0; i < v->v.str.len; ++i) {
        unsigned char c = (unsigned char)v->v.str.ptr[i];
        if (c < 32 || c == 127 ||
            (identifier && !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                             c == '-' || c == '_')))
            return false;
    }
    return true;
}
static bool number_ok(const sbj *body, const char *key, int64_t low, int64_t high) {
    const sbj *v = sbj_get(body, key);
    return v && v->type == SBJ_INT && v->v.i >= low && v->v.i <= high;
}
static int compare_identifiers(const void *left, const void *right) {
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}
static char *new_secret(bool base64, sb_err *err) {
    unsigned char raw[32];
    size_t size = base64 ? 16 : 32;
    if (sb_random_bytes(raw, size)) {
        sb_fail(err, SB_ERR_GENERIC, "Secure random generation failed");
        return NULL;
    }
    return base64 ? sb_base64_encode(raw, size) : sb_base64url_encode(raw, size);
}
static int begin(sqlite3 *db, sb_err *err) { return sbq_exec(db, "BEGIN IMMEDIATE", err); }
static int run_id(sqlite3 *db, const char *sql, const char *id, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, sql, err);
    if (!st)
        return -1;
    sbq_bind_text(st, 1, id);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    return rc;
}
static const char *column(sqlite3_stmt *st, int i) { return (const char *)sqlite3_column_text(st, i); }
int sb_proxy_runtime_report(sb_database *database, const char *host_id, const sbj *capabilities, int64_t now,
                            sb_err *err) {
    bool supported = false;
    if (!sbj_is_null(capabilities)) {
        if (!sbj_is_array(capabilities) || sbj_arr_len(capabilities) > 64)
            return sb_fail(err, SB_ERR_VALIDATION,
                           "Runtime capabilities must be an array of at most 64 identifiers");
        for (size_t i = 0; i < sbj_arr_len(capabilities); ++i) {
            const sbj *capability = sbj_arr_at(capabilities, i);
            if (!text_ok(capability, 128, true))
                return sb_fail(err, SB_ERR_VALIDATION, "Invalid runtime capability");
            if (sbj_string_is(capability, "proxy_users_v1"))
                supported = true;
        }
    }
    sb_database_lock(database);
    sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(
        db,
        "INSERT INTO proxy_runtime_reports(host_id,supported,observed_at) SELECT id,?,? FROM hosts WHERE "
        "id=? AND enabled=1 "
        "ON CONFLICT(host_id) DO UPDATE SET supported=excluded.supported,observed_at=excluded.observed_at",
        err);
    int result = -1;
    if (st) {
        sbq_bind_bool(st, 1, supported);
        sbq_bind_int(st, 2, now);
        sbq_bind_text(st, 3, host_id);
        result = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (!result && sqlite3_changes(db) != 1)
            result = sb_fail(err, SB_ERR_AUTH, "Runtime host is unknown or disabled");
    }
    sb_database_unlock(database);
    return result;
}
static int runtime_ready(sqlite3 *db, const char *host, int64_t now, int64_t *seen, sb_err *err) {
    sqlite3_stmt *st =
        sbq_prepare(db, "SELECT supported,observed_at FROM proxy_runtime_reports WHERE host_id=?", err);
    if (!st)
        return -1;
    sbq_bind_text(st, 1, host);
    int row = sbq_step_row(st, err), ready = 0;
    if (row == 1) {
        int64_t timestamp = sbq_int(st, 1);
        if (seen)
            *seen = timestamp;
        ready = sbq_int(st, 0) && timestamp >= now - RUNTIME_FRESH_SECONDS && timestamp <= now;
    }
    sqlite3_finalize(st);
    return row < 0 ? -1 : ready;
}
static sbj *devices_locked(sqlite3 *db, const char *id, bool policy, int64_t now, sb_err *err) {
    sqlite3_stmt *st =
        sbq_prepare(db,
                    policy ? "SELECT id,name,enabled,created_at,password,expires_at FROM proxy_devices "
                             "WHERE user_id=? AND enabled=1 AND (expires_at=0 OR expires_at>?) ORDER BY id"
                           : "SELECT id,name,enabled,created_at,'',expires_at FROM proxy_devices WHERE "
                             "user_id=? ORDER BY created_at,id",
                    err);
    if (!st)
        return NULL;
    sbq_bind_text(st, 1, id);
    if (policy)
        sbq_bind_int(st, 2, now);
    sbj *out = sbj_array();
    int row;
    while ((row = sbq_step_row(st, err)) == 1) {
        sbj *d = sbj_object();
        sbj_set_str(d, "id", column(st, 0));
        sbj_set_int(d, "expires_at", sbq_int(st, 5));
        if (policy)
            sbj_set_str(d, "password", column(st, 4));
        else {
            sbj_set_str(d, "name", column(st, 1));
            sbj_set_bool(d, "enabled", sbq_int(st, 2));
            sbj_set_int(d, "created_at", sbq_int(st, 3));
        }
        sbj_arr_push(out, d);
    }
    sqlite3_finalize(st);
    if (row < 0) {
        sbj_free(out);
        return NULL;
    }
    return out;
}
static sbj *user_locked(sb_database *database, const char *id, sb_err *err) {
    sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st =
        sbq_prepare(db,
                    "SELECT "
                    "u.id,u.name,u.enabled,u.quota_bytes,u.expires_at,u.max_devices,u.epoch,u.not_before,u."
                    "created_at,u.updated_at,COALESCE((SELECT SUM(grant_bytes) FROM proxy_leases WHERE "
                    "user_id=u.id AND epoch=u.epoch),0),COALESCE((SELECT SUM(used_bytes) FROM proxy_leases "
                    "WHERE user_id=u.id AND epoch=u.epoch),0) FROM proxy_users u WHERE id=? AND deleted=0",
                    err);
    if (!st)
        return NULL;
    sbq_bind_text(st, 1, id);
    int row = sbq_step_row(st, err);
    sbj *out = NULL;
    if (row == 1) {
        out = sbj_object();
        sbj_set_str(out, "id", column(st, 0));
        sbj_set_str(out, "name", column(st, 1));
        sbj_set_bool(out, "enabled", sbq_int(st, 2));
        const char *names[] = {"quota_bytes", "expires_at", "max_devices",     "epoch",         "not_before",
                               "created_at",  "updated_at", "allocated_bytes", "reported_bytes"};
        for (size_t i = 0; i < sizeof names / sizeof *names; ++i)
            sbj_set_int(out, names[i], sbq_int(st, (int)i + 3));
        int64_t wait_ms = sb_proxy_clock_wait_ms(database, id, sbq_int(st, 6));
        sbj_set_int(out, "lease_wait_seconds", (wait_ms + 999) / 1000);
    } else if (!row)
        sb_fail(err, SB_ERR_NOT_FOUND, "Proxy user not found");
    sqlite3_finalize(st);
    if (!out)
        return NULL;
    st = sbq_prepare(db, "SELECT host_id FROM proxy_user_nodes WHERE user_id=? ORDER BY host_id", err);
    if (!st) {
        sbj_free(out);
        return NULL;
    }
    sbq_bind_text(st, 1, id);
    sbj *hosts = sbj_array();
    while ((row = sbq_step_row(st, err)) == 1)
        sbj_arr_push(hosts, sbj_str(column(st, 0)));
    sqlite3_finalize(st);
    sbj_set(out, "host_ids", hosts);
    sbj *devices = row >= 0 ? devices_locked(db, id, false, 0, err) : NULL;
    if (!devices) {
        sbj_free(out);
        return NULL;
    }
    sbj_set(out, "devices", devices);
    return out;
}
sbj *sb_proxy_user_get(sb_database *database, const char *id, sb_err *err) {
    sb_database_lock(database);
    sbj *out = user_locked(database, id, err);
    sb_database_unlock(database);
    return out;
}
sbj *sb_proxy_users_list(sb_database *database, sb_err *err) {
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    sqlite3_stmt *st =
        sbq_prepare(db, "SELECT id FROM proxy_users WHERE deleted=0 ORDER BY created_at,id", err);
    sbj *out = sbj_array();
    int row = -1;
    if (st) {
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *u = user_locked(database, column(st, 0), err);
            if (!u) {
                row = -1;
                break;
            }
            sbj_arr_push(out, u);
        }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database);
    if (row < 0) {
        sbj_free(out);
        return NULL;
    }
    return out;
}
sbj *sb_proxy_user_save(sb_database *database, const char *id, const sbj *body, int64_t now, sb_err *err) {
    const sbj *hosts = sbj_get(body, "host_ids");
    if (!sbj_is_object(body) || sbj_obj_len(body) != 6 || !text_ok(sbj_get(body, "name"), 128, false) ||
        !sbj_is_bool(sbj_get(body, "enabled")) || !number_ok(body, "quota_bytes", 0, SAFE_INTEGER) ||
        !number_ok(body, "expires_at", 0, 4102444800LL) || !number_ok(body, "max_devices", 1, 32) ||
        !sbj_is_array(hosts) || sbj_arr_len(hosts) > 32) {
        sb_fail(
            err, SB_ERR_VALIDATION,
            "Proxy user requires name, enabled, quota_bytes, expires_at, max_devices and up to 32 host_ids");
        return NULL;
    }
    for (size_t i = 0; i < sbj_arr_len(hosts); ++i) {
        if (!text_ok(sbj_arr_at(hosts, i), 128, true)) {
            sb_fail(err, SB_ERR_VALIDATION, "Invalid proxy host ID");
            return NULL;
        }
        for (size_t j = 0; j < i; ++j)
            if (sbj_equal(sbj_arr_at(hosts, i), sbj_arr_at(hosts, j))) {
                sb_fail(err, SB_ERR_VALIDATION, "Duplicate proxy host ID");
                return NULL;
            }
    }
    char *generated = id ? NULL : sb_uuid_v4();
    if (!id)
        id = generated;
    sbj *out = NULL;
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    if (begin(db, err))
        goto done;
    if (!generated) {
        sbj *old = user_locked(database, id, err);
        if (!old)
            goto rollback;
        int active = 0;
        const sbj *devices = sbj_get(old, "devices");
        for (size_t i = 0; i < sbj_arr_len(devices); ++i)
            if (sbj_get_bool(sbj_arr_at(devices, i), "enabled", false) &&
                (!sbj_get_int(sbj_arr_at(devices, i), "expires_at", 0) ||
                 sbj_get_int(sbj_arr_at(devices, i), "expires_at", 0) > now))
                ++active;
        int64_t quota = sbj_get_int(body, "quota_bytes", 0);
        bool invalid = (quota && quota < sbj_get_int(old, "allocated_bytes", 0)) ||
                       active > sbj_get_int(body, "max_devices", 1);
        sbj_free(old);
        if (invalid) {
            sb_fail(err, SB_ERR_CONFLICT,
                    "Quota cannot fall below allocated bytes; reset the period first. Revoke devices before "
                    "reducing the device limit.");
            goto rollback;
        }
    } else {
        sqlite3_stmt *count = sbq_prepare(db, "SELECT COUNT(*) FROM proxy_users WHERE deleted=0", err);
        if (!count)
            goto rollback;
        int row = sbq_step_row(count, err);
        bool room = row == 1 && sbq_int(count, 0) < 256;
        sqlite3_finalize(count);
        if (!room) {
            if (row >= 0)
                sb_fail(err, SB_ERR_CONFLICT, "At most 256 active proxy users are supported");
            goto rollback;
        }
    }
    for (size_t i = 0; i < sbj_arr_len(hosts); ++i) {
        sqlite3_stmt *check = sbq_prepare(db, "SELECT 1 FROM proxy_ingress_nodes WHERE host_id=?", err);
        if (!check)
            goto rollback;
        sbq_bind_text(check, 1, sbj_as_str(sbj_arr_at(hosts, i), ""));
        int row = sbq_step_row(check, err);
        sqlite3_finalize(check);
        if (row != 1) {
            if (!row)
                sb_fail(err, SB_ERR_VALIDATION, "Configure the proxy ingress node before binding a user");
            goto rollback;
        }
    }
    sqlite3_stmt *st = sbq_prepare(
        db,
        "INSERT INTO proxy_users(id,name,enabled,quota_bytes,expires_at,max_devices,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
        "name=excluded.name,enabled=excluded.enabled,quota_bytes=excluded.quota_bytes,expires_at=excluded."
        "expires_at,max_devices=excluded.max_devices,updated_at=excluded.updated_at",
        err);
    if (!st)
        goto rollback;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, sbj_get_str(body, "name", ""));
    sbq_bind_bool(st, 3, sbj_get_bool(body, "enabled", true));
    sbq_bind_int(st, 4, sbj_get_int(body, "quota_bytes", 0));
    sbq_bind_int(st, 5, sbj_get_int(body, "expires_at", 0));
    sbq_bind_int(st, 6, sbj_get_int(body, "max_devices", 3));
    sbq_bind_int(st, 7, now);
    sbq_bind_int(st, 8, now);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc)
        goto rollback;
    if (run_id(db, "DELETE FROM proxy_user_nodes WHERE user_id=?", id, err))
        goto rollback;
    for (size_t i = 0; i < sbj_arr_len(hosts); ++i) {
        st = sbq_prepare(db, "INSERT INTO proxy_user_nodes(user_id,host_id) VALUES(?,?)", err);
        if (!st)
            goto rollback;
        sbq_bind_text(st, 1, id);
        sbq_bind_text(st, 2, sbj_as_str(sbj_arr_at(hosts, i), ""));
        rc = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (rc)
            goto rollback;
    }
    out = user_locked(database, id, err);
    if (!out || sbq_commit(db, err)) {
        sbj_free(out);
        out = NULL;
        goto rollback;
    }
    goto done;
rollback:
    sbq_rollback(db);
done:
    sb_database_unlock(database);
    free(generated);
    return out;
}
int sb_proxy_user_remove(sb_database *database, const char *id, int64_t now, sb_err *err) {
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    int rc = -1;
    if (begin(db, err))
        goto done;
    sqlite3_stmt *st = sbq_prepare(
        db,
        "UPDATE proxy_users SET enabled=0,deleted=1,claim_hash=NULL,updated_at=? WHERE id=? AND deleted=0",
        err);
    if (!st)
        goto rollback;
    sbq_bind_int(st, 1, now);
    sbq_bind_text(st, 2, id);
    rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc)
        goto rollback;
    if (sqlite3_changes(db) != 1) {
        rc = sb_fail(err, SB_ERR_NOT_FOUND, "Proxy user not found");
        goto rollback;
    }
    rc = run_id(db, "UPDATE proxy_devices SET enabled=0 WHERE user_id=?", id, err);
    if (rc || (rc = sbq_commit(db, err)))
        goto rollback;
    goto done;
rollback:
    sbq_rollback(db);
    rc = -1;
done:
    sb_database_unlock(database);
    return rc;
}
sbj *sb_proxy_user_reset(sb_database *database, const char *id, int64_t now, sb_err *err) {
    if (now < 1 || now > 4102444740LL) { sb_fail(err, SB_ERR_VALIDATION, "Invalid proxy reset time"); return NULL; }
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    sbj *out = NULL;
    if (begin(db, err))
        goto done;
    sqlite3_stmt *st =
        sbq_prepare(db,
                    "UPDATE proxy_users SET epoch=epoch+1,not_before=MAX(?,COALESCE((SELECT MAX(expires_at) "
                    "FROM proxy_leases WHERE user_id=proxy_users.id),0)),updated_at=? WHERE id=? AND "
                    "deleted=0 AND epoch<9007199254740991",
                    err);
    if (!st)
        goto rollback;
    sbq_bind_int(st, 1, now + LEASE_SECONDS);
    sbq_bind_int(st, 2, now);
    sbq_bind_text(st, 3, id);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc)
        goto rollback;
    if (sqlite3_changes(db) != 1) {
        sb_fail(err, SB_ERR_NOT_FOUND, "Proxy user not found");
        goto rollback;
    }
    out = user_locked(database, id, err);
    if (out) {
        sb_proxy_clock_reset_epoch(database, id, sbj_get_int(out, "epoch", 0));
        sbj_set_int(out, "lease_wait_seconds", LEASE_SECONDS);
    }
    if (!out || sbq_commit(db, err)) {
        sbj_free(out);
        out = NULL;
        goto rollback;
    }
    goto done;
rollback:
    sbq_rollback(db);
done:
    sb_database_unlock(database);
    return out;
}
sbj *sb_proxy_claim_rotate(sb_database *database, const char *id, int64_t now, sb_err *err) {
    char *token = new_secret(false, err);
    if (!token)
        return NULL;
    char *hash = sb_sha256_hex(token, strlen(token));
    sbj *out = NULL;
    sb_database_lock(database);
    sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st =
        sbq_prepare(db, "UPDATE proxy_users SET claim_hash=?,updated_at=? WHERE id=? AND deleted=0", err);
    if (st) {
        sbq_bind_text(st, 1, hash);
        sbq_bind_int(st, 2, now);
        sbq_bind_text(st, 3, id);
        int rc = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (!rc && sqlite3_changes(db) == 1) {
            out = sbj_object();
            sbj_set_str(out, "claim_token", token);
        } else if (!rc)
            sb_fail(err, SB_ERR_NOT_FOUND, "Proxy user not found");
    }
    sb_database_unlock(database);
    free(hash);
    free(token);
    return out;
}
char *sb_proxy_claim_resolve(sb_database *database, const char *token, int64_t now, sb_err *err) {
    if (!token || strlen(token) != 43) {
        sb_fail(err, SB_ERR_AUTH, "Invalid proxy claim token");
        return NULL;
    }
    char *hash = sb_sha256_hex(token, strlen(token)), *out = NULL;
    sb_database_lock(database);
    sqlite3_stmt *st = sbq_prepare(sb_database_handle(database),
                                   "SELECT id FROM proxy_users WHERE claim_hash=? AND deleted=0 AND "
                                   "enabled=1 AND (expires_at=0 OR expires_at>?)",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, hash);
        sbq_bind_int(st, 2, now);
        int row = sbq_step_row(st, err);
        if (row == 1)
            out = sbq_text(st, 0);
        else if (!row)
            sb_fail(err, SB_ERR_AUTH, "Invalid or expired proxy claim token");
        sqlite3_finalize(st);
    }
    sb_database_unlock(database);
    free(hash);
    return out;
}
sbj *sb_proxy_device_create(sb_database *database, const char *user_id, const sbj *body, int64_t now,
                            sb_err *err) {
    bool has_expiry = sbj_has(body, "expires_at");
    if (!sbj_is_object(body) || sbj_obj_len(body) != (has_expiry ? 2U : 1U) ||
        !text_ok(sbj_get(body, "name"), 128, false) ||
        (has_expiry && !number_ok(body, "expires_at", 0, 4102444800LL)) ||
        (sbj_get_int(body, "expires_at", 0) && sbj_get_int(body, "expires_at", 0) <= now)) {
        sb_fail(err, SB_ERR_VALIDATION,
                "Device requires a name and an optional future expires_at (0 means no device expiry)");
        return NULL;
    }
    char *id = sb_uuid_v4(), *password = new_secret(true, err), *token = new_secret(false, err),
         *hash = token ? sb_sha256_hex(token, strlen(token)) : NULL;
    sbj *out = NULL;
    if (!id || !password || !token)
        goto cleanup;
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    if (begin(db, err))
        goto done;
    sqlite3_stmt *st =
        sbq_prepare(db,
                    "SELECT max_devices,(SELECT COUNT(*) FROM proxy_devices WHERE user_id=u.id AND enabled=1 "
                    "AND (expires_at=0 OR expires_at>?)) FROM "
                    "proxy_users u WHERE id=? AND enabled=1 AND deleted=0 AND (expires_at=0 OR expires_at>?)",
                    err);
    if (!st)
        goto rollback;
    sbq_bind_int(st, 1, now);
    sbq_bind_text(st, 2, user_id);
    sbq_bind_int(st, 3, now);
    int row = sbq_step_row(st, err);
    bool room = row == 1 && sbq_int(st, 1) < sbq_int(st, 0);
    sqlite3_finalize(st);
    if (!room) {
        if (row >= 0)
            sb_fail(err, row ? SB_ERR_CONFLICT : SB_ERR_FORBIDDEN,
                    row ? "Proxy device limit reached" : "Proxy user is disabled or expired");
        goto rollback;
    }
    st = sbq_prepare(db,
                     "INSERT INTO proxy_devices(id,user_id,name,password,token_hash,created_at,expires_at) "
                     "VALUES(?,?,?,?,?,?,?)",
                     err);
    if (!st)
        goto rollback;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, user_id);
    sbq_bind_text(st, 3, sbj_get_str(body, "name", ""));
    sbq_bind_text(st, 4, password);
    sbq_bind_text(st, 5, hash);
    sbq_bind_int(st, 6, now);
    sbq_bind_int(st, 7, sbj_get_int(body, "expires_at", 0));
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc || sbq_commit(db, err))
        goto rollback;
    out = sbj_object();
    sbj_set_str(out, "id", id);
    sbj_set_str(out, "name", sbj_get_str(body, "name", ""));
    sbj_set_str(out, "subscription_token", token);
    sbj_set_int(out, "expires_at", sbj_get_int(body, "expires_at", 0));
    goto done;
rollback:
    sbq_rollback(db);
done:
    sb_database_unlock(database);
cleanup:
    free(id);
    free(password);
    free(token);
    free(hash);
    return out;
}
int sb_proxy_device_revoke(sb_database *database, const char *user_id, const char *device_id, int64_t now,
                           sb_err *err) {
    sb_database_lock(database);
    sqlite3 *db = sb_database_handle(database);
    int rc = -1;
    sqlite3_stmt *st =
        sbq_prepare(db, "UPDATE proxy_devices SET enabled=0,revoked_at=? WHERE id=? AND user_id=?", err);
    if (st) {
        sbq_bind_int(st, 1, now);
        sbq_bind_text(st, 2, device_id);
        sbq_bind_text(st, 3, user_id);
        rc = sbq_step_done(st, err);
        sqlite3_finalize(st);
        if (!rc && sqlite3_changes(db) != 1)
            rc = sb_fail(err, SB_ERR_NOT_FOUND, "Proxy device not found");
    }
    sb_database_unlock(database);
    return rc;
}
static bool server_name(const sbj *v) {
    if (!text_ok(v, 253, false))
        return false;
    unsigned char address[16];
    const char *s = v->v.str.ptr;
    if (inet_pton(AF_INET, s, address) == 1 || inet_pton(AF_INET6, s, address) == 1)
        return true;
    size_t label = 0;
    bool last_dash = false;
    for (size_t i = 0; i < v->v.str.len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (!label || last_dash)
                return false;
            label = 0;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') ||
            (!label && c == '-') || ++label > 63)
            return false;
        last_dash = c == '-';
    }
    return label && !last_dash;
}
static sbj *node_locked(sqlite3 *db, const char *host_id, bool policy, int64_t now, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db,
                                   "SELECT host_id,enabled,server,listen,listen_port,server_key,updated_at "
                                   "FROM proxy_ingress_nodes WHERE host_id=?",
                                   err);
    if (!st)
        return NULL;
    sbq_bind_text(st, 1, host_id);
    int row = sbq_step_row(st, err);
    sbj *out = NULL;
    if (row == 1) {
        out = sbj_object();
        sbj_set_str(out, "listen", column(st, 3));
        sbj_set_int(out, "listen_port", sbq_int(st, 4));
        if (policy) {
            sbj_set_str(out, "method", METHOD);
            sbj_set_str(out, "password", column(st, 5));
        } else {
            sbj_set_str(out, "host_id", column(st, 0));
            sbj_set_bool(out, "enabled", sbq_int(st, 1));
            sbj_set_str(out, "server", column(st, 2));
            sbj_set_int(out, "updated_at", sbq_int(st, 6));
        }
    } else if (!row)
        sb_fail(err, SB_ERR_NOT_FOUND, "Proxy ingress node not found");
    sqlite3_finalize(st);
    if (out && !policy) {
        int64_t seen = 0;
        int ready = runtime_ready(db, host_id, now, &seen, err);
        if (ready < 0) {
            sbj_free(out);
            return NULL;
        }
        sbj_set_bool(out, "runtime_supported", ready == 1);
        sbj_set_int(out, "runtime_seen_at", seen);
    }
    return out;
}
sbj *sb_proxy_ingress_list(sb_database *database, sb_err *err) {
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    sbj *out = sbj_array();
    int row = -1;
    sqlite3_stmt *st = sbq_prepare(db, "SELECT host_id FROM proxy_ingress_nodes ORDER BY host_id", err);
    if (st) {
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *node = node_locked(db, column(st, 0), false, sb_unix_now(), err);
            if (!node) {
                row = -1;
                break;
            }
            sbj_arr_push(out, node);
        }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database);
    if (row < 0) {
        sbj_free(out);
        return NULL;
    }
    return out;
}
sbj *sb_proxy_ingress_save(sb_database *database, const char *host_id, const sbj *body, int64_t now,
                           sb_err *err) {
    unsigned char address[16];
    const sbj *listen = sbj_get(body, "listen");
    if (!sbj_is_object(body) || sbj_obj_len(body) != 4 || !sbj_is_bool(sbj_get(body, "enabled")) ||
        !server_name(sbj_get(body, "server")) || !text_ok(listen, 64, false) ||
        (inet_pton(AF_INET, listen->v.str.ptr, address) != 1 &&
         inet_pton(AF_INET6, listen->v.str.ptr, address) != 1) ||
        !number_ok(body, "listen_port", 1, 65535)) {
        sb_fail(
            err, SB_ERR_VALIDATION,
            "Ingress requires enabled, a public server hostname/IP, a listen IP and listen_port 1..65535");
        return NULL;
    }
    char *key = new_secret(true, err);
    if (!key)
        return NULL;
    sbj *out = NULL;
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    if (begin(db, err))
        goto done;
    sqlite3_stmt *st = sbq_prepare(db, "SELECT 1 FROM hosts WHERE id=? AND enabled=1", err);
    if (!st)
        goto rollback;
    sbq_bind_text(st, 1, host_id);
    int row = sbq_step_row(st, err);
    sqlite3_finalize(st);
    if (row != 1) {
        if (!row)
            sb_fail(err, SB_ERR_VALIDATION, "Ingress requires an enabled host");
        goto rollback;
    }
    if (sbj_get_bool(body, "enabled", false)) {
        int ready = runtime_ready(db, host_id, now, NULL, err);
        if (ready != 1) {
            if (!ready)
                sb_fail(err, SB_ERR_CONFLICT,
                        "Host must report proxy_users_v1 support within the last 180 seconds before enabling "
                        "ingress");
            goto rollback;
        }
    }
    st = sbq_prepare(
        db,
        "INSERT INTO proxy_ingress_nodes(host_id,enabled,server,listen,listen_port,server_key,updated_at) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET "
        "enabled=excluded.enabled,server=excluded.server,listen=excluded.listen,listen_port=excluded.listen_"
        "port,updated_at=excluded.updated_at",
        err);
    if (!st)
        goto rollback;
    sbq_bind_text(st, 1, host_id);
    sbq_bind_bool(st, 2, sbj_get_bool(body, "enabled", false));
    sbq_bind_text(st, 3, sbj_get_str(body, "server", ""));
    sbq_bind_text(st, 4, listen->v.str.ptr);
    sbq_bind_int(st, 5, sbj_get_int(body, "listen_port", 0));
    sbq_bind_text(st, 6, key);
    sbq_bind_int(st, 7, now);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc)
        goto rollback;
    out = node_locked(db, host_id, false, now, err);
    if (!out || sbq_commit(db, err)) {
        sbj_free(out);
        out = NULL;
        goto rollback;
    }
    goto done;
rollback:
    sbq_rollback(db);
done:
    sb_database_unlock(database);
    free(key);
    return out;
}
sbj *sb_proxy_subscription(sb_database *database, const char *token, int64_t now, sb_err *err) {
    if (!token || strlen(token) != 43) {
        sb_fail(err, SB_ERR_AUTH, "Invalid device subscription token");
        return NULL;
    }
    char *hash = sb_sha256_hex(token, strlen(token)), *user = NULL, *device_key = NULL;
    sbj *out = NULL;
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    sqlite3_stmt *st = sbq_prepare(
        db,
        "SELECT d.user_id,d.password FROM proxy_devices d JOIN proxy_users u ON "
        "u.id=d.user_id WHERE d.token_hash=? AND d.enabled=1 AND u.enabled=1 AND "
        "u.deleted=0 AND (u.expires_at=0 OR u.expires_at>?) AND (d.expires_at=0 OR d.expires_at>?)",
        err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, hash);
    sbq_bind_int(st, 2, now);
    sbq_bind_int(st, 3, now);
    int row = sbq_step_row(st, err);
    if (row == 1) {
        user = sbq_text(st, 0);
        device_key = sbq_text(st, 1);
    } else if (!row)
        sb_fail(err, SB_ERR_AUTH, "Invalid, revoked or expired device subscription");
    sqlite3_finalize(st);
    if (!user)
        goto done;
    st = sbq_prepare(db,
                     "SELECT n.host_id,n.server,n.listen_port,n.server_key FROM proxy_user_nodes b JOIN "
                     "proxy_ingress_nodes n ON n.host_id=b.host_id JOIN hosts h ON h.id=n.host_id "
                     "JOIN proxy_runtime_reports r ON r.host_id=n.host_id WHERE b.user_id=? AND n.enabled=1 "
                     "AND h.enabled=1 "
                     "AND r.supported=1 AND r.observed_at BETWEEN ? AND ? ORDER BY n.host_id",
                     err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, user);
    sbq_bind_int(st, 2, now - RUNTIME_FRESH_SECONDS);
    sbq_bind_int(st, 3, now);
    out = sbj_object();
    sbj *nodes = sbj_array();
    sbj_set(out, "outbounds", nodes);
    while ((row = sbq_step_row(st, err)) == 1) {
        sbj *node = sbj_object();
        sbj_set_str(node, "type", "shadowsocks");
        sbj_set_str(node, "tag", column(st, 0));
        sbj_set_str(node, "server", column(st, 1));
        sbj_set_int(node, "server_port", sbq_int(st, 2));
        sbj_set_str(node, "method", METHOD);
        char *password = sb_asprintf("%s:%s", column(st, 3), device_key);
        sbj_set_str(node, "password", password);
        free(password);
        sbj_arr_push(nodes, node);
    }
    sqlite3_finalize(st);
    if (row < 0) {
        sbj_free(out);
        out = NULL;
    }
done:
    sb_database_unlock(database);
    free(hash);
    free(user);
    free(device_key);
    return out;
}
static int report_locked(sqlite3 *db, const char *host, const char *boot, const sbj *report, int64_t now,
                         sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(
        db, "SELECT grant_bytes,used_bytes FROM proxy_leases WHERE id=? AND host_id=? AND boot_id=?", err);
    if (!st)
        return -1;
    const char *id = sbj_get_str(report, "lease_id", "");
    int64_t used = sbj_get_int(report, "used_bytes", 0);
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, host);
    sbq_bind_text(st, 3, boot);
    int row = sbq_step_row(st, err);
    bool valid = row == 1 && used >= sbq_int(st, 1) && used <= sbq_int(st, 0);
    sqlite3_finalize(st);
    if (!valid)
        return row < 0 ? -1
                       : sb_fail(err, SB_ERR_CONFLICT,
                                 "Unknown lease, counter rollback or usage exceeding the grant");
    st = sbq_prepare(db, "UPDATE proxy_leases SET used_bytes=?,updated_at=? WHERE id=?", err);
    if (!st)
        return -1;
    sbq_bind_int(st, 1, used);
    sbq_bind_int(st, 2, now);
    sbq_bind_text(st, 3, id);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    return rc;
}
static sbj *lease_locked(sqlite3 *db, const char *host, const char *boot, const char *user, int64_t epoch,
                         int64_t quota, int64_t expiry, int64_t now, sb_err *err) {
    sbj *devices = devices_locked(db, user, true, now, err);
    if (!devices)
        return NULL;
    if (!sbj_arr_len(devices)) {
        sbj_free(devices);
        return sbj_null();
    }
    char *id = NULL;
    int64_t grant = 0, used = 0, allocated = 0, hosts = 1;
    sbj *out = NULL;
    sqlite3_stmt *st = sbq_prepare(db,
                                   "SELECT id,grant_bytes,used_bytes FROM proxy_leases WHERE user_id=? AND "
                                   "host_id=? AND boot_id=? AND epoch=?",
                                   err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, user);
    sbq_bind_text(st, 2, host);
    sbq_bind_text(st, 3, boot);
    sbq_bind_int(st, 4, epoch);
    int row = sbq_step_row(st, err);
    if (row == 1) {
        id = sbq_text(st, 0);
        grant = sbq_int(st, 1);
        used = sbq_int(st, 2);
    }
    sqlite3_finalize(st);
    if (row < 0)
        goto done;
    st = sbq_prepare(db, "SELECT COALESCE(SUM(grant_bytes),0) FROM proxy_leases WHERE user_id=? AND epoch=?",
                     err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, user);
    sbq_bind_int(st, 2, epoch);
    row = sbq_step_row(st, err);
    if (row == 1)
        allocated = sbq_int(st, 0);
    sqlite3_finalize(st);
    if (row != 1)
        goto done;
    st = sbq_prepare(
        db,
        "SELECT COUNT(*) FROM proxy_user_nodes b JOIN proxy_ingress_nodes n ON n.host_id=b.host_id JOIN "
        "hosts h ON h.id=n.host_id JOIN proxy_runtime_reports r ON r.host_id=n.host_id "
        "WHERE b.user_id=? AND n.enabled=1 AND h.enabled=1 AND r.supported=1 AND r.observed_at BETWEEN ? AND "
        "?",
        err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, user);
    sbq_bind_int(st, 2, now - RUNTIME_FRESH_SECONDS);
    sbq_bind_int(st, 3, now);
    row = sbq_step_row(st, err);
    if (row == 1)
        hosts = sbq_int(st, 0);
    sqlite3_finalize(st);
    if (row != 1 || hosts < 1)
        goto done;
    int64_t available = (quota ? quota : SAFE_INTEGER) - allocated;
    int64_t threshold = grant / 2;
    if (threshold > GRANT_CHUNK / 2)
        threshold = GRANT_CHUNK / 2;
    if ((grant == 0 || grant - used <= threshold) && available > 0) {
        int64_t add = available / hosts + (available % hosts ? 1 : 0);
        if (add > GRANT_CHUNK)
            add = GRANT_CHUNK;
        grant += add;
    }
    if (grant <= used) {
        out = sbj_null();
        goto done;
    }
    if (!id)
        id = sb_uuid_v4();
    if (!id)
        goto done;
    int64_t until = now + LEASE_SECONDS;
    if (expiry && expiry < until)
        until = expiry;
    st = sbq_prepare(
        db,
        "INSERT INTO "
        "proxy_leases(id,user_id,host_id,boot_id,epoch,grant_bytes,used_bytes,expires_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,host_id,boot_id,epoch) DO UPDATE SET "
        "grant_bytes=excluded.grant_bytes,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
        err);
    if (!st)
        goto done;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, user);
    sbq_bind_text(st, 3, host);
    sbq_bind_text(st, 4, boot);
    sbq_bind_int(st, 5, epoch);
    sbq_bind_int(st, 6, grant);
    sbq_bind_int(st, 7, used);
    sbq_bind_int(st, 8, until);
    sbq_bind_int(st, 9, now);
    int rc = sbq_step_done(st, err);
    sqlite3_finalize(st);
    if (rc)
        goto done;
    out = sbj_object();
    sbj_set_str(out, "id", user);
    sbj_set_int(out, "epoch", epoch);
    sbj *lease = sbj_object();
    sbj_set_str(lease, "id", id);
    sbj_set_int(lease, "grant_bytes", grant);
    sbj_set_int(lease, "used_bytes", used);
    sbj_set_int(lease, "expires_at", until);
    sbj_set(out, "lease", lease);
    sbj_set(out, "devices", devices);
    devices = NULL;
done:
    free(id);
    sbj_free(devices);
    return out;
}
/* Shape, range and duplicate checks for an exchange request; 0 or -1 (err set). */
static int validate_exchange_request(const sbj *request, int64_t now, sb_err *err) {
    const sbj *reports = sbj_get(request, "reports");
    if (!sbj_is_object(request) || sbj_obj_len(request) != 4 || !number_ok(request, "version", 1, 1) ||
        !text_ok(sbj_get(request, "boot_id"), 128, true) ||
        !number_ok(request, "request_seq", 1, SAFE_INTEGER) || !sbj_is_array(reports) ||
        sbj_arr_len(reports) > 4096 || now < 1 || now > 4102444740LL)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid proxy lease exchange");
    for (size_t i = 0; i < sbj_arr_len(reports); ++i) {
        const sbj *r = sbj_arr_at(reports, i);
        if (!sbj_is_object(r) || sbj_obj_len(r) != 2 || !text_ok(sbj_get(r, "lease_id"), 128, true) ||
            !number_ok(r, "used_bytes", 0, SAFE_INTEGER))
            return sb_fail(err, SB_ERR_VALIDATION, "Invalid proxy lease report");
    }
    size_t report_count = sbj_arr_len(reports);
    if (report_count > 1) {
        const char **ids = sb_xmalloc(report_count * sizeof *ids);
        for (size_t i = 0; i < report_count; ++i)
            ids[i] = sbj_get_str(sbj_arr_at(reports, i), "lease_id", "");
        qsort(ids, report_count, sizeof *ids, compare_identifiers);
        bool duplicate = false;
        for (size_t i = 1; i < report_count; ++i)
            if (!strcmp(ids[i - 1], ids[i])) {
                duplicate = true;
                break;
            }
        free(ids);
        if (duplicate) return sb_fail(err, SB_ERR_VALIDATION, "Duplicate proxy lease report");
    }
    return 0;
}

/* Upserts the stored response for (host, boot) so a retry of the same request
 * replays it; 0 or -1 (err set). Caller holds the database lock. */
static int save_lease_session(sqlite3 *db, const char *host, const char *boot, int64_t seq,
                              const char *hash, const sbj *response, int64_t now, sb_err *err) {
    char *encoded = sbj_dump(response, -1);
    int rc = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(
            db,
            "INSERT INTO proxy_lease_sessions(host_id,boot_id,request_seq,request_hash,response,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(host_id,boot_id) DO UPDATE SET "
            "request_seq=excluded.request_seq,request_hash=excluded.request_hash,response=excluded.response,"
            "updated_at=excluded.updated_at",
            err);
        if (q.rc == 0) {
            sbq_bind_text(q.st, 1, host);
            sbq_bind_text(q.st, 2, boot);
            sbq_bind_int(q.st, 3, seq);
            sbq_bind_text(q.st, 4, hash);
            sbq_bind_text(q.st, 5, encoded);
            sbq_bind_int(q.st, 6, now);
            rc = sbq_step_done(q.st, err);
        }
    }
    free(encoded);
    return rc;
}

sbj *sb_proxy_lease_exchange(sb_database *database, const char *host, const sbj *request, int64_t now,
                             sb_err *err) {
    if (validate_exchange_request(request, now, err) != 0) return NULL;
    const sbj *reports = sbj_get(request, "reports");
    const char *boot = sbj_get_str(request, "boot_id", "");
    int64_t seq = sbj_get_int(request, "request_seq", 0);
    char *encoded = sbj_dump(request, -1), *hash = sb_sha256_hex(encoded, strlen(encoded));
    free(encoded);
    sbj *out = NULL;
    sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    if (begin(db, err))
        goto done;
    int row = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(db, "SELECT 1 FROM hosts WHERE id=? AND enabled=1", err);
        if (q.rc == 0) {
            sbq_bind_text(q.st, 1, host);
            row = sbq_step_row(q.st, err);
        }
    }
    if (row != 1) {
        if (!row)
            sb_fail(err, SB_ERR_AUTH, "Proxy lease host is unknown or disabled");
        goto rollback;
    }
    bool replay = false, conflict = false;
    {
        SBQ_AUTO q = sbq_stmt_open(
            db,
            "SELECT request_seq,request_hash,response FROM proxy_lease_sessions WHERE host_id=? AND boot_id=?",
            err);
        if (q.rc != 0)
            goto rollback;
        sbq_bind_text(q.st, 1, host);
        sbq_bind_text(q.st, 2, boot);
        row = sbq_step_row(q.st, err);
        if (row == 1) {
            int64_t previous = sbq_int(q.st, 0);
            replay = seq == previous && sb_streq(hash, column(q.st, 1));
            conflict = seq != previous + 1 && !replay;
            if (replay)
                out = sbj_parse(column(q.st, 2), (size_t)sqlite3_column_bytes(q.st, 2), NULL, 0);
        } else if (!row)
            conflict = seq != 1;
    }
    if (row < 0)
        goto rollback;
    if (conflict) {
        sb_fail(err, SB_ERR_CONFLICT,
                "Proxy lease sequence changed; retry the same request or use the next sequence");
        goto rollback;
    }
    if (replay) {
        if (!out) {
            sb_fail(err, SB_ERR_GENERIC, "Stored proxy lease snapshot is invalid");
            goto rollback;
        }
        if (sbq_commit(db, err)) {
            sbj_free(out);
            out = NULL;
            goto rollback;
        }
        goto done;
    }
    for (size_t i = 0; i < sbj_arr_len(reports); ++i)
        if (report_locked(db, host, boot, sbj_arr_at(reports, i), now, err))
            goto rollback;
    out = sbj_object();
    sbj_set_int(out, "version", 1);
    sbj_set_str(out, "host_id", host);
    sbj_set_str(out, "boot_id", boot);
    sbj_set_int(out, "request_seq", seq);
    sbj_set_int(out, "generated_at", now);
    sbj_set_int(out, "expires_at", now + LEASE_SECONDS);
    sbj_set(out, "node", sbj_null());
    sbj *users = sbj_array();
    sbj_set(out, "users", users);
    {
        SBQ_AUTO q = sbq_stmt_open(db, "SELECT 1 FROM proxy_ingress_nodes WHERE host_id=? AND enabled=1", err);
        if (q.rc != 0)
            goto rollback;
        sbq_bind_text(q.st, 1, host);
        row = sbq_step_row(q.st, err);
    }
    if (row < 0)
        goto rollback;
    int ready = runtime_ready(db, host, now, NULL, err);
    if (ready < 0)
        goto rollback;
    if (row == 1 && ready == 1) {
        sbj *node = node_locked(db, host, true, now, err);
        if (!node)
            goto rollback;
        sbj_set(out, "node", node);
        {
            SBQ_AUTO q = sbq_stmt_open(
                db,
                "SELECT u.id,u.epoch,u.quota_bytes,u.expires_at,u.not_before FROM proxy_users u JOIN proxy_user_nodes b ON "
                "b.user_id=u.id WHERE b.host_id=? AND u.enabled=1 AND u.deleted=0 AND "
                "(u.expires_at=0 OR u.expires_at>?) ORDER BY u.id",
                err);
            if (q.rc != 0)
                goto rollback;
            sbq_bind_text(q.st, 1, host);
            sbq_bind_int(q.st, 2, now);
            while ((row = sbq_step_row(q.st, err)) == 1) {
                int64_t wait_ms = sb_proxy_clock_wait_ms(database, column(q.st, 0), sbq_int(q.st, 1));
                if (wait_ms > 0 || sbq_int(q.st, 4) > now) continue;
                sbj *u = lease_locked(db, host, boot, column(q.st, 0), sbq_int(q.st, 1), sbq_int(q.st, 2),
                                      sbq_int(q.st, 3), now, err);
                if (!u) {
                    row = -1;
                    break;
                }
                if (sbj_is_null(u))
                    sbj_free(u);
                else
                    sbj_arr_push(users, u);
            }
        }
        if (row < 0)
            goto rollback;
    }
    if (save_lease_session(db, host, boot, seq, hash, out, now, err) || sbq_commit(db, err))
        goto rollback;
    goto done;
rollback:
    sbq_rollback(db);
    sbj_free(out);
    out = NULL;
done:
    sb_database_unlock(database);
    free(hash);
    return out;
}
