#include "sb/config_sync.h"
#include "sb/config_etag.h"
#include "sqlite_internal.h"
#include <time.h>

#define CONFIG_SYNC_LIMIT (1024u * 1024u)

sbj *sb_config_merge_patch(const sbj *base, const sbj *patch) {
    if (!sbj_is_object(patch)) return sbj_clone(patch);
    sbj *out = sbj_object();
    if (sbj_is_object(base)) {
        for (size_t i = 0; i < base->v.obj.len; ++i) {
            const char *key = base->v.obj.keys[i]; size_t len = base->v.obj.key_lens[i];
            if (!sbj_getn(patch, key, len)) sbj_setn(out, key, len, sbj_clone(base->v.obj.vals[i]));
        }
    }
    for (size_t i = 0; i < patch->v.obj.len; ++i) {
        const char *key = patch->v.obj.keys[i]; size_t len = patch->v.obj.key_lens[i];
        const sbj *value = patch->v.obj.vals[i];
        if (!sbj_is_null(value)) sbj_setn(out, key, len, sb_config_merge_patch(sbj_getn(base, key, len), value));
    }
    return out;
}

sbj *sb_config_merge_diff(const sbj *base, const sbj *effective) {
    if (!sbj_is_object(effective)) return sbj_clone(effective);
    sbj *out = sbj_object();
    if (sbj_is_object(base)) {
        for (size_t i = 0; i < base->v.obj.len; ++i) {
            const char *key = base->v.obj.keys[i]; size_t len = base->v.obj.key_lens[i];
            if (!sbj_getn(effective, key, len)) sbj_setn(out, key, len, sbj_null());
        }
    }
    for (size_t i = 0; i < effective->v.obj.len; ++i) {
        const char *key = effective->v.obj.keys[i]; size_t len = effective->v.obj.key_lens[i];
        const sbj *before = sbj_getn(base, key, len), *after = effective->v.obj.vals[i];
        if (!before || !sbj_equal(before, after)) sbj_setn(out, key, len, sb_config_merge_diff(before, after));
    }
    return out;
}

static int64_t source_locked(sqlite3 *db, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "SELECT version FROM config_sync_clock WHERE id=1", err);
    if (!st) return -1;
    int row = sbq_step_row(st, err); int64_t version = row == 1 ? sbq_int(st, 0) : -1;
    sqlite3_finalize(st);
    if (!row) sb_fail(err, SB_ERR_GENERIC, "Configuration clock is missing");
    return version;
}
int64_t sb_config_sync_source_version(sb_database *db, sb_err *err) {
    sb_database_lock(db); int64_t version = source_locked(sb_database_handle(db), err);
    sb_database_unlock(db); return version;
}
int sb_config_sync_exists(sb_database *database, const char *host_id, sb_err *err) {
    sb_database_lock(database);
    sqlite3_stmt *st = sbq_prepare(sb_database_handle(database), "SELECT 1 FROM device_config_sync WHERE host_id=?", err);
    int row = -1;
    if (st) { sbq_bind_text(st, 1, host_id); row = sbq_step_row(st, err); sqlite3_finalize(st); }
    sb_database_unlock(database); return row;
}

static int64_t next_version(int64_t previous) {
    struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    int64_t ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    return ms > previous ? ms : previous + 1;
}
static int valid_object(const sbj *value, const char *name, sb_err *err) {
    if (!sbj_is_object(value)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a JSON object", name);
    if (sbj_validate_utf8(value, err) != 0) return -1;
    char *text = sbj_dump(value, -1); bool bounded = strlen(text) <= CONFIG_SYNC_LIMIT; free(text);
    return bounded ? 0 : sb_fail(err, SB_ERR_VALIDATION, "%s exceeds 1 MiB", name);
}
static sbj *state_locked(sqlite3 *db, const char *host_id, const sbj *base,
                          int64_t source_version, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "SELECT patch_version,patch,agent_settings,agent_settings_initialized FROM device_config_sync WHERE host_id=?", err);
    if (!st) return NULL;
    sbq_bind_text(st, 1, host_id); int row = sbq_step_row(st, err); sbj *out = NULL;
    if (row == 1) {
        sbj *patch = sbj_parse_cstr((const char *)sqlite3_column_text(st, 1));
        sbj *settings = sbj_parse_cstr((const char *)sqlite3_column_text(st, 2));
        if (sbj_is_object(patch) && sbj_is_object(settings)) {
            out = sbj_object(); sbj_set_int(out, "base_version", source_version);
            sbj_set_int(out, "patch_version", sbq_int(st, 0));
            sbj_set_bool(out, "agent_settings_initialized", sbq_int(st, 3) != 0);
            sbj_set(out, "base", sbj_clone(base)); sbj_set(out, "config", sb_config_merge_patch(base, patch));
            sbj_set(out, "patch", patch); sbj_set(out, "agent_settings", settings);
        } else { sbj_free(patch); sbj_free(settings); sb_fail(err, SB_ERR_GENERIC, "Stored device configuration is invalid"); }
    } else if (!row) sb_fail(err, SB_ERR_NOT_FOUND, "Device configuration not initialized");
    sqlite3_finalize(st); return out;
}
static int snapshot_locked(sqlite3 *db, int64_t version, sb_err *err) {
    int64_t current = source_locked(db, err);
    if (current < 0) return -1;
    return current == version ? 0 : sb_fail(err, SB_ERR_CONFLICT, "Base configuration changed; fetch before saving");
}

sbj *sb_config_sync_get(sb_database *database, const char *host_id, const sbj *base,
                        const sbj *legacy, int64_t source_version, sb_err *err) {
    if (valid_object(base, "Base configuration", err) != 0) return NULL;
    sbj *patch = legacy ? sb_config_merge_diff(base, legacy) : sbj_object();
    sbj *roundtrip = sb_config_merge_patch(base, patch);
    if (legacy && !sbj_equal(roundtrip, legacy)) {
        sbj_free(roundtrip); sbj_free(patch);
        sb_fail(err, SB_ERR_CONFLICT, "Legacy configuration contains literal null members that cannot be migrated losslessly"); return NULL;
    }
    sbj_free(roundtrip);
    char *text = sbj_dump(patch, -1); bool changed = sbj_obj_len(patch) > 0; sbj_free(patch);
    char *base_text = sbj_dump(base, -1), *fingerprint = sb_config_etag("", base_text, ""); free(base_text);
    if (!fingerprint) { free(text); sb_fail(err, SB_ERR_GENERIC, "Base configuration hash failed"); return NULL; }
    sbj *result = NULL; sqlite3 *db = sb_database_handle(database); sb_database_lock(database);
    if (sbq_begin(db, err) != 0) goto done;
    if (snapshot_locked(db, source_version, err) != 0) goto rollback;
    sqlite3_stmt *st = sbq_prepare(db, "INSERT OR IGNORE INTO device_config_sync(host_id,patch_version,patch) VALUES(?,?,?)", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, host_id); sbq_bind_int(st, 2, changed ? next_version(source_version) : 0); sbq_bind_text(st, 3, text);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st); if (rc != 0) goto rollback;
    /* Runtime/platform inputs (for example an expiring WireGuard peer) can
     * change rendered content without a SQL update. Advance the clock once
     * when this device observes such a change. SQL-triggered fanout already
     * advanced it and must not be advanced again for each device. */
    st = sbq_prepare(db, "SELECT base_fingerprint,base_seen_version FROM device_config_sync WHERE host_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, host_id); int row = sbq_step_row(st, err);
    const char *previous = row == 1 ? (const char *)sqlite3_column_text(st, 0) : "";
    bool untracked_change = row == 1 && *previous && strcmp(previous, fingerprint) != 0 && sbq_int(st, 1) == source_version;
    sqlite3_finalize(st); if (row < 0) goto rollback;
    if (untracked_change) {
        source_version = next_version(source_version);
        st = sbq_prepare(db, "UPDATE config_sync_clock SET version=? WHERE id=1", err);
        if (!st) goto rollback;
        sbq_bind_int(st, 1, source_version); rc = sbq_step_done(st, err); sqlite3_finalize(st); if (rc != 0) goto rollback;
    }
    st = sbq_prepare(db, "UPDATE device_config_sync SET base_fingerprint=?,base_seen_version=? WHERE host_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, fingerprint); sbq_bind_int(st, 2, source_version); sbq_bind_text(st, 3, host_id);
    rc = sbq_step_done(st, err); sqlite3_finalize(st); if (rc != 0) goto rollback;
    result = state_locked(db, host_id, base, source_version, err);
    if (!result || sbq_commit(db, err) != 0) { sbj_free(result); result = NULL; goto rollback; }
    goto done;
rollback: sbq_rollback(db);
done: sb_database_unlock(database); free(text); free(fingerprint); return result;
}

sbj *sb_config_sync_put(sb_database *database, const char *host_id, const sbj *base,
                        int64_t source_version, int64_t expected_base_version,
                        int64_t expected_patch_version, const sbj *patch,
                        const sbj *agent_settings, sb_err *err) {
    if (valid_object(patch, "Patch", err) != 0 || valid_object(agent_settings, "Agent settings", err) != 0) return NULL;
    if (source_version != expected_base_version || expected_patch_version < 0 || expected_patch_version == INT64_MAX) {
        sb_fail(err, SB_ERR_CONFLICT, "Configuration version changed; fetch before saving"); return NULL;
    }
    char *patch_text = sbj_dump(patch, -1), *settings_text = sbj_dump(agent_settings, -1);
    sbj *result = NULL; sqlite3 *db = sb_database_handle(database); sb_database_lock(database);
    if (sbq_begin(db, err) != 0) goto done;
    if (snapshot_locked(db, source_version, err) != 0) goto rollback;
    sqlite3_stmt *st = sbq_prepare(db, "SELECT patch_version,patch,agent_settings,agent_settings_initialized FROM device_config_sync WHERE host_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, host_id); int row = sbq_step_row(st, err);
    int64_t previous = row == 1 ? sbq_int(st, 0) : -1;
    bool same = row == 1 && sbq_int(st, 3) != 0 && strcmp((const char *)sqlite3_column_text(st, 1), patch_text) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 2), settings_text) == 0;
    sqlite3_finalize(st); if (row < 0) goto rollback;
    if (previous != expected_patch_version) { sb_fail(err, SB_ERR_CONFLICT, "Device patch changed; fetch before saving"); goto rollback; }
    if (!same) {
        st = sbq_prepare(db, "UPDATE device_config_sync SET patch_version=?,patch=?,agent_settings=?,agent_settings_initialized=1 WHERE host_id=?", err);
        if (!st) goto rollback;
        sbq_bind_int(st, 1, next_version(previous > source_version ? previous : source_version));
        sbq_bind_text(st, 2, patch_text); sbq_bind_text(st, 3, settings_text); sbq_bind_text(st, 4, host_id);
        int rc = sbq_step_done(st, err); sqlite3_finalize(st); if (rc != 0) goto rollback;
    }
    result = state_locked(db, host_id, base, source_version, err);
    if (!result || sbq_commit(db, err) != 0) { sbj_free(result); result = NULL; goto rollback; }
    goto done;
rollback: sbq_rollback(db);
done: sb_database_unlock(database); free(patch_text); free(settings_text); return result;
}
