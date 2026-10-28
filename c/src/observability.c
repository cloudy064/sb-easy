#include "sb/observability.h"
#include "sqlite_internal.h"
#include <openssl/crypto.h>
#include <pthread.h>
#include <time.h>

/* Remain exactly representable in the JSON/browser numeric contract. */
#define MAX_COUNTER INT64_C(9007199254740991)
struct sb_observability {
    sb_database *database;
    pthread_mutex_t mutex;
    pthread_cond_t wakeup;
    pthread_t thread;
    bool running, stopping;
};
static int finish(sqlite3_stmt *st, sb_err *err) {
    if (!st) return -1;
    int rc = sbq_step_done(st, err); sqlite3_finalize(st); return rc;
}
static int64_t saturated_add(int64_t a, int64_t b) { return a > MAX_COUNTER - b ? MAX_COUNTER : a + b; }
static bool valid_time(int64_t now) { return now > 0 && now < INT64_C(253402300800); }
static int ensure_host(sqlite3 *db, const char *host, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "INSERT OR IGNORE INTO observability_hosts(host_id) VALUES(?)", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, host); return finish(st, err);
}
int sb_observability_sample(sb_database *database, const char *host, const sbj *sample, int64_t now, sb_err *err) {
    if (!database || !host || !valid_time(now) || !sbj_is_object(sample))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid telemetry sample");
    const char *fields[] = {"up", "down", "up_total", "down_total", "conn_count"};
    int64_t values[5];
    for (size_t i = 0; i < 5; ++i) {
        const sbj *value = sbj_get(sample, fields[i]);
        if (!sbj_is_integer(value) || (values[i] = sbj_as_int(value, -1)) < 0 || values[i] > MAX_COUNTER)
            return sb_fail(err, SB_ERR_VALIDATION, "Telemetry counters must be nonnegative safe integers");
    }
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database); int rc = -1;
    if (sbq_begin(db, err) != 0) goto done;
    if (ensure_host(db, host, err) != 0) goto rollback;
    sqlite3_stmt *st = sbq_prepare(db, "SELECT sampled_at,up_counter,down_counter,observed_up,observed_down,counter_resets FROM observability_hosts WHERE host_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, host); int row = sbq_step_row(st, err);
    int64_t at = sbq_int(st, 0), up = sbq_int(st, 1), down = sbq_int(st, 2);
    int64_t observed_up = sbq_int(st, 3), observed_down = sbq_int(st, 4), resets = sbq_int(st, 5);
    sqlite3_finalize(st); if (row != 1) goto rollback;
    if (now < at) { rc = sbq_commit(db, err); goto done; }
    int64_t du = at ? (values[2] >= up ? values[2] - up : values[2]) : 0;
    int64_t dd = at ? (values[3] >= down ? values[3] - down : values[3]) : 0;
    int64_t reset = at && (values[2] < up || values[3] < down) ? 1 : 0;
    st = sbq_prepare(db, "UPDATE observability_hosts SET sampled_at=?,up_counter=?,down_counter=?,observed_up=?,observed_down=?,counter_resets=? WHERE host_id=?", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, now); sbq_bind_int(st, 2, values[2]); sbq_bind_int(st, 3, values[3]);
    sbq_bind_int(st, 4, saturated_add(observed_up, du)); sbq_bind_int(st, 5, saturated_add(observed_down, dd));
    sbq_bind_int(st, 6, saturated_add(resets, reset)); sbq_bind_text(st, 7, host);
    if (finish(st, err) != 0) goto rollback;
    st = sbq_prepare(db,
        "INSERT INTO observability_samples(host_id,bucket,samples,up_average,down_average,connections_max,up_bytes,down_bytes,counter_resets) VALUES(?,?,1,?,?,?,?,?,?) "
        "ON CONFLICT(host_id,bucket) DO UPDATE SET "
        "up_average=up_average+(excluded.up_average-up_average)/(samples+1),"
        "down_average=down_average+(excluded.down_average-down_average)/(samples+1),samples=MIN(samples+1,9007199254740991),"
        "connections_max=MAX(connections_max,excluded.connections_max),"
        "up_bytes=MIN(9007199254740991,up_bytes+excluded.up_bytes),down_bytes=MIN(9007199254740991,down_bytes+excluded.down_bytes),"
        "counter_resets=counter_resets+excluded.counter_resets", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, host); sbq_bind_int(st, 2, now / 60 * 60);
    sbq_bind_int(st, 3, values[0]); sbq_bind_int(st, 4, values[1]); sbq_bind_int(st, 5, values[4]);
    sbq_bind_int(st, 6, du); sbq_bind_int(st, 7, dd); sbq_bind_int(st, 8, reset);
    if (finish(st, err) != 0 || sbq_commit(db, err) != 0) goto rollback;
    rc = 0; goto done;
rollback: sbq_rollback(db);
done: sb_database_unlock(database); return rc;
}
int sb_observability_target(sb_database *database, const char *host, const char *etag, int64_t now, sb_err *err) {
    if (!database || !host || !etag || !*etag || strlen(etag) > 256 || !valid_time(now))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid configuration target");
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db, "INSERT INTO observability_hosts(host_id,target_etag,target_since) VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET target_since=CASE WHEN target_etag!=excluded.target_etag THEN excluded.target_since ELSE target_since END,target_etag=excluded.target_etag", err);
    int rc = -1;
    if (st) { sbq_bind_text(st, 1, host); sbq_bind_text(st, 2, etag); sbq_bind_int(st, 3, now); rc = finish(st, err); }
    sb_database_unlock(database); return rc;
}
int sb_observability_status(sb_database *database, const char *host, const sbj *state, int64_t now, sb_err *err) {
    if (!database || !host || !sbj_is_object(state) || !valid_time(now))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid runtime status");
    const char *etag = sbj_get_str(state, "etag", "");
    bool applied = sbj_get_bool(state, "running", false) && *etag && strlen(etag) <= 256 &&
                   !*sbj_get_str(state, "last_error", "");
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database); int rc = -1;
    sqlite3_stmt *st = sbq_prepare(db, "INSERT INTO observability_hosts(host_id,status_at,applied_etag,applied_at) VALUES(?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET status_at=MAX(status_at,excluded.status_at),applied_etag=CASE WHEN ? THEN excluded.applied_etag ELSE applied_etag END,applied_at=CASE WHEN ? THEN excluded.applied_at ELSE applied_at END", err);
    if (st) {
        sbq_bind_text(st, 1, host); sbq_bind_int(st, 2, now); sbq_bind_text(st, 3, applied ? etag : "");
        sbq_bind_int(st, 4, applied ? now : 0); sbq_bind_int(st, 5, applied); sbq_bind_int(st, 6, applied);
        rc = finish(st, err);
    }
    sb_database_unlock(database); return rc;
}
static sbj *settings_locked(sqlite3 *db, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "SELECT retention_days,offline_seconds,drift_seconds,node_latency_ms,metrics_token_hash IS NOT NULL FROM observability_settings WHERE id=1", err);
    if (!st) return NULL;
    sbj *out = NULL;
    if (sbq_step_row(st, err) == 1) {
        out = sbj_object(); const char *keys[] = {"retention_days", "offline_seconds", "drift_seconds", "node_latency_ms"};
        for (int i = 0; i < 4; ++i) sbj_set_int(out, keys[i], sbq_int(st, i));
        sbj_set_bool(out, "metrics_token_configured", sbq_int(st, 4) != 0);
        sbj_set_int(out, "sample_bucket_seconds", 60); sbj_set_int(out, "evaluation_interval_seconds", 30);
    }
    sqlite3_finalize(st); return out;
}
sbj *sb_observability_settings(sb_database *database, sb_err *err) {
    sb_database_lock(database); sbj *out = settings_locked(sb_database_handle(database), err); sb_database_unlock(database); return out;
}
int sb_observability_configure(sb_database *database, const sbj *settings, sb_err *err) {
    const char *fields[] = {"retention_days", "offline_seconds", "drift_seconds", "node_latency_ms"};
    const int64_t low[] = {1, 30, 30, 1}, high[] = {365, 86400, 86400, 60000}; int64_t v[4];
    for (int i = 0; i < 4; ++i)
        if (!sbj_is_integer(sbj_get(settings, fields[i])) || (v[i] = sbj_get_int(settings, fields[i], -1)) < low[i] || v[i] > high[i])
            return sb_fail(err, SB_ERR_VALIDATION, "Invalid observability setting: %s", fields[i]);
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db, "UPDATE observability_settings SET retention_days=?,offline_seconds=?,drift_seconds=?,node_latency_ms=? WHERE id=1", err);
    int rc = -1;
    if (st) { for (int i = 0; i < 4; ++i) sbq_bind_int(st, i + 1, v[i]); rc = finish(st, err); }
    sb_database_unlock(database); return rc;
}
/* Single active event per kind/resource. Acknowledgement does not suppress
 * recovery or a later recurrence, which receives a new event ID. */
static int alert_locked(sqlite3 *db, const char *kind, const char *resource, const char *host,
                         bool active, int64_t now, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, active ?
        "INSERT INTO observability_alerts(kind,resource_id,host_id,opened_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(kind,resource_id) WHERE resolved_at IS NULL DO UPDATE SET updated_at=excluded.updated_at" :
        "UPDATE observability_alerts SET resolved_at=?4,updated_at=?5 WHERE kind=?1 AND resource_id=?2 AND resolved_at IS NULL", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, kind); sbq_bind_text(st, 2, resource); sbq_bind_text(st, 3, host);
    sbq_bind_int(st, 4, now); sbq_bind_int(st, 5, now); return finish(st, err);
}
int sb_observability_evaluate(sb_database *database, int64_t now, sb_err *err) {
    if (!database || !valid_time(now)) return sb_fail(err, SB_ERR_VALIDATION, "Invalid monitor time");
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database); int rc = -1;
    if (sbq_begin(db, err) != 0) goto done;
    sbj *settings = settings_locked(db, err); if (!settings) goto rollback;
    int64_t retention = sbj_get_int(settings, "retention_days", 30) * 86400;
    int64_t offline = sbj_get_int(settings, "offline_seconds", 180), drift = sbj_get_int(settings, "drift_seconds", 300);
    int64_t latency = sbj_get_int(settings, "node_latency_ms", 5000); sbj_free(settings);
    sqlite3_stmt *st = sbq_prepare(db,
        "SELECT h.id,h.enabled,COALESCE(o.status_at,0),CAST(strftime('%s',h.created_at) AS INTEGER),"
        "COALESCE(o.target_etag,''),COALESCE(o.applied_etag,''),COALESCE(o.target_since,0),"
        "CASE WHEN json_valid(h.singbox_state) THEN COALESCE(json_extract(h.singbox_state,'$.last_error'),'') ELSE '' END "
        "FROM hosts h LEFT JOIN observability_hosts o ON o.host_id=h.id", err);
    if (!st) goto rollback;
    int row;
    while ((row = sbq_step_row(st, err)) == 1) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        bool enabled = sbq_int(st, 1) != 0;
        int64_t seen = sbq_int(st, 2), created = sbq_int(st, 3), target_since = sbq_int(st, 6);
        const char *target = (const char *)sqlite3_column_text(st, 4), *applied = (const char *)sqlite3_column_text(st, 5);
        const char *failure = (const char *)sqlite3_column_text(st, 7);
        bool missing = now - (seen ? seen : created) >= offline;
        bool mismatch = *target && strcmp(target, applied) != 0 && target_since && now - target_since >= drift;
        if (alert_locked(db, "device_offline", id, id, enabled && missing && strcmp(id, "self") != 0, now, err) != 0 ||
            alert_locked(db, "config_drift", id, id, enabled && mismatch, now, err) != 0 ||
            alert_locked(db, "config_failure", id, id, enabled && *failure, now, err) != 0) {
            sqlite3_finalize(st); goto rollback;
        }
    }
    sqlite3_finalize(st); if (row < 0) goto rollback;
    st = sbq_prepare(db, "SELECT id,enabled,latency,CAST(strftime('%s',last_latency_test) AS INTEGER) FROM proxy_nodes", err);
    if (!st) goto rollback;
    while ((row = sbq_step_row(st, err)) == 1) {
        const char *id = (const char *)sqlite3_column_text(st, 0); int64_t tested = sbq_int(st, 3);
        bool fresh = sbq_int(st, 1) && tested > 0 && now >= tested && now - tested <= 3600;
        bool failed = sqlite3_column_type(st, 2) == SQLITE_NULL || sqlite3_column_double(st, 2) < 0;
        if (alert_locked(db, "node_unreachable", id, NULL, fresh && failed, now, err) != 0 ||
            alert_locked(db, "node_slow", id, NULL, fresh && !failed && sqlite3_column_double(st, 2) >= latency, now, err) != 0 ||
            alert_locked(db, "node_probe_stale", id, NULL, sbq_int(st, 1) && tested > 0 && now - tested > 3600, now, err) != 0) {
            sqlite3_finalize(st); goto rollback;
        }
    }
    sqlite3_finalize(st); if (row < 0) goto rollback;
    st = sbq_prepare(db, "UPDATE observability_alerts SET resolved_at=?1,updated_at=?1 WHERE resolved_at IS NULL AND host_id IS NULL AND kind IN ('node_unreachable','node_slow','node_probe_stale') AND NOT EXISTS(SELECT 1 FROM proxy_nodes WHERE id=resource_id)", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, now); if (finish(st, err) != 0) goto rollback;
    st = sbq_prepare(db, "DELETE FROM observability_samples WHERE bucket<?", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, now - retention); if (finish(st, err) != 0) goto rollback;
    st = sbq_prepare(db, "DELETE FROM observability_alerts WHERE resolved_at IS NOT NULL AND updated_at<?", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, now - retention); if (finish(st, err) != 0) goto rollback;
    if (sbq_commit(db, err) != 0) goto rollback;
    rc = 0; goto done;
rollback: sbq_rollback(db);
done: sb_database_unlock(database); return rc;
}
sbj *sb_observability_history(sb_database *database, const char *host, int64_t from,
                              int64_t to, int64_t step, sb_err *err) {
    if (!host || !valid_time(from) || !valid_time(to) || to < from || to - from > 366LL * 86400 ||
        (step != 60 && step != 300 && step != 3600 && step != 86400) || (to - from) / step > 2000) {
        sb_fail(err, SB_ERR_VALIDATION, "History requires a range of at most 2000 buckets and a 60/300/3600/86400-second step"); return NULL;
    }
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db,
        "SELECT (bucket/?4)*?4,SUM(samples),SUM(up_average*samples)/SUM(samples),SUM(down_average*samples)/SUM(samples),"
        "MAX(connections_max),MIN(9007199254740991,SUM(CAST(up_bytes AS REAL))),MIN(9007199254740991,SUM(CAST(down_bytes AS REAL))),SUM(counter_resets) "
        "FROM observability_samples WHERE host_id=?1 AND bucket>=?2 AND bucket<=?3 GROUP BY (bucket/?4)*?4 ORDER BY 1", err);
    sbj *out = NULL;
    if (st) {
        sbq_bind_text(st, 1, host); sbq_bind_int(st, 2, from); sbq_bind_int(st, 3, to); sbq_bind_int(st, 4, step);
        out = sbj_array(); int row;
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *sample = sbj_object(); sbj_set_int(sample, "at", sbq_int(st, 0)); sbj_set_int(sample, "samples", sbq_int(st, 1));
            sbj_set(sample, "up_average", sbj_float(sqlite3_column_double(st, 2)));
            sbj_set(sample, "down_average", sbj_float(sqlite3_column_double(st, 3)));
            sbj_set_int(sample, "connections_max", sbq_int(st, 4)); sbj_set_int(sample, "up_bytes", sbq_int(st, 5));
            sbj_set_int(sample, "down_bytes", sbq_int(st, 6)); sbj_set_int(sample, "counter_resets", sbq_int(st, 7));
            sbj_arr_push(out, sample);
        }
        if (row < 0) { sbj_free(out); out = NULL; }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database); return out;
}
sbj *sb_observability_hosts(sb_database *database, int64_t now, sb_err *err) {
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db,
        "SELECT h.id,h.name,h.enabled,h.singbox_state,COALESCE(o.sampled_at,0),COALESCE(o.observed_up,0),COALESCE(o.observed_down,0),"
        "COALESCE(o.counter_resets,0),COALESCE(o.status_at,0),COALESCE(o.target_etag,''),COALESCE(o.applied_etag,''),COALESCE(o.applied_at,0),"
        "COALESCE(s.up_average,0),COALESCE(s.down_average,0),COALESCE(s.connections_max,0),"
        "(SELECT offline_seconds FROM observability_settings WHERE id=1) "
        "FROM hosts h LEFT JOIN observability_hosts o ON o.host_id=h.id LEFT JOIN observability_samples s ON s.host_id=h.id AND s.bucket=(o.sampled_at/60)*60 ORDER BY h.name,h.id", err);
    sbj *out = NULL;
    if (st) {
        out = sbj_array(); int row;
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *item = sbj_object(); char *id = sbq_text(st, 0), *name = sbq_text(st, 1), *state = sbq_text(st, 3);
            sbj *runtime = sbj_parse(state, strlen(state), NULL, 0); free(state);
            sbj_set_str(item, "host_id", id); sbj_set_str(item, "name", name); free(id); free(name);
            sbj_set_bool(item, "enabled", sbq_int(st, 2));
            const char *keys[] = {"sampled_at", "observed_up", "observed_down", "counter_resets", "status_at"};
            for (int i = 0; i < 5; ++i) sbj_set_int(item, keys[i], sbq_int(st, i + 4));
            char *target = sbq_text(st, 9), *applied = sbq_text(st, 10);
            sbj_set_str(item, "target_etag", target); sbj_set_str(item, "applied_etag", applied); free(target); free(applied);
            sbj_set_int(item, "applied_at", sbq_int(st, 11));
            sbj_set(item, "up_average", sbj_float(sqlite3_column_double(st, 12)));
            sbj_set(item, "down_average", sbj_float(sqlite3_column_double(st, 13)));
            sbj_set_int(item, "connections_max", sbq_int(st, 14));
            sbj_set_bool(item, "online", sbq_int(st, 2) && sbq_int(st, 8) > 0 && now - sbq_int(st, 8) < sbq_int(st, 15));
            sbj_set_str(item, "app_version", sbj_get_str(runtime, "app_version", ""));
            sbj_set_str(item, "core_version", sbj_get_str(runtime, "version", ""));
            sbj_set_str(item, "last_error", sbj_get_str(runtime, "last_error", ""));
            sbj_set_bool(item, "running", sbj_get_bool(runtime, "running", false)); sbj_free(runtime);
            sbj_arr_push(out, item);
        }
        if (row < 0) { sbj_free(out); out = NULL; }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database); return out;
}
sbj *sb_observability_alerts(sb_database *database, const char *host, bool active, sb_err *err) {
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db, "SELECT id,kind,resource_id,host_id,opened_at,updated_at,resolved_at,acknowledged_at FROM observability_alerts WHERE (?1 IS NULL OR host_id=?1) AND (?2=0 OR resolved_at IS NULL) ORDER BY opened_at DESC,id DESC LIMIT 500", err);
    sbj *out = NULL;
    if (st) {
        sbq_bind_text(st, 1, host); sbq_bind_int(st, 2, active); out = sbj_array(); int row;
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *item = sbj_object(); sbj_set_int(item, "id", sbq_int(st, 0));
            const char *texts[] = {"kind", "resource_id", "host_id"};
            for (int i = 0; i < 3; ++i) { char *text = sbq_opt_text(st, i + 1); sbj_set(item, texts[i], text ? sbj_str(text) : sbj_null()); free(text); }
            const char *dates[] = {"opened_at", "updated_at", "resolved_at", "acknowledged_at"};
            for (int i = 0; i < 4; ++i) sbj_set(item, dates[i], sqlite3_column_type(st, i + 4) == SQLITE_NULL ? sbj_null() : sbj_int(sbq_int(st, i + 4)));
            sbj_arr_push(out, item);
        }
        if (row < 0) { sbj_free(out); out = NULL; }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database); return out;
}
int sb_observability_ack(sb_database *database, int64_t id, const char *user, sb_err *err) {
    sb_database_lock(database); sqlite3 *db = sb_database_handle(database);
    sqlite3_stmt *st = sbq_prepare(db, "UPDATE observability_alerts SET acknowledged_at=?,acknowledged_by=? WHERE id=? AND resolved_at IS NULL", err);
    int rc = -1;
    if (st) {
        sbq_bind_int(st, 1, sb_unix_now()); sbq_bind_text(st, 2, user); sbq_bind_int(st, 3, id); rc = finish(st, err);
        if (rc == 0 && !sqlite3_changes(db)) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Active alert not found");
    }
    sb_database_unlock(database); return rc;
}
char *sb_observability_rotate_token(sb_database *database, bool revoke, sb_err *err) {
    char *random = revoke ? NULL : sb_random_hex(32);
    if (!revoke && !random) { sb_fail(err, SB_ERR_GENERIC, "Random generation failed"); return NULL; }
    char *token = random ? sb_asprintf("sbm_%s", random) : NULL; free(random);
    char *hash = token ? sb_sha256_hex(token, strlen(token)) : NULL;
    sb_database_lock(database); sqlite3_stmt *st = sbq_prepare(sb_database_handle(database), "UPDATE observability_settings SET metrics_token_hash=? WHERE id=1", err);
    int rc = -1;
    if (st) { sbq_bind_text(st, 1, hash); rc = finish(st, err); }
    sb_database_unlock(database); free(hash);
    if (rc != 0) { free(token); return NULL; }
    return revoke ? sb_strdup("") : token;
}
bool sb_observability_check_token(sb_database *database, const char *token) {
    if (!token || strlen(token) != 68 || strncmp(token, "sbm_", 4) != 0) return false;
    char *hash = sb_sha256_hex(token, strlen(token)); bool valid = false;
    sb_database_lock(database); sqlite3_stmt *st = sbq_prepare(sb_database_handle(database), "SELECT metrics_token_hash FROM observability_settings WHERE id=1", NULL);
    if (st) {
        if (sbq_step_row(st, NULL) == 1) {
            const char *saved = (const char *)sqlite3_column_text(st, 0);
            valid = saved && strlen(saved) == 64 && CRYPTO_memcmp(hash, saved, 64) == 0;
        }
        sqlite3_finalize(st);
    }
    sb_database_unlock(database); free(hash); return valid;
}
static void metric_label(sb_buf *out, const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '\\' || *p == '"') sb_buf_putc(out, '\\');
        if (*p == '\n') sb_buf_puts(out, "\\n");
        else if (*p < 32 || *p == 127) sb_buf_putc(out, '?');
        else sb_buf_putc(out, (char)*p);
    }
}
char *sb_observability_prometheus(sb_database *database, int64_t now, sb_err *err) {
    sbj *hosts = sb_observability_hosts(database, now, err); if (!hosts) return NULL;
    sbj *alerts = sb_observability_alerts(database, NULL, true, err);
    if (!alerts) { sbj_free(hosts); return NULL; }
    sb_buf out = {0};
    sb_buf_puts(&out, "# HELP sb_easy_device_online Recent enabled device status report.\n# TYPE sb_easy_device_online gauge\n"
        "# HELP sb_easy_device_report_timestamp_seconds Last device status receipt.\n# TYPE sb_easy_device_report_timestamp_seconds gauge\n"
        "# HELP sb_easy_traffic_observed_bytes_total Observed counter deltas since monitoring began; first sample is a baseline.\n# TYPE sb_easy_traffic_observed_bytes_total counter\n"
        "# HELP sb_easy_traffic_sample_timestamp_seconds Last telemetry receipt; check freshness before using bucket rates.\n# TYPE sb_easy_traffic_sample_timestamp_seconds gauge\n"
        "# HELP sb_easy_traffic_bytes_per_second Latest sampled minute mean rate.\n# TYPE sb_easy_traffic_bytes_per_second gauge\n"
        "# HELP sb_easy_traffic_counter_resets_total Observed device counter decreases.\n# TYPE sb_easy_traffic_counter_resets_total counter\n"
        "# HELP sb_easy_alert_active Active alert instances.\n# TYPE sb_easy_alert_active gauge\n");
    for (size_t i = 0; i < sbj_arr_len(hosts); ++i) {
        const sbj *host = sbj_arr_at(hosts, i); sb_buf label = {0}; metric_label(&label, sbj_get_str(host, "host_id", ""));
        const char *id = label.p ? label.p : "";
        sb_buf_printf(&out, "sb_easy_device_online{host_id=\"%s\"} %d\n", id, sbj_get_bool(host, "online", false));
        sb_buf_printf(&out, "sb_easy_device_report_timestamp_seconds{host_id=\"%s\"} %lld\n", id, (long long)sbj_get_int(host, "status_at", 0));
        sb_buf_printf(&out, "sb_easy_traffic_sample_timestamp_seconds{host_id=\"%s\"} %lld\n", id, (long long)sbj_get_int(host, "sampled_at", 0));
        sb_buf_printf(&out, "sb_easy_traffic_counter_resets_total{host_id=\"%s\"} %lld\n", id, (long long)sbj_get_int(host, "counter_resets", 0));
        const char *directions[] = {"up", "down"}, *counters[] = {"observed_up", "observed_down"}, *rates[] = {"up_average", "down_average"};
        for (int n = 0; n < 2; ++n) {
            sb_buf_printf(&out, "sb_easy_traffic_observed_bytes_total{host_id=\"%s\",direction=\"%s\"} %lld\n", id, directions[n], (long long)sbj_get_int(host, counters[n], 0));
            sb_buf_printf(&out, "sb_easy_traffic_bytes_per_second{host_id=\"%s\",direction=\"%s\"} %.6f\n", id, directions[n], sbj_as_double(sbj_get(host, rates[n]), 0));
        }
        sb_buf_free(&label);
    }
    for (size_t i = 0; i < sbj_arr_len(alerts); ++i) {
        const sbj *alert = sbj_arr_at(alerts, i); sb_buf resource = {0}; metric_label(&resource, sbj_get_str(alert, "resource_id", ""));
        sb_buf_printf(&out, "sb_easy_alert_active{kind=\"%s\",resource_id=\"%s\"} 1\n", sbj_get_str(alert, "kind", ""), resource.p ? resource.p : ""); sb_buf_free(&resource);
    }
    sbj_free(hosts); sbj_free(alerts); return sb_buf_detach(&out);
}
static void *monitor_loop(void *arg) {
    sb_observability *monitor = arg;
    pthread_mutex_lock(&monitor->mutex);
    while (!monitor->stopping) {
        pthread_mutex_unlock(&monitor->mutex);
        sb_observability_evaluate(monitor->database, sb_unix_now(), NULL);
        pthread_mutex_lock(&monitor->mutex);
        struct timespec wake; clock_gettime(CLOCK_MONOTONIC, &wake); wake.tv_sec += 30;
        if (!monitor->stopping) pthread_cond_timedwait(&monitor->wakeup, &monitor->mutex, &wake);
    }
    pthread_mutex_unlock(&monitor->mutex); return NULL;
}
sb_observability *sb_observability_new(sb_database *database) {
    sb_observability *monitor = sb_xcalloc(1, sizeof *monitor); monitor->database = database;
    pthread_mutex_init(&monitor->mutex, NULL); pthread_condattr_t attributes; pthread_condattr_init(&attributes); pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC); pthread_cond_init(&monitor->wakeup, &attributes); pthread_condattr_destroy(&attributes); return monitor;
}
int sb_observability_start(sb_observability *monitor, sb_err *err) {
    pthread_mutex_lock(&monitor->mutex);
    if (monitor->running) { pthread_mutex_unlock(&monitor->mutex); return 0; }
    monitor->stopping = false;
    int rc = pthread_create(&monitor->thread, NULL, monitor_loop, monitor);
    monitor->running = rc == 0; pthread_mutex_unlock(&monitor->mutex);
    return rc ? sb_fail(err, SB_ERR_GENERIC, "Could not start history/alert monitor") : 0;
}
void sb_observability_stop(sb_observability *monitor) {
    if (!monitor) return;
    pthread_mutex_lock(&monitor->mutex);
    bool running = monitor->running; monitor->stopping = true; pthread_cond_broadcast(&monitor->wakeup);
    pthread_mutex_unlock(&monitor->mutex);
    if (running) {
        pthread_join(monitor->thread, NULL); pthread_mutex_lock(&monitor->mutex); monitor->running = false; pthread_mutex_unlock(&monitor->mutex);
    }
}
void sb_observability_free(sb_observability *monitor) {
    if (!monitor) return;
    sb_observability_stop(monitor); pthread_cond_destroy(&monitor->wakeup); pthread_mutex_destroy(&monitor->mutex); free(monitor);
}
