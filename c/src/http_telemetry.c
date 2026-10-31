/* Host telemetry and diagnostic-report normalisation for the panel HTTP
 * server, plus the in-memory telemetry store and server log accessor. */
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "http_internal.h"

sbj *sb_http_default_telemetry(void) {
    sbj *t = sbj_object();
    sbj_set_str(t, "at", "");
    sbj_set_int(t, "up", 0);
    sbj_set_int(t, "down", 0);
    sbj_set_int(t, "up_total", 0);
    sbj_set_int(t, "down_total", 0);
    sbj_set_int(t, "conn_count", 0);
    sbj_set_null(t, "connections");
    sbj_set(t, "domain_stats", sbj_array());
    sbj_set(t, "logs", sbj_array());
    return t;
}

/* nlohmann get<int64_t>() on an integer value (unsigned wraps like static_cast). */
static int64_t json_int64(const sbj *v) { return v->type == SBJ_UINT ? (int64_t)v->v.u : v->v.i; }

/* bounded_string() lambda of normalize_telemetry(). */
static int bounded_string(const sbj *entry, const char *field, size_t maximum, bool required, sbj *out,
                          sb_err *err) {
    const sbj *found = sbj_get(entry, field);
    if (!found || found->type == SBJ_NULL) {
        if (required) return sb_fail(err, SB_ERR_VALIDATION, "%s is required", field);
        sbj_set_str(out, field, "");
        return 0;
    }
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    if ((required && found->v.str.len == 0) || found->v.str.len > maximum)
        return sb_fail(err, SB_ERR_VALIDATION, "%s has an invalid length", field);
    sbj_set(out, field, sbj_strn(found->v.str.ptr, found->v.str.len));
    return 0;
}

/* Most per-domain route statistics entries accepted in one report. */
#define SB_HTTP_MAX_DOMAIN_STATS 1000
static sbj *normalize_domain_stats(const sbj *stats, sb_err *err) {
    if (!sbj_is_array(stats)) {
        sb_fail(err, SB_ERR_VALIDATION, "domain_stats must be an array");
        return NULL;
    }
    if (sbj_arr_len(stats) > SB_HTTP_MAX_DOMAIN_STATS) {
        sb_fail(err, SB_ERR_VALIDATION, "domain_stats must contain at most 1000 entries");
        return NULL;
    }
    sbj *normalized = sbj_array();
    const sbj *entry;
    SBJ_ARR_FOREACH(stats, i, entry) {
        if (!sbj_is_object(entry)) {
            sb_fail(err, SB_ERR_VALIDATION, "domain_stats must contain only objects");
            goto fail;
        }
        sbj *chain = sbj_array();
        const sbj *value = sbj_get(entry, "chain");
        if (value) {
            if (!sbj_is_array(value) || sbj_arr_len(value) > 16) {
                sbj_free(chain);
                sb_fail(err, SB_ERR_VALIDATION, "domain_stats chain must be an array of at most 16 entries");
                goto fail;
            }
            const sbj *tag;
            SBJ_ARR_FOREACH(value, t, tag) {
                if (!sbj_is_string(tag) || tag->v.str.len > 256) {
                    sbj_free(chain);
                    sb_fail(err, SB_ERR_VALIDATION, "domain_stats chain contains an invalid tag");
                    goto fail;
                }
                sbj_arr_push(chain, sbj_clone(tag));
            }
        }
        static const char *const counters[] = {"connection_count", "uplink_total", "downlink_total", "first_seen",
                                               "last_seen"};
        int64_t values[5];
        for (size_t c = 0; c < 5; ++c) {
            if (sb_json_integer_field(entry, counters[c], &values[c], err) != 0) {
                sbj_free(chain);
                goto fail;
            }
        }
        for (size_t c = 0; c < 5; ++c) {
            if (values[c] < 0) {
                sbj_free(chain);
                sb_fail(err, SB_ERR_VALIDATION, "domain_stats counters must not be negative");
                goto fail;
            }
        }
        sbj *item = sbj_object();
        if (bounded_string(entry, "domain", 512, true, item, err) != 0 ||
            bounded_string(entry, "outbound", 256, false, item, err) != 0 ||
            bounded_string(entry, "outbound_type", 80, false, item, err) != 0 ||
            bounded_string(entry, "rule", 512, false, item, err) != 0) {
            sbj_free(item);
            sbj_free(chain);
            goto fail;
        }
        sbj_set(item, "chain", chain);
        for (size_t c = 0; c < 5; ++c) sbj_set_int(item, counters[c], values[c]);
        sbj_arr_push(normalized, item);
    }
    return normalized;
fail:
    sbj_free(normalized);
    return NULL;
}

/* Truncate a JSON byte string at a UTF-8 boundary without using strlen. */
static sbj *truncate_json_string(const sbj *value, size_t maximum) {
    size_t end = value->v.str.len;
    if (end > maximum) {
        end = maximum;
        while (end > 0 && (((unsigned char)value->v.str.ptr[end]) & 0xc0u) == 0x80u) --end;
    }
    return sbj_strn(value->v.str.ptr, end);
}

/* Keeps the last `limit` entries of a string array ("<field> must be an
 * array" / "<field> must contain only strings"); truncates when max > 0. */
static sbj *tail_strings(const sbj *array, size_t limit, size_t max_bytes, sb_err *err) {
    if (!sbj_is_array(array)) {
        sb_fail(err, SB_ERR_VALIDATION, "logs must be an array");
        return NULL;
    }
    sbj *out = sbj_array();
    size_t len = sbj_arr_len(array);
    for (size_t i = len > limit ? len - limit : 0; i < len; ++i) {
        const sbj *item = sbj_arr_at(array, i);
        if (!sbj_is_string(item)) {
            sbj_free(out);
            sb_fail(err, SB_ERR_VALIDATION, "logs must contain only strings");
            return NULL;
        }
        if (max_bytes) sbj_arr_push(out, truncate_json_string(item, max_bytes));
        else sbj_arr_push(out, sbj_clone(item));
    }
    return out;
}

sbj *sb_http_normalize_telemetry(const sbj *body, sb_err *err) {
    sbj *telemetry = sb_http_default_telemetry();
    sbj_set(telemetry, "at", sbj_str_take(sb_http_utc_now()));
    static const char *const fields[] = {"up", "down", "up_total", "down_total"};
    for (size_t i = 0; i < 4; ++i) {
        int64_t value = 0;
        if (sb_json_integer_field(body, fields[i], &value, err) != 0) goto fail;
        sbj_set_int(telemetry, fields[i], value);
    }
    int64_t count = 0;
    if (sb_json_integer_field(body, "conn_count", &count, err) != 0) goto fail;
    if (count < 0) {
        sb_fail(err, SB_ERR_VALIDATION, "conn_count must not be negative");
        goto fail;
    }
    sbj_set_int(telemetry, "conn_count", count);
    const sbj *connections = sbj_get(body, "connections");
    if (connections) sbj_set(telemetry, "connections", sbj_clone(connections));
    const sbj *stats = sbj_get(body, "domain_stats");
    if (stats) {
        sbj *normalized = normalize_domain_stats(stats, err);
        if (!normalized) goto fail;
        sbj_set(telemetry, "domain_stats", normalized);
    }
    const sbj *logs = sbj_get(body, "logs");
    if (logs) {
        sbj *normalized = tail_strings(logs, 500, 0, err);
        if (!normalized) goto fail;
        sbj_set(telemetry, "logs", normalized);
    }
    return telemetry;
fail:
    sbj_free(telemetry);
    return NULL;
}

/* diagnostic_string(): absent/null -> fallback; else truncated string. */
static int diagnostic_string(const sbj *body, const char *field, const char *fallback, size_t max_bytes, sbj *out,
                             sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set_str(out, field, fallback);
        return 0;
    }
    if (!sbj_is_string(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a string", field);
    sbj_set(out, field, truncate_json_string(found, max_bytes));
    return 0;
}

static int diagnostic_object(const sbj *body, const char *field, sbj *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set(out, field, sbj_object());
        return 0;
    }
    if (!sbj_is_object(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be a JSON object", field);
    sbj_set(out, field, sbj_clone(found));
    return 0;
}

static int diagnostic_count(const sbj *body, const char *field, sbj *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || found->type == SBJ_NULL) {
        sbj_set_int(out, field, 0);
        return 0;
    }
    if (!sbj_is_integer(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an integer", field);
    int64_t value = json_int64(found);
    if (value < 0) return sb_fail(err, SB_ERR_VALIDATION, "%s must not be negative", field);
    sbj_set_int(out, field, value);
    return 0;
}

sbj *sb_http_normalize_diagnostic_report(const sbj *body, sb_err *err) {
    sbj *logs = NULL;
    const sbj *found = sbj_get(body, "logs");
    if (found) {
        logs = tail_strings(found, 1500, 4000, err);
        if (!logs) return NULL;
    } else {
        logs = sbj_array();
    }
    sbj *report = sbj_object();
    if (diagnostic_string(body, "reason", "manual", 80, report, err) != 0 ||
        diagnostic_string(body, "app_version", "", 80, report, err) != 0 ||
        diagnostic_string(body, "core_version", "", 120, report, err) != 0 ||
        diagnostic_object(body, "device", report, err) != 0 || diagnostic_object(body, "vpn", report, err) != 0 ||
        diagnostic_object(body, "network", report, err) != 0 || diagnostic_object(body, "config", report, err) != 0 ||
        diagnostic_count(body, "runtime_log_count", report, err) != 0 ||
        diagnostic_count(body, "connection_count", report, err) != 0) {
        sbj_free(report);
        sbj_free(logs);
        return NULL;
    }
    sbj_set(report, "logs", logs);
    return report;
}

void sb_http_telemetry_put(sb_http_server *srv, const char *host_id, sbj *telemetry) {
    pthread_mutex_lock(&srv->telemetry_mutex);
    sbj_set(srv->telemetry, host_id ? host_id : "", telemetry);
    pthread_mutex_unlock(&srv->telemetry_mutex);
}

sbj *sb_http_telemetry_get(sb_http_server *srv, const char *host_id) {
    pthread_mutex_lock(&srv->telemetry_mutex);
    const sbj *found = sbj_get(srv->telemetry, host_id ? host_id : "");
    sbj *copy = found ? sbj_clone(found) : sb_http_default_telemetry();
    pthread_mutex_unlock(&srv->telemetry_mutex);
    return copy;
}

sbj *sb_http_log_lines(sb_http_server *srv) {
    sbj *lines = sbj_array();
    pthread_mutex_lock(&srv->log_mutex);
    for (size_t i = 0; i < srv->log_lines.len; ++i) {
        size_t index = (srv->log_head + i) % srv->log_lines.len;
        sbj_arr_push(lines, sbj_str(srv->log_lines.items[index]));
    }
    pthread_mutex_unlock(&srv->log_mutex);
    return lines;
}
