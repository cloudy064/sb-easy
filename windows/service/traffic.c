#include "traffic.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DETAIL_LIMIT 512
#define CHECKPOINT_LIMIT 20000
#define SAFE_MAX INT64_C(9007199254740991)
struct sbw_traffic {
    sbj *rows, *checkpoints;
    DWORD pid;
    int64_t generation;
    int64_t upload, download, previous_up, previous_down, sampled_at, cleared_at;
    bool limited;
};
static int64_t now_ms(void) {
    FILETIME ft; ULARGE_INTEGER ticks; GetSystemTimeAsFileTime(&ft);
    ticks.LowPart = ft.dwLowDateTime; ticks.HighPart = ft.dwHighDateTime;
    return (int64_t)((ticks.QuadPart - UINT64_C(116444736000000000)) / 10000);
}
static int64_t count(const sbj *v, const char *key) {
    int64_t n = sbj_get_int(v, key, 0); return n < 0 ? 0 : n > SAFE_MAX ? SAFE_MAX : n;
}
static int64_t plus(int64_t a, int64_t b) { return b > SAFE_MAX - a ? SAFE_MAX : a + b; }
static const char *text(const sbj *v, const char *key, size_t max) {
    const sbj *s = sbj_get(v, key);
    if (!sbw_json_string(s, max, true)) return "";
    const char *p = sbj_as_str(s, "");
    for (const char *c = p; *c; ++c) if ((unsigned char)*c < 32) return "";
    return p;
}
sbw_traffic *sbw_traffic_new(void) {
    sbw_traffic *t = sb_xcalloc(1, sizeof *t);
    t->rows = sbj_array(); t->checkpoints = sbj_object(); t->cleared_at = now_ms(); return t;
}
void sbw_traffic_free(sbw_traffic *t) {
    if (!t) return; sbj_free(t->rows); sbj_free(t->checkpoints); free(t);
}
void sbw_traffic_new_core(sbw_traffic *t) { t->pid = 0; }
void sbw_traffic_clear(sbw_traffic *t) {
    sbj_arr_clear(t->rows); t->upload = 0; t->download = 0;
    t->cleared_at = now_ms(); t->limited = false;
    /* Keep connection counters: clearing must not recount live connections. */
    for (size_t i = sbj_obj_len(t->checkpoints); i > 0; --i) {
        const char *key = sbj_obj_key(t->checkpoints, i - 1);
        if (sbj_get_int(sbj_obj_val(t->checkpoints, i - 1), "generation", -1) != t->generation)
            sbj_del(t->checkpoints, key);
    }
}
static sbj *detail(sbw_traffic *t, const sbj *source) {
    const sbj *m = sbj_get(source, "metadata");
    const char *path = text(m, "processPath", 32768), *app = path;
    for (const char *p = path; *p; ++p) if (*p == '/' || *p == '\\') app = p + 1;
    if (!*app || strlen(app) > 96) app = text(m, "process", 96);
    const char *host = text(m, "host", 253);
    if (!*host) host = text(m, "destinationIP", 253);
    const char *outbound = sbj_as_str(sbj_arr_at(sbj_get(source, "chains"), 0), "");
    if (strlen(outbound) > 128) outbound = "";
    for (const char *p = outbound; *p; ++p) if ((unsigned char)*p < 32) { outbound = ""; break; }
    const char *rule = text(source, "rule", 96);
    for (size_t i = 0; i < sbj_arr_len(t->rows); ++i) {
        sbj *r = sbj_arr_at(t->rows, i);
        if (sb_streq(app, sbj_get_str(r, "app", "")) && sb_streq(host, sbj_get_str(r, "host", "")) &&
            sb_streq(outbound, sbj_get_str(r, "outbound", "")) && sb_streq(rule, sbj_get_str(r, "rule", ""))) return r;
    }
    if (sbj_arr_len(t->rows) >= DETAIL_LIMIT) { t->limited = true; return NULL; }
    sbj *r = sbj_object();
    sbj_set_str(r, "app", app); sbj_set_str(r, "host", host);
    sbj_set_str(r, "outbound", outbound); sbj_set_str(r, "rule", rule);
    sbj_set_int(r, "upload", 0); sbj_set_int(r, "download", 0); sbj_set_int(r, "last_seen", 0);
    sbj_arr_push(t->rows, r); return r;
}
void sbw_traffic_record(sbw_traffic *t, const sbj *snapshot, DWORD pid) {
    if (!pid || !sbj_is_integer(sbj_get(snapshot, "uploadTotal")) ||
        !sbj_is_integer(sbj_get(snapshot, "downloadTotal"))) return;
    if (pid != t->pid) {
        sbj_free(t->checkpoints); t->checkpoints = sbj_object();
        t->pid = pid; t->previous_up = 0; t->previous_down = 0;
    }
    int64_t up = count(snapshot, "uploadTotal"), down = count(snapshot, "downloadTotal");
    t->upload = plus(t->upload, up > t->previous_up ? up - t->previous_up : 0);
    t->download = plus(t->download, down > t->previous_down ? down - t->previous_down : 0);
    if (up > t->previous_up) t->previous_up = up;
    if (down > t->previous_down) t->previous_down = down;
    t->sampled_at = now_ms(); ++t->generation;
    const sbj *connections = sbj_get(snapshot, "connections");
    for (size_t i = 0; i < sbj_arr_len(connections); ++i) {
        const sbj *c = sbj_arr_at(connections, i);
        const char *id = text(c, "id", 128); if (!*id) continue;
        sbj *checkpoint = sbj_get(t->checkpoints, id);
        if (!checkpoint) {
            if (sbj_obj_len(t->checkpoints) >= CHECKPOINT_LIMIT) { t->limited = true; continue; }
            checkpoint = sbj_object(); sbj_set(t->checkpoints, id, checkpoint);
            sbj *row = detail(t, c);
            /* Preserve attribution when later snapshots omit process/host. */
            if (row) sbj_set(checkpoint, "detail", sbj_clone(row));
        }
        if (!sbj_get(checkpoint, "detail")) {
            sbj *row = detail(t, c);
            if (row) sbj_set(checkpoint, "detail", sbj_clone(row));
        }
        sbj_set_int(checkpoint, "generation", t->generation);
        up = count(c, "upload"); down = count(c, "download");
        int64_t old_up = count(checkpoint, "upload"), old_down = count(checkpoint, "download");
        int64_t du = up > old_up ? up - old_up : 0, dd = down > old_down ? down - old_down : 0;
        sbj_set_int(checkpoint, "upload", up > old_up ? up : old_up);
        sbj_set_int(checkpoint, "download", down > old_down ? down : old_down);
        const sbj *attribution = sbj_get(checkpoint, "detail");
        if (!attribution || (!du && !dd)) continue;
        sbj *synthetic = sbj_object(), *metadata = sbj_object(), *chains = sbj_array();
        sbj_set_str(metadata, "process", sbj_get_str(attribution, "app", ""));
        sbj_set_str(metadata, "host", sbj_get_str(attribution, "host", ""));
        sbj_set(synthetic, "metadata", metadata);
        sbj_arr_push(chains, sbj_str(sbj_get_str(attribution, "outbound", "")));
        sbj_set(synthetic, "chains", chains); sbj_set_str(synthetic, "rule", sbj_get_str(attribution, "rule", ""));
        sbj *row = detail(t, synthetic); sbj_free(synthetic);
        if (!row) continue;
        sbj_set_int(row, "upload", plus(count(row, "upload"), du));
        sbj_set_int(row, "download", plus(count(row, "download"), dd));
        sbj_set_int(row, "last_seen", t->sampled_at);
    }
}
sbj *sbw_traffic_snapshot(const sbw_traffic *t) {
    sbj *result = sbj_object(); sbj_set_int(result, "version", 1);
    sbj_set_int(result, "upload", t->upload); sbj_set_int(result, "download", t->download);
    sbj_set_int(result, "sampled_at", t->sampled_at); sbj_set_int(result, "cleared_at", t->cleared_at);
    sbj_set_bool(result, "limited", t->limited); sbj_set(result, "rows", sbj_clone(t->rows)); return result;
}
bool sbw_traffic_restore(sbw_traffic *t, const sbj *saved) {
    const sbj *rows = sbj_get(saved, "rows");
    if (sbj_get_int(saved, "version", 0) != 1 || !sbj_is_array(rows) || sbj_arr_len(rows) > DETAIL_LIMIT) return false;
    for (size_t i = 0; i < sbj_arr_len(rows); ++i) {
        const sbj *r = sbj_arr_at(rows, i);
        if (!sbw_json_string(sbj_get(r, "app"), 96, true) || !sbw_json_string(sbj_get(r, "host"), 253, true) ||
            !sbw_json_string(sbj_get(r, "outbound"), 128, true) || !sbw_json_string(sbj_get(r, "rule"), 96, true) ||
            sbj_get_int(r, "upload", -1) < 0 || sbj_get_int(r, "upload", -1) > SAFE_MAX ||
            sbj_get_int(r, "download", -1) < 0 || sbj_get_int(r, "download", -1) > SAFE_MAX ||
            sbj_get_int(r, "last_seen", -1) < 0 || sbj_get_int(r, "last_seen", -1) > SAFE_MAX) return false;
    }
    sbj_free(t->rows); t->rows = sbj_clone(rows);
    t->upload = count(saved, "upload"); t->download = count(saved, "download");
    t->sampled_at = count(saved, "sampled_at"); t->cleared_at = count(saved, "cleared_at");
    t->limited = sbj_get_bool(saved, "limited", false); return true;
}
