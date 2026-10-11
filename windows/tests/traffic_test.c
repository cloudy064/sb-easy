#include "test_support.h"
#include "../service/traffic.h"

static sbj *sample(int64_t up, int64_t down, const char *id, const char *app) {
    sbj *root = sbj_object(), *rows = sbj_array(), *row = sbj_object(), *m = sbj_object(), *chains = sbj_array();
    sbj_set_int(root, "uploadTotal", up + 10); sbj_set_int(root, "downloadTotal", down + 20);
    sbj_set_str(row, "id", id); sbj_set_int(row, "upload", up); sbj_set_int(row, "download", down);
    sbj_set_str(m, "processPath", app); sbj_set_str(m, "host", "api.example.co.uk");
    sbj_set(row, "metadata", m); sbj_arr_push(chains, sbj_str("direct")); sbj_set(row, "chains", chains);
    sbj_arr_push(rows, row); sbj_set(root, "connections", rows); return root;
}
int main(void) {
    sbw_traffic *t = sbw_traffic_new(); sbj *s = sample(100, 200, "one", "C:\\Apps\\codex.exe");
    sbw_traffic_record(t, s, 10); sbw_traffic_record(t, s, 10); sbj_free(s);
    sbj *result = sbw_traffic_snapshot(t);
    CHECK(sbj_get_int(result, "upload", 0) == 110);
    CHECK(sbj_get_int(sbj_arr_at(sbj_get(result, "rows"), 0), "download", 0) == 200);
    CHECK(sb_streq(sbj_get_str(sbj_arr_at(sbj_get(result, "rows"), 0), "app", ""), "codex.exe")); sbj_free(result);
    s = sample(120, 260, "one", ""); sbw_traffic_record(t, s, 10); sbj_free(s);
    result = sbw_traffic_snapshot(t); CHECK(sbj_arr_len(sbj_get(result, "rows")) == 1); sbj_free(result);
    /* Out-of-order counters must not move checkpoints backwards. */
    s = sample(50, 100, "one", ""); sbw_traffic_record(t, s, 10); sbj_free(s);
    sbw_traffic_clear(t);
    s = sample(130, 280, "one", ""); sbw_traffic_record(t, s, 10); sbj_free(s);
    result = sbw_traffic_snapshot(t);
    CHECK(sbj_get_int(result, "upload", 0) == 10);
    CHECK(sbj_get_int(sbj_arr_at(sbj_get(result, "rows"), 0), "download", 0) == 20);
    sbw_traffic *restored = sbw_traffic_new(); CHECK(sbw_traffic_restore(restored, result)); sbj_free(result);
    s = sample(5, 6, "new", "C:\\Apps\\other.exe"); sbw_traffic_record(restored, s, 20); sbj_free(s);
    result = sbw_traffic_snapshot(restored); CHECK(sbj_get_int(result, "upload", 0) == 25);
    CHECK(sbj_arr_len(sbj_get(result, "rows")) == 2); sbj_free(result);
    sbw_traffic_new_core(restored);
    s = sample(5, 6, "new", "C:\\Apps\\other.exe"); sbw_traffic_record(restored, s, 20); sbj_free(s);
    result = sbw_traffic_snapshot(restored); CHECK(sbj_get_int(result, "upload", 0) == 40); sbj_free(result);
    sbj *bad = sbj_object(); sbj_set_int(bad, "version", 99);
    CHECK(!sbw_traffic_restore(restored, bad)); sbj_free(bad);
    sbw_traffic_free(restored); sbw_traffic_free(t);
    t = sbw_traffic_new();
    for (int i = 0; i < 520; ++i) {
        char id[32], app[32]; sprintf_s(id, sizeof id, "id-%d", i); sprintf_s(app, sizeof app, "app-%d.exe", i);
        s = sample(i + 1, i + 1, id, app); sbw_traffic_record(t, s, 30); sbj_free(s);
    }
    result = sbw_traffic_snapshot(t);
    CHECK(sbj_arr_len(sbj_get(result, "rows")) == 512 && sbj_get_bool(result, "limited", false));
    CHECK(sbj_get_int(result, "upload", 0) == 530);
    char *encoded = sbj_dump(result, -1); CHECK(strlen(encoded) < 1024U * 1024U);
    free(encoded); sbj_free(result); sbw_traffic_free(t); return 0;
}
