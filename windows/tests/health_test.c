#include "test_support.h"
#include "../service/health.h"

typedef struct fixture {
    int probes, selections, reads;
    bool fail_all, cancel, fail_select;
    char current[16];
} fixture;
static int proxies(void *context, sbj **out, sbw_error *error) {
    (void)error; fixture *f = context; ++f->reads;
    *out = sbj_parse_cstr("{\"proxies\":{\"group\":{\"now\":\"a\"},\"fixed\":{\"now\":\"fixed-a\"}}}");
    sbj_set_str(sbj_get(sbj_get(*out, "proxies"), "group"), "now", f->current);
    return 0;
}
static int probe(void *context, const char *target, const char *url, DWORD timeout, int64_t *delay, sbw_error *error) {
    fixture *f = context; ++f->probes;
    CHECK(!strcmp(url, "https://www.gstatic.com/generate_204") && timeout == 5000);
    if (f->cancel) { sbw_fail(error, "CORE_CANCELLED", "Cancelled"); return -1; }
    if (f->fail_all || !strcmp(target, "a") || !strcmp(target, "fixed-a")) {
        sbw_fail(error, "PROBE_FAILED", "Failed"); return -1;
    }
    *delay = !strcmp(target, "b") ? 100 : 1; return 0;
}
static int select_node(void *context, const char *selector, const char *target, sbw_error *error) {
    fixture *f = context; ++f->selections;
    CHECK(!strcmp(selector, "group") && !strcmp(target, "b"));
    if (f->fail_select) { sbw_fail(error, "CORE_ERROR", "Failed"); return -1; }
    strcpy_s(f->current, sizeof f->current, target); return 0;
}
static void cycle(sbw_health *health, const sbj *groups, const sbj *policy, fixture *f, LONG generation, uint64_t now) {
    sbw_health_transport io = {f, proxies, probe, select_node};
    for (unsigned i = 0; i < 20; ++i) {
        int before = f->probes + f->selections;
        sbw_health_step(health, groups, policy, 100, generation, now + i, &io);
        CHECK(f->probes + f->selections <= before + 1);
    }
}
int main(void) {
    sbj *identity = sbj_object(), *policy = sbw_health_policy(identity); sbw_error error = {0};
    CHECK(sbw_health_policy_valid(policy));
    const char *invalid[] = {"http://example.test", "https://user@example.test", "https://@example.test", "https://example.test/#fragment", "https://example.test/ bad"};
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        sbj *bad = sbj_clone(policy); sbj_set_str(bad, "probe_url", invalid[i]); CHECK(!sbw_health_policy_valid(bad)); sbj_free(bad);
    }
    sbj *bad = sbj_clone(policy); sbj_set_int(bad, "timeout_millis", 30001); CHECK(!sbw_health_policy_valid(bad)); sbj_free(bad);
    sbj *candidates = sbj_parse_cstr("[\"a\",\"b\"]");
    sbj *results = sbj_parse_cstr("[{\"tag\":\"a\",\"success\":true,\"delay_ms\":250},{\"tag\":\"b\",\"success\":true,\"delay_ms\":100},{\"tag\":\"unlisted\",\"success\":true,\"delay_ms\":1}]");
    CHECK(!strcmp(sbw_health_choose("a", candidates, results, policy), "a"));
    sbj_set_str(policy, "selection", "fastest"); CHECK(!strcmp(sbw_health_choose("a", candidates, results, policy), "b"));
    sbj_set_int(sbj_arr_at(results, 0), "delay_ms", 200); CHECK(!strcmp(sbw_health_choose("a", candidates, results, policy), "a"));
    CHECK(!strcmp(sbw_health_choose("unlisted", candidates, results, policy), "b"));
    sbj_set_bool(sbj_arr_at(results, 0), "success", false); sbj_set_bool(sbj_arr_at(results, 1), "success", false);
    CHECK(sbw_health_choose("a", candidates, results, policy) == NULL);
    sbj_free(candidates); sbj_free(results); sbj_set_str(policy, "selection", "failover");
    sbj_set(identity, "windows_routing", sbj_parse_cstr("{\"default\":{\"mode\":\"automatic\",\"automatic_candidates\":[\"a\",\"b\"]}}"));
    sbj_set_bool(policy, "enabled", false); CHECK(!sbw_health_change(identity, policy, &error) && !strcmp(error.code, "HEALTH_REQUIRED"));
    sbj_set_bool(policy, "enabled", true);
    sbj *groups = sbj_parse_cstr("[{\"id\":\"default\",\"selector\":\"group\",\"outbound\":\"a\",\"mode\":\"automatic\",\"automatic_candidates\":[\"a\",\"b\"]},{\"id\":\"work\",\"selector\":\"fixed\",\"outbound\":\"fixed-a\",\"mode\":\"node\"}]");
    fixture f = {0}; strcpy_s(f.current, sizeof f.current, "a"); sbw_health *health = sbw_health_new();
    cycle(health, groups, policy, &f, 1, 1000); CHECK(f.probes == 3 && f.selections == 1 && !strcmp(f.current, "b"));
    sbj *snapshot = sbw_health_snapshot(health);
    CHECK(!sbj_get_bool(snapshot, "checking", true) && sbj_get_int(snapshot, "checked_at", 0) > 0);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(snapshot, "groups"), 1), "error_code"), "FIXED_EXIT_UNHEALTHY")); sbj_free(snapshot);
    cycle(health, groups, policy, &f, 1, 2000); CHECK(f.probes == 3); /* interval honored */
    f.fail_all = true; cycle(health, groups, policy, &f, 2, 3000); CHECK(f.selections == 1 && !strcmp(f.current, "b"));
    snapshot = sbw_health_snapshot(health);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(snapshot, "groups"), 0), "error_code"), "AUTOMATIC_ALL_FAILED")); sbj_free(snapshot);
    /* A generation change discards partially collected results before selection. */
    f.fail_all = false; strcpy_s(f.current, sizeof f.current, "a");
    sbw_health_transport io = {&f, proxies, probe, select_node};
    sbw_health_step(health, groups, policy, 100, 3, 4000, &io);
    sbw_health_step(health, groups, policy, 100, 3, 4001, &io);
    sbw_health_step(health, groups, policy, 101, 3, 4002, &io);
    snapshot = sbw_health_snapshot(health); CHECK(sbj_get_int(snapshot, "completed", -1) == 0); sbj_free(snapshot);
    f.cancel = true; sbw_health_step(health, groups, policy, 101, 3, 4003, &io);
    snapshot = sbw_health_snapshot(health); CHECK(!sbj_get_bool(snapshot, "checking", true) && sbj_get_int(snapshot, "completed", -1) == 0); sbj_free(snapshot);
    f.cancel = false; f.fail_select = true; cycle(health, groups, policy, &f, 4, 5000);
    snapshot = sbw_health_snapshot(health); CHECK(!strcmp(f.current, "a"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(snapshot, "groups"), 0), "error_code"), "CORE_ERROR")); sbj_free(snapshot);
    sbw_health_free(health); sbj_free(groups); sbj_free(policy); sbj_free(identity);
    puts("Health policy: explicit candidates, failover, tolerance, fixed failures, cancellation and generation safety passed."); return 0;
}
