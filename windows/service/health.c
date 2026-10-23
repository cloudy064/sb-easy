#include "health.h"
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct sbw_health {
    sbj *groups, *policy, *targets, *results, *states;
    DWORD pid;
    LONG network_generation;
    uint64_t next_ms;
    int64_t checked_at;
    size_t cursor;
    unsigned phase; /* 0 idle, 1 probing, 2 selecting */
    sbw_error error;
};

sbj *sbw_health_policy(const sbj *identity) {
    const sbj *saved = sbj_get(identity, "windows_health");
    if (saved) return sbj_clone(saved);
    sbj *policy = sbj_object();
    sbj_set_bool(policy, "enabled", true);
    sbj_set_str(policy, "probe_url", "https://www.gstatic.com/generate_204");
    sbj_set_int(policy, "interval_seconds", 180);
    sbj_set_int(policy, "timeout_millis", 5000);
    sbj_set_int(policy, "tolerance_millis", 100);
    sbj_set_str(policy, "selection", "failover");
    return policy;
}
static bool integer_range(const sbj *object, const char *key, int64_t low, int64_t high) {
    const sbj *value = sbj_get(object, key);
    return sbj_is_integer(value) && sbj_as_int(value, -1) >= low && sbj_as_int(value, -1) <= high;
}
static bool probe_url_valid(const sbj *value) {
    if (!sbw_json_string(value, 2048, false)) return false;
    const char *url = sbj_as_str(value, "");
    if (strncmp(url, "https://", 8) || strchr(url, '#')) return false;
    const char *authority_end = strpbrk(url + 8, "/?");
    const char *userinfo = strchr(url + 8, '@');
    if (userinfo && (!authority_end || userinfo < authority_end)) return false;
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p) if (*p <= 32 || *p == 127) return false;
    wchar_t *wide = sbw_wide(url, NULL); if (!wide) return false;
    URL_COMPONENTS parts = {0}; parts.dwStructSize = sizeof parts;
    parts.dwHostNameLength = parts.dwUserNameLength = parts.dwPasswordLength = (DWORD)-1;
    bool valid = WinHttpCrackUrl(wide, 0, 0, &parts) && parts.nScheme == INTERNET_SCHEME_HTTPS &&
                 parts.dwHostNameLength && !parts.dwUserNameLength && !parts.dwPasswordLength;
    free(wide); return valid;
}
bool sbw_health_policy_valid(const sbj *policy) {
    return sbj_is_object(policy) && sbj_obj_len(policy) == 6 && sbj_is_bool(sbj_get(policy, "enabled")) &&
           probe_url_valid(sbj_get(policy, "probe_url")) && integer_range(policy, "interval_seconds", 30, 86400) &&
           integer_range(policy, "timeout_millis", 500, 30000) && integer_range(policy, "tolerance_millis", 0, 10000) &&
           (sbj_string_is(sbj_get(policy, "selection"), "failover") || sbj_string_is(sbj_get(policy, "selection"), "fastest"));
}
sbj *sbw_health_change(const sbj *identity, const sbj *policy, sbw_error *error) {
    if (!sbj_is_object(identity) || !sbw_health_policy_valid(policy)) {
        sbw_fail(error, "INVALID_REQUEST", "Use an HTTPS probe URL, a 30–86400 second interval, a 500–30000 ms timeout and a 0–10000 ms tolerance."); return NULL;
    }
    if (!sbj_get_bool(policy, "enabled", false)) {
        const sbj *routing = sbj_get(identity, "windows_routing");
        for (size_t i = 0; i < sbj_obj_len(routing); ++i)
            if (sbj_string_is(sbj_get(sbj_obj_val(routing, i), "mode"), "automatic")) {
                sbw_fail(error, "HEALTH_REQUIRED", "Choose a fixed node for every automatic group before disabling health checks."); return NULL;
            }
    }
    sbj *result = sbj_clone(identity); sbj_set(result, "windows_health", sbj_clone(policy)); return result;
}

static bool member(const sbj *values, const char *tag) {
    for (size_t i = 0; i < sbj_arr_len(values); ++i) if (sbj_string_is(sbj_arr_at(values, i), tag)) return true;
    return false;
}
static const sbj *result_for(const sbj *results, const char *tag) {
    for (size_t i = 0; i < sbj_arr_len(results); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(results, i), "tag"), tag)) return sbj_arr_at(results, i);
    return NULL;
}
static int64_t latency(const sbj *results, const char *tag, const sbj *policy) {
    const sbj *result = result_for(results, tag);
    int64_t delay = sbj_get_int(result, "delay_ms", -1);
    return sbj_get_bool(result, "success", false) && delay > 0 && delay <= sbj_get_int(policy, "timeout_millis", 0) ? delay : -1;
}
const char *sbw_health_choose(const char *current, const sbj *candidates, const sbj *results, const sbj *policy) {
    const char *best = NULL; int64_t best_delay = INT64_MAX;
    for (size_t i = 0; i < sbj_arr_len(candidates); ++i) {
        const char *candidate = sbj_as_str(sbj_arr_at(candidates, i), "");
        int64_t delay = latency(results, candidate, policy);
        if (delay > 0 && delay < best_delay) { best = candidate; best_delay = delay; }
    }
    if (!best) return NULL;
    int64_t current_delay = current && member(candidates, current) ? latency(results, current, policy) : -1;
    if (current_delay > 0 && (sbj_string_is(sbj_get(policy, "selection"), "failover") ||
        current_delay - best_delay <= sbj_get_int(policy, "tolerance_millis", 100))) return current;
    return best;
}
sbw_health *sbw_health_new(void) { return sb_xcalloc(1, sizeof(sbw_health)); }
void sbw_health_reset(sbw_health *health) {
    if (!health) return;
    sbj_free(health->groups); sbj_free(health->policy); sbj_free(health->targets);
    sbj_free(health->results); sbj_free(health->states); memset(health, 0, sizeof *health);
}
void sbw_health_free(sbw_health *health) { if (health) { sbw_health_reset(health); free(health); } }
static void finish(sbw_health *h, uint64_t now) {
    h->phase = 0; h->checked_at = (int64_t)time(NULL) * 1000;
    h->next_ms = now + (uint64_t)sbj_get_int(h->policy, "interval_seconds", 180) * 1000;
}
static bool cancelled(sbw_health *h, const sbw_error *error) {
    if (!sb_streq(error->code, "CANCELLED") && !sb_streq(error->code, "CORE_CANCELLED")) return false;
    h->phase = 0; h->next_ms = 0; h->cursor = 0;
    sbj_free(h->results); h->results = sbj_array();
    sbj_free(h->states); h->states = sbj_array();
    memset(&h->error, 0, sizeof h->error); return true;
}
static const char *selected(const sbj *proxies, const sbj *group) {
    const sbj *proxy = sbj_get(sbj_get(proxies, "proxies"), sbj_get_str(group, "selector", ""));
    return sbj_get_str(proxy, "now", sbj_get_str(group, "outbound", ""));
}
static void begin_cycle(sbw_health *h, uint64_t now, const sbw_health_transport *transport) {
    sbj *proxies = NULL; sbw_error error = {0};
    if (transport->proxies(transport->context, &proxies, &error)) {
        sbj_free(proxies); if (cancelled(h, &error)) return;
        h->error = error; finish(h, now); return;
    }
    sbj_free(h->targets); h->targets = sbj_array(); sbj_free(h->results); h->results = sbj_array();
    sbj_free(h->states); h->states = sbj_array(); memset(&h->error, 0, sizeof h->error);
    for (size_t i = 0; i < sbj_arr_len(h->groups); ++i) {
        const sbj *group = sbj_arr_at(h->groups, i);
        const char *current = selected(proxies, group);
        bool automatic = sbj_string_is(sbj_get(group, "mode"), "automatic");
        sbj *state = sbj_object(); sbj_set_str(state, "id", sbj_get_str(group, "id", ""));
        sbj_set_str(state, "selected", current); sbj_set_bool(state, "automatic", automatic);
        sbj_set_str(state, "error_code", ""); sbj_arr_push(h->states, state);
        if (automatic) {
            const sbj *candidates = sbj_get(group, "automatic_candidates");
            for (size_t j = 0; j < sbj_arr_len(candidates); ++j) {
                const char *tag = sbj_as_str(sbj_arr_at(candidates, j), "");
                if (*tag && !member(h->targets, tag)) sbj_arr_push(h->targets, sbj_str(tag));
            }
        } else if (*current && !member(h->targets, current)) sbj_arr_push(h->targets, sbj_str(current));
    }
    sbj_free(proxies);
    if (sbj_arr_len(h->targets) > 256) {
        sbw_fail(&h->error, "HEALTH_NODE_LIMIT", "Too many health targets; reduce automatic candidate lists."); finish(h, now); return;
    }
    h->cursor = 0; h->phase = 1;
}
void sbw_health_step(sbw_health *h, const sbj *groups, const sbj *policy, DWORD pid,
                      LONG generation, uint64_t now, const sbw_health_transport *transport) {
    if (!h || !transport || !transport->proxies || !transport->probe || !transport->select) return;
    if (h->pid != pid || h->network_generation != generation || !sbj_equal(h->groups, groups) || !sbj_equal(h->policy, policy)) {
        sbw_health_reset(h); h->pid = pid; h->network_generation = generation;
        h->groups = sbj_clone(groups); h->policy = sbj_clone(policy);
    }
    if (!sbw_health_policy_valid(policy)) {
        sbw_fail(&h->error, "HEALTH_POLICY_INVALID", "Saved health settings are invalid."); return;
    }
    if (!pid || !sbj_get_bool(policy, "enabled", false)) return;
    if (!h->phase) { if (now >= h->next_ms) begin_cycle(h, now, transport); return; }
    if (h->phase == 1) {
        if (h->cursor >= sbj_arr_len(h->targets)) { h->phase = 2; h->cursor = 0; return; }
        const char *tag = sbj_as_str(sbj_arr_at(h->targets, h->cursor), "");
        int64_t delay = -1; sbw_error error = {0};
        int rc = transport->probe(transport->context, tag, sbj_get_str(policy, "probe_url", ""),
            (DWORD)sbj_get_int(policy, "timeout_millis", 5000), &delay, &error);
        if (rc && cancelled(h, &error)) return;
        bool success = !rc && delay > 0 && delay <= sbj_get_int(policy, "timeout_millis", 5000);
        sbj *result = sbj_object(); sbj_set_str(result, "tag", tag); sbj_set_bool(result, "success", success);
        if (success) sbj_set_int(result, "delay_ms", delay); else sbj_set_null(result, "delay_ms");
        sbj_set_str(result, "error_code", success ? "" : error.code[0] ? error.code : "HEALTH_PROBE_FAILED");
        sbj_arr_push(h->results, result); ++h->cursor; return;
    }
    if (h->cursor >= sbj_arr_len(h->groups)) { finish(h, now); return; }
    const sbj *group = sbj_arr_at(h->groups, h->cursor); sbj *state = sbj_arr_at(h->states, h->cursor);
    if (!sbj_get_bool(state, "automatic", false)) {
        if (latency(h->results, sbj_get_str(state, "selected", ""), policy) < 0)
            sbj_set_str(state, "error_code", "FIXED_EXIT_UNHEALTHY");
        ++h->cursor; return;
    }
    sbj *proxies = NULL; sbw_error error = {0};
    if (transport->proxies(transport->context, &proxies, &error)) {
        sbj_free(proxies); if (cancelled(h, &error)) return;
        sbj_set_str(state, "error_code", error.code[0] ? error.code : "HEALTH_SELECTION_UNAVAILABLE"); ++h->cursor; return;
    }
    const char *current = selected(proxies, group);
    sbj_set_str(state, "selected", current);
    const char *choice = sbw_health_choose(current, sbj_get(group, "automatic_candidates"), h->results, policy);
    if (!choice) sbj_set_str(state, "error_code", "AUTOMATIC_ALL_FAILED");
    else if (!sb_streq(choice, current)) {
        int rc = transport->select(transport->context, sbj_get_str(group, "selector", ""), choice, &error);
        if (rc && cancelled(h, &error)) { sbj_free(proxies); return; }
        if (rc) sbj_set_str(state, "error_code", error.code[0] ? error.code : "HEALTH_SWITCH_FAILED");
        else sbj_set_str(state, "selected", choice);
    }
    sbj_free(proxies); ++h->cursor;
}
sbj *sbw_health_snapshot(const sbw_health *h) {
    sbj *result = sbj_object();
    sbj_set_bool(result, "running", h && h->pid); sbj_set_bool(result, "checking", h && h->phase);
    sbj_set_int(result, "checked_at", h ? h->checked_at : 0);
    sbj_set_int(result, "completed", h ? (int64_t)sbj_arr_len(h->results) : 0);
    sbj_set_int(result, "total", h ? (int64_t)sbj_arr_len(h->targets) : 0);
    sbj_set_str(result, "error_code", h ? h->error.code : "");
    sbj_set(result, "results", h && h->results ? sbj_clone(h->results) : sbj_array());
    sbj_set(result, "groups", h && h->states ? sbj_clone(h->states) : sbj_array());
    return result;
}
