#include "test_support.h"
#include "../service/routing.h"
#include "../service/health.h"
static const char *fixture =
    "{\"outbounds\":[{\"type\":\"http\",\"tag\":\"a\"},{\"type\":\"http\",\"tag\":\"b\"}],"
    "\"route\":{\"final\":\"a\",\"rules\":[{\"domain_suffix\":[\"chatgpt.com\",\"openai.com\"],"
    "\"outbound\":\"a\"},{\"domain_suffix\":[\"claude.ai\"],\"outbound\":\"b\"},{\"domain_suffix\":"
    "[\"other.test\"],\"outbound\":\"a\"}]},"
    "\"dns\":{\"final\":\"shared\",\"servers\":[{\"type\":\"https\",\"tag\":\"shared\",\"server\":"
    "\"1.1.1.1\",\"detour\":\"a\"}],"
    "\"rules\":[{\"domain_suffix\":[\"openai.com\",\"chatgpt.com\"],\"server\":\"shared\"},{"
    "\"domain_suffix\":[\"claude.ai\"],\"server\":\"shared\"},{\"domain_suffix\":[\"other.test\"],"
    "\"server\":\"shared\"}]}}";
static void choose(sbj *identity, const char *id, const char *mode, const char *node) {
    sbj *all = sbj_get(identity, "windows_routing");
    if (!all) {
        all = sbj_object();
        sbj_set(identity, "windows_routing", all);
    }
    sbj *p = sbj_object();
    sbj_set_str(p, "mode", mode);
    if (node)
        sbj_set_str(p, "node", node);
    sbj_set(all, id, p);
}
typedef struct test_state {
    sbj *source, *identity, *before, *params;
    char *other;
    sbw_error error;
    sbj *groups, *runtime, *cfg, *dns, *servers, *nodes, *effective, *changed, *rr, *dr;
} test_state;

static void scenario_groups_and_choices(test_state *t) {
    t->groups = sbw_routing_groups(t->source, t->identity);
    CHECK(sbj_arr_len(t->groups) == 4);
    for (size_t i = 0; i < 4; ++i)
        CHECK(sbj_get_bool(sbj_arr_at(t->groups, i), "editable", false));
    t->other = sb_strdup(sbj_get_str(sbj_arr_at(t->groups, 3), "id", ""));
    sbj_free(t->groups);
    choose(t->identity, "default", "node", "b");
    choose(t->identity, "claude", "default", NULL);
    choose(t->identity, t->other, "node", "b");
    sbj_set_str(t->identity, "windows_gpt_outbound",
                "b"); /* Upgrade preserves the former GPT preference. */
    t->runtime = sbw_routing_apply(t->source, t->identity, true, &t->error);
    CHECK(t->runtime && sbj_equal(t->source, t->before));
    t->cfg = sbj_parse_cstr(sbj_get_str(t->runtime, "content", ""));
    t->dns = sbj_get(t->cfg, "dns");
    t->servers = sbj_get(t->dns, "servers");
    t->nodes = sbj_get(t->cfg, "outbounds");
    CHECK(sbj_arr_len(t->nodes) == 6 && sbj_arr_len(t->servers) == 5);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->servers, 0), "detour"), "a"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->nodes, 2), "default"), "b"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->nodes, 3), "default"), "b"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->nodes, 4), "default"), SBW_DEFAULT_SELECTOR));
    CHECK(sbj_string_is(sbj_get(sbj_get(t->cfg, "route"), "final"), SBW_DEFAULT_SELECTOR));
    for (size_t i = 2; i < 6; ++i)
        CHECK(!sbj_get_bool(sbj_arr_at(t->nodes, i), "interrupt_exist_connections", true));
    for (size_t i = 1; i < 5; ++i)
        CHECK(strstr(sbj_get_str(sbj_arr_at(t->servers, i), "detour", ""), "sb-easy-local-") !=
              NULL);
    sbj_free(t->cfg);
    sbj_free(t->runtime);
}

static void scenario_effective_config(test_state *t) {
    t->effective = sbw_routing_apply(t->source, t->identity, false, &t->error);
    CHECK(t->effective);
    t->cfg = sbj_parse_cstr(sbj_get_str(t->effective, "content", ""));
    CHECK(sbj_string_is(sbj_get(sbj_get(t->cfg, "route"), "final"), "b"));
    CHECK(sbj_string_is(
        sbj_get(sbj_arr_at(sbj_get(sbj_get(t->cfg, "route"), "rules"), 1), "outbound"), "b"));
    sbj_free(t->cfg);
    sbj_free(t->effective);
}

static void scenario_server_mode_and_rejections(test_state *t) {
    choose(t->identity, "claude", "server", NULL);
    t->groups = sbw_routing_groups(t->source, t->identity);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->groups, 2), "mode"), "server"));
    sbj_free(t->groups);
    choose(t->identity, "claude", "node", "removed");
    CHECK(!sbw_routing_apply(t->source, t->identity, true, &t->error));
    CHECK(!strcmp(t->error.code, "ROUTING_NODE_UNAVAILABLE"));
    choose(t->identity, "claude", "node", "a");
    t->cfg = sbj_parse_cstr(fixture);
    sbj_set_bool(sbj_arr_at(sbj_get(sbj_get(t->cfg, "route"), "rules"), 1), "invert", true);
    sbj_set(t->source, "content", sbj_str_take(sbj_dump(t->cfg, -1)));
    sbj_free(t->cfg);
    CHECK(!sbw_routing_apply(t->source, t->identity, true, &t->error));
    CHECK(!strcmp(t->error.code, "ROUTING_UNSUPPORTED"));
    CHECK(sbj_string_is(sbj_get(t->before, "content"), fixture));
}

static void scenario_custom_group(test_state *t) {
    sbj_set_str(t->source, "content", fixture);
    sbj_free(t->identity);
    t->identity = sbj_object();
    t->params =
        sbj_parse_cstr("{\"id\":\"custom-work\",\"label\":\"Work\",\"domains\":[\"work.example\"],"
                       "\"processes\":[\"editor.exe\"],\"mode\":\"node\",\"node\":\"b\"}");
    t->changed = sbw_routing_change(t->identity, t->params, false, &t->error);
    CHECK(t->changed && !sbj_get(t->identity, "windows_local_groups"));
    sbj_free(t->identity);
    t->identity = t->changed;
    t->groups = sbw_routing_groups(t->source, t->identity);
    CHECK(sbj_arr_len(t->groups) == 5);
    CHECK(sbj_get_bool(sbj_arr_at(t->groups, 4), "local", false));
    sbj_free(t->groups);
    t->runtime = sbw_routing_apply(t->source, t->identity, true, &t->error);
    CHECK(t->runtime);
    t->cfg = sbj_parse_cstr(sbj_get_str(t->runtime, "content", ""));
    t->rr = sbj_get(sbj_get(t->cfg, "route"), "rules");
    t->dr = sbj_get(sbj_get(t->cfg, "dns"), "rules");
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->rr, 0), "outbound"), "sb-easy-local-custom-work"));
    CHECK(
        sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(t->rr, 1), "process_name"), 0), "editor.exe"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->dr, 0), "server"), "sb-easy-local-custom-work-dns"));
    CHECK(
        sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(t->dr, 1), "process_name"), 0), "editor.exe"));
    sbj_free(t->cfg);
    sbj_free(t->runtime);
}

static void scenario_protected_rules(test_state *t) {
    /* Preserve protected WireGuard management and DNS rules ahead of overrides. */
    t->cfg = sbj_parse_cstr(fixture);
    sbj_set(t->cfg, "endpoints",
            sbj_parse_cstr("[{\"type\":\"wireguard\",\"tag\":\"management\"}]"));
    sbj_arr_push(sbj_get(sbj_get(t->cfg, "route"), "rules"),
                 sbj_parse_cstr("{\"ip_cidr\":[\"10.42.0.0/16\"],\"outbound\":\"management\"}"));
    sbj_arr_push(sbj_get(sbj_get(t->cfg, "dns"), "rules"),
                 sbj_parse_cstr("{\"domain\":[\"panel.test\"],\"server\":\"shared\"}"));
    sbj_set(t->source, "content", sbj_str_take(sbj_dump(t->cfg, -1)));
    sbj_free(t->cfg);
    t->runtime = sbw_routing_apply(t->source, t->identity, true, &t->error);
    CHECK(t->runtime);
    t->cfg = sbj_parse_cstr(sbj_get_str(t->runtime, "content", ""));
    t->rr = sbj_get(sbj_get(t->cfg, "route"), "rules");
    t->dr = sbj_get(sbj_get(t->cfg, "dns"), "rules");
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->rr, 0), "outbound"), "management"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(t->rr, 1), "outbound"), "sb-easy-local-custom-work"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(t->dr, 0), "domain"), 0), "panel.test"));
    sbj_free(t->cfg);
    sbj_free(t->runtime);
}

static void scenario_custom_group_validation(test_state *t) {
    sbj_set_str(t->params, "id", "custom-two");
    sbj_set_str(t->params, "label", "Other");
    CHECK(!sbw_routing_change(t->identity, t->params, false,
                              &t->error)); /* overlaps domains/process */
    sbj_set_str(t->params, "id", "custom-work");
    sbj_set(t->params, "domains", sbj_parse_cstr("[\"BAD.example\"]"));
    CHECK(!sbw_routing_change(t->identity, t->params, false, &t->error));
    sbj_set(t->params, "domains", sbj_parse_cstr("[\"changed.example\"]"));
    sbj_set(t->params, "processes", sbj_parse_cstr("[\"C:\\\\bad.exe\"]"));
    CHECK(!sbw_routing_change(t->identity, t->params, false, &t->error));
    sbj_set(t->params, "processes", sbj_array());
    sbj_set_str(t->params, "mode", "default");
    sbj_del(t->params, "node");
    t->changed = sbw_routing_change(t->identity, t->params, false, &t->error);
    CHECK(t->changed);
    sbj_free(t->identity);
    t->identity = t->changed;
    t->runtime = sbw_routing_apply(t->source, t->identity, true, &t->error);
    CHECK(t->runtime);
    sbj_free(t->runtime);
    sbj_free(t->params);
    t->params = sbj_parse_cstr("{\"id\":\"custom-work\"}");
    t->changed = sbw_routing_change(t->identity, t->params, true, &t->error);
    CHECK(t->changed && !sbj_arr_len(sbj_get(t->changed, "windows_local_groups")));
    CHECK(!sbw_routing_change(t->changed, t->params, true, &t->error));
    sbj_free(t->changed);
    sbj_free(t->params);
}

static void scenario_automatic_groups(test_state *t) {
    /* Automatic groups restrict both traffic and DNS to explicit leaf proxies. */
    sbj_free(t->identity);
    t->identity = sbj_object();
    t->cfg = sbj_parse_cstr(fixture);
    t->nodes = sbj_get(t->cfg, "outbounds");
    sbj_set_str(sbj_arr_at(t->nodes, 0), "server", "a.example");
    sbj_set_str(sbj_arr_at(t->nodes, 1), "server", "b.example");
    sbj_arr_push(t->nodes, sbj_parse_cstr("{\"type\":\"direct\",\"tag\":\"direct\"}"));
    sbj_arr_push(
        t->nodes,
        sbj_parse_cstr("{\"type\":\"selector\",\"tag\":\"nested\",\"outbounds\":[\"a\",\"b\"]}"));
    sbj_set(t->source, "content", sbj_str_take(sbj_dump(t->cfg, -1)));
    sbj_free(t->cfg);
    t->params = sbj_parse_cstr("{\"group\":\"default\",\"candidates\":[\"a\",\"b\"]}");
    t->changed = sbw_routing_automatic(t->source, t->identity, t->params, &t->error);
    CHECK(t->changed);
    CHECK(!sbj_get(t->identity, "windows_routing"));
    sbj_free(t->identity);
    t->identity = t->changed;
    t->runtime = sbw_routing_apply(t->source, t->identity, true, &t->error);
    CHECK(t->runtime);
    t->cfg = sbj_parse_cstr(sbj_get_str(t->runtime, "content", ""));
    t->nodes = sbj_get(t->cfg, "outbounds");
    bool selector_found = false, dns_found = false;
    for (size_t i = 0; i < sbj_arr_len(t->nodes); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(t->nodes, i), "tag"), SBW_DEFAULT_SELECTOR)) {
            sbj *members = sbj_get(sbj_arr_at(t->nodes, i), "outbounds");
            CHECK(sbj_arr_len(members) == 2);
            CHECK(sbj_string_is(sbj_arr_at(members, 0), "a") &&
                  sbj_string_is(sbj_arr_at(members, 1), "b"));
            selector_found = true;
        }
    t->servers = sbj_get(sbj_get(t->cfg, "dns"), "servers");
    for (size_t i = 0; i < sbj_arr_len(t->servers); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(t->servers, i), "tag"), "sb-easy-local-default-dns")) {
            CHECK(
                sbj_string_is(sbj_get(sbj_arr_at(t->servers, i), "detour"), SBW_DEFAULT_SELECTOR));
            dns_found = true;
        }
    CHECK(selector_found && dns_found);
    sbj_free(t->cfg);
    sbj_free(t->runtime);
    const char *invalid_candidates[] = {"[\"direct\"]", "[\"nested\"]", "[\"unknown\"]",
                                        "[\"a\",\"a\"]", "[]"};
    for (size_t i = 0; i < sizeof invalid_candidates / sizeof *invalid_candidates; ++i) {
        sbj_set(t->params, "candidates", sbj_parse_cstr(invalid_candidates[i]));
        CHECK(!sbw_routing_automatic(t->source, t->identity, t->params, &t->error));
    }
    sbj_set(t->params, "candidates", sbj_parse_cstr("[\"b\"]"));
    sbj *policy = sbw_health_policy(t->identity);
    sbj_set_bool(policy, "enabled", false);
    CHECK(!sbw_health_change(t->identity, policy, &t->error));
    sbj_free(policy);
    /* Losing every allowed node rejects the candidate; caller keeps last good. */
    t->cfg = sbj_parse_cstr(sbj_get_str(t->source, "content", ""));
    sbj_set(t->cfg, "outbounds",
            sbj_parse_cstr("[{\"type\":\"http\",\"tag\":\"unlisted\",\"server\":\"x.example\"}]"));
    sbj_set(t->source, "content", sbj_str_take(sbj_dump(t->cfg, -1)));
    sbj_free(t->cfg);
    CHECK(!sbw_routing_apply(t->source, t->identity, true, &t->error));
}

static const struct {
    const char *name;
    void (*run)(test_state *);
} scenarios[] = {
    {"groups_and_choices", scenario_groups_and_choices},
    {"effective_config", scenario_effective_config},
    {"server_mode_and_rejections", scenario_server_mode_and_rejections},
    {"custom_group", scenario_custom_group},
    {"protected_rules", scenario_protected_rules},
    {"custom_group_validation", scenario_custom_group_validation},
    {"automatic_groups", scenario_automatic_groups},
};

int main(void) {
    test_state state = {0};
    test_state *t = &state;
    t->source = sbj_object();
    t->identity = sbj_object();
    sbj_set_str(t->source, "content", fixture);
    t->before = sbj_clone(t->source);
    for (size_t i = 0; i < sizeof scenarios / sizeof *scenarios; ++i)
        scenarios[i].run(t);
    sbj_free(t->params);
    free(t->other);
    sbj_free(t->source);
    sbj_free(t->before);
    sbj_free(t->identity);
    puts("Unified routing: default/Claude/GPT/custom groups, isolated DNS, migration and rejection "
         "passed.");
    return 0;
}
