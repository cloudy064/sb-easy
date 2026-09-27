#include "test.h"

#include "sb/json.h"
#include "sb/script_engine.h"
#include "sb/util.h"

TEST(quickjs_builds_json_route_rules) {
    sb_rule_script_engine engine;
    REQUIRE(sb_rule_script_engine_init(&engine, NULL, NULL) == 0);
    sbj *context = sbj_parse_cstr("{\"outboundTags\":[\"hk\",\"direct\"],\"currentRules\":[]}");
    sb_err err = {0};
    sbj *rules = sb_rule_script_engine_build_rules(
        &engine,
        "\nfunction buildRules(context) {\n  return [{\n    domain_suffix: [\".example.com\"],\n"
        "    outbound: context.outboundTags.includes(\"hk\") ? \"hk\" : \"direct\"\n  }];\n}\n",
        context, &err);
    REQUIRE(rules != NULL);
    CHECK_EQ_INT(sbj_arr_len(rules), 1);
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 0), "outbound", NULL), "hk");
    sbj_free(rules);
    sbj_free(context);
}

TEST(quickjs_counts_source_bytes_after_embedded_nul) {
    const char source[] = "function buildRules() { return [{value:'left\0right'}]; }";
    sb_script_limits limits = sb_script_limits_default();
    limits.source_bytes = sizeof source - 2;
    sb_rule_script_engine engine;
    REQUIRE(sb_rule_script_engine_init(&engine, &limits, NULL) == 0);
    sb_err err = {0};
    sbj *rules = sb_rule_script_engine_build_rules_n(&engine, source, sizeof source - 1, NULL, &err);
    CHECK(rules == NULL);
    CHECK_STR(err.msg, "rule script exceeds the configured source limit");
    limits.source_bytes++;
    REQUIRE(sb_rule_script_engine_init(&engine, &limits, NULL) == 0);
    char unterminated[sizeof source - 1];
    memcpy(unterminated, source, sizeof unterminated);
    rules = sb_rule_script_engine_build_rules_n(&engine, unterminated, sizeof unterminated, NULL, &err);
    REQUIRE(rules);
    sbj *expected = sbj_strn("left\0right", 10);
    CHECK(sbj_equal(sbj_get(sbj_arr_at(rules, 0), "value"), expected));
    sbj_free(expected);
    sbj_free(rules);
}

TEST(quickjs_interrupts_infinite_loops) {
    sb_script_limits limits = sb_script_limits_default();
    limits.timeout_ms = 20;
    sb_rule_script_engine engine;
    REQUIRE(sb_rule_script_engine_init(&engine, &limits, NULL) == 0);
    int64_t started = sb_monotonic_ms();
    sbj *context = sbj_object();
    sb_err err = {0};
    sbj *rules = sb_rule_script_engine_build_rules(
        &engine, "function buildRules() { while (true) {} }", context, &err);
    CHECK(rules == NULL);
    CHECK(err.code == SB_ERR_SCRIPT);
    CHECK(sb_monotonic_ms() - started < 1000);
    sbj_free(rules);
    sbj_free(context);
}

TEST(quickjs_disables_nondeterministic_globals) {
    sb_rule_script_engine engine;
    REQUIRE(sb_rule_script_engine_init(&engine, NULL, NULL) == 0);
    sbj *context = sbj_object();
    sb_err err = {0};
    sbj *rules = sb_rule_script_engine_build_rules(
        &engine, "function buildRules() { Math.random(); return []; }", context, &err);
    CHECK(rules == NULL);
    CHECK(err.code == SB_ERR_SCRIPT);
    CHECK_CONTAINS(err.msg, "<sb-easy-bootstrap>"); /* C++ reports the stack only */
    sbj_free(rules);
    sbj_free(context);
}

TEST(quickjs_enforces_its_memory_limit) {
    sb_script_limits limits = sb_script_limits_default();
    limits.memory_bytes = 4U * 1024U * 1024U;
    limits.timeout_ms = 500;
    sb_rule_script_engine engine;
    REQUIRE(sb_rule_script_engine_init(&engine, &limits, NULL) == 0);
    sbj *context = sbj_object();
    sb_err err = {0};
    sbj *rules = sb_rule_script_engine_build_rules(
        &engine,
        "\nfunction buildRules() {\n  const values = [];\n  while (true) {\n"
        "    values.push(\"x\".repeat(65536));\n  }\n}\n",
        context, &err);
    CHECK(rules == NULL);
    CHECK(err.code == SB_ERR_SCRIPT);
    sbj_free(rules);
    sbj_free(context);
}

/* Additional C-specific coverage of the validation paths. */
TEST(quickjs_validates_limits_and_output) {
    sb_script_limits limits = sb_script_limits_default();
    limits.timeout_ms = 0;
    sb_rule_script_engine engine;
    sb_err err = {0};
    CHECK(sb_rule_script_engine_init(&engine, &limits, &err) == -1);
    CHECK_STR(err.msg, "QuickJS limits must all be positive");
    REQUIRE(sb_rule_script_engine_init(&engine, NULL, NULL) == 0);
    sbj *context = sbj_object();
    struct { const char *src; const char *msg; } cases[] = {
        {"", "rule script is empty"},
        {"var x = 1;", "rule script must define function buildRules(context)"},
        {"function buildRules() { return undefined; }", "buildRules(context) returned undefined"},
        {"function buildRules() { return {}; }", "buildRules(context) must return an array"},
        {"function buildRules() { return [1]; }", "each generated rule must be a JSON object"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        sb_err_clear(&err);
        sbj *rules = sb_rule_script_engine_build_rules(&engine, cases[i].src, context, &err);
        CHECK(rules == NULL);
        CHECK(err.code == SB_ERR_SCRIPT);
        CHECK_STR(err.msg, cases[i].msg);
        sbj_free(rules);
    }
    sb_err_clear(&err);
    sbj *rules = sb_rule_script_engine_build_rules(&engine, "function buildRules() { return typeof Date; }", context, &err);
    CHECK(rules == NULL);
    CHECK_STR(err.msg, "buildRules(context) must return an array");
    sbj_free(context);
}
