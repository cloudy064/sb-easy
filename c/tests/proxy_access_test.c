#include "test.h"
#include "sb/proxy_access.h"
#include "sb/agent_config.h"
#include <stdlib.h>
#include <string.h>

static sbj *fixture(void) {
    return sbj_parse_cstr("{\"inbounds\":[{\"tag\":\"sb-easy-access\",\"type\":\"mixed\",\"listen_port\":1081,"
        "\"users\":[{\"username\":\"google\",\"password\":\"test-secret\"}]}],"
        "\"outbounds\":[{\"type\":\"selector\",\"tag\":\"Google\"}],\"route\":{\"rules\":["
        "{\"inbound\":\"sb-easy-access\",\"auth_user\":\"google\",\"action\":\"route\",\"outbound\":\"Google\"},"
        "{\"domain_suffix\":[\"google.com\"],\"outbound\":\"Other\"}]}}");
}
TEST(access_restores_routes_after_script_and_rejects_fallthrough) {
    sbj *src = fixture(), *dst = sbj_clone(src); sb_err err = {0};
    sbj_set(sbj_get(dst, "route"), "rules", sbj_parse_cstr("[{\"outbound\":\"Other\"}]"));
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, true, &err), 0);
    sbj *rules = sbj_get(sbj_get(dst, "route"), "rules");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 0), "outbound", ""), "Google");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 1), "action", ""), "reject");
    CHECK_EQ_INT(sbj_arr_len(rules), 3);
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, true, &err), 0);
    CHECK_EQ_INT(sbj_arr_len(rules), 3);
    sbj_free(src); sbj_free(dst);
}
TEST(access_missing_target_empty_credentials_and_duplicate_users_fail_closed) {
    sbj *src = fixture(), *dst = sbj_clone(src); sb_err err = {0};
    sbj_set(dst, "outbounds", sbj_array());
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, true, &err), -1);
    sbj *users = sbj_get(sbj_arr_at(sbj_get(src, "inbounds"), 0), "users");
    sbj_set_str(sbj_arr_at(users, 0), "password", "");
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, false, &err), -1);
    sbj_set_str(sbj_arr_at(users, 0), "password", "secret");
    sbj_arr_push(users, sbj_clone(sbj_arr_at(users, 0)));
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, false, &err), -1);
    sbj_arr_clear(users);
    CHECK_EQ_INT(sb_proxy_access_apply(src, dst, false, &err), -1);
    sbj_free(src); sbj_free(dst);
}
TEST(access_precedes_agent_local_domain_overrides) {
    sbj *src = fixture(); sb_err err = {0};
    CHECK_EQ_INT(sb_proxy_access_apply(src, src, true, &err), 0);
    char *body = sbj_dump(src, -1);
    sb_agent_config_options o; sb_agent_config_options_init(&o);
    o.local_proxy_egress = false;
    sbj_arr_push(o.local_route_rules, sbj_parse_cstr("{\"domain_keyword\":[\"google\"],\"outbound\":\"Other\"}"));
    char *result = sb_prepare_agent_config(body, strlen(body), &o, &err);
    REQUIRE(result);
    sbj *dst = sbj_parse_cstr(result); sbj *rules = sbj_get(sbj_get(dst, "route"), "rules");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 0), "outbound", ""), "Google");
    CHECK_STR(sbj_get_str(sbj_arr_at(rules, 1), "action", ""), "reject");
    CHECK(sbj_has(sbj_arr_at(rules, 2), "domain_keyword"));
    free(result); free(body); sbj_free(src); sbj_free(dst); sb_agent_config_options_free(&o);
}

TEST(outbound_rename_does_not_change_proxy_identity_or_secret) {
    sbj *src = fixture(); sb_err err = {0};
    sbj *user = sbj_arr_at(sbj_get(sbj_arr_at(sbj_get(src, "inbounds"), 0), "users"), 0);
    sbj_set_str(user, "username", "Google"); sbj_set_str(user, "password", "Google");
    sbj_set_str(sbj_arr_at(sbj_get(sbj_get(src, "route"), "rules"), 0), "auth_user", "Google");
    char *body = sbj_dump(src, -1);
    sb_agent_config_options o; sb_agent_config_options_init(&o);
    sbj_set(o.outbound_overrides, "Google", sbj_parse_cstr("{\"tag\":\"renamed\",\"type\":\"direct\"}"));
    char *result = sb_prepare_agent_config(body, strlen(body), &o, &err); REQUIRE(result);
    sbj *dst = sbj_parse_cstr(result);
    user = sbj_arr_at(sbj_get(sbj_arr_at(sbj_get(dst, "inbounds"), 0), "users"), 0);
    CHECK_STR(sbj_get_str(user, "username", ""), "Google");
    CHECK_STR(sbj_get_str(user, "password", ""), "Google");
    sbj *rule = sbj_arr_at(sbj_get(sbj_get(dst, "route"), "rules"), 0);
    CHECK_STR(sbj_get_str(rule, "auth_user", ""), "Google");
    CHECK_STR(sbj_get_str(rule, "outbound", ""), "renamed");
    free(result); free(body); sbj_free(src); sbj_free(dst); sb_agent_config_options_free(&o);
}

TEST(fixed_outbound_ignores_local_server_and_outbound_replacements) {
    const char *body = "{\"outbounds\":[{\"type\":\"http\",\"tag\":\"sb-easy-node-id\",\"server\":\"original\",\"server_port\":8080}]}";
    sb_agent_config_options o; sb_agent_config_options_init(&o);
    sbj_set(o.outbound_overrides, "sb-easy-node-id", sbj_parse_cstr("{\"type\":\"direct\",\"tag\":\"other\"}"));
    sbj_set_str(o.outbound_server_overrides, "sb-easy-node-id", "replacement");
    sb_err err = {0}; char *result = sb_prepare_agent_config(body, strlen(body), &o, &err); REQUIRE(result);
    CHECK_STR(result, body); free(result); sb_agent_config_options_free(&o);
}
