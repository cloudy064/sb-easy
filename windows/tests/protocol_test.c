#include "test_support.h"
#include "../service/protocol.h"
static sbj *exchange(const char *input) {
    char *reply = sbw_handle_request(input, strlen(input), NULL, false);
    CHECK(reply); sbj *json = sbw_json_parse(reply, strlen(reply), 32, NULL); free(reply); CHECK(json); return json;
}
static sbj *request(const char *method) {
    char *input = sb_asprintf("{\"id\":\"test\",\"version\":1,\"method\":\"%s\",\"params\":{}}", method);
    sbj *reply = exchange(input); free(input); return reply;
}
static void error_is(const char *input, const char *expected) {
    sbj *reply = exchange(input); CHECK(!sbj_get_bool(reply, "ok", true));
    CHECK(sb_streq(sbj_get_str(sbj_get(reply, "error"), "code", ""), expected)); sbj_free(reply);
}
int main(void) {
    sbj *reply = request("protocol.hello"), *result = sbj_get(reply, "result");
    CHECK(sbj_get_bool(reply, "ok", false) && sbj_arr_len(sbj_get(result, "supported_methods")) == 3);
    CHECK(!sbj_get_bool(sbj_get(result, "features"), "vpn", true) && !sbj_get_bool(sbj_get(result, "features"), "config_sync", true)); sbj_free(reply);
    reply = request("status.get"); result = sbj_get(reply, "result");
    CHECK(sb_streq(sbj_get_str(result, "phase", ""), "UNENROLLED") && !sbj_get_bool(result, "enrolled", true) && !sbj_get_bool(result, "core_running", true)); sbj_free(reply);
    const char *mutations[] = {"vpn.start", "enrollment.apply", "unknown"};
    for (size_t i = 0; i < 3; ++i) { reply = request(mutations[i]); CHECK(sb_streq(sbj_get_str(sbj_get(reply, "error"), "code", ""), "NOT_IMPLEMENTED")); sbj_free(reply); }
    const char *invalid[] = {"", "{", "null", "[]", "{}", "{\"id\":4,\"version\":1,\"method\":\"status.get\"}",
        "{\"id\":\"a\",\"version\":1,\"method\":\"status.get\",\"params\":[]}",
        "{\"id\":\"a\\u0000b\",\"version\":1,\"method\":\"status.get\"}",
        "{\"id\":\"a\",\"version\":1,\"method\":\"status.get\\u0000evil\"}"};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) error_is(invalid[i], "INVALID_REQUEST");
    error_is("{\"id\":\"a\",\"version\":2,\"method\":\"status.get\"}", "UNSUPPORTED_VERSION");
    error_is("{\"id\":\"a\",\"version\":18446744073709551615,\"method\":\"status.get\"}", "UNSUPPORTED_VERSION");
    char depth[130]; memset(depth, '[', 64); depth[64] = '0'; memset(depth + 65, ']', 64); depth[129] = '\0';
    error_is(depth, "INVALID_REQUEST");
    char *large = sb_xmalloc(SBW_MAX_FRAME + 2); memset(large, ' ', SBW_MAX_FRAME + 1); large[SBW_MAX_FRAME + 1] = 0;
    error_is(large, "INVALID_REQUEST"); free(large);
    error_is("{\"id\":\"\xff\"}", "INVALID_REQUEST");
    /* Shared C JSON retains escaped Unicode, embedded quotes and exact integers. */
    const char *unicode = "{\"name\":\"中 🚀 café\",\"int\":18446744073709551615,\"float\":1.25}";
    sbj *json = sbw_json_parse(unicode, strlen(unicode), 32, NULL); CHECK(json);
    char *serialized = sbj_dump(json, -1); sbj *copy = sbw_json_parse(serialized, strlen(serialized), 32, NULL);
    CHECK(sbj_equal(json, copy)); sbj_free(json); sbj_free(copy); free(serialized);
    puts("C protocol and shared JSON validation passed."); return 0;
}
