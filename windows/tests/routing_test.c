#include "test_support.h"
#include "../service/routing.h"
static const char *fixture =
 "{\"outbounds\":[{\"tag\":\"default\",\"type\":\"socks\",\"server\":\"127.0.0.1\",\"server_port\":1080}],"
 "\"route\":{\"final\":\"default\",\"rules\":[{\"domain_suffix\":[\"openai.com\",\"chatgpt.com\"],\"outbound\":\"broken\"}]},"
 "\"dns\":{\"servers\":[{\"type\":\"https\",\"tag\":\"shared\",\"server\":\"1.1.1.1\",\"detour\":\"broken\"}],"
 "\"rules\":[{\"domain_suffix\":[\"openai.com\",\"chatgpt.com\"],\"server\":\"shared\"},{\"domain_suffix\":[\"claude.ai\"],\"server\":\"shared\"}]}}";
int main(void) {
 sbj *source = sbj_object(); sbj_set_str(source, "content", fixture); sbj_set_str(source, "etag", "server-revision");
 sbj *before = sbj_clone(source); sbw_error error = {0};
 sbj *effective = sbw_routing_snapshot(source, true, &error); CHECK(effective && sbj_equal(before, source));
 CHECK(sb_streq(sbj_get_str(effective, "etag", ""), "server-revision"));
 sbj *config = sbj_parse_cstr(sbj_get_str(effective, "content", ""));
 sbj *dns = sbj_get(config, "dns"), *servers = sbj_get(dns, "servers"), *rules = sbj_get(dns, "rules");
 CHECK(sbj_arr_len(servers) == 2);
 CHECK(sb_streq(sbj_get_str(sbj_arr_at(servers, 0), "detour", ""), "broken"));
 CHECK(sb_streq(sbj_get_str(sbj_arr_at(servers, 1), "detour", ""), "default"));
 CHECK(sb_streq(sbj_get_str(sbj_arr_at(rules, 1), "server", ""), "shared"));
 CHECK(sb_streq(sbj_get_str(sbj_arr_at(rules, 0), "server", ""), "sb-easy-windows-gpt-dns"));
 CHECK(sb_streq(sbj_get_str(sbj_arr_at(sbj_get(sbj_get(config, "route"), "rules"), 0), "outbound", ""), "default"));
 sbj *reset = sbw_routing_snapshot(source, false, &error); CHECK(sbj_equal(reset, source)); sbj_free(reset);
 /* A reserved DNS tag collision must never produce a partially patched config. */
 CHECK(!sbw_routing_snapshot(effective, true, &error));
 CHECK(sb_streq(error.code, "GPT_ROUTING_UNSUPPORTED"));
 sbj_free(config); sbj_free(effective);
 config = sbj_parse_cstr(fixture);
 sbj_set_bool(sbj_arr_at(sbj_get(sbj_get(config, "route"), "rules"), 0), "invert", true);
 sbj_set(source, "content", sbj_str_take(sbj_dump(config, -1))); sbj_free(config);
 CHECK(!sbw_routing_snapshot(source, true, &error));
 config = sbj_parse_cstr(fixture);
 sbj_arr_push(sbj_get(sbj_arr_at(sbj_get(sbj_get(config, "dns"), "rules"), 0), "domain_suffix"), sbj_str("claude.ai"));
 sbj_set(source, "content", sbj_str_take(sbj_dump(config, -1))); sbj_free(config);
 CHECK(!sbw_routing_snapshot(source, true, &error));
 sbj_free(source); sbj_free(before);
 puts("GPT routing: route/DNS consistency, shared DNS isolation, source preservation and unsupported shapes passed."); return 0;
}
