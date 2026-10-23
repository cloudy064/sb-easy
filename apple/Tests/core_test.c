#include "SBEasyCore.h"
#include "sb/json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *subscriptions =
    "[{\"id\":\"alpha\",\"nodes\":[{\"type\":\"trojan\",\"tag\":\"one\",\"server\":\"proxy.example\","
    "\"server_port\":443,\"password\":\"fixture\",\"tls\":{\"enabled\":true,\"server_name\":\"proxy."
    "example\"}}]}]";
static size_t find_rule(const sbj *rules, const char *key) {
    for (size_t i = 0; i < sbj_arr_len(rules); ++i)
        if (sbj_get(sbj_arr_at(rules, i), key))
            return i;
    return SIZE_MAX;
}
int main(int argc, char **argv) {
    char *error = NULL;
    const char *uri = "trojan://fixture@proxy.example:443?security=tls#one\ntrojan://"
                      "other@proxy.example:443?security=tls#one";
    char *import = sba_import_subscription(uri, strlen(uri), &error);
    assert(import && !error);
    sbj *j = sbj_parse_cstr(import);
    assert(sbj_arr_len(sbj_get(j, "nodes")) == 2);
    sbj_free(j);
    sba_free(import);
    const char *b64 = "dHJvamFuOi8vZml4dHVyZUBwcm94eS5leGFtcGxlOjQ0Mz9zZWN1cml0eT10bHMjb25l";
    import = sba_import_subscription(b64, strlen(b64), &error);
    assert(import && !error);
    sba_free(import);
    assert(!sba_import_subscription("garbage", 7, &error));
    sba_free(error);
    error = NULL;
    const char *settings = "{\"local_groups\":[{\"id\":\"work\",\"name\":\"Work\",\"domains\":[\"example."
                           "org\"],\"outbound\":\"local-alpha/one\"}]}";
    char *runtime = sba_build_runtime(NULL, subscriptions, settings, "", &error);
    assert(runtime && !error);
    j = sbj_parse_cstr(runtime);
    assert(sbj_arr_len(sbj_get(j, "inbounds")) == 1);
    assert(sbj_string_is(sbj_get(sbj_get(j, "route"), "final"), "sb-easy-apple-default"));
    sbj_free(j);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "wb");
        assert(f);
        assert(fwrite(runtime, 1, strlen(runtime), f) == strlen(runtime));
        assert(!fclose(f));
    }
    sba_free(runtime);
    const char *managed = "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"final\":"
                          "\"direct\",\"rules\":[{\"domain_suffix\":[\"central.test\"],\"outbound\":"
                          "\"direct\"},{\"ip_cidr\":[\"10.0.0.0/8\"],\"outbound\":\"direct\"}]}}";
    runtime = sba_build_runtime(managed, subscriptions, settings, "2001:db8::1", &error);
    assert(runtime && !error);
    j = sbj_parse_cstr(runtime);
    const sbj *rules = sbj_get(sbj_get(j, "route"), "rules");
    assert(find_rule(rules, "ip_cidr") < find_rule(rules, "domain_suffix"));
    assert(strstr(runtime, "2001:db8::1/128"));
    sbj_free(j);
    sba_free(runtime);
    assert(!sba_build_runtime(NULL, subscriptions, "{\"selected_tag\":\"missing\"}", "", &error));
    sba_free(error);
    error = NULL;
    assert(!sba_build_runtime(NULL, "[]", "{}", "", &error));
    sba_free(error);
    error = NULL;
    assert(!sba_build_runtime(managed, subscriptions, "{}", "999.999.999.999", &error));
    sba_free(error);
    error = NULL;
    assert(!sba_build_runtime("{\"services\":{}}", subscriptions, "{}", "", &error));
    sba_free(error);
    error = NULL;
    assert(
        !sba_build_runtime("{\"route\":{\"rule_set\":[{\"type\":\"local\",\"path\":\"/private/secret\"}]}}",
                           subscriptions, "{}", "", &error));
    sba_free(error);
    error = NULL;
    assert(!sba_validate_settings("{\"local_groups\":[{\"id\":\"a\",\"name\":\"A\",\"outbound\":\"x\","
                                  "\"domains\":[\"example.org\",\"sub.example.org\"]}]}",
                                  &error));
    sba_free(error);
    char *metadata = sba_subscription_metadata("upload=10; download=20; total=100; expire=200", 100);
    j = sbj_parse_cstr(metadata);
    assert(sbj_get_bool(j, "available", false));
    assert(sbj_get_int(j, "remaining_bytes", 0) == 70);
    sbj_free(j);
    sba_free(metadata);
    metadata = sba_subscription_metadata("upload=10; upload=20", 100);
    j = sbj_parse_cstr(metadata);
    assert(!sbj_get_bool(j, "available", true));
    sbj_free(j);
    sba_free(metadata);
    metadata = sba_subscription_metadata("expire=200", 100);
    j = sbj_parse_cstr(metadata);
    assert(sbj_get_bool(j, "available", false));
    assert(!sbj_get(j, "used_bytes") && !sbj_get(j, "remaining_bytes"));
    sbj_free(j);
    sba_free(metadata);
    /* A small YAML anchor must not expand a multi-megabyte proxy value. */
    sb_buf bomb = {0};
    sb_buf_puts(&bomb, "payload: &payload ");
    for (size_t i = 0; i < 16384; ++i)
        sb_buf_putc(&bomb, 'a');
    sb_buf_puts(&bomb, "\nproxies:\n- type: trojan\n  name: bounded\n  server: proxy.example\n  port: 443\n  "
                       "password: fixture\n  nested: [");
    for (size_t i = 0; i < 200; ++i)
        sb_buf_puts(&bomb, i ? ",*payload" : "*payload");
    sb_buf_puts(&bomb, "]\n");
    error = NULL;
    assert(!sba_import_subscription(bomb.p, bomb.len, &error));
    sba_free(error);
    sb_buf_free(&bomb);
    sb_buf_puts(&bomb, "trojan://fixture@proxy.example:443#one\n");
    for (size_t i = 0; i < 8193; ++i)
        sb_buf_puts(&bomb, "# comment\n");
    error = NULL;
    assert(!sba_import_subscription(bomb.p, bomb.len, &error));
    sba_free(error);
    sb_buf_free(&bomb);
    sb_buf_puts(&bomb, "proxies: [");
    for (size_t i = 0; i < 65; ++i)
        sb_buf_putc(&bomb, '[');
    sb_buf_puts(&bomb, "null");
    for (size_t i = 0; i < 66; ++i)
        sb_buf_putc(&bomb, ']');
    error = NULL;
    assert(!sba_import_subscription(bomb.p, bomb.len, &error));
    sba_free(error);
    sb_buf_free(&bomb);
    puts("Apple C runtime/import contracts passed");
    return 0;
}
