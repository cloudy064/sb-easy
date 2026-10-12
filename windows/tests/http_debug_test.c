#include "test_support.h"
#include "../service/http_debug.h"
int main(void) {
    const char *source="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"vpn\"}],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"normal\"}],\"route\":{\"rules\":[{\"domain_suffix\":[\"example.com\"],\"outbound\":\"normal\"}],\"final\":\"normal\"}}";
    sbj *domains=sbj_array();sbj_arr_push(domains,sbj_str("example.com"));sbw_error error={0};
    char password[65];memset(password,'a',64);password[64]=0;
    char *json=sbw_http_debug_overlay(source,domains,password,&error);CHECK(json);
    sbj *root=sbj_parse_cstr(json),*rules=sbj_get(sbj_get(root,"route"),"rules");
    CHECK(sbj_arr_len(rules)==4);CHECK(sbj_string_is(sbj_get(sbj_arr_at(rules,0),"action"),"sniff"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(rules,2),"inbound"),0),"vpn"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(rules,3),"outbound"),"normal"));
    CHECK(!sbw_http_debug_overlay(json,domains,password,&error));
    sbj_arr_push(domains,sbj_str("https://example.com"));CHECK(!sbw_http_debug_overlay(source,domains,password,&error));
    sbj_free(domains);sbj_free(root);free(json);puts("HTTP debugging targets TUN only and preserves the normal upstream route.");return 0;
}
