#include "test_support.h"
#include "../service/dashboard.h"

int main(void) {
    sbj *snapshot = sbj_object();
    sbj_set_str(snapshot, "etag", "catalog-1");
    sbj_set_str(snapshot, "content", "{\"outbounds\":[{\"type\":\"trojan\",\"tag\":\"Tokyo\",\"password\":\"secret-proxy-value\",\"tls\":{\"private_key\":\"private-agent-token\"}},{\"type\":\"selector\",\"tag\":\"Default\",\"default\":\"Tokyo\",\"outbounds\":[\"Tokyo\"]}],\"route\":{\"final\":\"Default\",\"rules\":[{\"domain_suffix\":[\"example.test\"],\"outbound\":\"Tokyo\",\"secret\":\"secret-proxy-value\"}]},\"experimental\":{\"clash_api\":{\"secret\":\"private-agent-token\"}}}");
    sbj *catalog = sbw_config_catalog(snapshot); test_redacted(catalog);
    CHECK(sbj_get_int(catalog, "node_count", 0) == 2);
    CHECK(sb_streq(sbj_get_str(catalog, "final", ""), "Default"));
    CHECK(strstr(sbj_get_str(sbj_arr_at(sbj_get(catalog, "rules"), 0), "match", ""), "example.test"));
    sbj_free(catalog); sbj_free(snapshot);
    CHECK(sbj_is_null(catalog = sbw_config_catalog(NULL))); sbj_free(catalog);

    sbj *connections = sbj_parse_cstr("{\"uploadTotal\":1024,\"downloadTotal\":2048,\"connections\":[{\"id\":\"test-1\",\"metadata\":{\"host\":\"example.test\",\"destinationPort\":\"443\",\"processPath\":\"C:/private-user/app.exe\",\"network\":\"tcp\",\"secret\":\"private-agent-token\"},\"chains\":[\"Tokyo\"],\"upload\":512,\"download\":1024,\"rule\":\"final\"}]}");
    sbj *proxies = sbj_parse_cstr("{\"proxies\":{\"GLOBAL\":{\"name\":\"GLOBAL\"},\"Default\":{\"name\":\"Default\",\"type\":\"Selector\",\"now\":\"Tokyo\",\"all\":[\"Tokyo\"],\"history\":[{\"delay\":42}],\"password\":\"secret-proxy-value\"}}}");
    sbj *result = sbw_dashboard_snapshot(connections, proxies); test_redacted(result);
    CHECK(sbj_get_int(result, "connection_count", 0) == 1 && sbj_get_int(result, "download_total", 0) == 2048);
    CHECK(sb_streq(sbj_get_str(sbj_arr_at(sbj_get(result, "connections"), 0), "process", ""), "app.exe"));
    CHECK(sbj_get_int(sbj_arr_at(sbj_get(result, "nodes"), 0), "delay", 0) == 42);
    char *serialized = sbj_dump(result, -1); CHECK(!strstr(serialized, "private-user")); free(serialized); sbj_free(result);
    /* Bounds stay below a frame even with maximal rows, nested/secret extras. */
    sbj *rows = sbj_get(connections, "connections");
    for (size_t i = 0; i < 300; ++i) sbj_arr_push(rows, sbj_clone(sbj_arr_at(rows, 0)));
    result = sbw_dashboard_snapshot(connections, proxies);
    CHECK(sbj_get_int(result, "connection_count", 0) == 301 && sbj_arr_len(sbj_get(result, "connections")) == 128);
    serialized = sbj_dump(result, -1); CHECK(strlen(serialized) < 1048576); free(serialized);
    sbj_free(result); sbj_free(connections); sbj_free(proxies);
    test_data data; test_data_init(&data); sbw_controller *controller = test_controller(&data, NULL);
    sbj *params = sbj_object(); sbw_error error = {0};
    CHECK(!sbw_controller_dispatch(controller, "runtime.snapshot", params, false, &error) && sb_streq(error.code, "FORBIDDEN"));
    result = sbw_controller_dispatch(controller, "runtime.snapshot", params, true, &error);
    CHECK(result && !sbj_get_bool(result, "running", true)); test_redacted(result); sbj_free(result);
    sbj_set_str(params, "path", "/arbitrary-endpoint");
    CHECK(!sbw_controller_dispatch(controller, "runtime.snapshot", params, true, &error) && sb_streq(error.code, "INVALID_REQUEST"));
    sbj_free(params); sbw_controller_free(controller); test_data_free(&data);
    puts("Dashboard projections, redaction, collection bounds and authorization passed."); return 0;
}
