#include "test.h"
#include "../src/http_internal.h"

static sbj *release(const char *tag, bool preview) {
    sbj *r = sbj_object(), *assets = sbj_array();
    sbj_set(r, "assets", assets);
    sbj_set_str(r, "tag_name", tag);
    sbj_set_bool(r, "draft", false);
    sbj_set_bool(r, "prerelease", preview);
    char *apk = sb_asprintf("sb-easy-%s-arm64-v8a.apk", tag);
    const char *names[] = {"sb-easy-android-catalog.json", apk};
    for (size_t i = 0; i < 2; ++i) {
        sbj *a = sbj_object();
        sbj_set_str(a, "name", names[i]);
        sbj_set_str(a, "state", "uploaded");
        sbj_set(a, "browser_download_url", sbj_str_take(sb_asprintf("https://github.com/cloudy064/sb-easy/releases/download/%s/%s", tag, names[i])));
        sbj_arr_push(assets, a);
    }
    free(apk);
    return r;
}

TEST(newest_stable_android_tag_across_pages_and_checked_asset_urls) {
    sbj *page = sbj_array(), *latest = NULL;
    sbj_arr_push(page, release("android-v1.9.3", false));
    sbj_arr_push(page, release("windows-v2.0.0", false));
    sbj_arr_push(page, release("android-v3.0.0", true));
    sbj *draft = release("android-v4.0.0", false);
    sbj_set_bool(draft, "draft", true);
    sbj_arr_push(page, draft);
    sb_android_release_consider(page, &latest);
    CHECK_STR(sbj_get_str(latest, "tag", ""), "android-v1.9.3");
    sbj_arr_clear(page);
    sbj_arr_push(page, release("android-v1.10.0", false));
    sb_android_release_consider(page, &latest);
    CHECK_STR(sbj_get_str(latest, "tag", ""), "android-v1.10.0");
    CHECK_CONTAINS(sbj_get_str(latest, "arm64-v8a", ""), "android-v1.10.0-arm64-v8a.apk");
    sbj *bad = release("android-v1.11.0", false);
    sbj_set_str(sbj_arr_at(sbj_get(bad, "assets"), 0), "browser_download_url", "https://example.org/catalog");
    sbj_arr_push(page, bad);
    sb_android_release_consider(page, &latest);
    CHECK(!sbj_get_str(latest, "catalog_url", NULL));
    sbj_free(latest);
    sbj_free(page);
}

TEST(device_abi_order_and_universal_fallback) {
    sb_http_server srv = {0};
    pthread_mutex_init(&srv.android_release_mutex, NULL);
    srv.android_release_retry_ms = INT64_MAX;
    srv.android_release = sbj_parse_cstr("{\"tag\":\"android-v1.4.1\",\"catalog_url\":\"catalog\",\"x86\":\"32bit\",\"universal\":\"all\"}");
    sb_http_req req = {.server = &srv, .params = {"x86_64,x86"}};
    sb_http_resp resp = {0};
    sb_err err = {0};
    CHECK(sb_http_android_update(&req, &resp, &err) == 0);
    CHECK_STR(sbj_get_str(resp.json, "apk_url", ""), "32bit");
    req.params[0] = "arm64-v8a";
    CHECK(sb_http_android_update(&req, &resp, &err) == 0);
    CHECK_STR(sbj_get_str(resp.json, "apk_url", ""), "all");
    req.params[0] = "invalid";
    CHECK(sb_http_android_update(&req, &resp, &err) < 0 && err.code == SB_ERR_VALIDATION);
    sbj_free(resp.json);
    sbj_free(srv.android_release);
    pthread_mutex_destroy(&srv.android_release_mutex);
}
