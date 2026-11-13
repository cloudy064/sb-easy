#include "desktop.h"
#include "sb/http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (%s)\n", __FILE__, __LINE__, #x, err.msg); exit(1); } } while (0)
static sb_err err;
int main(int argc, char** argv) {
    CHECK(argc == 2);
    sbj* p = sbl_new_profile("Sync fixture");
    sbj_set_str(p, "mode", "managed"); sbj_set_str(p, "server", argv[1]); sbj_set_str(p, "token", "fixture-token");
    sbj_set_str(p, "host_id", "fixture-device"); bool changed = false;
    CHECK(!sbl_sync_profile(p, &changed, &err)); CHECK(changed); CHECK(!sbl_sync_pending(p));
    CHECK(sbj_get_int(sbj_get(p, "config_sync"), "patch_version", -1) == 0);
    sbj_set_int(p, "refresh_minutes", 60); sbj_set_bool(p, "system_proxy", true); CHECK(sbl_sync_pending(p));
    char* serialized = sbj_dump(p, -1); sbj_free(p); p = sbj_parse_cstr(serialized); free(serialized);
    CHECK(!sbl_sync_profile(p, &changed, &err)); CHECK(!sbl_sync_pending(p));
    CHECK(sbj_get_int(sbj_get(p, "config_sync"), "patch_version", 0) == 101);
    CHECK(sbj_get_bool(sbj_get(sbj_get(sbj_get(p, "config_sync"), "agent_settings"), "linux_preferences"), "system_proxy", false));
    sbj_set_int(p, "refresh_minutes", 1440);
    char* url = sb_asprintf("%s/fixture/change", argv[1]);
    sb_http_request request = {.url = url, .timeout_ms = 5000, .max_body_bytes = 1024}; sb_http_response response = {0};
    CHECK(!sb_http_perform(&request, &response, &err)); CHECK(response.status == 200); sb_http_response_free(&response); free(url);
    CHECK(sbl_sync_profile(p, &changed, &err) == -1 && err.code == SB_ERR_CONFLICT); CHECK(sbl_sync_pending(p));
    CHECK(!sbl_sync_resolve_profile(p, true, &changed, &err)); CHECK(!sbl_sync_pending(p));
    CHECK(sbj_get_int(p, "refresh_minutes", 0) == 1440);
    sbj_set_int(p, "refresh_minutes", 60); sbj_set_bool(p, "system_proxy", false); CHECK(sbl_sync_pending(p));
    CHECK(!sbl_sync_resolve_profile(p, false, &changed, &err)); CHECK(!sbl_sync_pending(p));
    CHECK(sbj_get_int(p, "refresh_minutes", 0) == 1440); CHECK(sbj_get_bool(p, "system_proxy", false));
    /* An initialized empty server policy wins over a stale legacy cache. */
    sbj_del(p, "config_sync"); sbj_set_int(p, "refresh_minutes", 60);
    CHECK(!sbl_sync_profile(p, &changed, &err)); CHECK(sbj_get_int(p, "refresh_minutes", 0) == 1440);
    url = sb_asprintf("%s/fixture/invalid-proxy", argv[1]); request.url = url;
    CHECK(!sb_http_perform(&request, &response, &err)); CHECK(response.status == 200); sb_http_response_free(&response); free(url);
    CHECK(sbl_sync_profile(p, &changed, &err) == -1 && err.code == SB_ERR_VALIDATION);
    CHECK(sbj_get_bool(p, "system_proxy", false)); CHECK(!sbl_sync_pending(p));
    sbj_free(p); puts("Linux config sync tests passed"); return 0;
}
