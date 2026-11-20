#include "http_internal.h"
#include "sb/http_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RELEASES_API "https://api.github.com/repos/cloudy064/sb-easy/releases"
#define RELEASE_BASE "https://github.com/cloudy064/sb-easy/releases/download/"
#define CATALOG_NAME "sb-easy-android-catalog.json"

static const char *const architectures[] = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86", "universal"};

/* Only stable Android tags participate. Compare numbers, including e.g. 1.10 vs 1.9. */
static int64_t release_number(const char *tag) {
    unsigned major, minor, patch;
    if (sscanf(tag, "android-v%6u.%6u.%6u", &major, &minor, &patch) != 3) return -1;
    char canonical[40];
    snprintf(canonical, sizeof canonical, "android-v%u.%u.%u", major, minor, patch);
    if (strcmp(tag, canonical) != 0) return -1;
    return ((int64_t)major * 1000000 + minor) * 1000000 + patch;
}

static const char *uploaded(const sbj *assets, const char *tag, const char *name) {
    char *expected = sb_asprintf(RELEASE_BASE "%s/%s", tag, name);
    const char *found = NULL;
    for (size_t i = 0; i < sbj_arr_len(assets); ++i) {
        const sbj *asset = sbj_arr_at(assets, i);
        const char *url = sbj_get_str(asset, "browser_download_url", "");
        if (strcmp(sbj_get_str(asset, "name", ""), name) == 0 &&
            strcmp(sbj_get_str(asset, "state", ""), "uploaded") == 0 && strcmp(expected, url) == 0) {
            found = url;
            break;
        }
    }
    free(expected);
    return found;
}

void sb_android_release_consider(const sbj *page, sbj **latest) {
    for (size_t i = 0; i < sbj_arr_len(page); ++i) {
        const sbj *release = sbj_arr_at(page, i);
        if (sbj_get_bool(release, "draft", true) || sbj_get_bool(release, "prerelease", true)) continue;
        const char *tag = sbj_get_str(release, "tag_name", "");
        int64_t version = release_number(tag);
        if (version <= sbj_get_int(*latest, "number", -1)) continue;
        const sbj *assets = sbj_get(release, "assets");
        sbj *row = sbj_object();
        sbj_set_int(row, "number", version);
        sbj_set_str(row, "tag", tag);
        sbj_set_str(row, "catalog_url", uploaded(assets, tag, CATALOG_NAME));
        for (size_t a = 0; a < sizeof architectures / sizeof *architectures; ++a) {
            const char *abi = architectures[a];
            char *name = sb_asprintf("sb-easy-android-%s-%s.apk", tag + strlen("android-"), abi);
            const char *url = uploaded(assets, tag, name);
            if (url) sbj_set_str(row, abi, url);
            free(name);
        }
        sbj_free(*latest);
        *latest = row; /* Keep an incomplete newer release visible as an error. */
    }
}

static sbj *fetch_latest(void) {
    sbj *latest = NULL;
    int64_t deadline = sb_monotonic_ms() + 15000;
    for (unsigned page = 1; page <= 8; ++page) {
        int64_t remaining = deadline - sb_monotonic_ms();
        if (remaining <= 0) break;
        char url[160];
        snprintf(url, sizeof url, RELEASES_API "?per_page=100&page=%u", page);
        sb_http_request request = {.url = url, .user_agent = "sb-easy-android-updater",
                                   .timeout_ms = remaining, .max_body_bytes = 8 * 1024 * 1024};
        sb_http_response response;
        sb_err err = {0};
        if (sb_http_perform(&request, &response, &err) != 0) break;
        sbj *rows = response.status == 200 ? sbj_parse(response.body, response.body_len, NULL, 0) : NULL;
        sb_http_response_free(&response);
        if (!sbj_is_array(rows)) { sbj_free(rows); break; }
        size_t count = sbj_arr_len(rows);
        sb_android_release_consider(rows, &latest);
        sbj_free(rows);
        if (count < 100) return latest;
    }
    sbj_free(latest); /* Incomplete pagination or upstream failure must remain retryable. */
    return NULL;
}

int sb_http_android_update(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *input = req->params[0];
    if (!input || strlen(input) >= 64) return sb_fail(err, SB_ERR_VALIDATION, "Invalid Android ABI list");
    char list[64];
    strcpy(list, input);
    const char *ordered[5];
    size_t count = 0;
    char *cursor = list, *abi;
    while ((abi = strsep(&cursor, ",")) != NULL) {
        size_t index = 0;
        while (index < 4 && strcmp(abi, architectures[index]) != 0) ++index;
        if (index == 4 || count == 4) return sb_fail(err, SB_ERR_VALIDATION, "Unknown Android ABI");
        ordered[count++] = architectures[index];
    }
    ordered[count++] = "universal";
    sb_http_server *srv = req->server;
    if (pthread_mutex_trylock(&srv->android_release_mutex) != 0)
        return sb_fail(err, SB_ERR_UNAVAILABLE, "Checking GitHub releases, retry shortly");
    if (sb_monotonic_ms() >= srv->android_release_retry_ms) {
        sbj_free(srv->android_release);
        srv->android_release = fetch_latest();
        srv->android_release_retry_ms = sb_monotonic_ms() + (srv->android_release ? 300000 : 30000);
    }
    const sbj *latest = srv->android_release;
    int result = 0;
    const char *catalog = sbj_get_str(latest, "catalog_url", NULL);
    size_t match = 0;
    while (match < count && !sbj_has(latest, ordered[match])) ++match;
    if (!latest || !catalog) result = sb_fail(err, SB_ERR_UNAVAILABLE, "GitHub Android release or signed catalog unavailable");
    else if (match == count) result = sb_fail(err, SB_ERR_NOT_FOUND, "No compatible Android APK in latest release");
    else {
        sbj *body = sbj_object();
        sbj_set_str(body, "tag", sbj_get_str(latest, "tag", ""));
        sbj_set_str(body, "abi", ordered[match]);
        sbj_set_str(body, "apk_url", sbj_get_str(latest, ordered[match], ""));
        sbj_set_str(body, "catalog_url", catalog);
        sb_resp_json(resp, 200, body);
    }
    pthread_mutex_unlock(&srv->android_release_mutex);
    return result;
}
