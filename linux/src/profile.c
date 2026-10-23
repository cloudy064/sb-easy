#include "SBEasyCore.h"
#include "desktop.h"
#include "sb/http_client.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
static bool bounded_text(const sbj* v, size_t limit, bool empty) {
    if (!sbj_is_string(v) || (!empty && !v->v.str.len) || v->v.str.len > limit ||
        memchr(v->v.str.ptr, 0, v->v.str.len))
        return false;
    for (size_t i = 0; i < v->v.str.len; ++i)
        if ((unsigned char)v->v.str.ptr[i] < 32 ||
            (unsigned char)v->v.str.ptr[i] == 127)
            return false;
    return true;
}
static bool identifier(const sbj* v) {
    return bounded_text(v, 64, false) &&
           strspn(v->v.str.ptr, "abcdefghijklmnopqrstuvwxyz0123456789-") ==
               v->v.str.len;
}
sbj* sbl_new_state(void) {
    sbj* s = sbj_object();
    sbj_set_int(s, "schema", 1);
    sbj_set_int(s, "revision", 0);
    sbj_set(s, "profiles", sbj_array());
    sbj_set_str(s, "selected_id", "");
    sbj_set_bool(s, "system_proxy", false);
    return s;
}
sbj* sbl_new_profile(const char* name) {
    sbj* p = sbj_object();
    char* id = sbl_uuid();
    sbj_set_str(p, "id", id);
    free(id);
    sbj_set_str(p, "name", name && *name ? name : "独立连接");
    sbj_set_str(p, "mode", "independent");
    sbj_set(p, "subscriptions", sbj_array());
    sbj_set(p, "settings", sbj_object());
    sbj_set_int(p, "refresh_minutes", 360);
    return p;
}
sbj* sbl_profile(sbj* state, const char* id) {
    sbj* ps = sbj_get(state, "profiles");
    for (size_t i = 0; i < sbj_arr_len(ps); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(ps, i), "id"), id))
            return sbj_arr_at(ps, i);
    return NULL;
}
int sbl_validate_state(const sbj* s, sb_err* err) {
    const sbj* ps = sbj_get(s, "profiles");
    if (!sbj_is_object(s) || sbj_get_int(s, "schema", 0) != 1 ||
        sbj_get_int(s, "revision", -1) < 0 || !sbj_is_array(ps) ||
        sbj_arr_len(ps) > 32 || !bounded_text(sbj_get(s, "selected_id"), 64, true))
        goto bad;
    sb_strvec ids = {0};
    bool valid = true;
    for (size_t i = 0; i < sbj_arr_len(ps) && valid; ++i) {
        const sbj *p = sbj_arr_at(ps, i), *id = sbj_get(p, "id"),
                  *subs = sbj_get(p, "subscriptions");
        if (!identifier(id) || sb_strvec_contains(&ids, sbj_as_str(id, "")) ||
            !bounded_text(sbj_get(p, "name"), 128, false) || !sbj_is_array(subs) ||
            sbj_arr_len(subs) > 32 || !sbj_is_object(sbj_get(p, "settings"))) {
            valid = false;
            break;
        }
        sb_strvec_push(&ids, sbj_as_str(id, ""));
        const char* mode = sbj_get_str(p, "mode", "");
        if (strcmp(mode, "managed") && strcmp(mode, "independent")) {
            valid = false;
            break;
        }
        if (!strcmp(mode, "managed") &&
            (!sbl_url(sbj_get_str(p, "server", ""), true, NULL) ||
             !bounded_text(sbj_get(p, "token"), 8192, false))) {
            valid = false;
            break;
        }
        int64_t interval = sbj_get_int(p, "refresh_minutes", 360);
        if (interval != 0 && interval != 60 && interval != 360 && interval != 1440) {
            valid = false;
            break;
        }
        sb_strvec subids = {0};
        for (size_t j = 0; j < sbj_arr_len(subs) && valid; ++j) {
            const sbj *sub = sbj_arr_at(subs, j), *sid = sbj_get(sub, "id");
            const char* url = sbj_get_str(sub, "url", "");
            valid = identifier(sid) &&
                    !sb_strvec_contains(&subids, sbj_as_str(sid, "")) &&
                    bounded_text(sbj_get(sub, "name"), 128, false) &&
                    sbj_is_array(sbj_get(sub, "nodes")) &&
                    sbj_arr_len(sbj_get(sub, "nodes")) <= 256 &&
                    (!*url || sbl_url(url, true, NULL));
            if (valid)
                sb_strvec_push(&subids, sbj_as_str(sid, ""));
        }
        sb_strvec_free(&subids);
    }
    if (*sbj_get_str(s, "selected_id", "") &&
        !sb_strvec_contains(&ids, sbj_get_str(s, "selected_id", "")))
        valid = false;
    sb_strvec_free(&ids);
    if (valid)
        return 0;
bad:
    return sb_fail(err, SB_ERR_VALIDATION, "Invalid desktop profile repository");
}
int sbl_import(sbj* p, const char* name, const char* url, const char* body,
               sb_err* err) {
    if (!p || !name || !*name || strlen(name) > 128 || !body ||
        sbj_arr_len(sbj_get(p, "subscriptions")) >= 32 ||
        (url && *url && !sbl_url(url, true, err)))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Invalid subscription or subscription limit exceeded");
    char *message = NULL, *raw = sba_import_subscription(body, strlen(body), &message);
    free(message);
    if (!raw)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "No supported proxy nodes were found in this subscription");
    sbj* parsed = sbl_parse(raw, SBL_MAX_STATE, err);
    free(raw);
    if (!parsed)
        return -1;
    sbj* sub = sbj_object();
    char* id = sbl_uuid();
    sbj_set_str(sub, "id", id);
    free(id);
    sbj_set_str(sub, "name", name);
    sbj_set_str(sub, "url", url ? url : "");
    sbj_set(sub, "nodes", sbj_take(parsed, "nodes"));
    sbj_set(sub, "report", sbj_take(parsed, "report"));
    sbj_set_int(sub, "updated_at", (int64_t)time(NULL));
    sbj_arr_push(sbj_get_or_array(p, "subscriptions"), sub);
    sbj_free(parsed);
    return 0;
}
static sbj* subscription(sbj* p, const char* id) {
    sbj* subs = sbj_get(p, "subscriptions");
    for (size_t i = 0; i < sbj_arr_len(subs); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(subs, i), "id"), id))
            return sbj_arr_at(subs, i);
    return NULL;
}
int sbl_refresh_subscription(sbj* p, const char* id, sb_err* err) {
    sbj* sub = subscription(p, id);
    const char* url = sbj_get_str(sub, "url", "");
    if (!sub || !sbl_url(url, true, err))
        return -1;
    char* etag_header = NULL;
    const char* etag = sbj_get_str(sub, "etag", "");
    if (*etag && !strpbrk(etag, "\r\n"))
        etag_header = sb_asprintf("If-None-Match: %s", etag);
    const char* headers[] = {etag_header, NULL};
    sb_http_request req = {.url = url,
                           .headers = headers,
                           .timeout_ms = 15000,
                           .max_body_bytes = 512u * 1024u,
                           .user_agent = "sb-easy-linux/" SBL_VERSION};
    sb_http_response resp = {0};
    sb_err private_error = {0};
    int rc = sb_http_perform(&req, &resp, &private_error);
    free(etag_header);
    if (rc || (resp.status != 200 && resp.status != 304)) {
        sb_http_response_free(&resp);
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "Subscription refresh failed. The last valid nodes were kept.");
    }
    if (resp.status == 200) {
        char *message = NULL,
             *raw = sba_import_subscription(resp.body, resp.body_len, &message);
        free(message);
        if (!raw) {
            sb_http_response_free(&resp);
            return sb_fail(err, SB_ERR_VALIDATION,
                           "Updated subscription has no compatible nodes. Previous "
                           "nodes were kept.");
        }
        sbj* parsed = sbl_parse(raw, SBL_MAX_STATE, err);
        free(raw);
        if (!parsed) {
            sb_http_response_free(&resp);
            return -1;
        }
        sbj_set(sub, "nodes", sbj_take(parsed, "nodes"));
        sbj_set(sub, "report", sbj_take(parsed, "report"));
        sbj_free(parsed);
        if (resp.etag && strlen(resp.etag) <= 2048 && !strpbrk(resp.etag, "\r\n"))
            sbj_set_str(sub, "etag", resp.etag);
        else
            sbj_del(sub, "etag");
        char *user_info = sb_http_response_header(&resp, "subscription-userinfo"),
             *metadata = sba_subscription_metadata(user_info, (long long)time(NULL));
        free(user_info);
        sbj* meta = sbl_parse(metadata, 4096, NULL);
        free(metadata);
        if (meta)
            sbj_set(sub, "metadata", meta);
    }
    sbj_set_int(sub, "updated_at", (int64_t)time(NULL));
    sbj_del(sub, "last_error");
    sb_http_response_free(&resp);
    return 0;
}
int sbl_enroll(sbj* p, const char* url, const char* code, sb_err* err) {
    if (!sbl_url(url, true, err) || !code || !*code || strlen(code) > 4096 ||
        strpbrk(code, "\r\n"))
        return -1;
    sbj* device = sbj_object();
    sbj_set_str(device, "name", g_get_host_name());
    sbj_set_str(device, "platform", "linux");
    sbj_set_str(device, "client_version", SBL_VERSION);
    sb_device_enrollment_options opts = {
        .server = url, .code = code, .device = device, .timeout_ms = 15000};
    sb_device_credential cred = {0};
    sb_err private_error = {0};
    int rc = sb_enroll_device(&opts, &cred, &private_error);
    sbj_free(device);
    if (rc) {
        sb_device_credential_free(&cred);
        return sb_fail(
            err, SB_ERR_UPSTREAM,
            "Enrollment failed. Check the server and unused enrollment code.");
    }
    sbj_set_str(p, "mode", "managed");
    sbj_set_str(p, "server", cred.server);
    sbj_set_str(p, "token", cred.token);
    sbj_set_str(p, "host_id", cred.host_id);
    sbj_set_str(p, "name",
                cred.host_name && *cred.host_name ? cred.host_name : "托管连接");
    sb_device_credential_free(&cred);
    return 0;
}
int sbl_sync_profile(sbj* p, bool* changed, sb_err* err) {
    *changed = false;
    if (!sbj_string_is(sbj_get(p, "mode"), "managed"))
        return 0;
    sb_agent_client_options opts = {.server = sbj_get_str(p, "server", ""),
                                    .token = sbj_get_str(p, "token", ""),
                                    .timeout_ms = 15000};
    sb_err private_error = {0};
    sb_agent_client* client = sb_agent_client_new(&opts, &private_error);
    sb_agent_client_proxy_capability(client, false);
    sb_agent_config_response response = {0};
    int rc = client ? sb_agent_client_poll_config(client, sbj_get_str(p, "etag", ""),
                                                  &response, &private_error)
                    : -1;
    sb_agent_client_free(client);
    if (rc) {
        sb_agent_config_response_free(&response);
        return sb_fail(
            err, SB_ERR_UPSTREAM,
            "Management sync failed. The saved configuration is still available.");
    }
    if (response.modified) {
        sbj* config = sbl_parse(response.body, 1024u * 1024u, NULL);
        if (!sbj_is_object(config)) {
            sbj_free(config);
            sb_agent_config_response_free(&response);
            return sb_fail(err, SB_ERR_VALIDATION,
                           "Management server returned an invalid configuration");
        }
        sbj_free(config);
        sbj_set_str(p, "source", response.body);
        sbj_set_str(p, "etag", response.etag ? response.etag : "");
        *changed = true;
    }
    sbj_set_int(p, "synced_at", (int64_t)time(NULL));
    sb_agent_config_response_free(&response);
    return 0;
}
