#include "preferences_cloud.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sbw_preferences_cloud {
    sbw_panel_send send; void *context;
    char *server, *token, *cookie, *challenge, *username;
    char binding[65];
    uint64_t challenge_expires;
    int64_t revision;
    bool revision_known;
};
static void clear(sbw_preferences_cloud *cloud) {
    sbw_secret_free(cloud->token); sbw_secret_free(cloud->cookie); sbw_secret_free(cloud->challenge);
    free(cloud->server); free(cloud->username); cloud->server = cloud->username = NULL;
    cloud->token = cloud->cookie = cloud->challenge = NULL; cloud->challenge_expires = 0;
    cloud->revision = 0; cloud->revision_known = false;
    SecureZeroMemory(cloud->binding, sizeof cloud->binding);
}
sbw_preferences_cloud *sbw_preferences_cloud_new(sbw_panel_send send, void *context) {
    sbw_preferences_cloud *cloud = sb_xcalloc(1, sizeof *cloud); cloud->send = send ? send : sbw_panel_request;
    cloud->context = context; return cloud;
}
void sbw_preferences_cloud_free(sbw_preferences_cloud *cloud) { if (cloud) { clear(cloud); free(cloud); } }
sbj *sbw_preferences_cloud_status(const sbw_preferences_cloud *cloud) {
    sbj *out = sbj_object(); sbj_set_bool(out, "connected", cloud && cloud->token);
    sbj_set_bool(out, "mfa_required", cloud && cloud->challenge && cloud->challenge_expires > GetTickCount64());
    sbj_set_str(out, "server", cloud && cloud->server ? cloud->server : "");
    sbj_set_str(out, "username", cloud && cloud->username ? cloud->username : "");
    sbj_set_bool(out, "revision_known", cloud && cloud->revision_known);
    sbj_set_str(out, "session_id", cloud ? cloud->binding : "");
    sbj_set_int(out, "revision", cloud ? cloud->revision : 0); return out;
}
static bool token_valid(const sbj *value, size_t maximum) {
    if (!sbw_json_string(value, maximum, false)) return false;
    const char *text = sbj_as_str(value, "");
    for (; *text; ++text) if ((unsigned char)*text <= 32 || (unsigned char)*text >= 127) return false;
    return true;
}
static bool revision_valid(const sbj *value) {
    return sbj_is_integer(value) && sbj_as_int(value, -1) >= 0 && sbj_as_int(value, 0) <= INT64_C(9007199254740991);
}
static sbj *http_failure(sbw_preferences_cloud *cloud, DWORD status, sbw_error *error) {
    if (status == 401) {
        clear(cloud); sbw_fail(error, "PREFERENCES_AUTH_REQUIRED", "The panel login was rejected or expired. Sign in again.");
    } else if (status == 409) {
        cloud->revision_known = false;
        sbw_fail(error, "PREFERENCES_CONFLICT", "The remote archive changed. Fetch and review it before uploading or deleting again.");
    } else sbw_fail(error, "PREFERENCES_REMOTE_ERROR", "The panel rejected the preference request.");
    return NULL;
}
sbj *sbw_preferences_cloud_call(sbw_preferences_cloud *cloud, const char *operation,
    const sbj *params, HANDLE cancel, sbw_error *error) {
    sbj *body = NULL, *response = NULL, *result = NULL; char *cookie = NULL;
    const char *path = NULL, *method = "POST"; char conditional[32] = ""; DWORD status = 0;
    bool login = !strcmp(operation, "login"), mfa = !strcmp(operation, "mfa"), logout = !strcmp(operation, "logout");
    bool get = !strcmp(operation, "get"), put = !strcmp(operation, "put"), remove = !strcmp(operation, "delete");
    if (!cloud || !sbj_is_object(params) || (!login && !mfa && !logout && !get && !put && !remove)) goto invalid;
    if (!login && (!sbw_json_string(sbj_get(params, "session_id"), 64, false) ||
        !*cloud->binding || strcmp(sbj_get_str(params, "session_id", ""), cloud->binding))) goto auth_required;
    if (login) {
        if (sbj_obj_len(params) != 3 || !sbw_json_string(sbj_get(params, "server"), 8192, false) ||
            strncmp(sbj_get_str(params, "server", ""), "https://", 8) || !sbw_json_string(sbj_get(params, "username"), 256, false) ||
            !sbw_json_string(sbj_get(params, "password"), 4096, false)) goto invalid;
        if (cloud->token) {
            /* A new window cannot inherit an account session from a previous
             * console user. Best-effort revoke before replacing its capability. */
            DWORD ignored_status = 0; sbj *ignored_response = NULL; char *ignored_cookie = NULL; sbw_error ignored = {0};
            cloud->send(cloud->context, cloud->server, "POST", "/api/auth/logout", cloud->token, NULL, NULL,
                NULL, cancel, &ignored_status, &ignored_response, &ignored_cookie, &ignored);
            sbj_free(ignored_response); sbw_secret_free(ignored_cookie);
        }
        clear(cloud); cloud->server = sb_strdup(sbj_get_str(params, "server", ""));
        cloud->username = sb_strdup(sbj_get_str(params, "username", ""));
        unsigned char random[32];
        if (BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { clear(cloud); goto invalid; }
        for (size_t i = 0; i < sizeof random; ++i) sprintf_s(cloud->binding + i * 2, 3, "%02x", random[i]);
        SecureZeroMemory(random, sizeof random);
        body = sbj_object(); sbj_set_str(body, "username", cloud->username); sbj_set(body, "password", sbj_clone(sbj_get(params, "password")));
        path = "/api/auth/login";
    } else if (mfa) {
        if (sbj_obj_len(params) != 2 || !token_valid(sbj_get(params, "code"), 128)) goto invalid;
        if (!cloud->challenge || !cloud->cookie || cloud->challenge_expires <= GetTickCount64()) { clear(cloud); goto auth_required; }
        body = sbj_object(); sbj_set_str(body, "challenge", cloud->challenge); sbj_set(body, "code", sbj_clone(sbj_get(params, "code")));
        path = "/api/auth/login/mfa";
    } else {
        if (!cloud->token) goto auth_required;
        if (logout || get) { if (sbj_obj_len(params) != 1) goto invalid; }
        else if (sbj_obj_len(params) != (put ? 3U : 2U) || !revision_valid(sbj_get(params, "revision"))) goto invalid;
        if (logout) { path = "/api/auth/logout"; body = sbj_object(); }
        else {
            path = "/api/auth/preferences/windows-personal";
            if (get) method = "GET";
            else {
                if (!cloud->revision_known || sbj_get_int(params, "revision", -1) != cloud->revision) { sbw_fail(error, "PREFERENCES_CONFLICT", "Fetch and review the current remote archive before uploading or deleting."); goto done; }
                sprintf_s(conditional, sizeof conditional, "\"%lld\"", (long long)cloud->revision);
                method = put ? "PUT" : "DELETE";
                if (put) {
                    if (!sbw_preferences_envelope_valid(sbj_get(params, "envelope"))) goto invalid;
                    body = sbj_clone(sbj_get(params, "envelope"));
                }
            }
        }
    }
    if (cloud->send(cloud->context, cloud->server, method, path, cloud->token, mfa ? cloud->cookie : NULL,
        *conditional ? conditional : NULL, body, cancel, &status, &response, &cookie, error)) {
        if (logout) clear(cloud);
        goto done;
    }
    if (logout) { clear(cloud); if (status != 200) { http_failure(cloud, status, error); goto done; } result = sbw_preferences_cloud_status(cloud); goto done; }
    if (get && status == 404) {
        cloud->revision = 0; cloud->revision_known = true;
        result = sbw_preferences_cloud_status(cloud); sbj_set_int(result, "updated_at", 0); sbj_set_bool(result, "deleted", false); sbj_set_null(result, "envelope"); goto done;
    }
    if (status != 200 && !(put && status == 201)) { http_failure(cloud, status, error); goto done; }
    if (login || mfa) {
        if (!mfa && sbj_get_bool(response, "mfa_required", false)) {
            if (!token_valid(sbj_get(response, "challenge"), 256) || !cookie || !*cookie) goto invalid_response;
            cloud->challenge = sb_strdup(sbj_get_str(response, "challenge", "")); cloud->cookie = cookie; cookie = NULL;
            cloud->challenge_expires = GetTickCount64() + 300000; result = sbw_preferences_cloud_status(cloud); goto done;
        }
        if (!token_valid(sbj_get(response, "token"), 1024) || !sbw_json_string(sbj_get(response, "username"), 256, false)) goto invalid_response;
        cloud->token = sb_strdup(sbj_get_str(response, "token", "")); free(cloud->username); cloud->username = sb_strdup(sbj_get_str(response, "username", ""));
        sbw_secret_free(cloud->cookie); cloud->cookie = NULL; sbw_secret_free(cloud->challenge); cloud->challenge = NULL;
        cloud->challenge_expires = 0; result = sbw_preferences_cloud_status(cloud); goto done;
    }
    if (!revision_valid(sbj_get(response, "revision")) || sbj_get_int(response, "revision", 0) < 1 ||
        !revision_valid(sbj_get(response, "updated_at"))) goto invalid_response;
    const sbj *envelope = sbj_get(response, "envelope"); bool deleted = sbj_get_bool(response, "deleted", false);
    if ((!deleted && !sbw_preferences_envelope_valid(envelope)) || (deleted && !sbj_is_null(envelope))) goto invalid_response;
    if ((put || remove) && sbj_get_int(response, "revision", 0) <= cloud->revision) goto invalid_response;
    cloud->revision = sbj_get_int(response, "revision", 0); cloud->revision_known = true;
    result = sbw_preferences_cloud_status(cloud); sbj_set(result, "envelope", sbj_clone(envelope));
    sbj_set_bool(result, "deleted", deleted); sbj_set(result, "updated_at", sbj_clone(sbj_get(response, "updated_at"))); goto done;
auth_required:
    sbw_fail(error, "PREFERENCES_AUTH_REQUIRED", "Sign in with a panel account before synchronizing preferences."); goto done;
invalid_response:
    sbw_fail(error, "PREFERENCES_INVALID_RESPONSE", "The panel returned an invalid preference response."); goto done;
invalid:
    sbw_fail(error, "INVALID_REQUEST", "Invalid preference synchronization request.");
done:
    if (body) {
        sbj *password = sbj_get(body, "password"), *code = sbj_get(body, "code");
        if (sbj_is_string(password)) SecureZeroMemory(password->v.str.ptr, password->v.str.len);
        if (sbj_is_string(code)) SecureZeroMemory(code->v.str.ptr, code->v.str.len);
    }
    if (response) { sbj *token = sbj_get(response, "token"); if (sbj_is_string(token)) SecureZeroMemory(token->v.str.ptr, token->v.str.len); }
    sbj_free(body); sbj_free(response); sbw_secret_free(cookie); return result;
}
