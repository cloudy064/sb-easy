/* Stateful panel authentication and device-scoped authorization. */
#include "http_internal.h"
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *request_token(const sb_http_req *req) {
    const char *value = sb_req_header(req, "Authorization");
    return value && strncmp(value, "Bearer ", 7) == 0 ? sb_http_trim(value + 7) : NULL;
}
static const char *text_field(const sbj *body, const char *key, sb_err *err) {
    const char *s = sb_json_required_string(body, key, err);
    if (s && strlen(s) != sbj_get(body, key)->v.str.len) {
        sb_fail(err, SB_ERR_VALIDATION, "%s contains an invalid character", key); return NULL;
    }
    return s;
}
static void no_cache(sb_http_resp *resp) { sb_resp_header(resp, "Cache-Control", "no-store"); }
static void success(sb_http_resp *resp) {
    sbj *out = sbj_object(); sbj_set_bool(out, "success", true); no_cache(resp); sb_resp_json(resp, 200, out);
}
static char *cookie_binding(const sb_http_req *req) {
    const char *cookies = sb_req_header(req, "Cookie");
    if (!cookies) return NULL;
    const char *p = cookies;
    char *result = NULL;
    while (*p) {
        while (*p == ' ' || *p == ';') ++p;
        const char *end = strchr(p, ';'); if (!end) end = p + strlen(p);
        if ((size_t)(end - p) > 13 && strncmp(p, "sb_auth_flow=", 13) == 0) {
            /* Ambiguous duplicate cookies are rejected. */
            if (result) { free(result); return NULL; }
            result = sb_strndup(p + 13, (size_t)(end - p - 13));
        }
        p = end;
    }
    return result;
}
static void binding_cookie(const sb_http_req *req, sb_http_resp *resp, const char *binding) {
    bool secure = sb_starts_with(req->server->opts.public_server, "https://");
    char *value = sb_asprintf("sb_auth_flow=%s; Path=/api/auth/; HttpOnly; SameSite=Lax; Max-Age=%d%s",
                             binding ? binding : "", binding ? 300 : 0, secure ? "; Secure" : "");
    sb_resp_header(resp, "Set-Cookie", value); free(value); no_cache(resp);
}
static char *new_binding(sb_err *err) {
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof bytes) != 1) { sb_fail(err, SB_ERR_GENERIC, "Random generation failed"); return NULL; }
    char *out = sb_xmalloc(65);
    for (size_t i = 0; i < sizeof bytes; ++i) snprintf(out + i * 2, 3, "%02x", bytes[i]);
    return out;
}
static const char *client_label(const sb_http_req *req, char out[129]) {
    const char *ua = sb_req_header(req, "User-Agent");
    size_t i = 0;
    for (; ua && ua[i] && i < 128; ++i) out[i] = ua[i] >= 32 && ua[i] <= 126 ? ua[i] : '?';
    out[i] = 0; return out;
}
static int token_response(sb_http_req *req, sb_http_resp *resp, char *token, sb_err *err) {
    if (!token) return -1;
    sb_auth_claims claims = {0};
    if (!sb_auth_security_verify(req->server->security, token, &claims, err)) { free(token); return -1; }
    sbj *out = sbj_object();
    sbj_set(out, "token", sbj_str_take(token));
    sbj_set(out, "username", sbj_strn(claims.username, claims.username_len));
    sbj_set_str(out, "role", claims.role);
    sb_auth_claims_free(&claims); binding_cookie(req, resp, NULL); sb_resp_json(resp, 200, out); return 0;
}
int sb_http_security_login(sb_http_req *req, sb_http_resp *resp, const char *user_id,
                           const char *method, sb_err *err) {
    char label[129];
    sbj *status = sb_auth_mfa_status(req->server->security, user_id, err);
    if (!status) return -1;
    bool enabled = sbj_get_bool(status, "enabled", false); sbj_free(status);
    if (!enabled) return token_response(req, resp, sb_auth_security_issue(req->server->security,
        user_id, method, client_label(req, label), err), err);
    char *binding = new_binding(err); if (!binding) return -1;
    char *challenge = sb_auth_security_challenge_bound(req->server->security, user_id, method, binding, err);
    if (!challenge) { free(binding); return -1; }
    sbj *out = sbj_object(); sbj_set_bool(out, "mfa_required", true);
    sbj_set(out, "challenge", sbj_str_take(challenge));
    binding_cookie(req, resp, binding); free(binding); sb_resp_json(resp, 200, out); return 0;
}
/* Reauthenticate sensitive account changes; codes are one-use, including recovery codes. */
static int fresh_proof(sb_http_req *req, const sbj *body, sb_err *err) {
    const char *password = sb_json_required_string(body, "password", err);
    if (!password) return -1;
    sb_user_account user; sb_user_account_init(&user);
    int found = sb_store_find_user_by_username_n(req->server->store, req->claims->username,
                                                req->claims->username_len, &user, err);
    bool valid = found == 1 && sb_streq(user.id, req->claims->subject) &&
        sb_verify_password_n(password, sbj_get(body, "password")->v.str.len, user.password_hash);
    sb_user_account_free(&user);
    if (!valid) return sb_fail(err, SB_ERR_FORBIDDEN, "Current password is incorrect");
    sbj *status = sb_auth_mfa_status(req->server->security, req->claims->subject, err);
    if (!status) return -1;
    bool enabled = sbj_get_bool(status, "enabled", false); sbj_free(status);
    if (enabled) {
        const char *code = text_field(body, "code", err);
        if (!code) return -1;
        if (!sb_auth_mfa_verify(req->server->security, req->claims->subject, code, err)) {
            if (err && err->code == SB_ERR_AUTH) err->code = SB_ERR_FORBIDDEN;
            return -1;
        }
    }
    return 0;
}
static int login_mfa(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err); if (!body) return -1;
    const char *challenge = text_field(body, "challenge", err), *code = NULL;
    if (challenge) code = text_field(body, "code", err);
    char label[129];
    char *binding = cookie_binding(req), *token = NULL;
    if (code && binding) token = sb_auth_security_complete_bound(req->server->security, challenge, code,
        client_label(req, label), binding, err);
    else if (code) sb_fail(err, SB_ERR_AUTH, "Login browser binding is missing");
    free(binding); sbj_free(body); return token_response(req, resp, token, err);
}
static int logout_session(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *token = request_token(req); int rc = sb_auth_security_logout(req->server->security, token, err);
    free(token); if (rc != 0) return -1; success(resp); return 0;
}
static int sessions(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *token = request_token(req);
    sbj *out = sb_auth_security_sessions(req->server->security, req->claims->subject, token, err);
    free(token); if (!out) return -1;
    no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
static int revoke_session(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *id = req->param_count ? req->params[0] : NULL;
    if (sb_auth_security_revoke(req->server->security, req->claims->subject, id, NULL, err) != 0) return -1;
    success(resp); return 0;
}
static int mfa_status(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *out = sb_auth_mfa_status(req->server->security, req->claims->subject, err);
    if (!out) return -1;
    no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
static int mfa_change(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err), *out = NULL; if (!body) return -1;
    char *token = request_token(req); int rc = -1;
    if (strcmp(req->params[0], "confirm") == 0) {
        const char *code = text_field(body, "code", err);
        if (code) out = sb_auth_mfa_confirm(req->server->security, req->claims->subject, code, token, err);
    } else if (fresh_proof(req, body, err) == 0) {
        if (strcmp(req->params[0], "setup") == 0)
            out = sb_auth_mfa_begin(req->server->security, req->claims->subject, err);
        else if (strcmp(req->params[0], "disable") == 0) {
            if (sb_auth_mfa_disable(req->server->security, req->claims->subject, token, err) == 0) {
                success(resp); rc = 0;
            }
        } else sb_fail(err, SB_ERR_NOT_FOUND, "Unknown MFA action");
    }
    if (out) { no_cache(resp); sb_resp_json(resp, 200, out); rc = 0; }
    free(token); sbj_free(body); return rc;
}
static int own_password(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err); if (!body) return -1;
    int rc = -1; char *hash = NULL;
    if (fresh_proof(req, body, err) != 0) goto done;
    const char *password = sb_json_required_string(body, "new_password", err);
    if (!password) goto done;
    size_t len = sbj_get(body, "new_password")->v.str.len;
    if (len < 8) { sb_fail(err, SB_ERR_VALIDATION, "New password must be at least 8 characters"); goto done; }
    hash = sb_hash_password_n(password, len, err); if (!hash) goto done;
    if (sb_store_reset_user_password(req->server->store, req->claims->subject, hash, err) != 0 ||
        sb_auth_security_revoke(req->server->security, req->claims->subject, NULL, NULL, err) != 0) goto done;
    success(resp); rc = 0;
done: free(hash); sbj_free(body); return rc;
}
static int oidc_public(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *config = sb_auth_oidc_config(req->server->security, err); if (!config) return -1;
    sbj *out = sbj_object(); sbj_set_bool(out, "enabled", sbj_get_bool(config, "enabled", false));
    sbj_free(config); no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
static int oidc_start(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (!sb_starts_with(req->server->opts.public_server, "https://"))
        return sb_fail(err, SB_ERR_VALIDATION, "OIDC requires an HTTPS PUBLIC_SERVER");
    sb_auth_oidc_start start = {0};
    if (sb_auth_oidc_begin(req->server->security, &start, err) != 0) return -1;
    sbj *out = sbj_object(); sbj_set_str(out, "authorization_url", start.authorization_url);
    binding_cookie(req, resp, start.browser_binding); sb_auth_oidc_start_free(&start);
    sb_resp_json(resp, 200, out); return 0;
}
static int oidc_finish(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err); if (!body) return -1;
    const char *state = text_field(body, "state", err), *code = NULL;
    if (state) code = text_field(body, "code", err);
    char *binding = cookie_binding(req), *user = NULL;
    if (code && binding) user = sb_auth_oidc_finish(req->server->security, state, code, binding, err);
    else if (code) sb_fail(err, SB_ERR_AUTH, "Login browser binding is missing");
    free(binding); sbj_free(body); if (!user) return -1;
    int rc = sb_http_security_login(req, resp, user, "oidc", err); free(user); return rc;
}
static int oidc_config(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (strcmp(req->method, "PUT") == 0) {
        sbj *body = sb_req_json_object(req, err); if (!body) return -1;
        int rc = fresh_proof(req, body, err);
        if (rc == 0) {
            const sbj *config = sb_json_required_object(body, "config", err);
            if (config && sbj_get_bool(config, "enabled", false) &&
                !sb_starts_with(req->server->opts.public_server, "https://"))
                rc = sb_fail(err, SB_ERR_VALIDATION, "OIDC requires an HTTPS PUBLIC_SERVER");
            else rc = config ? sb_auth_oidc_configure(req->server->security, config, err) : -1;
        }
        sbj_free(body); if (rc != 0) return -1;
    }
    sbj *out = sb_auth_oidc_config(req->server->security, err); if (!out) return -1;
    no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
static int oidc_links(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (strcmp(req->method, "GET") != 0) {
        sbj *body = sb_req_json_object(req, err); if (!body) return -1;
        int rc = fresh_proof(req, body, err);
        if (rc == 0) {
            const char *issuer = text_field(body, "issuer", err), *subject = NULL;
            if (issuer) subject = text_field(body, "subject", err);
            rc = subject ? sb_auth_oidc_link(req->server->security, req->params[0], issuer, subject,
                                             strcmp(req->method, "DELETE") == 0, err) : -1;
        }
        sbj_free(body); if (rc != 0) return -1;
    }
    sbj *out = sb_auth_oidc_links(req->server->security, req->params[0], err); if (!out) return -1;
    no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
static int groups(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (strcmp(req->method, "PUT") == 0) {
        sbj *body = sb_req_json_object(req, err); if (!body) return -1;
        int rc = sb_auth_device_group_save(req->server->security, body, err); sbj_free(body);
        if (rc != 0) return -1;
    } else if (strcmp(req->method, "DELETE") == 0) {
        if (sb_auth_device_group_remove(req->server->security, req->params[0], err) != 0) return -1;
    }
    sbj *out = sb_auth_device_groups(req->server->security, err); if (!out) return -1;
    sb_resp_json(resp, 200, out); return 0;
}
static int scope(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (strcmp(req->method, "PUT") == 0) {
        sbj *body = sb_req_json_object(req, err); if (!body) return -1;
        int rc = sb_auth_user_scope_set(req->server->security, req->params[0], body, err); sbj_free(body);
        if (rc != 0) return -1;
    }
    sbj *out = sb_auth_user_scope(req->server->security, req->params[0], err); if (!out) return -1;
    sb_resp_json(resp, 200, out); return 0;
}
static int change_role(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    sbj *body = sb_req_json_object(req, err); if (!body) return -1;
    const char *role = text_field(body, "role", err);
    int rc = role ? sb_auth_security_change_role(req->server->security, req->params[0], role, err) : -1;
    sbj_free(body); if (rc != 0) return -1; success(resp); return 0;
}
static int admin_sessions(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (strcmp(req->method, "DELETE") == 0) {
        if (sb_auth_security_revoke(req->server->security, req->params[0], NULL, NULL, err) != 0) return -1;
        success(resp); return 0;
    }
    sbj *out = sb_auth_security_sessions(req->server->security, req->params[0], NULL, err); if (!out) return -1;
    no_cache(resp); sb_resp_json(resp, 200, out); return 0;
}
/* Default-deny all global configuration. Only listed device operations and a
 * user's own account-security endpoints are available to non-admin users. */
int sb_http_security_authorize(const sb_http_req *req, sb_err *err) {
    if (!req->claims) return sb_fail(err, SB_ERR_AUTH, "Invalid or expired token");
    if (sb_streq(req->claims->role, "admin")) return 0;
    char *path = sb_lower_dup(req->path);
    bool read = strcmp(req->method, "GET") == 0 || strcmp(req->method, "HEAD") == 0 || strcmp(req->method, "OPTIONS") == 0;
    bool own = strcmp(path, "/api/auth/session") == 0 || strcmp(path, "/api/auth/logout") == 0 ||
        strcmp(path, "/api/auth/password") == 0 || strcmp(path, "/api/auth/sessions") == 0 ||
        sb_starts_with(path, "/api/auth/sessions/") || sb_starts_with(path, "/api/auth/preferences/") || strcmp(path, "/api/auth/mfa") == 0 || sb_starts_with(path, "/api/auth/mfa/");
    if (own) { free(path); return 0; }
    if (sb_streq(req->claims->role, "viewer") && !read) {
        free(path); return sb_fail(err, SB_ERR_FORBIDDEN, "Viewer role is read-only");
    }
    if (read && strcmp(path, "/api/hosts") == 0) { free(path); return 0; }
    char *host = NULL;
    bool operation = false;
    if (sb_starts_with(path, "/api/hosts/")) {
        const char *raw = req->path + strlen("/api/hosts/");
        const char *slash = strchr(raw, '/');
        const char *tail = slash ? path + (slash - req->path) : "";
        operation = read ? (!*tail || strcmp(tail, "/telemetry") == 0 || strcmp(tail, "/diagnostics") == 0 ||
                            strcmp(tail, "/commands") == 0 || strcmp(tail, "/outbounds") == 0 ||
                            strcmp(tail, "/history") == 0 || strcmp(tail, "/alerts") == 0)
                         : strcmp(req->method, "POST") == 0 && strcmp(tail, "/commands") == 0;
        if (operation) host = slash ? sb_strndup(raw, (size_t)(slash - raw)) : sb_strdup(raw);
    } else if (sb_starts_with(path, "/api/sing-box/")) {
        char *raw = sb_req_query_param(req, "host"); host = sb_http_trim(raw ? raw : ""); free(raw);
        operation = read || (strcmp(req->method, "PUT") == 0 && sb_starts_with(path, "/api/sing-box/proxies/")) ||
            (strcmp(req->method, "DELETE") == 0 && sb_starts_with(path, "/api/sing-box/connections"));
    }
    bool device_path = sb_starts_with(path, "/api/hosts/") || sb_starts_with(path, "/api/sing-box/");
    free(path);
    bool allowed = operation && host && *host && sb_auth_device_allowed(req->server->security,
        req->claims->subject, host, !read, err);
    free(host);
    return allowed ? 0 : sb_fail(err, SB_ERR_FORBIDDEN, "%s", device_path ? "Authorized device scope required" : "Admin role required");
}
void sb_http_register_security_routes(sb_http_server *srv) {
    sb_http_route(srv, "POST", "/api/auth/login/mfa", login_mfa);
    sb_http_route(srv, "POST", "/api/auth/logout", logout_session);
    sb_http_route(srv, "GET", "/api/auth/sessions", sessions);
    sb_http_route(srv, "DELETE", "/api/auth/sessions", revoke_session);
    sb_http_route(srv, "DELETE", "/api/auth/sessions/{id}", revoke_session);
    sb_http_route(srv, "GET", "/api/auth/mfa", mfa_status);
    sb_http_route(srv, "POST", "/api/auth/mfa/{action}", mfa_change);
    sb_http_route(srv, "POST", "/api/auth/password", own_password);
    sb_http_route(srv, "GET", "/api/auth/oidc", oidc_public);
    sb_http_route(srv, "POST", "/api/auth/oidc/start", oidc_start);
    sb_http_route(srv, "POST", "/api/auth/oidc/finish", oidc_finish);
    sb_http_route(srv, "GET,PUT", "/api/auth/oidc/config", oidc_config);
    sb_http_route(srv, "GET,PUT,DELETE", "/api/users/{id}/oidc", oidc_links);
    sb_http_route(srv, "GET,PUT", "/api/device-groups", groups);
    sb_http_route(srv, "DELETE", "/api/device-groups/{id}", groups);
    sb_http_route(srv, "GET,PUT", "/api/users/{id}/scope", scope);
    sb_http_route(srv, "GET,DELETE", "/api/users/{id}/sessions", admin_sessions);
    sb_http_route(srv, "PUT", "/api/users/{id}/role", change_role);
}
