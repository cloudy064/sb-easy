/* Panel HTTP routes: /api/health, /api/system/..., /api/auth/..., /api/users*,
 * /api/settings*, /api/wireguard/..., /api/config/sing-box/...
 * Port of the corresponding handlers in cpp/src/http_server.cpp
 * (register_http_routes, "/api/health" through "/api/config/sing-box/outbound/{id}").
 *
 * The C++ server registers no /api/one-time/... handler (the one-time-link
 * route only builds the URL), so those paths reach the core's JWT advice and
 * "API route not found" fallback exactly as they did with Drogon. */
#include "http_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sb/config_renderer.h"
#include "sb/types.h"
#include "sb/wireguard.h"
#include <ctype.h>

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

#define S(x) ((x) ? (x) : "")

/* ======================================================================
 * file-local helpers (C++ anonymous-namespace helpers only these routes use)
 * ====================================================================== */

/* handle_response() turns any nlohmann exception escaping a handler into
 * 400 {"error": "Invalid JSON request: <what()>"}. The C ports of the store,
 * renderer and WireGuard service report those failures as SB_ERR_GENERIC
 * carrying nlohmann's what() text, so reclassify them. Always returns -1. */
static int fail_json_aware(sb_err *err) {
    if (err && err->code == SB_ERR_GENERIC && sb_starts_with(err->msg, "[json.exception."))
        err->code = SB_ERR_BAD_JSON;
    return -1;
}

static int type_error_302(sb_err *err, const char *expected, const sbj *value) {
    return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be %s, but is %s",
                   expected, sbj_type_name(value));
}

/* static_cast<std::int32_t / std::int64_t>(double) as compiled for x86-64
 * (cvttsd2si): NaN and out-of-range values become the type's minimum. */
static int32_t double_to_i32(double d) {
    if (!(d > -2147483649.0 && d < 2147483648.0)) return INT32_MIN;
    return (int32_t)d;
}

static int64_t double_to_i64(double d) {
    if (!(d >= -9223372036854775808.0 && d < 9223372036854775808.0)) return INT64_MIN;
    return (int64_t)d;
}

/* nlohmann get<int>() (and value("field", 25)): numbers and booleans,
 * narrowed like static_cast; anything else is type_error.302. */
static int json_get_i32(const sbj *v, int32_t *out, sb_err *err) {
    switch (v ? v->type : SBJ_NULL) {
    case SBJ_INT: *out = (int32_t)(uint32_t)(uint64_t)v->v.i; return 0;
    case SBJ_UINT: *out = (int32_t)(uint32_t)v->v.u; return 0;
    case SBJ_FLOAT: *out = double_to_i32(v->v.f); return 0;
    case SBJ_BOOL: *out = v->v.b ? 1 : 0; return 0;
    default: return type_error_302(err, "number", v);
    }
}

/* nlohmann get<std::int64_t>(): numbers only (booleans are rejected). */
static int json_get_i64(const sbj *v, int64_t *out, sb_err *err) {
    switch (v ? v->type : SBJ_NULL) {
    case SBJ_INT: *out = v->v.i; return 0;
    case SBJ_UINT: *out = (int64_t)v->v.u; return 0;
    case SBJ_FLOAT: *out = double_to_i64(v->v.f); return 0;
    default: return type_error_302(err, "number", v);
    }
}

/* nlohmann body.value(field, fallback) for strings: absent -> fallback;
 * present (null included) but not a string -> type_error.302. *out is
 * borrowed from body or fallback. */
static int json_value_string(const sbj *body, const char *field, const char *fallback, const char **out,
                             sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(found)) return type_error_302(err, "string", found);
    *out = found->v.str.ptr;
    return 0;
}

/* std::string == literal, honouring embedded NUL bytes. */
static bool json_string_is(const sbj *value, const char *literal) {
    size_t n = strlen(literal);
    return sbj_is_string(value) && value->v.str.len == n && memcmp(value->v.str.ptr, literal, n) == 0;
}

/* utc_after(): "%Y-%m-%dT%H:%M:%SZ" for now + `minutes`. NULL on failure. */
static char *utc_after_minutes(int64_t minutes) {
    time_t when = time(NULL) + (time_t)(minutes * 60);
    struct tm utc;
    if (!gmtime_r(&when, &utc)) return NULL;
    char text[64];
    if (strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) return NULL;
    return sb_strdup(text);
}

/* renderer_node(): ProxyRecord -> ProxyNode. `out` must be initialised. */
static void renderer_node(const sb_proxy_record *record, sb_proxy_node *out) {
    sb_str_set(&out->id, S(record->id));
    sb_str_set(&out->tag, S(record->tag));
    sb_str_set(&out->type, S(record->node_type));
    out->enabled = record->enabled;
    sb_str_set(&out->server, S(record->server));
    out->server_port = record->server_port;
    sbj_free(out->protocol_config);
    out->protocol_config = record->protocol_config ? sbj_clone(record->protocol_config) : sbj_object();
}

/* bearer_token(): the trimmed token after a case-sensitive "Bearer "
 * prefix, or NULL when missing/empty. malloc'd. */
static char *bearer_token(const sb_http_req *req) {
    const char *authorization = sb_req_header(req, "Authorization");
    if (!authorization || strncmp(authorization, "Bearer ", 7) != 0) return NULL;
    char *token = sb_http_trim(authorization + 7);
    if (token && !*token) {
        free(token);
        return NULL;
    }
    return token;
}

/* find_wireguard_peer() or NotFoundError("Peer not found"). */
static int require_peer(sb_http_server *srv, const char *id, sb_wireguard_peer *out, sb_err *err) {
    int found = sb_store_find_wireguard_peer(srv->store, id, out, err);
    if (found < 0) return -1;
    if (found == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Peer not found");
    return 0;
}

static void respond_success(sb_http_resp *resp) {
    sbj *body = sbj_object();
    sbj_set_bool(body, "success", true);
    sb_resp_json(resp, 200, body);
}

/* GET/PUT /api/settings body: the persisted settings with an effective
 * "wireguard_interface" section (runtime options overlaid by the saved
 * section's non-null members). NULL on store failure. */
static sbj *settings_view(sb_http_server *srv, sb_err *err) {
    sbj *settings = sb_store_app_settings(srv->store, err);
    if (!settings) return NULL;
    const sb_http_server_options *o = &srv->opts;
    sbj *wireguard = sbj_object();
    sbj_set_str(wireguard, "interface", S(o->wireguard_interface));
    sbj_set_int(wireguard, "listen_port", o->wireguard_port);
    sbj_set_str(wireguard, "address", S(o->wireguard_address));
    sbj_set_str(wireguard, "dns", S(o->wireguard_dns));
    sbj_set_int(wireguard, "mtu", o->wireguard_mtu);
    const sbj *saved = sbj_get(settings, "wireguard_interface");
    if (sbj_is_object(saved)) {
        const char *key;
        sbj *value;
        SBJ_OBJ_FOREACH(saved, i, key, value) {
            if (!sbj_is_null(value)) sbj_set(wireguard, key, sbj_clone(value));
        }
    }
    sbj_set(settings, "wireguard_interface", wireguard);
    return settings;
}

/* ======================================================================
 * /api/health, /api/system/...
 * ====================================================================== */

/* GET /api/health (public) */
static int handle_health(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set_str(body, "status", "ok");
    sbj_set_str(body, "service", "sb-easy-c");
    sb_resp_json(resp, 200, body);
    return 0;
}

/* GET /api/system/status (public) */
static int handle_system_status(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_store *store = req->server->store;
    sb_wireguard_peer_vec peers = {0};
    sb_proxy_record_vec nodes = {0};
    sb_subscription_vec subscriptions = {0};
    sbj *body, *section;
    int rc = -1;
    if (sb_store_list_wireguard_peers(store, &peers, err) != 0 ||
        sb_store_list_proxy_nodes(store, &nodes, err) != 0 ||
        sb_store_list_subscriptions(store, &subscriptions, err) != 0)
        goto done;
    body = sbj_object();
    sbj_set_str(body, "version", SB_EASY_VERSION);
    sbj_set_str(body, "status", "running");
    section = sbj_object();
    sbj_set_int(section, "peer_count", (int64_t)peers.len);
    sbj_set(body, "wireguard", section);
    section = sbj_object();
    sbj_set_int(section, "node_count", (int64_t)nodes.len);
    sbj_set(body, "sing_box", section);
    section = sbj_object();
    sbj_set_int(section, "count", (int64_t)subscriptions.len);
    sbj_set(body, "subscriptions", section);
    sb_resp_json(resp, 200, body);
    rc = 0;
done:
    sb_wireguard_peer_vec_free(&peers);
    sb_proxy_record_vec_free(&nodes);
    sb_subscription_vec_free(&subscriptions);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/system/logs */
static int handle_system_logs(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set(body, "lines", sb_http_log_lines(req->server));
    sb_resp_json(resp, 200, body);
    return 0;
}

/* POST /api/system/migrate/wg-easy */
static int handle_migrate_wg_easy(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set_str(body, "status", "not_implemented");
    sbj_set_str(body, "message",
                "wg-easy migration coming in a future update. Use manual import for now.");
    sb_resp_json(resp, 200, body);
    return 0;
}

/* ======================================================================
 * /api/auth/...
 * ====================================================================== */

/* POST /api/auth/login (public) */
static int handle_auth_login(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_user_account user;
    sb_user_account_init(&user);
    const sbj *found;
    size_t username_len = 5;
    const char *username = "admin", *password;
    char *token;
    sbj *out;
    int rc = -1, status;

    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    found = sbj_get(body, "username");
    if (found && !sbj_is_null(found)) {
        if (!sbj_is_string(found)) {
            sb_fail(err, SB_ERR_VALIDATION, "username must be a string");
            goto done;
        }
        username_len = found->v.str.len;
        username = found->v.str.ptr;
    }
    password = sb_json_required_string(body, "password", err);
    if (!password) goto done;
    status = sb_store_find_user_by_username_n(srv->store, username, username_len, &user, err);
    if (status < 0) goto done;
    if (status == 0 || !sb_verify_password_n(password, sbj_get(body, "password")->v.str.len,
                                           user.password_hash)) {
        sb_fail(err, SB_ERR_AUTH, "Invalid credentials");
        goto done;
    }
    token = sb_auth_create_token_n(srv->opts.jwt_secret, user.id, user.username, user.username_len, user.role);
    if (!token) {
        sb_fail(err, SB_ERR_GENERIC, "JWT secret is not configured");
        goto done;
    }
    out = sbj_object();
    sbj_set(out, "token", sbj_str_take(token));
    sbj_set(out, "username", sbj_strn(S(user.username), user.username_len));
    sbj_set_str(out, "role", S(user.role));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sb_user_account_free(&user);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/auth/session (public; verifies the bearer token itself) */
static int handle_auth_session(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_auth_claims claims;
    memset(&claims, 0, sizeof claims);
    char *token = bearer_token(req);
    bool valid = token && sb_auth_verify_token(req->server->opts.jwt_secret, token, &claims);
    free(token);
    if (!valid) {
        sb_auth_claims_free(&claims);
        return sb_fail(err, SB_ERR_AUTH, "Invalid or expired token");
    }
    sbj *body = sbj_object();
    sbj_set(body, "username", sbj_strn(S(claims.username), claims.username_len));
    sbj_set_str(body, "role", S(claims.role));
    sbj_set_bool(body, "authenticated", true);
    sb_auth_claims_free(&claims);
    sb_resp_json(resp, 200, body);
    return 0;
}

/* ======================================================================
 * /api/users*
 * ====================================================================== */

/* GET /api/users/audit */
static int handle_users_audit(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    sb_audit_entry_vec entries = {0};
    if (sb_store_list_audit(req->server->store, 200, &entries, err) != 0) {
        sb_audit_entry_vec_free(&entries);
        return fail_json_aware(err);
    }
    sbj *body = sbj_array();
    for (size_t i = 0; i < entries.len; ++i) sbj_arr_push(body, sb_audit_entry_to_json(&entries.items[i]));
    sb_audit_entry_vec_free(&entries);
    sb_resp_json(resp, 200, body);
    return 0;
}

/* GET /api/users */
static int handle_users_list(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    sb_user_account_vec users = {0};
    if (sb_store_list_users(req->server->store, &users, err) != 0) {
        sb_user_account_vec_free(&users);
        return fail_json_aware(err);
    }
    sbj *body = sbj_array();
    for (size_t i = 0; i < users.len; ++i) sbj_arr_push(body, sb_user_account_to_json(&users.items[i]));
    sb_user_account_vec_free(&users);
    sb_resp_json(resp, 200, body);
    return 0;
}

/* POST /api/users */
static int handle_users_create(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_user_account user;
    sb_user_account_init(&user);
    sbj *body = NULL;
    const sbj *found, *role_value = NULL;
    const char *username, *password, *role = "viewer";
    char *hash = NULL;
    bool blank;
    int rc = -1;

    if (sb_require_admin(req, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    username = sb_json_required_string(body, "username", err);
    if (!username) goto done;
    password = sb_json_required_string(body, "password", err);
    if (!password) goto done;
    found = sbj_get(body, "role");
    if (found && !sbj_is_null(found)) {
        if (!sbj_is_string(found)) {
            sb_fail(err, SB_ERR_VALIDATION, "role must be a string");
            goto done;
        }
        role_value = found;
        role = found->v.str.ptr;
    }
    size_t username_len = sbj_get(body, "username")->v.str.len;
    blank = true;
    for (size_t i = 0; i < username_len; ++i)
        if (!isspace((unsigned char)username[i])) { blank = false; break; }
    if (blank || sbj_get(body, "password")->v.str.len < 4) {
        sb_fail(err, SB_ERR_VALIDATION, "Username required, password must be at least 4 characters");
        goto done;
    }
    if (role_value && !json_string_is(role_value, "admin") && !json_string_is(role_value, "viewer")) {
        sb_fail(err, SB_ERR_VALIDATION, "Role must be admin or viewer");
        goto done;
    }
    hash = sb_hash_password_n(password, sbj_get(body, "password")->v.str.len, err);
    if (!hash) goto done;
    if (sb_store_create_user_n(srv->store, username, username_len, hash, role, &user, err) != 0) goto done;
    sb_resp_json(resp, 200, sb_user_account_to_json(&user));
    rc = 0;
done:
    sbj_free(body);
    free(hash);
    sb_user_account_free(&user);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* DELETE /api/users/{id} */
static int handle_users_delete(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (!req->claims) return sb_fail(err, SB_ERR_AUTH, "Invalid or expired token");
    if (sb_store_delete_user(req->server->store, S(req->claims->subject), req->params[0], err) != 0)
        return fail_json_aware(err);
    respond_success(resp);
    return 0;
}

/* POST /api/users/{id}/password */
static int handle_users_password(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = NULL;
    const char *password;
    char *hash = NULL;
    int rc = -1;

    if (sb_require_admin(req, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    password = sb_json_required_string(body, "password", err);
    if (!password) goto done;
    if (sbj_get(body, "password")->v.str.len < 4) {
        sb_fail(err, SB_ERR_VALIDATION, "Password must be at least 4 characters");
        goto done;
    }
    hash = sb_hash_password_n(password, sbj_get(body, "password")->v.str.len, err);
    if (!hash) goto done;
    if (sb_store_reset_user_password(req->server->store, req->params[0], hash, err) != 0) goto done;
    respond_success(resp);
    rc = 0;
done:
    sbj_free(body);
    free(hash);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* ======================================================================
 * /api/settings*
 * ====================================================================== */

/* GET /api/settings */
static int handle_settings_get(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *settings = settings_view(req->server, err);
    if (!settings) return fail_json_aware(err);
    sb_resp_json(resp, 200, settings);
    return 0;
}

/* PUT /api/settings */
static int handle_settings_put(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err);
    if (!body) return -1;
    int rc = sb_store_update_app_settings(req->server->store, body, err);
    sbj_free(body);
    if (rc != 0) return fail_json_aware(err);
    sb_http_sync_wireguard_best_effort(req->server);
    sbj *settings = settings_view(req->server, err);
    if (!settings) return fail_json_aware(err);
    sb_resp_json(resp, 200, settings);
    return 0;
}

/* GET /api/settings/backup */
static int handle_settings_backup(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *backup = sb_store_export_backup(req->server->store, err);
    if (!backup) return fail_json_aware(err);
    sbj_set_int(backup, "version", 1);
    char *now = sb_http_utc_now();
    if (!now) {
        sbj_free(backup);
        return sb_fail(err, SB_ERR_GENERIC, "UTC timestamp conversion failed");
    }
    sbj_set(backup, "exported_at", sbj_str_take(now));
    sb_resp_json(resp, 200, backup);
    return 0;
}

/* POST /api/settings/restore */
static int handle_settings_restore(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err);
    if (!body) return -1;
    sbj *restored = sb_store_restore_backup(req->server->store, body, err);
    sbj_free(body);
    if (!restored) return fail_json_aware(err);
    sb_http_sync_wireguard_best_effort(req->server);
    sbj *out = sbj_object();
    sbj_set(out, "restored", restored);
    sb_resp_json(resp, 200, out);
    return 0;
}

/* ======================================================================
 * /api/wireguard/...
 * ====================================================================== */

/* GET /api/wireguard/peers */
static int handle_wireguard_peers_list(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer_stats_vec stats = {0};
    sb_wireguard_peer_vec peers = {0};
    sb_err ignored = {0};
    sbj *result = NULL;
    int rc = -1;

    /* Live statistics are best effort: any failure means "no live data". */
    if (sb_wireguard_stats(srv->wireguard, &stats, &ignored) != 0) sb_wireguard_peer_stats_vec_free(&stats);
    if (sb_store_list_wireguard_peers(srv->store, &peers, err) != 0) goto done;
    result = sbj_array();
    for (size_t i = 0; i < peers.len; ++i) {
        const sb_wireguard_peer *peer = &peers.items[i];
        sbj *value = sb_wireguard_peer_to_json(peer);
        sbj_set_bool(value, "expired", sb_wireguard_peer_expired(peer));
        sbj_set_str(value, "kind", peer->host_id ? "agent" : "wg");
        if (peer->host_id) {
            sb_host host;
            sb_host_init(&host);
            int found = sb_store_find_host(srv->store, peer->host_id, &host, err);
            if (found >= 0) sbj_set(value, "host_name", found == 1 ? sbj_strn(S(host.name), host.name_len) : sbj_null());
            sb_host_free(&host);
            if (found < 0) {
                sbj_free(value);
                goto done;
            }
        }
        const sb_wireguard_peer_stats *live = NULL;
        for (size_t j = 0; j < stats.len && !live; ++j)
            if (sb_streq(stats.items[j].public_key, peer->public_key)) live = &stats.items[j];
        if (live) {
            sbj_set(value, "endpoint", live->endpoint ? sbj_str(live->endpoint) : sbj_null());
            sbj_set(value, "latest_handshake",
                    live->has_latest_handshake ? sbj_int(live->latest_handshake) : sbj_null());
            sbj_set_int(value, "transfer_rx", live->transfer_rx);
            sbj_set_int(value, "transfer_tx", live->transfer_tx);
        }
        sbj_arr_push(result, value);
    }
    sb_resp_json(resp, 200, result);
    result = NULL;
    rc = 0;
done:
    sbj_free(result);
    sb_wireguard_peer_stats_vec_free(&stats);
    sb_wireguard_peer_vec_free(&peers);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/wireguard/peers. The steps (and so which error wins) follow the
 * C++ designated-initialiser evaluation order. */
static int handle_wireguard_peers_create(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_options runtime;
    memset(&runtime, 0, sizeof runtime);
    sb_wireguard_keypair keys = {0};
    sb_wireguard_peer peer, created;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&created);
    sbj *body = NULL;
    const sbj *found;
    const char *name = NULL, *text = NULL;
    int32_t number;
    int rc = -1;

    body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (sb_wireguard_runtime_options(srv->wireguard, &runtime, err) != 0) goto done;
    if (sb_wireguard_generate_keypair(&keys, err) != 0) goto done;
    name = sb_json_required_string(body, "name", err);
    if (!name) goto done;
    free(peer.name);
    peer.name = sb_http_trim_n(name, sbj_get(body, "name")->v.str.len, &peer.name_len);
    sb_str_set(&peer.private_key, S(keys.private_key));
    sb_str_set(&peer.public_key, S(keys.public_key));
    free(peer.preshared_key);
    peer.preshared_key = sb_wireguard_generate_preshared_key(err);
    if (!peer.preshared_key) goto done;
    found = sbj_get(body, "address");
    if (sbj_is_string(found)) {
        sb_str_set(&peer.address, found->v.str.ptr);
    } else {
        char *next = sb_store_next_wireguard_address(srv->store, S(runtime.address), err);
        if (!next) goto done;
        free(peer.address);
        peer.address = next;
    }
    if (json_value_string(body, "dns", S(runtime.dns), &text, err) != 0) goto done;
    sb_str_set(&peer.dns, text);
    peer.enabled = true;
    number = 25;
    found = sbj_get(body, "persistent_keepalive");
    if (found && json_get_i32(found, &number, err) != 0) goto done;
    peer.persistent_keepalive = number;
    if (json_value_string(body, "allowed_ips", "0.0.0.0/0, ::/0", &text, err) != 0) goto done;
    sb_str_set(&peer.allowed_ips, text);
    found = sbj_get(body, "expire_at");
    if (sbj_is_string(found)) sb_str_set(&peer.expire_at, found->v.str.ptr);
    /* body.value("quota_bytes", 0) deduces int: values are narrowed to 32 bits. */
    number = 0;
    found = sbj_get(body, "quota_bytes");
    if (found && json_get_i32(found, &number, err) != 0) goto done;
    peer.quota_bytes = number;
    found = sbj_get(body, "notes");
    if (sbj_is_string(found)) sb_str_set(&peer.notes, found->v.str.ptr);
    if (sb_store_create_wireguard_peer(srv->store, &peer, &created, err) != 0) goto done;
    sb_http_sync_wireguard_best_effort(srv);
    sb_resp_json(resp, 200, sb_wireguard_peer_to_json(&created));
    rc = 0;
done:
    sbj_free(body);
    sb_wireguard_options_free(&runtime);
    sb_wireguard_keypair_free(&keys);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_free(&created);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/wireguard/peers/{id} */
static int handle_wireguard_peer_get(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    int rc = require_peer(req->server, req->params[0], &peer, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_wireguard_peer_to_json(&peer));
    sb_wireguard_peer_free(&peer);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* PUT /api/wireguard/peers/{id} */
static int handle_wireguard_peer_update(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer peer, updated;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&updated);
    sbj *body = NULL;
    const sbj *found;
    int rc = -1;

    if (require_peer(srv, req->params[0], &peer, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (sb_json_assign_string_n(body, "name", &peer.name, &peer.name_len, err) != 0 ||
        sb_json_assign_string(body, "dns", &peer.dns, err) != 0 ||
        sb_json_assign_bool(body, "enabled", &peer.enabled, err) != 0 ||
        sb_json_assign_string(body, "allowed_ips", &peer.allowed_ips, err) != 0)
        goto done;
    found = sbj_get(body, "persistent_keepalive");
    if (found && !sbj_is_null(found) && json_get_i32(found, &peer.persistent_keepalive, err) != 0) goto done;
    found = sbj_get(body, "quota_bytes");
    if (found && !sbj_is_null(found) && json_get_i64(found, &peer.quota_bytes, err) != 0) goto done;
    found = sbj_get(body, "expire_at");
    if (sbj_is_string(found)) sb_str_set(&peer.expire_at, found->v.str.ptr);
    found = sbj_get(body, "notes");
    if (sbj_is_string(found)) sb_str_set(&peer.notes, found->v.str.ptr);
    if (sb_store_update_wireguard_peer(srv->store, &peer, &updated, err) != 0) goto done;
    sb_http_sync_wireguard_best_effort(srv);
    sb_resp_json(resp, 200, sb_wireguard_peer_to_json(&updated));
    rc = 0;
done:
    sbj_free(body);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_free(&updated);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* DELETE /api/wireguard/peers/{id} */
static int handle_wireguard_peer_delete(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    int rc = require_peer(srv, req->params[0], &peer, err);
    if (rc == 0) {
        sb_wireguard_remove_peer(srv->wireguard, S(peer.public_key));
        rc = sb_store_delete_wireguard_peer(srv->store, req->params[0], err);
    }
    sb_wireguard_peer_free(&peer);
    if (rc != 0) return fail_json_aware(err);
    respond_success(resp);
    return 0;
}

/* POST /api/wireguard/peers/{id}/enable and .../disable */
static int set_peer_enabled(sb_http_req *req, sb_http_resp *resp, sb_err *err, bool enabled) {
    if (sb_store_set_wireguard_peer_enabled(req->server->store, req->params[0], enabled, err) != 0)
        return fail_json_aware(err);
    sb_http_sync_wireguard_best_effort(req->server);
    respond_success(resp);
    return 0;
}

static int handle_wireguard_peer_enable(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return set_peer_enabled(req, resp, err, true);
}

static int handle_wireguard_peer_disable(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return set_peer_enabled(req, resp, err, false);
}

/* GET /api/wireguard/peers/{id}/config */
static int handle_wireguard_peer_config(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    char *config = NULL;
    int rc = -1;

    if (require_peer(srv, req->params[0], &peer, err) != 0) goto done;
    size_t config_len = 0;
    config = sb_wireguard_client_config_n(srv->wireguard, &peer, &config_len, err);
    if (!config) goto done;
    sb_resp_text(resp, 200, "application/octet-stream", config, config_len);
    config = NULL;
    sb_resp_attachment(resp, S(peer.name), peer.name_len, ".conf");
    rc = 0;
done:
    free(config);
    sb_wireguard_peer_free(&peer);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/wireguard/peers/{id}/qr */
static int handle_wireguard_peer_qr(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    char *svg = NULL;
    int rc = require_peer(srv, req->params[0], &peer, err);
    if (rc == 0) {
        svg = sb_wireguard_qr_svg(srv->wireguard, &peer, err);
        if (svg) sb_resp_text(resp, 200, "image/svg+xml", svg, strlen(svg));
        else rc = -1;
    }
    sb_wireguard_peer_free(&peer);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/wireguard/peers/{id}/one-time-link */
static int handle_wireguard_peer_one_time_link(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    char *token = NULL, *expires = NULL;
    sbj *body;
    int rc = -1;

    if (require_peer(srv, req->params[0], &peer, err) != 0) goto done;
    token = sb_http_secure_token(16);
    if (!token) {
        sb_fail(err, SB_ERR_GENERIC, "secure token generation failed");
        goto done;
    }
    expires = utc_after_minutes(5);
    if (!expires) {
        sb_fail(err, SB_ERR_GENERIC, "UTC timestamp conversion failed");
        goto done;
    }
    if (sb_store_create_one_time_link(srv->store, token, req->params[0], expires, err) != 0) goto done;
    body = sbj_object();
    sbj_set(body, "url",
            sbj_str_take(sb_asprintf("https://%s/api/one-time/%s", S(srv->opts.external_hostname), token)));
    sbj_set_str(body, "expires_at", expires);
    sb_resp_json(resp, 200, body);
    rc = 0;
done:
    free(token);
    free(expires);
    sb_wireguard_peer_free(&peer);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/wireguard/stats */
static int handle_wireguard_stats(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_wireguard_peer_stats_vec stats = {0};
    sb_err ignored = {0};
    sbj *peers = sb_wireguard_stats(req->server->wireguard, &stats, &ignored) == 0
                     ? sb_wireguard_peer_stats_vec_to_json(&stats)
                     : sbj_array();
    sb_wireguard_peer_stats_vec_free(&stats);
    sbj *body = sbj_object();
    sbj_set(body, "peers", peers);
    sb_resp_json(resp, 200, body);
    return 0;
}

/* POST /api/wireguard/sync */
static int handle_wireguard_sync(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_wireguard_sync(req->server->wireguard, err) != 0) return fail_json_aware(err);
    respond_success(resp);
    return 0;
}

/* ======================================================================
 * /api/config/sing-box/...
 * ====================================================================== */

/* GET /api/config/sing-box/full: the self host's profile rendered with the
 * panel's own Clash controller settings. */
static int handle_config_full(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_render_request request;
    sb_render_request_init(&request);
    sb_config_renderer renderer;
    sbj *config;
    int rc = -1;

    if (sb_store_render_request_for_host(srv->store, "self", &request, err) != 0) goto done;
    free(request.clash_controller);
    request.clash_controller = sb_http_clash_controller_address(S(srv->opts.clash_api_url));
    sb_str_set(&request.clash_secret, S(srv->opts.clash_api_secret));
    if (sb_config_renderer_init(&renderer, NULL, err) != 0) goto done;
    config = sb_config_renderer_render(&renderer, &request, err);
    if (!config) goto done;
    sb_resp_json(resp, 200, config);
    rc = 0;
done:
    sb_render_request_free(&request);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/config/sing-box/outbounds */
static int handle_config_outbounds(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_proxy_record_vec records = {0};
    sb_proxy_node_vec nodes = {0};
    sbj *outbounds;
    int rc = -1;

    if (sb_store_list_proxy_nodes(req->server->store, &records, err) != 0) goto done;
    for (size_t i = 0; i < records.len; ++i) renderer_node(&records.items[i], sb_proxy_node_vec_push(&nodes));
    outbounds = sb_config_generate_outbounds(nodes.items, nodes.len, err);
    if (!outbounds) goto done;
    sb_resp_json(resp, 200, outbounds);
    rc = 0;
done:
    sb_proxy_record_vec_free(&records);
    sb_proxy_node_vec_free(&nodes);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/config/sing-box/outbound/{id} */
static int handle_config_outbound(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_proxy_record record;
    sb_proxy_record_init(&record);
    sb_proxy_node node;
    sb_proxy_node_init(&node);
    sbj *outbound;
    int rc = -1;

    if (sb_http_require_proxy(req->server, req->params[0], &record, err) != 0) goto done;
    renderer_node(&record, &node);
    outbound = sb_config_generate_outbound(&node, err);
    if (!outbound) goto done;
    sb_resp_json(resp, 200, outbound);
    rc = 0;
done:
    sb_proxy_record_free(&record);
    sb_proxy_node_free(&node);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* ====================================================================== */

void sb_http_register_admin_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET", "/api/health", handle_health);
    sb_http_route(srv, "GET", "/api/system/status", handle_system_status);
    sb_http_route(srv, "GET", "/api/system/logs", handle_system_logs);
    sb_http_route(srv, "POST", "/api/system/migrate/wg-easy", handle_migrate_wg_easy);
    sb_http_route(srv, "POST", "/api/auth/login", handle_auth_login);
    sb_http_route(srv, "GET", "/api/auth/session", handle_auth_session);
    sb_http_route(srv, "GET", "/api/users/audit", handle_users_audit);
    sb_http_route(srv, "GET", "/api/users", handle_users_list);
    sb_http_route(srv, "POST", "/api/users", handle_users_create);
    sb_http_route(srv, "DELETE", "/api/users/{id}", handle_users_delete);
    sb_http_route(srv, "POST", "/api/users/{id}/password", handle_users_password);
    sb_http_route(srv, "GET", "/api/settings", handle_settings_get);
    sb_http_route(srv, "PUT", "/api/settings", handle_settings_put);
    sb_http_route(srv, "GET", "/api/settings/backup", handle_settings_backup);
    sb_http_route(srv, "POST", "/api/settings/restore", handle_settings_restore);
    sb_http_route(srv, "GET", "/api/wireguard/peers", handle_wireguard_peers_list);
    sb_http_route(srv, "POST", "/api/wireguard/peers", handle_wireguard_peers_create);
    sb_http_route(srv, "GET", "/api/wireguard/peers/{id}", handle_wireguard_peer_get);
    sb_http_route(srv, "PUT", "/api/wireguard/peers/{id}", handle_wireguard_peer_update);
    sb_http_route(srv, "DELETE", "/api/wireguard/peers/{id}", handle_wireguard_peer_delete);
    sb_http_route(srv, "POST", "/api/wireguard/peers/{id}/enable", handle_wireguard_peer_enable);
    sb_http_route(srv, "POST", "/api/wireguard/peers/{id}/disable", handle_wireguard_peer_disable);
    sb_http_route(srv, "GET", "/api/wireguard/peers/{id}/config", handle_wireguard_peer_config);
    sb_http_route(srv, "GET", "/api/wireguard/peers/{id}/qr", handle_wireguard_peer_qr);
    sb_http_route(srv, "POST", "/api/wireguard/peers/{id}/one-time-link", handle_wireguard_peer_one_time_link);
    sb_http_route(srv, "GET", "/api/wireguard/stats", handle_wireguard_stats);
    sb_http_route(srv, "POST", "/api/wireguard/sync", handle_wireguard_sync);
    sb_http_route(srv, "GET", "/api/config/sing-box/full", handle_config_full);
    sb_http_route(srv, "GET", "/api/config/sing-box/outbounds", handle_config_outbounds);
    sb_http_route(srv, "GET", "/api/config/sing-box/outbound/{id}", handle_config_outbound);
}
