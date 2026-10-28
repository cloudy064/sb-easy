#include "http_internal.h"
#include "sb/proxy_users.h"
#include <stdlib.h>
#include <string.h>

static sbj *body_object(const sb_http_req *req, sb_err *err) {
    if (req->body_len > 1024 * 1024) {
        sb_fail(err, SB_ERR_VALIDATION, "Proxy request exceeds 1 MiB");
        return NULL;
    }
    char error[128];
    sbj *body = sbj_parse_strict(req->body, req->body_len, error, sizeof error);
    if (!sbj_is_object(body)) {
        sbj_free(body);
        sb_fail(err, SB_ERR_VALIDATION, "Request must be a JSON object with unique keys");
        return NULL;
    }
    return body;
}
static int response(sb_http_resp *resp, sbj *out) {
    if (!out)
        return -1;
    sb_resp_header(resp, "Cache-Control", "no-store");
    sb_resp_header(resp, "Referrer-Policy", "no-referrer");
    sb_resp_json(resp, 200, out);
    return 0;
}
static sbj *ok(void) {
    sbj *out = sbj_object();
    sbj_set_bool(out, "ok", true);
    return out;
}
static int users(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    sb_database *db = sb_store_database(req->server->store);
    if (!strcmp(req->method, "GET"))
        return response(resp, sb_proxy_users_list(db, err));
    sbj *body = body_object(req, err);
    if (!body)
        return -1;
    sbj *out = sb_proxy_user_save(db, NULL, body, sb_unix_now(), err);
    sbj_free(body);
    return response(resp, out);
}
static int user(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    sb_database *db = sb_store_database(req->server->store);
    const char *id = req->params[0];
    if (!strcmp(req->method, "GET"))
        return response(resp, sb_proxy_user_get(db, id, err));
    if (!strcmp(req->method, "DELETE"))
        return sb_proxy_user_remove(db, id, sb_unix_now(), err) ? -1 : response(resp, ok());
    sbj *body = body_object(req, err);
    if (!body)
        return -1;
    sbj *out = sb_proxy_user_save(db, id, body, sb_unix_now(), err);
    sbj_free(body);
    return response(resp, out);
}
static int reset(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    return response(
        resp, sb_proxy_user_reset(sb_store_database(req->server->store), req->params[0], sb_unix_now(), err));
}
static int claim(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    return response(resp, sb_proxy_claim_rotate(sb_store_database(req->server->store), req->params[0],
                                                sb_unix_now(), err));
}
static int admin_device(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    sb_database *db = sb_store_database(req->server->store);
    if (!strcmp(req->method, "DELETE"))
        return sb_proxy_device_revoke(db, req->params[0], req->params[1], sb_unix_now(), err)
                   ? -1
                   : response(resp, ok());
    sbj *body = body_object(req, err);
    if (!body)
        return -1;
    sbj *out = sb_proxy_device_create(db, req->params[0], body, sb_unix_now(), err);
    sbj_free(body);
    return response(resp, out);
}
static int ingress(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err))
        return -1;
    sb_database *db = sb_store_database(req->server->store);
    if (!strcmp(req->method, "GET"))
        return response(resp, sb_proxy_ingress_list(db, err));
    sbj *body = body_object(req, err);
    if (!body)
        return -1;
    sbj *out = sb_proxy_ingress_save(db, req->params[0], body, sb_unix_now(), err);
    sbj_free(body);
    return response(resp, out);
}
static const char *bearer(const sb_http_req *req, sb_err *err) {
    const char *value = sb_req_header(req, "Authorization");
    if (!value || strncmp(value, "Bearer ", 7) || !value[7]) {
        sb_fail(err, SB_ERR_AUTH, "Bearer credential required");
        return NULL;
    }
    return value + 7;
}
static int self_service(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *token = bearer(req, err);
    if (!token)
        return -1;
    sb_database *db = sb_store_database(req->server->store);
    char *id = sb_proxy_claim_resolve(db, token, sb_unix_now(), err);
    if (!id)
        return -1;
    sbj *out = NULL;
    if (!strcmp(req->path, "/api/proxy-self/status"))
        out = sb_proxy_user_get(db, id, err);
    else if (!strcmp(req->method, "DELETE")) {
        if (!sb_proxy_device_revoke(db, id, req->params[0], sb_unix_now(), err))
            out = ok();
    } else {
        sbj *body = body_object(req, err);
        if (body) {
            out = sb_proxy_device_create(db, id, body, sb_unix_now(), err);
            sbj_free(body);
        }
    }
    if (out && strcmp(req->path, "/api/proxy-self/status")) {
        sb_err audit = {0};
        if (sb_store_record_audit(req->server->store, "proxy-self", req->method, id, &audit))
            SB_ERROR("proxy self-service audit failed: %s", audit.msg);
    }
    free(id);
    return response(resp, out);
}
static int subscription(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *token = sb_req_query_param(req, "token");
    sbj *out = sb_proxy_subscription(sb_store_database(req->server->store), token, sb_unix_now(), err);
    free(token);
    return response(resp, out);
}
static int exchange(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (req->body_len > 512 * 1024)
        return sb_fail(err, SB_ERR_VALIDATION, "Proxy lease request exceeds 512 KiB");
    const char *token = bearer(req, err);
    if (!token)
        return -1;
    sb_host host;
    sb_host_init(&host);
    int found = sb_store_find_enabled_host_by_token(req->server->store, token, &host, err);
    if (found == 0 && !sb_str_empty(req->server->legacy_agent_token) &&
        sb_consttime_streq(token, req->server->legacy_agent_token))
        found = sb_store_find_host(req->server->store, "self", &host, err);
    if (found != 1 || !host.enabled) {
        sb_host_free(&host);
        return found < 0 ? -1 : sb_fail(err, SB_ERR_AUTH, "Invalid or disabled agent token");
    }
    sbj *body = body_object(req, err), *out = NULL;
    if (body) {
        out =
            sb_proxy_lease_exchange(sb_store_database(req->server->store), host.id, body, sb_unix_now(), err);
        sbj_free(body);
    }
    sb_host_free(&host);
    return response(resp, out);
}
void sb_http_register_proxy_user_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET,POST", "/api/proxy-users", users);
    sb_http_route(srv, "GET,PUT,DELETE", "/api/proxy-users/{id}", user);
    sb_http_route(srv, "POST", "/api/proxy-users/{id}/reset", reset);
    sb_http_route(srv, "POST", "/api/proxy-users/{id}/claim-token", claim);
    sb_http_route(srv, "POST", "/api/proxy-users/{id}/devices", admin_device);
    sb_http_route(srv, "DELETE", "/api/proxy-users/{id}/devices/{device}", admin_device);
    sb_http_route(srv, "GET", "/api/proxy-ingress", ingress);
    sb_http_route(srv, "PUT", "/api/proxy-ingress/{host}", ingress);
    sb_http_route(srv, "POST", "/api/proxy-self/status", self_service);
    sb_http_route(srv, "POST", "/api/proxy-self/devices", self_service);
    sb_http_route(srv, "DELETE", "/api/proxy-self/devices/{device}", self_service);
    sb_http_route(srv, "GET", "/api/proxy-self/subscription", subscription);
    sb_http_route(srv, "POST", "/api/agent/proxy-leases", exchange);
}
