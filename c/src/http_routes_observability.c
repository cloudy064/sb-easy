#include "http_internal.h"
#include "sb/observability.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static sb_database *database(sb_http_req *req) { return sb_store_database(req->server->store); }
static int json_result(sb_http_resp *resp, sbj *out) {
    if (!out) return -1;
    sb_resp_header(resp, "Cache-Control", "no-store"); sb_resp_json(resp, 200, out); return 0;
}
static int number(const char *text, int64_t *value, sb_err *err) {
    if (!text || !*text || strlen(text) > 18) return sb_fail(err, SB_ERR_VALIDATION, "Expected a positive integer");
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return sb_fail(err, SB_ERR_VALIDATION, "Expected a positive integer");
    errno = 0; *value = strtoll(text, NULL, 10);
    return errno || *value <= 0 ? sb_fail(err, SB_ERR_VALIDATION, "Expected a positive integer") : 0;
}
static int query_number(const sb_http_req *req, const char *key, int64_t fallback, int64_t *out, sb_err *err) {
    char *value = sb_req_query_param(req, key); *out = fallback;
    int rc = value ? number(value, out, err) : 0; free(value); return rc;
}
static int history(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host host; sb_host_init(&host);
    int rc = sb_http_require_host(req->server, req->params[0], &host, err); sb_host_free(&host); if (rc != 0) return -1;
    int64_t now = sb_unix_now(), from, to, step;
    if (query_number(req, "from", now - 86400, &from, err) != 0 || query_number(req, "to", now, &to, err) != 0 ||
        query_number(req, "step", 300, &step, err) != 0) return -1;
    sbj *samples = sb_observability_history(database(req), req->params[0], from, to, step, err); if (!samples) return -1;
    sbj *out = sbj_object(); sbj_set_str(out, "host_id", req->params[0]); sbj_set_int(out, "from", from);
    sbj_set_int(out, "to", to); sbj_set_int(out, "step", step); sbj_set(out, "samples", samples);
    sbj_set_str(out, "quality", "receipt-time samples; gaps are unknown; initial totals are baselines; counter resets may lose unreported traffic");
    return json_result(resp, out);
}
static int overview(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *hosts = sb_observability_hosts(database(req), sb_unix_now(), err); if (!hosts) return -1;
    sbj *out = sbj_object(); sbj_set_int(out, "at", sb_unix_now()); sbj_set(out, "hosts", hosts); return json_result(resp, out);
}
static int alerts(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *active = sb_req_query_param(req, "active"); bool only_active = !active || strcmp(active, "0") != 0; free(active);
    const char *host = sb_starts_with(req->path, "/api/hosts/") ? req->params[0] : NULL;
    return json_result(resp, sb_observability_alerts(database(req), host, only_active, err));
}
static int acknowledge(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int64_t id; if (number(req->params[0], &id, err) != 0) return -1;
    if (sb_observability_ack(database(req), id, req->claims->subject, err) != 0) return -1;
    sbj *out = sbj_object(); sbj_set_bool(out, "success", true); return json_result(resp, out);
}
static int settings(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (strcmp(req->method, "PUT") == 0) {
        sbj *body = sb_req_json_object(req, err); if (!body) return -1;
        int rc = sb_observability_configure(database(req), body, err); sbj_free(body); if (rc != 0) return -1;
    }
    return json_result(resp, sb_observability_settings(database(req), err));
}
static int token(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *value = sb_observability_rotate_token(database(req), strcmp(req->method, "DELETE") == 0, err);
    if (!value) return -1;
    sbj *out = sbj_object(); sbj_set(out, "token", sbj_str_take(value)); return json_result(resp, out);
}
static int prometheus(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *authorization = sb_req_header(req, "Authorization");
    if (!authorization || strncmp(authorization, "Bearer ", 7) != 0 || !sb_observability_check_token(database(req), authorization + 7))
        return sb_fail(err, SB_ERR_AUTH, "A valid metrics read-only token is required");
    char *out = sb_observability_prometheus(database(req), sb_unix_now(), err); if (!out) return -1;
    sb_resp_header(resp, "Cache-Control", "no-store");
    sb_resp_text(resp, 200, "text/plain; version=0.0.4; charset=utf-8", out, strlen(out)); return 0;
}
void sb_http_register_observability_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET", "/api/hosts/{id}/history", history);
    sb_http_route(srv, "GET", "/api/hosts/{id}/alerts", alerts);
    sb_http_route(srv, "GET", "/api/observability", overview);
    sb_http_route(srv, "GET", "/api/observability/alerts", alerts);
    sb_http_route(srv, "POST", "/api/observability/alerts/{id}/ack", acknowledge);
    sb_http_route(srv, "GET,PUT", "/api/observability/settings", settings);
    sb_http_route(srv, "POST,DELETE", "/api/observability/token", token);
    sb_http_route(srv, "GET", "/api/metrics", prometheus);
}
