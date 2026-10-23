#include "http_internal.h"
#include "sb/preferences_sync.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int expected_revision(const sb_http_req *req, int64_t *out, sb_err *err) {
    const char *match = sb_req_header(req, "If-Match");
    if (!match) return sb_fail(err, SB_ERR_VALIDATION, "If-Match preference revision is required (0 for a new slot)");
    bool quoted = *match == '"'; if (quoted) ++match;
    const char *p = match; while (*p >= '0' && *p <= '9') ++p;
    if (p == match || (quoted ? strcmp(p, "\"") != 0 : *p != 0) || p - match > 18)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid If-Match preference revision");
    errno = 0; char *end; long long revision = strtoll(match, &end, 10);
    if (errno || revision < 0) return sb_fail(err, SB_ERR_VALIDATION, "Invalid If-Match preference revision");
    *out = revision; return 0;
}
static int preferences(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const sb_auth_claims *claims = sb_req_claims(req, err); if (!claims) return -1;
    sb_database *db = sb_store_database(req->server->store);
    sbj *result = NULL; int64_t revision = 0;
    if (strcmp(req->method, "GET") == 0) result = sb_preferences_get(db, claims->subject, req->params[0], err);
    else {
        if (expected_revision(req, &revision, err) != 0) return -1;
        if (strcmp(req->method, "DELETE") == 0) {
            if (sb_preferences_delete(db, claims->subject, req->params[0], revision, err) != 0) return -1;
            result = sb_preferences_get(db, claims->subject, req->params[0], err);
        } else {
            sbj *body = sb_req_json_object(req, err); if (!body) return -1;
            result = sb_preferences_put(db, claims->subject, req->params[0], revision, body, err); sbj_free(body);
        }
    }
    if (!result) return -1;
    if (sbj_has(result, "revision")) {
        char *etag = sb_asprintf("\"%lld\"", (long long)sbj_get_int(result, "revision", 0));
        sb_resp_header(resp, "ETag", etag); free(etag);
    }
    sb_resp_header(resp, "Cache-Control", "no-store"); sb_resp_json(resp, 200, result); return 0;
}
void sb_http_register_preferences_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET,PUT,DELETE", "/api/auth/preferences/{slot}", preferences);
}
