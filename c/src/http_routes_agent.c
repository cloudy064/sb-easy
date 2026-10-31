/* Panel HTTP routes for agents and devices: /api/agent/..., /api/devices/enroll
 * and the host packet-capture endpoints. Split out of http_routes_hosts.c. */
#include "http_internal.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http_routes_hosts_internal.h"
#include "sb/config_etag.h"
#include "sb/config_renderer.h"
#include "sb/script_engine.h"
#include "sb/types.h"
#include "sb/wireguard.h"
#include "sb/observability.h"
#include "sb/proxy_users.h"

#define S(x) ((x) ? (x) : "")

/* ======================================================================
 * /api/agent/..., /api/devices/enroll
 * ====================================================================== */

/* agent_token(): the trimmed value after a case-sensitive "Bearer " prefix;
 * 401 "Missing agent token" otherwise. malloc'd or NULL. */
static char *agent_token(const sb_http_req *req, sb_err *err) {
    const char *authorization = sb_req_header(req, "Authorization");
    if (!authorization || strncmp(authorization, "Bearer ", 7) != 0) {
        sb_fail(err, SB_ERR_AUTH, "Missing agent token");
        return NULL;
    }
    char *token = sb_http_trim(authorization + 7);
    if (!token || !*token) {
        free(token);
        sb_fail(err, SB_ERR_AUTH, "Missing agent token");
        return NULL;
    }
    return token;
}

/* resolve_agent_host(): the enabled host owning the bearer token, or the
 * "self" host for the legacy AGENT_TOKEN. `out` must be initialised. */
static int resolve_agent_host(const sb_http_req *req, sb_host *out, sb_err *err) {
    sb_http_server *srv = req->server;
    char *token = agent_token(req, err);
    if (!token) return -1;
    int found = sb_store_find_enabled_host_by_token(srv->store, token, out, err);
    if (found == 0 && !sb_str_empty(srv->legacy_agent_token) && sb_consttime_streq(token, srv->legacy_agent_token))
        found = sb_store_find_host(srv->store, "self", out, err);
    free(token);
    if (found < 0) return -1;
    if (found == 0) return sb_fail(err, SB_ERR_AUTH, "Invalid agent token");
    return 0;
}

/* optional_string_field() / optional_boolean_field(): absent or null -> null,
 * otherwise the value itself when it has the right type. */
static sbj *optional_field(const sbj *body, const char *field, bool boolean, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!found || sbj_is_null(found)) return sbj_null();
    if (boolean ? !sbj_is_bool(found) : !sbj_is_string(found)) {
        sb_fail(err, SB_ERR_VALIDATION, "%s must be a %s or null", field, boolean ? "boolean" : "string");
        return NULL;
    }
    return sbj_clone(found);
}

/* GET /api/agent/health (public) */
static int handle_agent_health(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    (void)req; (void)err;
    sbj *body = sbj_object();
    sbj_set_str(body, "status", "ok");
    sb_resp_json(resp, 200, body);
    return 0;
}

/* POST /api/devices/enroll and the released-Android alias /api/agent/enroll
 * (redeem_device_enrollment; public). */
static int handle_redeem_device_enrollment(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    int rc = -1;
    sbj *device = NULL;
    sb_agent_enrollment_result enrollment;
    sb_agent_enrollment_result_init(&enrollment);
    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    /* body.value("device", json::object()) */
    const sbj *found = sbj_get(body, "device");
    device = found ? sbj_clone(found) : sbj_object();
    const char *code = sb_json_required_string(body, "code", err);
    if (!code) goto done;
    const sbj *code_value = sbj_get(body, "code");
    if (json_string_has_nul(code_value)) {
        /* C++ hashes every byte of the code, so a code with an embedded NUL
         * never matches an issued (hex) code. Mirror the store's checks
         * instead of letting a C string silently drop the suffix. */
        if (code_value->v.str.len < 32U || !sbj_is_object(device))
            sb_fail(err, SB_ERR_VALIDATION, "A valid enrollment code and device are required");
        else
            sb_fail(err, SB_ERR_VALIDATION, "Enrollment code is invalid or expired");
        goto done;
    }
    if (sb_store_redeem_agent_enrollment(srv->store, code, device, &enrollment, err) != 0) goto done;
    sbj *out = sbj_object();
    sbj_set_str(out, "server", S(srv->enrollment_server));
    sbj_set_str(out, "host_id", S(enrollment.host_id));
    sbj_set(out, "host_name", sbj_strn(S(enrollment.host_name), enrollment.host_name_len));
    sbj_set_str(out, "agent_token", S(enrollment.agent_token));
    sbj *profile = sbj_object();
    sbj_set_str(profile, "id", S(enrollment.profile_id));
    sbj_set(profile, "name", sbj_strn(S(enrollment.profile_name), enrollment.profile_name_len));
    sbj_set(out, "profile", profile);
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sbj_free(device);
    sb_agent_enrollment_result_free(&enrollment);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* Metadata is restricted to nodes actually rendered for this device. Never
 * return subscription URLs, credentials, or other devices' proxy inventories. */
static sbj *agent_subscription_sources(sb_http_server *srv,const sbj *config,sb_err *err) {
    sb_proxy_record_vec nodes={0};sb_subscription_vec subscriptions={0};sbj *result=NULL;
    if(sb_store_list_proxy_nodes(srv->store,&nodes,err)!=0 || sb_store_list_subscriptions(srv->store,&subscriptions,err)!=0)goto done;
    result=sbj_array();const sbj *outbounds=sbj_get(config,"outbounds");
    for(size_t i=0;i<subscriptions.len;++i){
        const sb_subscription *sub=&subscriptions.items[i];sbj *tags=sbj_array();
        for(size_t j=0;j<nodes.len;++j){const sb_proxy_record *node=&nodes.items[j];
            if(!node->subscription_id || strcmp(node->subscription_id,sub->id))continue;
            for(size_t k=0;k<sbj_arr_len(outbounds);++k){const sbj *out=sbj_arr_at(outbounds,k);
                if(sbj_string_is(sbj_get(out,"tag"),node->tag) && sbj_string_is(sbj_get(out,"server"),node->server) && sbj_get_int(out,"server_port",0)==node->server_port && sbj_string_is(sbj_get(out,"type"),node->node_type)){sbj_arr_push(tags,sbj_str(node->tag));break;}
            }
        }
        if(sbj_arr_len(tags)){sbj *entry=sbj_object();sbj_set_str(entry,"id",sub->id);sbj_set(entry,"name",sbj_strn(S(sub->name),sub->name_len));sbj_set(entry,"tags",tags);sbj_arr_push(result,entry);}else sbj_free(tags);
    }
 done:sb_proxy_record_vec_free(&nodes);sb_subscription_vec_free(&subscriptions);return result;
}

/* GET /api/agent/config: the rendered config as pretty JSON with the config
 * ETag; If-None-Match equal to it yields an empty 304. */
static int handle_agent_config(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    int rc = -1;
    char *previous_address = NULL, *body = NULL, *etag = NULL;
    sbj *config = NULL;
    sb_host host;
    sb_config_profile profile;
    sb_render_request request;
    sb_host_init(&host);
    sb_config_profile_init(&profile);
    sb_render_request_init(&request);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    previous_address = sb_strdup(host.wg_address);
    if (managed_render_request(srv, &host, true, srv->enrollment_server, &request, err) != 0) goto done;
    if (!sb_streq(host.wg_address, previous_address)) sb_http_sync_wireguard_best_effort(srv);
    const char *profile_id = host.profile_id ? host.profile_id : "default";
    if (sb_http_require_profile(srv, profile_id, &profile, err) != 0) goto done;
    const char *rule_source = request.rule_script ? "quickjs" : "profile";
    config = render_config(&request, err);
    if (!config) goto done;
    char *sources_requested=sb_req_query_param(req,"sources");
    bool include_sources=sb_streq(sources_requested,"1");free(sources_requested);
    if(include_sources){
        sbj *sources=agent_subscription_sources(srv,config,err);if(!sources)goto done;
        sbj *envelope=sbj_object();sbj_set(envelope,"config",sbj_clone(config));sbj_set(envelope,"subscription_sources",sources);
        body=sbj_dump(envelope,2);sbj_free(envelope);
    }else body = sbj_dump(config, 2);
    etag = sb_config_etag(host.id, body, srv->opts.config_hash_seed);
    if (!etag) {
        sb_fail(err, SB_ERR_GENERIC, "SHA-256 ETag finalization failed");
        goto done;
    }
    if (sb_store_touch_host(srv->store, host.id, err) != 0) goto done;
    if (sb_observability_target(sb_store_database(srv->store), host.id, etag, sb_unix_now(), err) != 0) goto done;

    const char *if_none_match = sb_req_header(req, "If-None-Match");
    if (if_none_match && strcmp(if_none_match, etag) == 0) {
        /* A bare Drogon response: 304, empty body, default content type. */
        sb_resp_text(resp, 304, "text/html; charset=utf-8", sb_strdup(""), 0);
    } else {
        size_t len = strlen(body);
        sb_resp_text(resp, 200, "application/json; charset=utf-8", body, len);
        body = NULL;
    }
    sb_resp_header(resp, "ETag", etag);
    sb_resp_header(resp, "X-SB-Easy-Rule-Source", rule_source);
    sb_resp_header(resp, "X-SB-Easy-Profile-Id", profile_id);
    sb_resp_header_n(resp, "X-SB-Easy-Profile-Name", S(profile.name), profile.name_len);
    rc = 0;
done:
    free(previous_address);
    free(body);
    free(etag);
    sbj_free(config);
    sb_host_free(&host);
    sb_config_profile_free(&profile);
    sb_render_request_free(&request);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/agent/status */
static int handle_agent_status(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL, *state = NULL;
    sb_host host;
    sb_host_init(&host);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    /* Braced-init-list order: fields are validated left to right. */
    static const struct {
        const char *key, *field;
        bool boolean;
    } fields[] = {
        {"version", "singbox_version", false},  {"app_version", "app_version", false},
        {"running", "singbox_running", true},   {"etag", "config_etag", false},
        {"last_error", "last_error", false},
    };
    state = sbj_object();
    for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
        sbj *value = optional_field(body, fields[i].field, fields[i].boolean, err);
        if (!value) goto done;
        sbj_set(state, fields[i].key, value);
    }
    if (sb_proxy_runtime_report(sb_store_database(req->server->store), host.id,
                                sbj_get(body, "capabilities"), sb_unix_now(), err) != 0) goto done;
    if (sb_store_update_agent_status(req->server->store, host.id, state, err) != 0) goto done;
    if (sb_observability_status(sb_store_database(req->server->store), host.id, state, sb_unix_now(), err) != 0) goto done;
    respond_ok(resp);
    rc = 0;
done:
    sbj_free(body);
    sbj_free(state);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/agent/commands: the agent's pending commands. */
static int handle_agent_commands(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sb_host host;
    sb_host_command_vec commands = {0};
    sb_host_init(&host);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    if (sb_store_list_host_commands(req->server->store, host.id, true, &commands, err) != 0) goto done;
    sb_resp_json(resp, 200, commands_to_json(&commands));
    rc = 0;
done:
    sb_host_command_vec_free(&commands);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/agent/commands/{command_id}/ack. Acknowledging another host's
 * command silently matches nothing (existence is not leaked). */
static int handle_agent_command_ack(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL;
    sb_host host;
    sb_host_init(&host);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    const sbj *status_value = NULL;
    const char *ignored = NULL;
    if (json_value_string(body, "status", "", &status_value, &ignored, err) != 0) goto done;
    const char *status = status_value && sb_json_string_is(status_value, "done") ? "done" : "failed";
    /* optional_result(): "result must be a string or null". */
    const sbj *result = sbj_get(body, "result");
    if (result && !sbj_is_null(result) && !sbj_is_string(result)) {
        sb_fail(err, SB_ERR_VALIDATION, "result must be a string or null");
        goto done;
    }
    const char *result_text = result && sbj_is_string(result) ? result->v.str.ptr : NULL;
    if (sb_store_acknowledge_host_command_n(req->server->store, host.id, route_param(req), status, result_text,
                                            result_text ? result->v.str.len : 0, err) < 0)
        goto done;
    respond_ok(resp);
    rc = 0;
done:
    sbj_free(body);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/agent/proxy-latency */
static int handle_agent_proxy_latency(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL;
    sb_host host;
    sb_host_init(&host);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    size_t updated = 0;
    const sbj *results = sbj_get(body, "results");
    if (results && sb_store_update_proxy_latencies(req->server->store, results, &updated, err) != 0) goto done;
    sbj *out = sbj_object();
    sbj_set_bool(out, "ok", true);
    sbj_set(out, "updated", sbj_uint(updated));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/agent/telemetry */
static int handle_agent_telemetry(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL, *telemetry = NULL;
    sb_host host;
    sb_host_init(&host);
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    telemetry = sb_http_normalize_telemetry(body, err);
    if (!telemetry) goto done;
    if (sb_observability_sample(sb_store_database(req->server->store), host.id, telemetry, sb_unix_now(), err) != 0) goto done;
    sb_http_telemetry_put(req->server, host.id, telemetry);
    telemetry = NULL;
    respond_ok(resp);
    rc = 0;
done:
    sbj_free(body);
    sbj_free(telemetry);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/agent/diagnostics: an explicitly uploaded, whitelisted report. */
static int handle_agent_diagnostics(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL, *report = NULL;
    char *report_id = NULL;
    sb_host host;
    sb_host_init(&host);
    if (req->body_len > 1000000U) {
        sb_fail(err, SB_ERR_VALIDATION, "Diagnostic report exceeds 1 MB");
        goto done;
    }
    if (resolve_agent_host(req, &host, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    report = sb_http_normalize_diagnostic_report(body, err);
    if (!report) goto done;
    char *dumped = sbj_dump(report, -1);
    size_t dumped_len = strlen(dumped);
    free(dumped);
    if (dumped_len > 1000000U) {
        sb_fail(err, SB_ERR_VALIDATION, "Diagnostic report exceeds 1 MB");
        goto done;
    }
    report_id = sb_store_save_diagnostic_report(req->server->store, host.id, report, err);
    if (!report_id) goto done;
    sbj *out = sbj_object();
    sbj_set_bool(out, "ok", true);
    sbj_set(out, "report_id", sbj_str_take(report_id));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sbj_free(report);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

static uint32_t pcap_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static bool valid_pcap(const char *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    if (len < 40 || len > 768*1024 || pcap_u32(p) != 0xa1b2c3d4 ||
        p[4] != 2 || p[5] != 0 || p[6] != 4 || p[7] != 0 ||
        pcap_u32(p+16) != 65535 || pcap_u32(p+20) != 101) return false;
    size_t offset = 24;
    while (offset < len) {
        if (len-offset < 16) return false;
        uint32_t size = pcap_u32(p+offset+8);
        if (size == 0 || size > 65535 || size != pcap_u32(p+offset+12) ||
            pcap_u32(p+offset+4) >= 1000000 || size > len-offset-16) return false;
        offset += 16+size;
    }
    return offset == len;
}
static int handle_agent_capture(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host host; sb_host_init(&host);
    int rc = resolve_agent_host(req, &host, err);
    if (rc != 0) { sb_host_free(&host); return fail_json_aware(err); }
    const char *digest = route_param(req);
    char *actual = sb_sha256_hex(req->body, req->body_len);
    if (!valid_pcap(req->body, req->body_len) || !sb_streq(digest, actual))
        rc = sb_fail(err, SB_ERR_VALIDATION, "Invalid raw-IP PCAP or SHA-256 digest");
    else rc = sb_store_save_capture(req->server->store, host.id, digest, req->body, req->body_len, err);
    free(actual); sb_host_free(&host);
    if (rc != 0) return fail_json_aware(err);
    sbj *out = sbj_object(); sbj_set_bool(out, "ok", true); sbj_set_str(out, "digest", digest);
    sb_resp_json(resp, 200, out); return 0;
}
static int handle_host_captures(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    sbj *out = sb_store_list_captures(req->server->store, route_param(req), err);
    if (!out) return fail_json_aware(err);
    sb_resp_json(resp, 200, out); return 0;
}
static int handle_host_capture(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_require_admin(req, err) != 0) return -1;
    if (req->param_count != 2) return sb_fail(err, SB_ERR_VALIDATION, "Missing capture digest");
    const char *host = req->params[0], *digest = req->params[1];
    if (strcmp(req->method, "DELETE") == 0) {
        if (sb_store_delete_capture(req->server->store, host, digest, err) != 0) return fail_json_aware(err);
        sbj *out = sbj_object(); sbj_set_bool(out, "ok", true); sb_resp_json(resp, 200, out); return 0;
    }
    size_t len = 0;
    char *data = sb_store_get_capture(req->server->store, host, digest, &len, err);
    if (!data) return fail_json_aware(err);
    sb_resp_text(resp, 200, "application/vnd.tcpdump.pcap", data, len);
    sb_resp_attachment(resp, digest, strlen(digest), ".pcap");
    sb_resp_header(resp, "Cache-Control", "no-store");
    return 0;
}

void sb_http_register_agent_routes(sb_http_server *srv) {
    sb_http_route(srv, "POST", "/api/agent/captures/{digest}", handle_agent_capture);
    sb_http_route(srv, "GET", "/api/hosts/{id}/captures", handle_host_captures);
    sb_http_route(srv, "GET,DELETE", "/api/hosts/{id}/captures/{digest}", handle_host_capture);
    sb_http_route(srv, "GET", "/api/agent/health", handle_agent_health);
    sb_http_route(srv, "POST", "/api/devices/enroll", handle_redeem_device_enrollment);
    /* Backward-compatible alias used by already released Android apps. */
    sb_http_route(srv, "POST", "/api/agent/enroll", handle_redeem_device_enrollment);
    sb_http_route(srv, "GET", "/api/agent/config", handle_agent_config);
    sb_http_route(srv, "POST", "/api/agent/status", handle_agent_status);
    sb_http_route(srv, "GET", "/api/agent/commands", handle_agent_commands);
    sb_http_route(srv, "POST", "/api/agent/commands/{command_id}/ack", handle_agent_command_ack);
    sb_http_route(srv, "POST", "/api/agent/proxy-latency", handle_agent_proxy_latency);
    sb_http_route(srv, "POST", "/api/agent/telemetry", handle_agent_telemetry);
    sb_http_route(srv, "POST", "/api/agent/diagnostics", handle_agent_diagnostics);
}
