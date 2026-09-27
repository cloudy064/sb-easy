/* Panel HTTP routes: /api/hosts*, /api/devices/..., /api/agent/...
 * Port of the corresponding handlers in cpp/src/http_server.cpp
 * (register_http_routes, "/api/hosts/profiles" through "/api/agent/diagnostics")
 * plus the anonymous-namespace helpers only these routes use
 * (profile_from_request, host_from_*_request, normalized_command, agent_token,
 * resolve_agent_host, optional_*_field, managed_render_request, ...). */
#include "http_internal.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sb/config_etag.h"
#include "sb/config_renderer.h"
#include "sb/script_engine.h"
#include "sb/types.h"
#include "sb/wireguard.h"

#define S(x) ((x) ? (x) : "")

/* ======================================================================
 * file-local helpers
 * ====================================================================== */

/* handle_response() answers any nlohmann json::exception escaping a handler
 * with 400 {"error": "Invalid JSON request: <what()>"}. The C renderer and
 * WireGuard service report those failures as SB_ERR_GENERIC carrying
 * nlohmann's what() text, so reclassify them. Always returns -1. */
static int fail_json_aware(sb_err *err) {
    if (err && err->code == SB_ERR_GENERIC && sb_starts_with(err->msg, "[json.exception."))
        err->code = SB_ERR_BAD_JSON;
    return -1;
}

static int type_error_302(sb_err *err, const char *expected, const sbj *value) {
    return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be %s, but is %s",
                   expected, sbj_type_name(value));
}

/* nlohmann object.value(key, bool fallback): absent -> fallback; present
 * (null included) but not a boolean -> type_error.302; non-object ->
 * type_error.306. */
static int json_value_bool(const sbj *object, const char *key, bool fallback, bool *out, sb_err *err) {
    if (!sbj_is_object(object))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(object));
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_bool(found)) return type_error_302(err, "boolean", found);
    *out = found->v.b;
    return 0;
}

/* nlohmann object.value(key, "fallback") for strings. *out is borrowed from
 * object or fallback. */
static int json_value_string(const sbj *object, const char *key, const char *fallback, const sbj **found_out,
                             const char **out, sb_err *err) {
    if (!sbj_is_object(object))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(object));
    const sbj *found = sbj_get(object, key);
    if (found_out) *found_out = found;
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

/* True when a JSON string holds an embedded NUL (C++ keeps the full bytes). */
static bool json_string_has_nul(const sbj *value) {
    return sbj_is_string(value) && strlen(value->v.str.ptr) != value->v.str.len;
}

/* trim() for a byte string that may contain NULs: std::isspace in the "C"
 * locale. Returns [start, start+len) inside `value`. */
static void trim_span(const char *value, size_t len, size_t *start, size_t *out_len) {
    size_t first = 0, last = len;
    while (first < last && isspace((unsigned char)value[first])) ++first;
    while (last > first && isspace((unsigned char)value[last - 1])) --last;
    *start = first;
    *out_len = last - first;
}

static void respond_success(sb_http_resp *resp) {
    sbj *body = sbj_object();
    sbj_set_bool(body, "success", true);
    sb_resp_json(resp, 200, body);
}

static void respond_ok(sb_http_resp *resp) {
    sbj *body = sbj_object();
    sbj_set_bool(body, "ok", true);
    sb_resp_json(resp, 200, body);
}

/* The first {param} of the route (e.g. {id}). */
static const char *route_param(const sb_http_req *req) {
    return req->param_count > 0 && req->params[0] ? req->params[0] : "";
}

/* profile_mode(): body.value("mode", "managed") == "full". */
static int profile_mode(const sbj *body, sb_profile_mode *out, sb_err *err) {
    const sbj *found = NULL;
    const char *mode = NULL;
    if (json_value_string(body, "mode", "managed", &found, &mode, err) != 0) return -1;
    *out = found && json_string_is(found, "full") ? SB_PROFILE_FULL : SB_PROFILE_MANAGED;
    return 0;
}

/* profile_from_request(body, existing): `profile` holds the existing profile
 * (or a fresh sb_config_profile_init one) and is updated in place. */
static int profile_from_request(const sbj *body, sb_config_profile *profile, sb_err *err) {
    const char *name = sb_json_required_string(body, "name", err);
    if (!name) return -1;
    const sbj *name_value = sbj_get(body, "name");
    const sbj *template_value = sb_json_required_object(body, "template", err);
    if (!template_value) return -1;
    sb_profile_mode mode;
    if (profile_mode(body, &mode, err) != 0) return -1;
    const sbj *script = sbj_get(body, "rule_script");
    if (script && !sbj_is_string(script)) return sb_fail(err, SB_ERR_VALIDATION, "rule_script must be a string");
    const sbj *enabled = sbj_get(body, "rule_script_enabled");
    if (enabled && !sbj_is_bool(enabled))
        return sb_fail(err, SB_ERR_VALIDATION, "rule_script_enabled must be a boolean");

    sb_str_setn(&profile->name, name_value->v.str.ptr, name_value->v.str.len);
    profile->name_len = name_value->v.str.len;
    sbj_free(profile->profile);
    profile->profile = sbj_clone(template_value);
    profile->mode = mode;
    if (script) {
        sb_str_setn(&profile->rule_script, script->v.str.ptr, script->v.str.len);
        profile->rule_script_len = script->v.str.len;
    }
    if (enabled) profile->rule_script_enabled = enabled->v.b;
    if (profile->rule_script_enabled) {
        /* trim(rule_script).empty(), judged on the full JSON bytes when the
         * script came from this request. */
        size_t start = 0, len = 0;
        if (script)
            trim_span(script->v.str.ptr, script->v.str.len, &start, &len);
        else
            trim_span(S(profile->rule_script), profile->rule_script_len, &start, &len);
        if (len == 0)
            return sb_fail(err, SB_ERR_VALIDATION, "rule_script must not be empty when rule_script_enabled is true");
    }
    return 0;
}

/* ======================================================================
 * /api/hosts/profiles, /api/hosts/rule-script/test
 * ====================================================================== */

/* GET /api/hosts/profiles */
static int handle_list_profiles(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_config_profile_vec profiles = {0};
    if (sb_store_list_profiles(req->server->store, &profiles, err) != 0) return fail_json_aware(err);
    sbj *out = sbj_array();
    for (size_t i = 0; i < profiles.len; ++i) sbj_arr_push(out, sb_config_profile_to_json(&profiles.items[i]));
    sb_config_profile_vec_free(&profiles);
    sb_resp_json(resp, 200, out);
    return 0;
}

/* POST /api/hosts/profiles */
static int handle_create_profile(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sb_config_profile profile, created;
    sb_config_profile_init(&profile);
    sb_config_profile_init(&created);
    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (profile_from_request(body, &profile, err) != 0) goto done;
    if (sb_store_create_profile(req->server->store, &profile, &created, err) != 0) goto done;
    sb_resp_json(resp, 200, sb_config_profile_to_json(&created));
    rc = 0;
done:
    sbj_free(body);
    sb_config_profile_free(&profile);
    sb_config_profile_free(&created);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* POST /api/hosts/rule-script/test */
static int handle_rule_script_test(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *context = NULL, *rules = NULL;
    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    const char *script = sb_json_required_string(body, "rule_script", err);
    if (!script) goto done;
    /* body.value("context", json::object()) */
    const sbj *found = sbj_get(body, "context");
    context = found ? sbj_clone(found) : sbj_object();
    if (!sbj_is_object(context)) {
        sb_fail(err, SB_ERR_VALIDATION, "context must be a JSON object");
        goto done;
    }
    if (!sbj_has(context, "host")) {
        sbj *host = sbj_object();
        sbj_set_str(host, "id", "preview");
        sbj_set_str(host, "name", "QuickJS preview");
        sbj_set(host, "capabilities", sbj_object());
        sbj_set(context, "host", host);
    }
    if (!sbj_has(context, "outboundTags")) {
        sbj *tags = sbj_array();
        sbj_arr_push(tags, sbj_str("Proxy"));
        sbj_arr_push(tags, sbj_str("direct"));
        sbj_arr_push(tags, sbj_str("block"));
        sbj_set(context, "outboundTags", tags);
    }
    if (!sbj_has(context, "currentRules")) sbj_set(context, "currentRules", sbj_array());
    if (!sbj_is_object(sbj_get(context, "host")) || !sbj_is_array(sbj_get(context, "outboundTags")) ||
        !sbj_is_array(sbj_get(context, "currentRules"))) {
        sb_fail(err, SB_ERR_VALIDATION, "context host/outboundTags/currentRules have invalid types");
        goto done;
    }
    sb_rule_script_engine engine;
    if (sb_rule_script_engine_init(&engine, NULL, err) != 0) goto done;
    rules = sb_rule_script_engine_build_rules_n(&engine, script, sbj_get(body, "rule_script")->v.str.len, context, err);
    if (!rules) goto done;
    sbj *out = sbj_object();
    sbj_set_bool(out, "success", true);
    sbj_set(out, "count", sbj_uint(sbj_arr_len(rules)));
    sbj_set(out, "rules", rules);
    rules = NULL;
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sbj_free(context);
    sbj_free(rules);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/profiles/{id} */
static int handle_get_profile(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_config_profile profile;
    sb_config_profile_init(&profile);
    int rc = sb_http_require_profile(req->server, route_param(req), &profile, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_config_profile_to_json(&profile));
    sb_config_profile_free(&profile);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* PUT /api/hosts/profiles/{id} */
static int handle_update_profile(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    int rc = -1;
    sbj *body = NULL;
    sb_config_profile profile, updated;
    sb_config_profile_init(&profile);
    sb_config_profile_init(&updated);
    if (sb_http_require_profile(req->server, route_param(req), &profile, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (profile_from_request(body, &profile, err) != 0) goto done;
    if (sb_store_update_profile(req->server->store, &profile, &updated, err) != 0) goto done;
    sb_resp_json(resp, 200, sb_config_profile_to_json(&updated));
    rc = 0;
done:
    sbj_free(body);
    sb_config_profile_free(&profile);
    sb_config_profile_free(&updated);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* DELETE /api/hosts/profiles/{id} */
static int handle_delete_profile(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_store_delete_profile(req->server->store, route_param(req), err) != 0) return fail_json_aware(err);
    respond_success(resp);
    return 0;
}

/* ======================================================================
 * /api/hosts, /api/hosts/{id}
 * ====================================================================== */

/* host_from_create_request(): `host` must be freshly initialised. */
static int host_from_create_request(const sbj *body, sb_host *host, sb_err *err) {
    if (!sb_json_required_string(body, "name", err)) return -1;
    const sbj *name = sbj_get(body, "name");
    sb_str_setn(&host->name, name->v.str.ptr, name->v.str.len);
    host->name_len = name->v.str.len;
    const sbj *capabilities = sbj_get(body, "capabilities");
    if (capabilities && !sbj_is_null(capabilities)) {
        if (!sbj_is_object(capabilities))
            return sb_fail(err, SB_ERR_VALIDATION, "capabilities must be a JSON object");
        sbj_free(host->capabilities);
        host->capabilities = sbj_clone(capabilities);
    } else {
        sbj_free(host->capabilities);
        host->capabilities = sbj_object();
        sbj_set_bool(host->capabilities, "runs_singbox", true);
        sbj_set_bool(host->capabilities, "is_wg_member", true);
        sbj_set_bool(host->capabilities, "is_wg_hub", false);
        sbj_set_bool(host->capabilities, "is_self", false);
    }
    if (sb_json_assign_string(body, "profile_id", &host->profile_id, err) != 0 ||
        sb_json_assign_string(body, "wg_address", &host->wg_address, err) != 0 ||
        sb_json_assign_string(body, "wg_endpoint", &host->wg_endpoint, err) != 0 ||
        sb_json_assign_string(body, "clash_api", &host->clash_api, err) != 0)
        return -1;
    if (host->wg_endpoint && !*host->wg_endpoint) {
        free(host->wg_endpoint);
        host->wg_endpoint = NULL;
    }
    const sbj *secret = sbj_get(body, "clash_secret");
    if (secret && !sbj_is_null(secret)) {
        if (!sbj_is_string(secret)) return sb_fail(err, SB_ERR_VALIDATION, "clash_secret must be a string");
        sb_str_set(&host->clash_secret, secret->v.str.ptr);
    }
    return 0;
}

/* host_from_update_request(): updates `host` in place. */
static int host_from_update_request(sb_host *host, const sbj *body, sb_err *err) {
    const sbj *name = sbj_get(body, "name");
    if (name && !sbj_is_null(name)) {
        if (!sbj_is_string(name) || name->v.str.len == 0)
            return sb_fail(err, SB_ERR_VALIDATION, "name must be a non-empty string");
        sb_str_setn(&host->name, name->v.str.ptr, name->v.str.len);
        host->name_len = name->v.str.len;
    }
    const sbj *capabilities = sbj_get(body, "capabilities");
    if (capabilities && !sbj_is_null(capabilities)) {
        if (!sbj_is_object(capabilities))
            return sb_fail(err, SB_ERR_VALIDATION, "capabilities must be a JSON object");
        sbj_free(host->capabilities);
        host->capabilities = sbj_clone(capabilities);
    }
    if (sb_json_assign_string(body, "profile_id", &host->profile_id, err) != 0 ||
        sb_json_assign_string(body, "wg_address", &host->wg_address, err) != 0 ||
        sb_json_assign_string(body, "wg_public_key", &host->wg_public_key, err) != 0 ||
        sb_json_assign_string(body, "wg_endpoint", &host->wg_endpoint, err) != 0 ||
        sb_json_assign_string(body, "clash_api", &host->clash_api, err) != 0)
        return -1;
    const sbj *secret = sbj_get(body, "clash_secret");
    if (secret && !sbj_is_null(secret)) {
        if (!sbj_is_string(secret)) return sb_fail(err, SB_ERR_VALIDATION, "clash_secret must be a string");
        sb_str_set(&host->clash_secret, secret->v.str.ptr);
    }
    const sbj *enabled = sbj_get(body, "enabled");
    if (enabled && !sbj_is_null(enabled)) {
        if (!sbj_is_bool(enabled)) return sb_fail(err, SB_ERR_VALIDATION, "enabled must be a boolean");
        host->enabled = enabled->v.b;
    }
    return 0;
}

/* host = wireguard->provision_host(host, set_default_clash) followed by
 * sync_wireguard_best_effort(), inside the C++ try/catch that only logs. */
static void provision_host_logged(sb_http_server *srv, sb_host *host, bool set_default_clash) {
    sb_err err = {0};
    sb_host provisioned;
    sb_host_init(&provisioned);
    if (sb_wireguard_provision_host(srv->wireguard, host, set_default_clash, &provisioned, &err) == 0) {
        sb_host_free(host);
        *host = provisioned;
        sb_http_sync_wireguard_best_effort(srv);
    } else {
        sb_host_free(&provisioned);
        SB_ERROR("managed host WireGuard provisioning failed: %s", err.msg);
    }
}

/* GET /api/hosts */
static int handle_list_hosts(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host_vec hosts = {0};
    if (sb_store_list_hosts(req->server->store, &hosts, err) != 0) return fail_json_aware(err);
    sbj *out = sbj_array();
    for (size_t i = 0; i < hosts.len; ++i) sbj_arr_push(out, sb_host_to_json(&hosts.items[i]));
    sb_host_vec_free(&hosts);
    sb_resp_json(resp, 200, out);
    return 0;
}

/* POST /api/hosts */
static int handle_create_host(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    int rc = -1;
    sb_host request_host, host;
    sb_host_init(&request_host);
    sb_host_init(&host);
    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (host_from_create_request(body, &request_host, err) != 0) goto done;
    if (sb_store_create_host(srv->store, &request_host, &host, err) != 0) goto done;
    if (!sb_streq(host.id, "self")) {
        bool member = false;
        if (json_value_bool(host.capabilities, "is_wg_member", false, &member, err) != 0) goto done;
        if (member) provision_host_logged(srv, &host, !sbj_has(body, "clash_api"));
    }
    sb_resp_json(resp, 200, sb_host_to_json(&host));
    rc = 0;
done:
    sbj_free(body);
    sb_host_free(&request_host);
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/{id} */
static int handle_get_host(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int rc = sb_http_require_host(req->server, route_param(req), &host, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_host_to_json(&host));
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* PUT /api/hosts/{id} */
static int handle_update_host(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    const char *id = route_param(req);
    int rc = -1;
    sbj *body = NULL;
    sb_host host, updated;
    sb_host_init(&host);
    sb_host_init(&updated);
    bool was_member = false, is_member = false;
    if (sb_http_require_host(srv, id, &host, err) != 0) goto done;
    if (json_value_bool(host.capabilities, "is_wg_member", false, &was_member, err) != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (host_from_update_request(&host, body, err) != 0) goto done;
    if (sb_store_update_host(srv->store, &host, &updated, err) != 0) goto done;
    if (json_value_bool(updated.capabilities, "is_wg_member", false, &is_member, err) != 0) goto done;
    if (is_member && !was_member && !sb_streq(id, "self")) {
        provision_host_logged(srv, &updated, updated.clash_api == NULL);
    } else if (!is_member && was_member) {
        if (sb_wireguard_deprovision_host(srv->wireguard, id, err) != 0) goto done;
        sb_http_sync_wireguard_best_effort(srv);
    }
    sb_resp_json(resp, 200, sb_host_to_json(&updated));
    rc = 0;
done:
    sbj_free(body);
    sb_host_free(&host);
    sb_host_free(&updated);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* DELETE /api/hosts/{id} */
static int handle_delete_host(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    const char *id = route_param(req);
    if (sb_wireguard_deprovision_host(srv->wireguard, id, err) != 0) return fail_json_aware(err);
    if (sb_store_delete_host(srv->store, id, err) != 0) return fail_json_aware(err);
    sb_http_sync_wireguard_best_effort(srv);
    respond_success(resp);
    return 0;
}

/* ======================================================================
 * managed_render_request()
 * ====================================================================== */

/* uses_embedded_managed_network(): capabilities.embedded_wireguard, or
 * capabilities.platform == "android" (json type errors propagate). */
static int uses_embedded_managed_network(const sb_host *host, bool *out, sb_err *err) {
    *out = false;
    if (!sbj_is_object(host->capabilities)) return 0;
    bool embedded = false;
    if (json_value_bool(host->capabilities, "embedded_wireguard", false, &embedded, err) != 0) return -1;
    if (embedded) {
        *out = true;
        return 0;
    }
    const sbj *found = NULL;
    const char *platform = NULL;
    if (json_value_string(host->capabilities, "platform", "", &found, &platform, err) != 0) return -1;
    *out = found && json_string_is(found, "android");
    return 0;
}

/* tag_in_use() of managed_render_request(): any endpoint object whose
 * value("tag", "") equals candidate, or any node with that tag. The endpoint
 * scan stops at the first match, like std::ranges::any_of. */
static int endpoint_tag_in_use(const sbj *endpoints, const sb_render_request *request, const char *candidate,
                               bool *out, sb_err *err) {
    bool in_endpoints = false;
    const sbj *value;
    SBJ_ARR_FOREACH(endpoints, i, value) {
        if (!sbj_is_object(value)) continue;
        const sbj *tag = sbj_get(value, "tag");
        if (tag && !sbj_is_string(tag)) return type_error_302(err, "string", tag);
        if ((tag ? json_string_is(tag, candidate) : *candidate == '\0')) {
            in_endpoints = true;
            break;
        }
    }
    bool in_nodes = false;
    for (size_t i = 0; i < request->nodes.len && !in_nodes; ++i)
        in_nodes = sb_strn_eq(request->nodes.items[i].tag, request->nodes.items[i].tag_len, candidate);
    *out = in_endpoints || in_nodes;
    return 0;
}

/* managed_render_request(store, wireguard, host, provision, control_plane):
 * `host` may be replaced by its provisioned version; `out` must be
 * initialised (sb_render_request_init). */
static int managed_render_request(sb_http_server *srv, sb_host *host, bool provision_network_identity,
                                  const char *control_plane_server, sb_render_request *out, sb_err *err) {
    bool embedded = false;
    if (uses_embedded_managed_network(host, &embedded, err) != 0) return -1;
    if (embedded && provision_network_identity && !host->wg_address) {
        sb_host provisioned;
        sb_host_init(&provisioned);
        if (sb_wireguard_provision_host(srv->wireguard, host, false, &provisioned, err) != 0) {
            sb_host_free(&provisioned);
            return -1;
        }
        sb_host_free(host);
        *host = provisioned;
    }

    if (sb_store_render_request_for_host(srv->store, host->id, out, err) != 0) return -1;
    if (uses_embedded_managed_network(host, &embedded, err) != 0) return -1;
    if (!embedded) return 0;
    sb_str_set(&out->control_plane_server, S(control_plane_server));
    /* Android controls libbox through its in-process CommandServer. A TCP
     * Clash controller is redundant there and makes hot reload race the old
     * service for 0.0.0.0:9090. Remove both the repository default and any
     * controller accidentally persisted in the profile template. */
    sb_str_set(&out->clash_controller, "");
    sbj *experimental = sbj_get(out->profile, "experimental");
    if (sbj_is_object(experimental)) sbj_del(experimental, "clash_api");

    sbj *endpoint = NULL;
    int found = sb_wireguard_client_endpoint(srv->wireguard, host, &endpoint, err);
    if (found < 0) return -1;
    if (found == 0) return 0;

    /* auto& endpoints = request.profile["endpoints"]; non-arrays become []. */
    sbj *endpoints = sbj_get(out->profile, "endpoints");
    if (!sbj_is_array(endpoints)) {
        sbj_set(out->profile, "endpoints", sbj_array());
        endpoints = sbj_get(out->profile, "endpoints");
    }
    const sbj *endpoint_tag = NULL;
    const char *tag_value = NULL;
    if (json_value_string(endpoint, "tag", "sb-easy-network", &endpoint_tag, &tag_value, err) != 0) {
        sbj_free(endpoint);
        return -1;
    }
    sb_buf tag = {0};
    sb_buf_puts(&tag, tag_value);
    for (;;) {
        bool in_use = false;
        if (endpoint_tag_in_use(endpoints, out, tag.p, &in_use, err) != 0) {
            sb_buf_free(&tag);
            sbj_free(endpoint);
            return -1;
        }
        if (!in_use) break;
        sb_buf_puts(&tag, " group");
    }
    sbj_set_str(endpoint, "tag", tag.p);
    sbj_arr_push(endpoints, endpoint);
    sbj_arr_push(out->external_route_tags, sbj_strn(tag.p, tag.len));

    /* endpoints.back().at("peers").at(0).at("allowed_ips") */
    const sbj *peers = sbj_get(endpoint, "peers");
    const sbj *first_peer = sbj_arr_at(peers, 0);
    const sbj *allowed_ips = sbj_get(first_peer, "allowed_ips");
    if (!sbj_is_array(peers) || !first_peer || !allowed_ips) {
        sb_buf_free(&tag);
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.out_of_range.403] key 'allowed_ips' not found");
    }
    sbj *rule = sbj_object();
    sbj_set(rule, "ip_cidr", sbj_clone(allowed_ips));
    sbj_set_str(rule, "outbound", tag.p);
    sbj_arr_push(out->priority_route_rules, rule);
    sb_buf_free(&tag);
    return 0;
}

/* renderer.render(request) with a default-constructed ConfigRenderer. */
static sbj *render_config(const sb_render_request *request, sb_err *err) {
    sb_config_renderer renderer;
    if (sb_config_renderer_init(&renderer, NULL, err) != 0) return NULL;
    return sb_config_renderer_render(&renderer, request, err);
}

/* ======================================================================
 * /api/hosts/{id}/...
 * ====================================================================== */

/* GET /api/hosts/{id}/telemetry */
static int handle_host_telemetry(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int rc = sb_http_require_host(req->server, route_param(req), &host, err);
    sb_host_free(&host);
    if (rc != 0) return fail_json_aware(err);
    sbj *telemetry = sb_http_telemetry_get(req->server, route_param(req));
    sb_resp_json(resp, 200, telemetry ? telemetry : sb_http_default_telemetry());
    return 0;
}

/* GET /api/hosts/{id}/diagnostics */
static int handle_host_diagnostics(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *reports = sb_store_list_diagnostic_reports(req->server->store, route_param(req), 20, err);
    if (!reports) return fail_json_aware(err);
    sb_resp_json(resp, 200, reports);
    return 0;
}

static sbj *commands_to_json(const sb_host_command_vec *commands) {
    sbj *out = sbj_array();
    for (size_t i = 0; i < commands->len; ++i) sbj_arr_push(out, sb_host_command_to_json(&commands->items[i]));
    return out;
}

/* GET /api/hosts/{id}/commands */
static int handle_list_host_commands(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_host_command_vec commands = {0};
    if (sb_store_list_host_commands(req->server->store, route_param(req), false, &commands, err) != 0)
        return fail_json_aware(err);
    sb_resp_json(resp, 200, commands_to_json(&commands));
    sb_host_command_vec_free(&commands);
    return 0;
}

/* normalized_command(): trim + ASCII lowercase of required "command"; only
 * "reload" / "restart". Returns the command (malloc'd) or NULL. The C++
 * ValidationError("Unknown command: " + command) reaches the client through
 * what(), i.e. cut at the first NUL but otherwise unbounded; when that text
 * does not fit sb_err's buffer the 400 response is written directly to
 * *resp and *responded is set. */
static char *normalized_command(const sbj *body, sb_http_resp *resp, bool *responded, sb_err *err) {
    *responded = false;
    if (!sb_json_required_string(body, "command", err)) return NULL;
    const sbj *value = sbj_get(body, "command");
    size_t start = 0, len = 0;
    trim_span(value->v.str.ptr, value->v.str.len, &start, &len);
    char *command = sb_xmalloc(len + 1);
    for (size_t i = 0; i < len; ++i) command[i] = (char)tolower((unsigned char)value->v.str.ptr[start + i]);
    command[len] = '\0';
    if ((len == 6 && memcmp(command, "reload", 6) == 0) || (len == 7 && memcmp(command, "restart", 7) == 0))
        return command;
    static const char prefix[] = "Unknown command: ";
    size_t shown = strlen(command); /* what() stops at the first NUL */
    if (sizeof prefix - 1 + shown >= sizeof err->msg) {
        char *message = sb_asprintf("%s%s", prefix, command);
        sb_resp_error(resp, 400, message);
        free(message);
        *responded = true;
    } else {
        sb_fail(err, SB_ERR_VALIDATION, "%s%s", prefix, command);
    }
    free(command);
    return NULL;
}

/* POST /api/hosts/{id}/commands */
static int handle_enqueue_host_command(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    const char *id = route_param(req);
    int rc = -1;
    sbj *body = NULL;
    char *command = NULL;
    sb_host host;
    sb_host_command queued;
    sb_host_init(&host);
    sb_host_command_init(&queued);
    if (sb_http_require_host(srv, id, &host, err) != 0) goto done;
    if (sb_streq(host.id, "self")) {
        sb_fail(err, SB_ERR_VALIDATION, "The self host has no remote agent");
        goto done;
    }
    body = sb_req_json_object(req, err);
    if (!body) goto done;
    bool responded = false;
    command = normalized_command(body, resp, &responded, err);
    if (!command) {
        rc = responded ? 0 : -1;
        goto done;
    }
    if (sb_store_enqueue_host_command(srv->store, id, command, &queued, err) != 0) goto done;
    sbj *out = sbj_object();
    sbj_set_str(out, "id", S(queued.id));
    sbj_set_str(out, "command", S(queued.command));
    sbj_set_str(out, "status", S(queued.status));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    free(command);
    sb_host_free(&host);
    sb_host_command_free(&queued);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/{id}/outbounds */
static int handle_get_host_outbounds(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *id = route_param(req);
    sb_strvec node_ids = {0};
    if (sb_store_host_outbounds(req->server->store, id, &node_ids, err) != 0) return fail_json_aware(err);
    sbj *ids = sbj_array();
    for (size_t i = 0; i < node_ids.len; ++i) sbj_arr_push(ids, sbj_str(node_ids.items[i]));
    sb_strvec_free(&node_ids);
    sbj *out = sbj_object();
    sbj_set_str(out, "host_id", id);
    sbj_set(out, "node_ids", ids);
    sbj_set_bool(out, "uses_all_when_empty", true);
    sb_resp_json(resp, 200, out);
    return 0;
}

/* PUT /api/hosts/{id}/outbounds */
static int handle_set_host_outbounds(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *id = route_param(req);
    int rc = -1;
    sb_strvec node_ids = {0};
    sbj *body = sb_req_json_object(req, err);
    if (!body) goto done;
    if (sb_json_required_string_array(body, "node_ids", &node_ids, err) != 0) goto done;
    if (sb_store_set_host_outbounds(req->server->store, id, &node_ids, err) != 0) goto done;
    sbj *out = sbj_object();
    sbj_set_str(out, "host_id", id);
    /* The validated request array: identical to the echoed std::vector. */
    sbj_set(out, "node_ids", sbj_clone(sbj_get(body, "node_ids")));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sbj_free(body);
    sb_strvec_free(&node_ids);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/{id}/config (administrative preview; compact JSON) */
static int handle_host_config(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    int rc = -1;
    sb_host host;
    sb_render_request request;
    sb_host_init(&host);
    sb_render_request_init(&request);
    if (sb_http_require_host(srv, route_param(req), &host, err) != 0) goto done;
    if (managed_render_request(srv, &host, false, srv->enrollment_server, &request, err) != 0) goto done;
    sbj *config = render_config(&request, err);
    if (!config) goto done;
    sb_resp_json(resp, 200, config);
    rc = 0;
done:
    sb_host_free(&host);
    sb_render_request_free(&request);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/{id}/wg-config */
static int handle_host_wg_config(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    int rc = -1;
    sb_host host;
    sb_host_init(&host);
    if (sb_http_require_host(srv, route_param(req), &host, err) != 0) goto done;
    size_t config_len = 0;
    char *config = sb_wireguard_host_config_n(srv->wireguard, &host, &config_len, err);
    if (!config) goto done;
    sb_resp_text(resp, 200, "application/octet-stream", config, config_len);
    sb_resp_attachment(resp, S(host.name), host.name_len, "-wg.conf");
    rc = 0;
done:
    sb_host_free(&host);
    return rc == 0 ? 0 : fail_json_aware(err);
}

/* GET /api/hosts/{id}/token */
static int handle_host_token(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_host host;
    sb_host_init(&host);
    if (sb_http_require_host(srv, route_param(req), &host, err) != 0) {
        sb_host_free(&host);
        return fail_json_aware(err);
    }
    sbj *out = sbj_object();
    sbj_set_str(out, "host_id", S(host.id));
    sbj_set_str(out, "agent_token", S(host.agent_token));
    sbj_set_str(out, "server", S(srv->opts.public_server));
    sb_host_free(&host);
    sb_resp_json(resp, 200, out);
    return 0;
}

/* POST /api/hosts/{id}/rotate-token */
static int handle_rotate_host_token(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    const char *id = route_param(req);
    char *token = sb_store_rotate_agent_token(req->server->store, id, err);
    if (!token) return fail_json_aware(err);
    sbj *out = sbj_object();
    sbj_set_str(out, "host_id", id);
    sbj_set(out, "agent_token", sbj_str_take(token));
    sb_resp_json(resp, 200, out);
    return 0;
}

/* POST /api/devices/{id}/enrollment-codes and the legacy
 * /api/hosts/{id}/enrollment-codes alias (create_device_enrollment). */
static int handle_create_device_enrollment(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_agent_enrollment enrollment;
    sb_agent_enrollment_init(&enrollment);
    if (sb_store_create_agent_enrollment(srv->store, route_param(req), &enrollment, err) != 0) {
        sb_agent_enrollment_free(&enrollment);
        return fail_json_aware(err);
    }
    char *server = sb_http_encode_component(S(srv->enrollment_server));
    char *code = sb_http_encode_component(S(enrollment.code));
    char *uri = sb_asprintf("sbeasy://enroll?server=%s&code=%s", server, code);
    free(server);
    free(code);
    char *svg = sb_qr_svg_for_text(uri, err);
    if (!svg) {
        free(uri);
        sb_agent_enrollment_free(&enrollment);
        return fail_json_aware(err);
    }
    sbj *out = sbj_object();
    sbj_set_str(out, "host_id", S(enrollment.host_id));
    sbj_set_str(out, "server", S(srv->enrollment_server));
    sbj_set_str(out, "code", S(enrollment.code));
    sbj_set_str(out, "expires_at", S(enrollment.expires_at));
    sbj_set(out, "enrollment_uri", sbj_str_take(uri));
    sbj_set(out, "qr_svg", sbj_str_take(svg));
    sb_agent_enrollment_free(&enrollment);
    sb_resp_json(resp, 200, out);
    return 0;
}

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
    if (found == 0 && !sb_str_empty(srv->legacy_agent_token) && strcmp(token, srv->legacy_agent_token) == 0)
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
    body = sbj_dump(config, 2);
    etag = sb_config_etag(host.id, body, srv->opts.config_hash_seed);
    if (!etag) {
        sb_fail(err, SB_ERR_GENERIC, "SHA-256 ETag finalization failed");
        goto done;
    }
    if (sb_store_touch_host(srv->store, host.id, err) != 0) goto done;

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
    if (sb_store_update_agent_status(req->server->store, host.id, state, err) != 0) goto done;
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
    const char *status = status_value && json_string_is(status_value, "done") ? "done" : "failed";
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

/* ======================================================================
 * registration
 * ====================================================================== */

void sb_http_register_hosts_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET", "/api/hosts/profiles", handle_list_profiles);
    sb_http_route(srv, "POST", "/api/hosts/profiles", handle_create_profile);
    sb_http_route(srv, "POST", "/api/hosts/rule-script/test", handle_rule_script_test);
    sb_http_route(srv, "GET", "/api/hosts/profiles/{id}", handle_get_profile);
    sb_http_route(srv, "PUT", "/api/hosts/profiles/{id}", handle_update_profile);
    sb_http_route(srv, "DELETE", "/api/hosts/profiles/{id}", handle_delete_profile);

    sb_http_route(srv, "GET", "/api/hosts", handle_list_hosts);
    sb_http_route(srv, "POST", "/api/hosts", handle_create_host);
    sb_http_route(srv, "GET", "/api/hosts/{id}", handle_get_host);
    sb_http_route(srv, "PUT", "/api/hosts/{id}", handle_update_host);
    sb_http_route(srv, "DELETE", "/api/hosts/{id}", handle_delete_host);

    sb_http_route(srv, "GET", "/api/hosts/{id}/telemetry", handle_host_telemetry);
    sb_http_route(srv, "GET", "/api/hosts/{id}/diagnostics", handle_host_diagnostics);
    sb_http_route(srv, "GET", "/api/hosts/{id}/commands", handle_list_host_commands);
    sb_http_route(srv, "POST", "/api/hosts/{id}/commands", handle_enqueue_host_command);
    sb_http_route(srv, "GET", "/api/hosts/{id}/outbounds", handle_get_host_outbounds);
    sb_http_route(srv, "PUT", "/api/hosts/{id}/outbounds", handle_set_host_outbounds);
    sb_http_route(srv, "GET", "/api/hosts/{id}/config", handle_host_config);
    sb_http_route(srv, "GET", "/api/hosts/{id}/wg-config", handle_host_wg_config);
    sb_http_route(srv, "GET", "/api/hosts/{id}/token", handle_host_token);
    sb_http_route(srv, "POST", "/api/hosts/{id}/rotate-token", handle_rotate_host_token);
    sb_http_route(srv, "POST", "/api/devices/{id}/enrollment-codes", handle_create_device_enrollment);
    /* Backward-compatible alias for older panels and Android releases. */
    sb_http_route(srv, "POST", "/api/hosts/{id}/enrollment-codes", handle_create_device_enrollment);

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
