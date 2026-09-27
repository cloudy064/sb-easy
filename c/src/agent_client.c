#include "sb/agent_client.h"

#include <stdlib.h>
#include <string.h>

#include "sb/http_client.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

#define AGENT_USER_AGENT "sb-easy-cpp-agent/" SB_EASY_VERSION
#define JSON_CONTENT_TYPE "Content-Type: application/json; charset=utf-8"
/* Drogon's client imposes no response size limit; keep a generous cap. */
#define AGENT_MAX_BODY ((size_t)256u * 1024u * 1024u)

struct sb_agent_client {
    char *token;
    int64_t timeout_ms;
    char *origin;
    char *path_prefix;
};

void sb_agent_config_response_free(sb_agent_config_response *r) {
    if (!r) return;
    free(r->etag);
    free(r->body);
    free(r->rule_source);
    memset(r, 0, sizeof *r);
}

void sb_device_credential_free(sb_device_credential *c) {
    if (!c) return;
    free(c->server);
    free(c->host_id);
    free(c->host_name);
    free(c->token);
    free(c->profile_id);
    free(c->profile_name);
    memset(c, 0, sizeof *c);
}

void sb_agent_command_vec_free(sb_agent_command_vec *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; ++i) {
        free(v->items[i].id);
        free(v->items[i].command);
    }
    free(v->items);
    memset(v, 0, sizeof *v);
}

/* C++ parse_server(). */
static int parse_server(const char *server, char **origin, char **prefix, sb_err *err) {
    char *url = sb_strdup(server ? server : "");
    size_t len = strlen(url);
    while (len > 0 && url[len - 1] == '/') url[--len] = '\0';
    if (!sb_starts_with(url, "http://") && !sb_starts_with(url, "https://")) {
        free(url);
        return sb_fail(err, SB_ERR_VALIDATION, "agent server must include http:// or https://");
    }
    if (strpbrk(url, "?#")) {
        free(url);
        return sb_fail(err, SB_ERR_VALIDATION,
                       "agent server must not contain a query or fragment");
    }
    const char *authority = strstr(url, "://") + 3;
    const char *path = strchr(authority, '/');
    if (path) {
        *origin = sb_strndup(url, (size_t)(path - url));
        *prefix = sb_strdup(path);
    } else {
        *origin = sb_strdup(url);
        *prefix = sb_strdup("");
    }
    free(url);
    if ((*origin)[0] == '\0' || sb_ends_with(*origin, "://")) {
        free(*origin);
        free(*prefix);
        return sb_fail(err, SB_ERR_VALIDATION, "invalid agent server URL");
    }
    return 0;
}

/* Performs one request; transport failures become "agent HTTP request failed". */
static int send_request(const char *method, const char *url, const char *const *headers,
                        const char *body, int64_t timeout_ms, sb_http_response *resp,
                        sb_err *err) {
    sb_http_request req = {0};
    req.method = method;
    req.url = url;
    req.headers = headers;
    req.body = body;
    req.body_len = body ? strlen(body) : 0;
    req.timeout_ms = timeout_ms;
    req.max_body_bytes = AGENT_MAX_BODY;
    req.user_agent = AGENT_USER_AGENT;
    sb_err transport = {0};
    if (sb_http_perform(&req, resp, &transport) != 0) {
        SB_DEBUG("agent HTTP transport error: %s", transport.msg);
        return sb_fail(err, SB_ERR_UPSTREAM, "agent HTTP request failed: %s",
                       sb_http_failure_reason(transport.msg));
    }
    return 0;
}

static sbj *parse_response_json(const sb_http_response *resp, sb_err *err) {
    sbj *body = sbj_parse(resp->body ? resp->body : "", resp->body_len, NULL, 0);
    if (!body) sb_fail(err, SB_ERR_UPSTREAM, "agent endpoint returned invalid JSON");
    return body;
}

/* nlohmann value(key, std::string fallback) on an object. */
static int value_string(const sbj *object, const char *key, const char *fallback, char **out,
                        sb_err *err) {
    if (!sbj_is_object(object))
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(object));
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = sb_strdup(fallback);
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = sb_strndup(found->v.str.ptr, found->v.str.len);
    return 0;
}

int sb_enroll_device(const sb_device_enrollment_options *options, sb_device_credential *out,
                     sb_err *err) {
    memset(out, 0, sizeof *out);
    char *origin = NULL, *prefix = NULL;
    if (parse_server(options->server, &origin, &prefix, err) != 0) return -1;
    int rc = -1;
    char *url = NULL, *payload = NULL;
    sbj *body = NULL;
    sb_http_response resp = {0};
    if (!options->code || strlen(options->code) < 32) {
        sb_fail(err, SB_ERR_VALIDATION, "device enrollment code is required");
        goto out;
    }
    if (options->device && !sbj_is_object(options->device)) {
        sb_fail(err, SB_ERR_VALIDATION, "device enrollment metadata must be an object");
        goto out;
    }
    if (options->timeout_ms <= 0) {
        sb_fail(err, SB_ERR_VALIDATION, "device enrollment timeout must be positive");
        goto out;
    }
    {
        sbj *request = sbj_object();
        sbj_set_str(request, "code", options->code);
        sbj_set(request, "device", options->device ? sbj_clone(options->device) : sbj_object());
        payload = sbj_dump(request, -1);
        sbj_free(request);
    }
    url = sb_asprintf("%s%s/api/devices/enroll", origin, prefix);
    const char *headers[] = {JSON_CONTENT_TYPE, NULL};
    if (send_request("POST", url, headers, payload, options->timeout_ms, &resp, err) != 0)
        goto out;
    if (resp.status < 200 || resp.status >= 300) {
        sb_fail(err, SB_ERR_UPSTREAM, "device enrollment endpoint returned HTTP %ld",
                resp.status);
        goto out;
    }
    body = parse_response_json(&resp, err);
    if (!body) goto out;
    if (!sbj_is_object(body)) {
        sb_fail(err, SB_ERR_UPSTREAM,
                "[json.exception.type_error.306] cannot use value() with %s",
                sbj_type_name(body));
        goto out;
    }
    const sbj *profile = sbj_get(body, "profile");
    sbj *empty_profile = sbj_object();
    if (!profile) profile = empty_profile;
    int value_rc = 0;
    value_rc |= value_string(body, "server", options->server, &out->server, err);
    if (!value_rc) value_rc |= value_string(body, "host_id", "", &out->host_id, err);
    if (!value_rc) value_rc |= value_string(body, "host_name", "", &out->host_name, err);
    if (!value_rc) value_rc |= value_string(body, "agent_token", "", &out->token, err);
    if (!value_rc) value_rc |= value_string(profile, "id", "", &out->profile_id, err);
    if (!value_rc) value_rc |= value_string(profile, "name", "", &out->profile_name, err);
    const sbj *profile_name = sbj_get(profile, "name");
    out->profile_name_len = sbj_is_string(profile_name) ? profile_name->v.str.len : 0;
    sbj_free(empty_profile);
    if (value_rc) goto out;
    if (sb_str_empty(out->server) || sb_str_empty(out->host_id) || sb_str_empty(out->token)) {
        sb_fail(err, SB_ERR_UPSTREAM, "device enrollment response is incomplete");
        goto out;
    }
    rc = 0;
out:
    if (rc != 0) sb_device_credential_free(out);
    sb_http_response_free(&resp);
    sbj_free(body);
    free(payload);
    free(url);
    free(origin);
    free(prefix);
    return rc;
}

sb_agent_client *sb_agent_client_new(const sb_agent_client_options *options, sb_err *err) {
    char *origin = NULL, *prefix = NULL;
    if (parse_server(options->server, &origin, &prefix, err) != 0) return NULL;
    if (sb_str_empty(options->token)) {
        free(origin);
        free(prefix);
        sb_fail(err, SB_ERR_VALIDATION, "agent token is required");
        return NULL;
    }
    if (options->timeout_ms <= 0) {
        free(origin);
        free(prefix);
        sb_fail(err, SB_ERR_VALIDATION, "agent HTTP timeout must be positive");
        return NULL;
    }
    sb_http_global_init();
    sb_agent_client *client = sb_xcalloc(1, sizeof *client);
    client->token = sb_strdup(options->token);
    client->timeout_ms = options->timeout_ms;
    client->origin = origin;
    client->path_prefix = prefix;
    return client;
}

void sb_agent_client_free(sb_agent_client *client) {
    if (!client) return;
    free(client->token);
    free(client->origin);
    free(client->path_prefix);
    free(client);
}

/* Impl::send(). body/etag may be NULL. */
static int client_send(sb_agent_client *client, const char *method, const char *path,
                       const sbj *body, const char *etag, sb_http_response *resp,
                       sb_err *err) {
    char *url = sb_asprintf("%s%s%s", client->origin, client->path_prefix, path);
    char *authorization = sb_asprintf("Authorization: Bearer %s", client->token);
    char *if_none_match = etag ? sb_asprintf("If-None-Match: %s", etag) : NULL;
    char *payload = body ? sbj_dump(body, -1) : NULL;
    const char *headers[4];
    size_t n = 0;
    headers[n++] = authorization;
    if (if_none_match) headers[n++] = if_none_match;
    if (payload) headers[n++] = JSON_CONTENT_TYPE;
    headers[n] = NULL;
    int rc = send_request(method, url, headers, payload, client->timeout_ms, resp, err);
    free(url);
    free(authorization);
    free(if_none_match);
    free(payload);
    return rc;
}

/* Impl::require_success_json(). */
static sbj *require_success_json(const sb_http_response *resp, sb_err *err) {
    if (resp->status < 200 || resp->status >= 300) {
        sb_fail(err, SB_ERR_UPSTREAM, "agent endpoint returned HTTP %ld", resp->status);
        return NULL;
    }
    return parse_response_json(resp, err);
}

static sbj *send_json(sb_agent_client *client, const char *method, const char *path,
                      const sbj *body, sb_err *err) {
    sb_http_response resp = {0};
    if (client_send(client, method, path, body, NULL, &resp, err) != 0) return NULL;
    sbj *result = require_success_json(&resp, err);
    sb_http_response_free(&resp);
    return result;
}

/* Drogon getHeader(): "" when absent. */
static char *header_or_empty(const sb_http_response *resp, const char *name) {
    char *value = sb_http_response_header(resp, name);
    return value ? value : sb_strdup("");
}

int sb_agent_client_poll_config(sb_agent_client *client, const char *etag,
                                sb_agent_config_response *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    sb_http_response resp = {0};
    if (client_send(client, "GET", "/api/agent/config", NULL, etag, &resp, err) != 0) return -1;
    char *response_etag = header_or_empty(&resp, "etag");
    char *rule_source = header_or_empty(&resp, "x-sb-easy-rule-source");
    int rc = -1;
    if (rule_source[0] == '\0') sb_str_set(&rule_source, "profile");
    if (resp.status == 304) {
        out->modified = false;
        out->etag = response_etag[0] ? sb_strdup(response_etag) : sb_strdup(etag ? etag : "");
        out->body = sb_strdup("");
        out->rule_source = rule_source;
        rule_source = NULL;
        rc = 0;
        goto out;
    }
    if (resp.status != 200) {
        sb_fail(err, SB_ERR_UPSTREAM, "agent config endpoint returned HTTP %ld", resp.status);
        goto out;
    }
    if (response_etag[0] == '\0') {
        sb_fail(err, SB_ERR_UPSTREAM, "agent config response is missing ETag");
        goto out;
    }
    sbj *parsed = sbj_parse(resp.body ? resp.body : "", resp.body_len, NULL, 0);
    bool is_object = sbj_is_object(parsed);
    sbj_free(parsed);
    if (!is_object) {
        sb_fail(err, SB_ERR_UPSTREAM, "agent config response must be a JSON object");
        goto out;
    }
    out->modified = true;
    out->etag = response_etag;
    response_etag = NULL;
    out->body = sb_strndup(resp.body ? resp.body : "", resp.body_len);
    out->rule_source = rule_source;
    rule_source = NULL;
    rc = 0;
out:
    free(response_etag);
    free(rule_source);
    sb_http_response_free(&resp);
    return rc;
}

int sb_agent_client_pending_commands(sb_agent_client *client, sb_agent_command_vec *out,
                                     sb_err *err) {
    memset(out, 0, sizeof *out);
    sbj *body = send_json(client, "GET", "/api/agent/commands", NULL, err);
    if (!body) return -1;
    if (!sbj_is_array(body)) {
        sbj_free(body);
        return sb_fail(err, SB_ERR_UPSTREAM, "agent commands response must be an array");
    }
    const sbj *value;
    SBJ_ARR_FOREACH(body, i, value) {
        const sbj *id = sbj_get(value, "id");
        const sbj *command = sbj_get(value, "command");
        if (!sbj_is_object(value) || !sbj_is_string(id) || !sbj_is_string(command)) {
            sb_agent_command_vec_free(out);
            sbj_free(body);
            return sb_fail(err, SB_ERR_UPSTREAM, "agent command has an invalid shape");
        }
        if (out->len == out->cap) {
            out->cap = out->cap ? out->cap * 2 : 4;
            out->items = sb_xrealloc(out->items, out->cap * sizeof *out->items);
        }
        out->items[out->len].id = sb_strdup(id->v.str.ptr);
        out->items[out->len].command = sb_strdup(command->v.str.ptr);
        ++out->len;
    }
    sbj_free(body);
    return 0;
}

static int post_expect_success(sb_agent_client *client, const char *path, const sbj *body,
                               sb_err *err) {
    sbj *response = send_json(client, "POST", path, body, err);
    if (!response) return -1;
    sbj_free(response);
    return 0;
}

int sb_agent_client_acknowledge_command(sb_agent_client *client, const char *id, bool success,
                                        const char *result, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set_str(body, "status", success ? "done" : "failed");
    sbj_set(body, "result", sbj_str(result));
    char *path = sb_asprintf("/api/agent/commands/%s/ack", id);
    int rc = post_expect_success(client, path, body, err);
    free(path);
    sbj_free(body);
    return rc;
}

int sb_agent_client_report_status(sb_agent_client *client, const char *version,
                                  const bool *running, const char *etag, sb_err *err) {
    sbj *body = sbj_object();
    sbj_set_str(body, "singbox_version", version);
    sbj_set(body, "singbox_running", running ? sbj_bool(*running) : sbj_null());
    sbj_set(body, "config_etag", sbj_str(etag));
    int rc = post_expect_success(client, "/api/agent/status", body, err);
    sbj_free(body);
    return rc;
}

int sb_agent_client_report_telemetry(sb_agent_client *client, const sbj *telemetry,
                                     sb_err *err) {
    if (!sbj_is_object(telemetry))
        return sb_fail(err, SB_ERR_VALIDATION, "agent telemetry must be a JSON object");
    return post_expect_success(client, "/api/agent/telemetry", telemetry, err);
}

int sb_agent_client_report_proxy_latencies(sb_agent_client *client, const sbj *results,
                                           size_t *updated, sb_err *err) {
    if (!sbj_is_object(results))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "agent proxy latency results must be a JSON object");
    sbj *body = sbj_object();
    sbj_set(body, "results", sbj_clone(results));
    sbj *response = send_json(client, "POST", "/api/agent/proxy-latency", body, err);
    sbj_free(body);
    if (!response) return -1;
    int rc = 0;
    const sbj *count = sbj_get(response, "updated");
    if (!sbj_is_object(response)) {
        rc = sb_fail(err, SB_ERR_UPSTREAM,
                     "[json.exception.type_error.304] cannot use at() with %s",
                     sbj_type_name(response));
    } else if (!count) {
        rc = sb_fail(err, SB_ERR_UPSTREAM, "[json.exception.out_of_range.403] key 'updated' not found");
    } else if (!sbj_is_number(count)) {
        rc = sb_fail(err, SB_ERR_UPSTREAM,
                     "[json.exception.type_error.302] type must be number, but is %s",
                     sbj_type_name(count));
    } else if (count->type == SBJ_FLOAT) {
        *updated = (size_t)count->v.f;
    } else if (count->type == SBJ_UINT) {
        *updated = (size_t)count->v.u;
    } else {
        *updated = (size_t)count->v.i;
    }
    sbj_free(response);
    return rc;
}
