/* Panel HTTP routes: /api/proxy/nodes*, /api/subscriptions*, /api/sing-box/... (Clash HTTP control)
 * Port of the corresponding handlers in cpp/src/http_server.cpp. */
#include "http_internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "sb/clash_client.h"
#include "sb/proxy_parser.h"
#include "sb/subscription_fetcher.h"

/* ---- shared bits --------------------------------------------------------- */

static const char default_delay_url[] = "https://www.gstatic.com/generate_204";

static sbj *success_body(void) {
    sbj *body = sbj_object();
    sbj_set_bool(body, "success", true);
    return body;
}

/* trim(request->getParameter(name)); malloc'd, never NULL. */
static char *trimmed_query_param(const sb_http_req *req, const char *name) {
    char *raw = sb_req_query_param(req, name);
    char *value = sb_http_trim(raw ? raw : "");
    free(raw);
    return value;
}

/* request->getParameter(name) untrimmed; malloc'd, never NULL. */
static char *query_param_or_empty(const sb_http_req *req, const char *name) {
    char *raw = sb_req_query_param(req, name);
    return raw ? raw : sb_strdup("");
}

/* A parser exception that C++ lets escape is an nlohmann json::exception,
 * which handle_response() turns into 400 "Invalid JSON request: <what>". */
static int parser_failure(sb_err *err) {
    if (err && strncmp(err->msg, "[json.exception.", 16) == 0) err->code = SB_ERR_BAD_JSON;
    return -1;
}

/* ---- Clash targets (resolve_clash_target / request_clash / call_clash) ---- */

typedef struct {
    char *base_url;
    char *secret;
} clash_target;

static void clash_target_free(clash_target *t) {
    free(t->base_url);
    free(t->secret);
    t->base_url = t->secret = NULL;
}

/* resolve_clash_target(): a ?host= naming a host with a non-empty clash_api
 * selects that controller and its secret; everything else (no host, "self",
 * unknown host, host without controller) falls back to the local API. */
static int resolve_clash_target(const sb_http_req *req, clash_target *out, sb_err *err) {
    sb_http_server *srv = req->server;
    out->base_url = out->secret = NULL;
    char *host_id = trimmed_query_param(req, "host");
    if (*host_id && strcmp(host_id, "self") != 0) {
        sb_host host;
        sb_host_init(&host);
        int found = sb_store_find_host(srv->store, host_id, &host, err);
        if (found < 0) {
            sb_host_free(&host);
            free(host_id);
            return -1;
        }
        if (found == 1 && host.clash_api) {
            char *url = sb_http_trim_trailing_slashes(host.clash_api);
            if (*url) {
                out->base_url = url;
                out->secret = sb_strdup(host.clash_secret ? host.clash_secret : "");
                sb_host_free(&host);
                free(host_id);
                return 0;
            }
            free(url);
        }
        sb_host_free(&host);
    }
    free(host_id);
    out->base_url = sb_http_trim_trailing_slashes(srv->opts.clash_api_url ? srv->opts.clash_api_url : "");
    out->secret = sb_strdup(srv->opts.clash_api_secret ? srv->opts.clash_api_secret : "");
    return 0;
}

static int no_clash_url(sb_err *err) {
    return sb_fail(err, SB_ERR_UNAVAILABLE, "No sing-box Clash API URL is configured");
}

typedef enum { CLASH_GET, CLASH_PUT, CLASH_DELETE } clash_method;

/* request_clash(): transport failures (ClashRequestError) and a 401 from the
 * controller become 503 ServiceUnavailable; any other status is returned. */
static int request_clash(sb_http_server *srv, const clash_target *target, clash_method method,
                         const char *path, const sbj *body, sb_clash_response *out, sb_err *err) {
    if (sb_str_empty(target->base_url)) return no_clash_url(err);
    sb_clash_target t = {target->base_url, target->secret};
    sb_err cerr = {0};
    int rc;
    out->status = 0;
    out->body = NULL;
    switch (method) {
    case CLASH_PUT:
        rc = sb_clash_put(srv->clash, &t, path, body, out, &cerr);
        break;
    case CLASH_DELETE:
        rc = sb_clash_remove(srv->clash, &t, path, out, &cerr);
        break;
    default:
        rc = sb_clash_get(srv->clash, &t, path, out, &cerr);
        break;
    }
    if (rc != 0) {
        if (cerr.code == SB_ERR_UPSTREAM)
            return sb_fail(err, SB_ERR_UNAVAILABLE, "Could not reach sing-box Clash API (%s): %s",
                           target->base_url, cerr.msg);
        if (err) *err = cerr;
        return -1;
    }
    if (out->status == 401) {
        sb_clash_response_free(out);
        return sb_fail(err, SB_ERR_UNAVAILABLE,
                       "sing-box Clash API authentication failed for %s; check the configured secret",
                       target->base_url);
    }
    return 0;
}

/* call_clash() for a route: resolve the target from ?host= and answer 200
 * with the controller's JSON body (whatever its status, except 401). */
static int clash_passthrough(sb_http_req *req, sb_http_resp *resp, clash_method method, const char *path,
                             sb_err *err) {
    clash_target target;
    if (resolve_clash_target(req, &target, err) != 0) return -1;
    sb_clash_response response;
    int rc = request_clash(req->server, &target, method, path, NULL, &response, err);
    clash_target_free(&target);
    if (rc != 0) return -1;
    sb_resp_json(resp, 200, response.body);
    response.body = NULL;
    return 0;
}

/* test_proxy_latency(): NULL-latency (returns false) on any transport error,
 * non-2xx status or missing numeric "delay" (matches the Rust API). */
static bool test_proxy_latency(sb_http_server *srv, const clash_target *target, const char *tag,
                               size_t tag_len, double *latency) {
    if (sb_str_empty(target->base_url)) return false;
    char *name = sb_http_encode_component_n(tag, tag_len);
    char *url = sb_http_encode_component(default_delay_url);
    char *path = sb_asprintf("/proxies/%s/delay?url=%s&timeout=5000", name, url);
    free(name);
    free(url);
    sb_clash_target t = {target->base_url, target->secret};
    sb_clash_response response = {0};
    sb_err cerr = {0};
    bool measured = false;
    if (sb_clash_get(srv->clash, &t, path, &response, &cerr) == 0) {
        if (response.status >= 200 && response.status < 300) {
            const sbj *delay = sbj_get(response.body, "delay");
            if (sbj_is_number(delay)) {
                *latency = sbj_as_double(delay, 0.0);
                measured = true;
            }
        }
        sb_clash_response_free(&response);
    }
    free(path);
    return measured;
}

/* ---- /api/sing-box/... Clash HTTP control ------------------------------- */

static int h_clash_proxies(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_passthrough(req, resp, CLASH_GET, "/proxies", err);
}

static int h_clash_proxy_get(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *name = sb_http_encode_component(req->params[0]);
    char *path = sb_asprintf("/proxies/%s", name);
    free(name);
    int rc = clash_passthrough(req, resp, CLASH_GET, path, err);
    free(path);
    return rc;
}

static int h_clash_proxy_put(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    clash_target target;
    if (resolve_clash_target(req, &target, err) != 0) return -1;
    /* request_clash() checks the URL before the lambda parses the body. */
    if (sb_str_empty(target.base_url)) {
        clash_target_free(&target);
        return no_clash_url(err);
    }
    sbj *body = sb_req_json_object(req, err);
    if (!body) {
        clash_target_free(&target);
        return -1;
    }
    char *name = sb_http_encode_component(req->params[0]);
    char *path = sb_asprintf("/proxies/%s", name);
    free(name);
    sb_clash_response response;
    int rc = request_clash(req->server, &target, CLASH_PUT, path, body, &response, err);
    free(path);
    sbj_free(body);
    clash_target_free(&target);
    if (rc != 0) return -1;
    int status = response.status;
    sb_clash_response_free(&response);
    if (status < 200 || status >= 300)
        return sb_fail(err, SB_ERR_VALIDATION, "sing-box returned HTTP %d", status);
    sb_resp_json(resp, 200, success_body());
    return 0;
}

/* /proxies/{name}/delay and /group/{name}/delay with defaulted url/timeout. */
static int clash_delay(sb_http_req *req, sb_http_resp *resp, const char *kind, sb_err *err) {
    clash_target target;
    if (resolve_clash_target(req, &target, err) != 0) return -1;
    char *url = query_param_or_empty(req, "url");
    char *timeout = query_param_or_empty(req, "timeout");
    if (!*url) sb_str_set(&url, default_delay_url);
    if (!*timeout) sb_str_set(&timeout, "5000");
    char *name = sb_http_encode_component(req->params[0]);
    char *url_enc = sb_http_encode_component(url);
    char *timeout_enc = sb_http_encode_component(timeout);
    char *path = sb_asprintf("/%s/%s/delay?url=%s&timeout=%s", kind, name, url_enc, timeout_enc);
    free(name);
    free(url_enc);
    free(timeout_enc);
    free(url);
    free(timeout);
    sb_clash_response response;
    int rc = request_clash(req->server, &target, CLASH_GET, path, NULL, &response, err);
    free(path);
    clash_target_free(&target);
    if (rc != 0) return -1;
    sb_resp_json(resp, 200, response.body);
    response.body = NULL;
    return 0;
}

static int h_clash_proxy_delay(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_delay(req, resp, "proxies", err);
}

static int h_clash_group_delay(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_delay(req, resp, "group", err);
}

static int h_clash_rules(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_passthrough(req, resp, CLASH_GET, "/rules", err);
}

static int h_clash_connections(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_passthrough(req, resp, CLASH_GET, "/connections", err);
}

static int h_clash_version(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_passthrough(req, resp, CLASH_GET, "/version", err);
}

static int h_clash_close_connections(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    return clash_passthrough(req, resp, CLASH_DELETE, "/connections", err);
}

static int h_clash_close_connection(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    char *id = sb_http_encode_component(req->params[0]);
    char *path = sb_asprintf("/connections/%s", id);
    free(id);
    int rc = clash_passthrough(req, resp, CLASH_DELETE, path, err);
    free(path);
    return rc;
}

/* ---- /api/proxy/nodes ----------------------------------------------------- */

static sbj *strvec_json(const sb_strvec *values) {
    sbj *array = sbj_array();
    for (size_t i = 0; i < values->len; ++i) sbj_arr_push(array, sbj_str(values->items[i]));
    return array;
}

/* {"queued": true, "host": host_id} */
static void respond_queued(sb_http_resp *resp, const char *host_id) {
    sbj *body = sbj_object();
    sbj_set_bool(body, "queued", true);
    sbj_set_str(body, "host", host_id);
    sb_resp_json(resp, 200, body);
}

/* require_host() + enqueue_host_command() for remote latency tests. */
static int enqueue_remote_test(sb_http_server *srv, const char *host_id, const char *command, sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int rc = sb_http_require_host(srv, host_id, &host, err);
    sb_host_free(&host);
    if (rc != 0) return -1;
    sb_host_command queued;
    sb_host_command_init(&queued);
    rc = sb_store_enqueue_host_command(srv->store, host_id, command, &queued, err);
    sb_host_command_free(&queued);
    return rc;
}

/* required_port(): "<field> must be an integer" / "... between 1 and 65535".
 * A number_unsigned beyond INT64_MAX wraps negative in get<int64_t>(). */
static int required_port(const sbj *body, const char *field, uint16_t *out, sb_err *err) {
    const sbj *found = sbj_get(body, field);
    if (!sbj_is_integer(found)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an integer", field);
    int64_t value = found->type == SBJ_UINT ? -1 : found->v.i;
    if (value <= 0 || value > 65535)
        return sb_fail(err, SB_ERR_VALIDATION, "%s must be between 1 and 65535", field);
    *out = (uint16_t)value;
    return 0;
}

/* proxy_from_create_request(); `node` is an initialised record. */
static int proxy_from_create_request(const sbj *body, sb_proxy_record *node, sb_err *err) {
    const char *tag = sb_json_required_string(body, "tag", err);
    if (!tag) return -1;
    const char *node_type = sb_json_required_string(body, "node_type", err);
    if (!node_type) return -1;
    /* body.value("enabled", true): a present non-boolean (even null) throws
     * nlohmann type_error 302 -> 400 "Invalid JSON request: ...". */
    bool enabled = true;
    const sbj *found = sbj_get(body, "enabled");
    if (found) {
        if (!sbj_is_bool(found))
            return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be boolean, but is %s",
                           sbj_type_name(found));
        enabled = found->v.b;
    }
    const char *server = sb_json_required_string(body, "server", err);
    if (!server) return -1;
    uint16_t port = 0;
    if (required_port(body, "server_port", &port, err) != 0) return -1;
    const sbj *config = sb_json_required_object(body, "protocol_config", err);
    if (!config) return -1;
    node->tag_len = sbj_get(body, "tag")->v.str.len;
    sb_str_setn(&node->tag, tag, node->tag_len);
    node->node_type_len = sbj_get(body, "node_type")->v.str.len;
    sb_str_setn(&node->node_type, node_type, node->node_type_len);
    node->enabled = enabled;
    node->server_len = sbj_get(body, "server")->v.str.len;
    sb_str_setn(&node->server, server, node->server_len);
    node->server_port = port;
    sbj_free(node->protocol_config);
    node->protocol_config = sbj_clone(config);
    return 0;
}

/* proxy_from_update_request(): present, non-null fields replace the stored
 * ones; node_type and subscription ownership are not updatable. */
static int proxy_from_update_request(const sbj *body, sb_proxy_record *node, sb_err *err) {
    const sbj *found = sbj_get(body, "tag");
    if (found && found->type != SBJ_NULL) {
        const char *tag = sb_json_required_string(body, "tag", err);
        if (!tag) return -1;
        node->tag_len = sbj_get(body, "tag")->v.str.len;
        sb_str_setn(&node->tag, tag, node->tag_len);
    }
    found = sbj_get(body, "server");
    if (found && found->type != SBJ_NULL) {
        const char *server = sb_json_required_string(body, "server", err);
        if (!server) return -1;
        node->server_len = sbj_get(body, "server")->v.str.len;
        sb_str_setn(&node->server, server, node->server_len);
    }
    found = sbj_get(body, "server_port");
    if (found && found->type != SBJ_NULL) {
        if (required_port(body, "server_port", &node->server_port, err) != 0) return -1;
    }
    found = sbj_get(body, "protocol_config");
    if (found && found->type != SBJ_NULL) {
        if (!sbj_is_object(found)) return sb_fail(err, SB_ERR_VALIDATION, "protocol_config must be a JSON object");
        sbj_free(node->protocol_config);
        node->protocol_config = sbj_clone(found);
    }
    found = sbj_get(body, "enabled");
    if (found && found->type != SBJ_NULL) {
        if (!sbj_is_bool(found)) return sb_fail(err, SB_ERR_VALIDATION, "enabled must be a boolean");
        node->enabled = found->v.b;
    }
    return 0;
}

static int h_nodes_list(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_proxy_record_vec nodes = {0};
    if (sb_store_list_proxy_nodes(req->server->store, &nodes, err) != 0) return -1;
    sbj *body = sbj_array();
    for (size_t i = 0; i < nodes.len; ++i) sbj_arr_push(body, sb_proxy_record_to_json(&nodes.items[i]));
    sb_proxy_record_vec_free(&nodes);
    sb_resp_json(resp, 200, body);
    return 0;
}

static int h_nodes_create(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err);
    if (!body) return -1;
    sb_proxy_record node, created;
    sb_proxy_record_init(&node);
    sb_proxy_record_init(&created);
    int rc = proxy_from_create_request(body, &node, err);
    if (rc == 0) rc = sb_store_create_proxy_node(req->server->store, &node, &created, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_proxy_record_to_json(&created));
    sb_proxy_record_free(&node);
    sb_proxy_record_free(&created);
    sbj_free(body);
    return rc;
}

static int h_nodes_import(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err);
    if (!body) return -1;
    int rc = -1;
    sbj *config = NULL;
    sb_proxy_import parsed;
    sb_proxy_import_init(&parsed);
    sb_proxy_upsert_result result;
    sb_proxy_upsert_result_init(&result);
    const sbj *profile_id = sbj_get(body, "profile_id");
    const sbj *raw = sbj_get(body, "config");
    if (sbj_is_string(profile_id) && profile_id->v.str.len > 0) {
        sb_config_profile profile;
        sb_config_profile_init(&profile);
        if (sb_http_require_profile(req->server, profile_id->v.str.ptr, &profile, err) == 0) {
            config = profile.profile;
            profile.profile = NULL;
        }
        sb_config_profile_free(&profile);
        if (!config) goto done;
    } else if (sbj_is_string(raw)) {
        config = sbj_parse(raw->v.str.ptr, raw->v.str.len, NULL, 0);
        if (!config) {
            sb_fail(err, SB_ERR_VALIDATION, "Pasted config is not valid JSON");
            goto done;
        }
    } else {
        sb_fail(err, SB_ERR_VALIDATION, "Provide either profile_id or config");
        goto done;
    }
    if (sb_parse_outbound_config(config, &parsed, err) != 0) {
        parser_failure(err);
        goto done;
    }
    if (sb_store_upsert_proxy_nodes(req->server->store, parsed.nodes.items, parsed.nodes.len, NULL, &result,
                                    err) != 0)
        goto done;
    sbj *out = sbj_object();
    sbj_set(out, "found", sbj_uint(parsed.nodes.len));
    sbj_set(out, "added", sbj_uint(result.added));
    sbj_set(out, "updated", sbj_uint(result.updated));
    sbj_set(out, "skipped", strvec_json(&parsed.skipped));
    sbj_set(out, "errors", strvec_json(&result.errors));
    sb_resp_json(resp, 200, out);
    rc = 0;
done:
    sb_proxy_upsert_result_free(&result);
    sb_proxy_import_free(&parsed);
    sbj_free(config);
    sbj_free(body);
    return rc;
}

/* One std::async measurement of test-all. */
typedef struct {
    sb_http_server *srv;
    const clash_target *target;
    const char *tag;
    size_t tag_len;
    double latency;
    bool measured;
    bool threaded;
    pthread_t thread;
} latency_job;

static void *latency_job_main(void *arg) {
    latency_job *job = arg;
    job->measured = test_proxy_latency(job->srv, job->target, job->tag, job->tag_len, &job->latency);
    return NULL;
}

static void latency_job_wait(latency_job *job) {
    if (job->threaded) pthread_join(job->thread, NULL);
    job->threaded = false;
}

/* POST /api/proxy/nodes/test-all: remote hosts get a queued agent command;
 * locally every enabled node is measured, eight at a time. */
static int h_nodes_test_all(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    char *host_id = trimmed_query_param(req, "host");
    if (*host_id && strcmp(host_id, "self") != 0) {
        int rc = enqueue_remote_test(srv, host_id, "test-proxies", err);
        if (rc == 0) respond_queued(resp, host_id);
        free(host_id);
        return rc;
    }
    free(host_id);

    clash_target target;
    if (resolve_clash_target(req, &target, err) != 0) return -1;
    sb_proxy_record_vec all = {0};
    if (sb_store_list_proxy_nodes(srv->store, &all, err) != 0) {
        clash_target_free(&target);
        return -1;
    }
    size_t count = 0;
    for (size_t i = 0; i < all.len; ++i)
        if (all.items[i].enabled) ++count;
    const sb_proxy_record **nodes = sb_xcalloc(count ? count : 1, sizeof *nodes);
    count = 0;
    for (size_t i = 0; i < all.len; ++i)
        if (all.items[i].enabled) nodes[count++] = &all.items[i];

    enum { concurrency = 8 };
    latency_job jobs[concurrency];
    sbj *results = sbj_object();
    size_t tested = 0;
    int rc = 0;
    for (size_t offset = 0; offset < count && rc == 0; offset += concurrency) {
        size_t end = count < offset + concurrency ? count : offset + concurrency;
        for (size_t i = offset; i < end; ++i) {
            latency_job *job = &jobs[i - offset];
            memset(job, 0, sizeof *job);
            job->srv = srv;
            job->target = &target;
            job->tag = nodes[i]->tag;
            job->tag_len = nodes[i]->tag_len;
            job->threaded = pthread_create(&job->thread, NULL, latency_job_main, job) == 0;
            if (!job->threaded) latency_job_main(job);
        }
        for (size_t i = offset; i < end; ++i) {
            latency_job *job = &jobs[i - offset];
            latency_job_wait(job);
            if (rc != 0) continue; /* futures are still awaited after a throw */
            rc = sb_store_update_proxy_latency(srv->store, nodes[i]->id, job->measured ? &job->latency : NULL,
                                               err);
            if (rc != 0) continue;
            sbj_setn(results, nodes[i]->tag, nodes[i]->tag_len, job->measured ? sbj_float(job->latency) : sbj_null());
            ++tested;
        }
    }
    if (rc == 0) {
        sbj *body = sbj_object();
        sbj_set(body, "tested", sbj_uint(tested));
        sbj_set(body, "results", results);
        results = NULL;
        sbj_set(body, "tested_at", sbj_str_take(sb_http_utc_now()));
        sb_resp_json(resp, 200, body);
    }
    sbj_free(results);
    free(nodes);
    sb_proxy_record_vec_free(&all);
    clash_target_free(&target);
    return rc;
}

static int h_node_test_latency(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_proxy_record node;
    sb_proxy_record_init(&node);
    char *host_id = NULL;
    int rc = sb_http_require_proxy(srv, req->params[0], &node, err);
    if (rc != 0) goto done;
    host_id = trimmed_query_param(req, "host");
    if (*host_id && strcmp(host_id, "self") != 0) {
        sbj *tags = sbj_array();
        sbj_arr_push(tags, sbj_str(node.tag));
        char *list = sbj_dump(tags, -1);
        sbj_free(tags);
        char *command = sb_asprintf("test-proxies %s", list);
        free(list);
        rc = enqueue_remote_test(srv, host_id, command, err);
        free(command);
        if (rc == 0) respond_queued(resp, host_id);
        goto done;
    }
    clash_target target;
    rc = resolve_clash_target(req, &target, err);
    if (rc != 0) goto done;
    double latency = 0.0;
    bool measured = test_proxy_latency(srv, &target, node.tag, node.tag_len, &latency);
    clash_target_free(&target);
    rc = sb_store_update_proxy_latency(srv->store, node.id, measured ? &latency : NULL, err);
    if (rc != 0) goto done;
    sbj *body = sbj_object();
    sbj_set_str(body, "node_id", node.id);
    sbj_set(body, "latency", measured ? sbj_float(latency) : sbj_null());
    sbj_set(body, "tested_at", sbj_str_take(sb_http_utc_now()));
    sb_resp_json(resp, 200, body);
done:
    free(host_id);
    sb_proxy_record_free(&node);
    return rc;
}

static int h_node_get(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_proxy_record node;
    sb_proxy_record_init(&node);
    int rc = sb_http_require_proxy(req->server, req->params[0], &node, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_proxy_record_to_json(&node));
    sb_proxy_record_free(&node);
    return rc;
}

static int h_node_update(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_proxy_record node, updated;
    sb_proxy_record_init(&node);
    sb_proxy_record_init(&updated);
    sbj *body = NULL;
    int rc = sb_http_require_proxy(req->server, req->params[0], &node, err);
    if (rc != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) {
        rc = -1;
        goto done;
    }
    rc = proxy_from_update_request(body, &node, err);
    if (rc == 0) rc = sb_store_update_proxy_node(req->server->store, &node, &updated, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_proxy_record_to_json(&updated));
done:
    sbj_free(body);
    sb_proxy_record_free(&node);
    sb_proxy_record_free(&updated);
    return rc;
}

static int h_node_delete(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_store_delete_proxy_node(req->server->store, req->params[0], err) != 0) return -1;
    sb_resp_json(resp, 200, success_body());
    return 0;
}

/* ---- /api/subscriptions ------------------------------------------------- */

static int require_subscription(sb_http_server *srv, const char *id, sb_subscription *out, sb_err *err) {
    int rc = sb_store_find_subscription(srv->store, id ? id : "", out, err);
    if (rc < 0) return -1;
    if (rc == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
    return 0;
}

/* default_subscription_name(): the URL host without credentials, port or
 * IPv6 brackets; "Subscription" when nothing is left. */
static char *default_subscription_name(const char *url, size_t len, size_t *name_len) {
    size_t start = 0, end = len;
    for (size_t i = 0; i + 2 < len; ++i) {
        if (memcmp(url + i, "://", 3) == 0) { start = i + 3; break; }
    }
    for (size_t i = start; i < len; ++i) {
        if (url[i] == '/') { end = i; break; }
    }
    for (size_t i = start; i < end; ++i) {
        if (url[i] == '@') start = i + 1;
    }
    if (start < end && url[start] == '[') {
        for (size_t i = start + 1; i < end; ++i) {
            if (url[i] == ']') { ++start; end = i; break; }
        }
    } else {
        for (size_t i = end; i > start; --i) {
            if (url[i - 1] == ':') { end = i - 1; break; }
        }
    }
    if (start == end) {
        *name_len = strlen("Subscription");
        return sb_strdup("Subscription");
    }
    *name_len = end - start;
    return sb_strndup(url + start, *name_len);
}

/* refresh_interval(): absent/null -> fallback; "must be an integer" /
 * "must be positive" (number_unsigned beyond INT64_MAX wraps negative). */
static int refresh_interval(const sbj *body, int64_t fallback, int64_t *out, sb_err *err) {
    const sbj *found = sbj_get(body, "refresh_interval");
    if (!found || found->type == SBJ_NULL) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_integer(found)) return sb_fail(err, SB_ERR_VALIDATION, "refresh_interval must be an integer");
    int64_t value = found->type == SBJ_UINT ? -1 : found->v.i;
    if (value <= 0) return sb_fail(err, SB_ERR_VALIDATION, "refresh_interval must be positive");
    *out = value;
    return 0;
}

/* subscription_from_create_request(); `sub` is an initialised record. */
static int subscription_from_create_request(const sbj *body, sb_subscription *sub, sb_err *err) {
    const char *url = sb_json_required_string(body, "url", err);
    if (!url) return -1;
    const sbj *name = sbj_get(body, "name");
    if (!sbj_is_string(name)) return sb_fail(err, SB_ERR_VALIDATION, "name must be a string");
    size_t name_len = 0;
    const size_t url_len = sbj_get(body, "url")->v.str.len;
    char *trimmed = sb_http_trim_n(name->v.str.ptr, name->v.str.len, &name_len);
    if (!name_len) {
        free(trimmed);
        trimmed = default_subscription_name(url, url_len, &name_len);
    }
    int64_t interval = 0;
    if (refresh_interval(body, 3600, &interval, err) != 0) {
        free(trimmed);
        return -1;
    }
    free(sub->name);
    sub->name = trimmed;
    sub->name_len = name_len;
    sb_str_setn(&sub->url, url, url_len);
    sub->url_len = url_len;
    sub->enabled = true;
    sub->refresh_interval = interval;
    return 0;
}

/* subscription_from_update_request(): present, non-null fields replace the
 * stored ones (the name is trimmed after the non-empty check). */
static int subscription_from_update_request(const sbj *body, sb_subscription *sub, sb_err *err) {
    const sbj *found = sbj_get(body, "name");
    if (found && found->type != SBJ_NULL) {
        const char *name = sb_json_required_string(body, "name", err);
        if (!name) return -1;
        free(sub->name);
        sub->name = sb_http_trim_n(name, found->v.str.len, &sub->name_len);
    }
    found = sbj_get(body, "url");
    if (found && found->type != SBJ_NULL) {
        const char *url = sb_json_required_string(body, "url", err);
        if (!url) return -1;
        sb_str_setn(&sub->url, url, found->v.str.len);
        sub->url_len = found->v.str.len;
    }
    found = sbj_get(body, "enabled");
    if (found && found->type != SBJ_NULL) {
        if (!sbj_is_bool(found)) return sb_fail(err, SB_ERR_VALIDATION, "enabled must be a boolean");
        sub->enabled = found->v.b;
    }
    return refresh_interval(body, sub->refresh_interval, &sub->refresh_interval, err);
}

/* fetch_subscription(): download, parse, upsert the nodes under the
 * subscription and record the fetch metadata. Download failures become
 * ValidationError "Failed to fetch subscription: <reason>". */
static int fetch_subscription(sb_http_server *srv, const sb_subscription *sub, sb_subscription_fetch_result *result,
                              sb_err *err) {
    size_t len = 0;
    sb_err fetch_err = {0};
    char *body = sb_subscription_fetcher_fetch_n(srv->fetcher, sub->url, sub->url_len, &len, &fetch_err);
    if (!body) return sb_fail(err, SB_ERR_VALIDATION, "Failed to fetch subscription: %s", fetch_err.msg);
    sb_parsed_node_vec nodes;
    int rc = sb_parse_subscription_body_ex(body, len, &nodes, err);
    free(body);
    if (rc != 0) return parser_failure(err);
    sb_proxy_upsert_result upsert;
    sb_proxy_upsert_result_init(&upsert);
    rc = sb_store_upsert_proxy_nodes(srv->store, nodes.items, nodes.len, sub->id, &upsert, err);
    if (rc == 0) {
        sb_subscription_fetch_result_free(result);
        result->added = upsert.added;
        result->updated = upsert.updated;
        result->skipped = 0;
        result->found = nodes.len;
        result->errors = upsert.errors;
        memset(&upsert.errors, 0, sizeof upsert.errors);
        rc = sb_store_record_subscription_fetch(srv->store, sub->id, result, err);
    }
    sb_proxy_upsert_result_free(&upsert);
    sb_parsed_node_vec_free(&nodes);
    return rc;
}

static int h_subscriptions_list(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_subscription_vec subs = {0};
    if (sb_store_list_subscriptions(req->server->store, &subs, err) != 0) return -1;
    sbj *body = sbj_array();
    for (size_t i = 0; i < subs.len; ++i) sbj_arr_push(body, sb_subscription_to_json(&subs.items[i]));
    sb_subscription_vec_free(&subs);
    sb_resp_json(resp, 200, body);
    return 0;
}

static int h_subscriptions_create(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sbj *body = sb_req_json_object(req, err);
    if (!body) return -1;
    sb_subscription sub, created;
    sb_subscription_init(&sub);
    sb_subscription_init(&created);
    int rc = subscription_from_create_request(body, &sub, err);
    if (rc == 0) rc = sb_store_create_subscription(req->server->store, &sub, &created, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_subscription_to_json(&created));
    sb_subscription_free(&sub);
    sb_subscription_free(&created);
    sbj_free(body);
    return rc;
}

/* POST /api/subscriptions/fetch-all: every enabled subscription, failures
 * reported per entry instead of failing the request. */
static int h_subscriptions_fetch_all(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_http_server *srv = req->server;
    sb_subscription_vec subs = {0};
    if (sb_store_list_subscriptions(srv->store, &subs, err) != 0) return -1;
    sbj *results = sbj_array();
    for (size_t i = 0; i < subs.len; ++i) {
        const sb_subscription *sub = &subs.items[i];
        if (!sub->enabled) continue;
        sb_subscription_fetch_result result;
        sb_subscription_fetch_result_init(&result);
        sb_err fetch_err = {0};
        sbj *entry = sbj_object();
        sbj_set_str(entry, "id", sub->id);
        sbj_set(entry, "name", sbj_strn(sub->name, sub->name_len));
        if (fetch_subscription(srv, sub, &result, &fetch_err) == 0) {
            sbj_set(entry, "added", sbj_uint(result.added));
            sbj_set(entry, "updated", sbj_uint(result.updated));
            sbj_set(entry, "found", sbj_uint(result.found));
            sbj_set(entry, "errors", strvec_json(&result.errors));
        } else {
            sbj_set_str(entry, "error", fetch_err.msg);
        }
        sbj_arr_push(results, entry);
        sb_subscription_fetch_result_free(&result);
    }
    sb_subscription_vec_free(&subs);
    sb_resp_json(resp, 200, results);
    return 0;
}

static int h_subscription_get(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_subscription sub;
    sb_subscription_init(&sub);
    int rc = require_subscription(req->server, req->params[0], &sub, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_subscription_to_json(&sub));
    sb_subscription_free(&sub);
    return rc;
}

static int h_subscription_update(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_subscription sub, updated;
    sb_subscription_init(&sub);
    sb_subscription_init(&updated);
    sbj *body = NULL;
    int rc = require_subscription(req->server, req->params[0], &sub, err);
    if (rc != 0) goto done;
    body = sb_req_json_object(req, err);
    if (!body) {
        rc = -1;
        goto done;
    }
    rc = subscription_from_update_request(body, &sub, err);
    if (rc == 0) rc = sb_store_update_subscription(req->server->store, &sub, &updated, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_subscription_to_json(&updated));
done:
    sbj_free(body);
    sb_subscription_free(&sub);
    sb_subscription_free(&updated);
    return rc;
}

static int h_subscription_delete(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    if (sb_store_delete_subscription(req->server->store, req->params[0], err) != 0) return -1;
    sb_resp_json(resp, 200, success_body());
    return 0;
}

static int h_subscription_fetch(sb_http_req *req, sb_http_resp *resp, sb_err *err) {
    sb_subscription sub;
    sb_subscription_init(&sub);
    sb_subscription_fetch_result result;
    sb_subscription_fetch_result_init(&result);
    int rc = require_subscription(req->server, req->params[0], &sub, err);
    if (rc == 0) rc = fetch_subscription(req->server, &sub, &result, err);
    if (rc == 0) sb_resp_json(resp, 200, sb_subscription_fetch_result_to_json(&result));
    sb_subscription_fetch_result_free(&result);
    sb_subscription_free(&sub);
    return rc;
}

/* ---- registration ------------------------------------------------------- */

void sb_http_register_proxy_routes(sb_http_server *srv) {
    sb_http_route(srv, "GET", "/api/sing-box/proxies", h_clash_proxies);
    sb_http_route(srv, "GET", "/api/sing-box/proxies/{name}", h_clash_proxy_get);
    sb_http_route(srv, "PUT", "/api/sing-box/proxies/{name}", h_clash_proxy_put);
    sb_http_route(srv, "GET", "/api/sing-box/proxies/{name}/delay", h_clash_proxy_delay);
    sb_http_route(srv, "GET", "/api/sing-box/group/{name}/delay", h_clash_group_delay);
    sb_http_route(srv, "GET", "/api/sing-box/rules", h_clash_rules);
    sb_http_route(srv, "GET", "/api/sing-box/connections", h_clash_connections);
    sb_http_route(srv, "GET", "/api/sing-box/version", h_clash_version);
    sb_http_route(srv, "DELETE", "/api/sing-box/connections", h_clash_close_connections);
    sb_http_route(srv, "DELETE", "/api/sing-box/connections/{id}", h_clash_close_connection);

    sb_http_route(srv, "GET", "/api/proxy/nodes", h_nodes_list);
    sb_http_route(srv, "POST", "/api/proxy/nodes", h_nodes_create);
    sb_http_route(srv, "POST", "/api/proxy/nodes/import", h_nodes_import);
    sb_http_route(srv, "POST", "/api/proxy/nodes/test-all", h_nodes_test_all);
    sb_http_route(srv, "POST", "/api/proxy/nodes/{id}/test-latency", h_node_test_latency);
    sb_http_route(srv, "GET", "/api/proxy/nodes/{id}", h_node_get);
    sb_http_route(srv, "PUT", "/api/proxy/nodes/{id}", h_node_update);
    sb_http_route(srv, "DELETE", "/api/proxy/nodes/{id}", h_node_delete);

    sb_http_route(srv, "GET", "/api/subscriptions", h_subscriptions_list);
    sb_http_route(srv, "POST", "/api/subscriptions", h_subscriptions_create);
    sb_http_route(srv, "POST", "/api/subscriptions/fetch-all", h_subscriptions_fetch_all);
    sb_http_route(srv, "GET", "/api/subscriptions/{id}", h_subscription_get);
    sb_http_route(srv, "PUT", "/api/subscriptions/{id}", h_subscription_update);
    sb_http_route(srv, "DELETE", "/api/subscriptions/{id}", h_subscription_delete);
    sb_http_route(srv, "POST", "/api/subscriptions/{id}/fetch", h_subscription_fetch);
}
