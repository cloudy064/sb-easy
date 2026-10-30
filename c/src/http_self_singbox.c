/* Managed self sing-box loop. Moved verbatim from http_server.c. */
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "http_internal.h"
#include "sb/clash_client.h"
#include "sb/config_etag.h"
#include "sb/config_renderer.h"
#include "sb/observability.h"
#include "sb/proxy_runtime.h"
#include "sb/singbox_supervisor.h"

/* ---- managed self sing-box (run_self_singbox) ------------------------------ */

static bool self_singbox_stop_requested(sb_http_server *srv) {
    pthread_mutex_lock(&srv->self_singbox_mutex);
    bool stop = srv->self_singbox_stop;
    pthread_mutex_unlock(&srv->self_singbox_mutex);
    return stop;
}

/* capabilities.value("runs_singbox", false) with nlohmann's type errors. */
static int capability_flag(const sbj *capabilities, const char *key, bool *out, sb_err *err) {
    if (!sbj_is_object(capabilities))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(capabilities));
    const sbj *value = sbj_get(capabilities, key);
    if (!value) {
        *out = false;
        return 0;
    }
    if (!sbj_is_bool(value))
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be boolean, but is %s",
                       sbj_type_name(value));
    *out = value->v.b;
    return 0;
}

/* One iteration of the C++ loop body up to (not including) ensure_alive().
 * Returns -1 with err set where the C++ code would throw. */
static int self_singbox_render(sb_http_server *srv, sb_singbox_supervisor *supervisor, char **last_etag,
                               sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int found = sb_store_find_host(srv->store, "self", &host, err);
    int rc = found < 0 ? -1 : 0;
    bool runs = false;
    if (found == 1 && host.enabled && capability_flag(host.capabilities, "runs_singbox", &runs, err) != 0) rc = -1;
    if (rc == 0 && found == 1 && host.enabled && runs) {
        sb_render_request request;
        sb_render_request_init(&request);
        sb_config_renderer renderer;
        sbj *config = NULL;
        char *body = NULL, *etag = NULL;
        rc = -1;
        if (sb_store_render_request_for_host(srv->store, "self", &request, err) == 0) {
            free(request.clash_controller);
            request.clash_controller = sb_http_clash_controller_address(srv->opts.clash_api_url);
            request.clash_controller_len = request.clash_controller ? strlen(request.clash_controller) : 0;
            sb_str_set(&request.clash_secret, srv->opts.clash_api_secret);
            request.clash_secret_len = request.clash_secret ? strlen(request.clash_secret) : 0;
            if (sb_config_renderer_init(&renderer, NULL, err) == 0 &&
                (config = sb_config_renderer_render(&renderer, &request, err)) != NULL) {
                body = sbj_dump(config, 2);
                etag = sb_config_etag("self", body, srv->opts.config_hash_seed);
                if (etag) sb_observability_target(sb_store_database(srv->store), "self", etag, sb_unix_now(), NULL);
                if (!etag) {
                    sb_fail(err, SB_ERR_GENERIC, "config ETag hashing failed");
                } else if (*last_etag && strcmp(*last_etag, etag) == 0) {
                    rc = 0;
                } else if (sb_singbox_supervisor_apply_config(supervisor, body, strlen(body), err) == 0) {
                    free(*last_etag);
                    *last_etag = sb_strdup(etag);
                    SB_INFO("managed sing-box config applied: %s", etag);
                    rc = 0;
                }
            }
        }
        free(etag);
        free(body);
        sbj_free(config);
        sb_render_request_free(&request);
    }
    sb_host_free(&host);
    return rc;
}

static void *self_singbox_main(void *arg) {
    sb_http_server *srv = arg;
    const sb_http_server_options *o = &srv->opts;
    char *config_path = sb_http_trim(o->self_singbox_config_path);
    if (!*config_path) sb_str_set(&config_path, "data/sing-box.gen.json");
    sb_singbox_supervisor_options so;
    sb_singbox_supervisor_options_init(&so);
    so.binary = o->singbox_binary;
    so.config_path = config_path;
    so.validate_config = o->singbox_validate_config;
    sb_err e = {0};
    sb_singbox_supervisor *supervisor = sb_singbox_supervisor_new(&so, &e);
    if (!supervisor) {
        /* C++ would terminate here (exception escaping the jthread). */
        SB_ERROR("managed sing-box cycle failed: %s", e.msg);
        free(config_path);
        return NULL;
    }
    uint64_t interval = o->self_singbox_interval_seconds < 2 ? 2 : o->self_singbox_interval_seconds;
    SB_INFO("managed sing-box enabled: binary=%s config=%s interval=%llus", o->singbox_binary, config_path,
            (unsigned long long)interval);
    char *last_etag = NULL, *logged_error = NULL, *core_version = NULL;
    sb_clash_client_options observation_options; sb_clash_client_options_init(&observation_options);
    observation_options.timeout_ms = 1500; observation_options.maximum_body_bytes = 1024 * 1024;
    sb_clash_client *observation = sb_clash_client_new(&observation_options, NULL);
    sb_clash_target observation_target = {o->clash_api_url, o->clash_api_secret};
    int64_t sampled_ms = 0, previous_up = 0, previous_down = 0;
    while (!self_singbox_stop_requested(srv)) {
        sb_err_clear(&e);
        if (self_singbox_render(srv, supervisor, &last_etag, &e) == 0) {
            sb_singbox_supervisor_ensure_alive(supervisor);
            const char *last_error = sb_singbox_supervisor_last_error(supervisor);
            if (last_error && !sb_streq(last_error, logged_error)) {
                SB_ERROR("%s", last_error);
                sb_str_set(&logged_error, last_error);
            } else if (!last_error) {
                free(logged_error);
                logged_error = NULL;
            }
        } else if (!sb_streq(logged_error, e.msg)) {
            SB_ERROR("managed sing-box cycle failed: %s", e.msg);
            sb_str_set(&logged_error, e.msg);
        }
        bool running = sb_singbox_supervisor_running(supervisor);
        if (running && observation) {
            sb_clash_response response = {0};
            if (!core_version && sb_clash_get(observation, &observation_target, "/version", &response, NULL) == 0 && response.status == 200) {
                const char *version = sbj_get_str(response.body, "version", "");
                if (*version && strlen(version) <= 128) core_version = sb_strdup(version);
            }
            sb_clash_response_free(&response);
            if (sb_clash_get(observation, &observation_target, "/connections", &response, NULL) == 0 && response.status == 200 &&
                sbj_is_integer(sbj_get(response.body, "uploadTotal")) && sbj_is_integer(sbj_get(response.body, "downloadTotal")) &&
                sbj_get_int(response.body, "uploadTotal", -1) >= 0 && sbj_get_int(response.body, "uploadTotal", INT64_MAX) <= INT64_C(9007199254740991) &&
                sbj_get_int(response.body, "downloadTotal", -1) >= 0 && sbj_get_int(response.body, "downloadTotal", INT64_MAX) <= INT64_C(9007199254740991)) {
                int64_t now_ms = sb_monotonic_ms();
                int64_t up = sbj_get_int(response.body, "uploadTotal", 0), down = sbj_get_int(response.body, "downloadTotal", 0);
                sbj *sample = sbj_object(); sbj_set_int(sample, "up_total", up); sbj_set_int(sample, "down_total", down);
                sbj_set_int(sample, "up", sampled_ms && now_ms > sampled_ms && up >= previous_up ? (int64_t)((double)(up - previous_up) * 1000.0 / (double)(now_ms - sampled_ms)) : 0);
                sbj_set_int(sample, "down", sampled_ms && now_ms > sampled_ms && down >= previous_down ? (int64_t)((double)(down - previous_down) * 1000.0 / (double)(now_ms - sampled_ms)) : 0);
                sbj_set_int(sample, "conn_count", (int64_t)sbj_arr_len(sbj_get(response.body, "connections")));
                if (sb_observability_sample(sb_store_database(srv->store), "self", sample, sb_unix_now(), NULL) == 0) {
                    sampled_ms = now_ms; previous_up = up; previous_down = down;
                }
                sbj_free(sample);
            }
            sb_clash_response_free(&response);
        }
        sbj *state = sbj_object(); sbj_set_str(state, "app_version", SB_EASY_VERSION);
        sbj_set_str(state, "version", core_version ? core_version : ""); sbj_set_bool(state, "running", running);
        sbj_set_str(state, "etag", last_etag ? last_etag : ""); sbj_set_str(state, "last_error", logged_error ? logged_error : "");
        sb_store_update_agent_status(srv->store, "self", state, NULL);
        sb_observability_status(sb_store_database(srv->store), "self", state, sb_unix_now(), NULL); sbj_free(state);
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += (time_t)interval;
        pthread_mutex_lock(&srv->self_singbox_mutex);
        while (!srv->self_singbox_stop &&
               pthread_cond_timedwait(&srv->self_singbox_wakeup, &srv->self_singbox_mutex, &deadline) != ETIMEDOUT) {
        }
        pthread_mutex_unlock(&srv->self_singbox_mutex);
    }
    sb_singbox_supervisor_stop(supervisor);
    sb_singbox_supervisor_free(supervisor);
    free(last_etag);
    free(logged_error);
    free(core_version);
    sb_clash_client_free(observation);
    free(config_path);
    return NULL;
}

int self_singbox_start(sb_http_server *srv, sb_err *err) {
    if (srv->self_singbox_running) return 0;
    srv->self_singbox_stop = false;
    if (sb_proxy_runtime_available()) {
        if (!srv->self_proxy) srv->self_proxy = sb_proxy_runtime_new_self(sb_store_database(srv->store), NULL, err);
        if (!srv->self_proxy || sb_proxy_runtime_start(srv->self_proxy, err)) return -1;
    }
    if (pthread_create(&srv->self_singbox_thread, NULL, self_singbox_main, srv) != 0) {
        sb_proxy_runtime_stop(srv->self_proxy);
        return sb_fail(err, SB_ERR_GENERIC, "could not start the managed sing-box thread");
    }
    srv->self_singbox_running = true;
    return 0;
}

void self_singbox_request_stop(sb_http_server *srv) {
    sb_proxy_runtime_request_stop(srv->self_proxy);
    if (!srv->self_singbox_running) return;
    pthread_mutex_lock(&srv->self_singbox_mutex);
    srv->self_singbox_stop = true;
    pthread_cond_broadcast(&srv->self_singbox_wakeup);
    pthread_mutex_unlock(&srv->self_singbox_mutex);
}

void self_singbox_join(sb_http_server *srv) {
    if (!srv->self_singbox_running) { sb_proxy_runtime_stop(srv->self_proxy); return; }
    self_singbox_request_stop(srv);
    pthread_join(srv->self_singbox_thread, NULL);
    srv->self_singbox_running = false;
    sb_proxy_runtime_stop(srv->self_proxy);
}
