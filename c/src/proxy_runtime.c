#include "sb/proxy_runtime.h"
#include "sb/proxy_users.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1)
#include "libsb_easy_singbox.h"
/* Global state: the embedded sing-box engine is a process-wide singleton, so
 * only one runtime may own it. `native_owned` is guarded by
 * `native_owner_mutex`. */
static pthread_mutex_t native_owner_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool native_owned;
#endif

#define SAFE_INTEGER INT64_C(9007199254740991)
struct sb_proxy_runtime {
    sb_proxy_bridge bridge;
    sb_proxy_exchange_fn exchange;
    void *context;
    sb_database *self_database;
    char *host, *boot, *pending, *reports;
    size_t pending_length;
    int64_t sequence, began_ms;
    bool begun;
    pthread_mutex_t operation, mutex;
    pthread_cond_t wakeup;
    pthread_t thread;
    bool started, stopping;
    bool native_owner;
    int64_t last_accepted_at;
    char issue[64];
};
static void secret_free(char *value, size_t length) {
    if (value) { OPENSSL_cleanse(value, length); free(value); }
}
static int failure(sb_err *err, const char *message) {
    return sb_fail(err, SB_ERR_UPSTREAM, "%s", message);
}
static int64_t request_time_ms(void) {
#ifdef __linux__
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
#else
    /* Non-Linux builds only use injected test bridges, never production
     * capability reporting. The production engine requires CLOCK_BOOTTIME. */
    return sb_monotonic_ms();
#endif
}
bool sb_proxy_runtime_available(void) {
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1) && defined(__linux__)
    return request_time_ms() >= 0;
#else
    return false;
#endif
}
sbj *sb_proxy_runtime_capabilities(void) {
    sbj *out = sbj_array();
    if (sb_proxy_runtime_available()) sbj_arr_push(out, sbj_str("proxy_users_v1"));
    return out;
}
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1)
static int bridge_result(char *value, sb_err *err) {
    if (!value) return 0;
    SBEasySingBoxFree(value);
    return failure(err, "Proxy engine operation failed");
}
static int native_begin(void *context, const char *value, sb_err *err) {
    (void)context; return bridge_result(SBEasyProxyRequestBegin((char *)value), err);
}
static int native_apply(void *context, const char *value, sb_err *err) {
    (void)context; return bridge_result(SBEasyProxyApplyPolicy((char *)value), err);
}
static int native_acknowledge(void *context, const char *value, sb_err *err) {
    (void)context; return bridge_result(SBEasyProxyAcknowledgeReports((char *)value), err);
}
static int native_stats(void *context, char **value, size_t *length, sb_err *err) {
    (void)context; *value = NULL; *length = 0;
    char *raw = SBEasyProxyStats();
    if (!raw) return failure(err, "Proxy engine counters are unavailable");
    size_t size = strnlen(raw, SB_PROXY_REQUEST_LIMIT + 1);
    if (size <= SB_PROXY_REQUEST_LIMIT) { *value = sb_strndup(raw, size); *length = size; }
    SBEasySingBoxFree(raw);
    return *value ? 0 : failure(err, "Proxy engine counters exceeded the limit");
}
static void native_stop(void *context) { (void)context; SBEasyProxyStop(); }
#endif
static bool identifier(const sbj *value) {
    if (!sbj_is_string(value) || !value->v.str.len || value->v.str.len > 128) return false;
    const char *allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    return strspn(value->v.str.ptr, allowed) == value->v.str.len;
}
static bool integer(const sbj *object, const char *key, int64_t minimum, int64_t maximum) {
    const sbj *value = sbj_get(object, key);
    return sbj_is_integer(value) && sbj_as_int(value, -1) >= minimum && sbj_as_int(value, -1) <= maximum;
}
static bool key_valid(const sbj *value) {
    if (!sbj_is_string(value) || value->v.str.len != 24) return false;
    size_t length = 0; unsigned char *key = sb_base64_decode_strict(value->v.str.ptr, value->v.str.len, &length);
    bool valid = key && length == 16;
    char *canonical = valid ? sb_base64_encode(key, length) : NULL;
    valid = valid && !strcmp(canonical, value->v.str.ptr);
    secret_free(canonical, canonical ? strlen(canonical) : 0);
    if (key) { OPENSSL_cleanse(key, length); free(key); }
    return valid;
}
static int compare_ids(const void *left, const void *right) {
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}
static bool distinct(const char **items, size_t count) {
    qsort(items, count, sizeof(*items), compare_ids);
    for (size_t i = 1; i < count; ++i) if (!strcmp(items[i - 1], items[i])) return false;
    return true;
}
static bool reports_valid(const sbj *reports) {
    if (!sbj_is_array(reports) || sbj_arr_len(reports) > 4096) return false;
    size_t count = sbj_arr_len(reports); const char **ids = sb_xcalloc(count ? count : 1, sizeof(*ids));
    bool valid = true;
    for (size_t i = 0; i < count; ++i) {
        const sbj *r = sbj_arr_at(reports, i);
        if (!sbj_is_object(r) || sbj_obj_len(r) != 2 || !identifier(sbj_get(r, "lease_id")) ||
            !integer(r, "used_bytes", 0, SAFE_INTEGER)) { valid = false; break; }
        ids[i] = sbj_get_str(r, "lease_id", "");
    }
    if (valid) valid = distinct(ids, count);
    free(ids); return valid;
}
static bool policy_valid(sb_proxy_runtime *runtime, const sbj *policy) {
    const sbj *node = sbj_get(policy, "node"), *users = sbj_get(policy, "users");
    if (!sbj_is_object(policy) || sbj_obj_len(policy) != 8 || !integer(policy, "version", 1, 1) ||
        !identifier(sbj_get(policy, "host_id")) || !sbj_string_is(sbj_get(policy, "boot_id"), runtime->boot) ||
        !integer(policy, "request_seq", runtime->sequence, runtime->sequence) ||
        (*runtime->host && !sbj_string_is(sbj_get(policy, "host_id"), runtime->host)) ||
        !integer(policy, "generated_at", 1, 4102444800LL) || !sbj_is_array(users) || sbj_arr_len(users) > 256) return false;
    int64_t generated = sbj_get_int(policy, "generated_at", 0);
    if (!integer(policy, "expires_at", generated + 1, generated + 60) || !node) return false;
    if (sbj_is_null(node)) return sbj_arr_len(users) == 0;
    unsigned char ip[16]; const sbj *listen = sbj_get(node, "listen");
    if (!sbj_is_object(node) || sbj_obj_len(node) != 4 || !sbj_is_string(listen) ||
        listen->v.str.len != strlen(listen->v.str.ptr) ||
        (inet_pton(AF_INET, listen->v.str.ptr, ip) != 1 && inet_pton(AF_INET6, listen->v.str.ptr, ip) != 1) ||
        !integer(node, "listen_port", 1, 65535) ||
        !sbj_string_is(sbj_get(node, "method"), "2022-blake3-aes-128-gcm") || !key_valid(sbj_get(node, "password"))) return false;
    const char *user_ids[256], *lease_ids[256];
    const char **device_ids = sb_xcalloc(8192, sizeof(*device_ids)), **keys = sb_xcalloc(8192, sizeof(*keys));
    size_t device_count = 0, count = sbj_arr_len(users); bool valid = true;
    for (size_t i = 0; i < count && valid; ++i) {
        const sbj *user = sbj_arr_at(users, i), *lease = sbj_get(user, "lease"), *devices = sbj_get(user, "devices");
        valid = sbj_is_object(user) && sbj_obj_len(user) == 4 && identifier(sbj_get(user, "id")) &&
            integer(user, "epoch", 1, SAFE_INTEGER) && sbj_is_object(lease) && sbj_obj_len(lease) == 4 &&
            identifier(sbj_get(lease, "id")) && integer(lease, "grant_bytes", 1, SAFE_INTEGER) &&
            integer(lease, "used_bytes", 0, sbj_get_int(lease, "grant_bytes", -1)) &&
            integer(lease, "expires_at", generated + 1, sbj_get_int(policy, "expires_at", 0)) &&
            sbj_is_array(devices) && sbj_arr_len(devices) >= 1 && sbj_arr_len(devices) <= 32;
        if (!valid) break;
        user_ids[i] = sbj_get_str(user, "id", ""); lease_ids[i] = sbj_get_str(lease, "id", "");
        for (size_t j = 0; j < sbj_arr_len(devices); ++j) {
            const sbj *device = sbj_arr_at(devices, j);
            int64_t expires = sbj_get_int(device, "expires_at", -1);
            if (!sbj_is_object(device) || sbj_obj_len(device) != 3 || !identifier(sbj_get(device, "id")) ||
                !key_valid(sbj_get(device, "password")) || !integer(device, "expires_at", 0, 4102444800LL) ||
                (expires != 0 && expires <= generated) || sbj_equal(sbj_get(device, "password"), sbj_get(node, "password"))) { valid = false; break; }
            device_ids[device_count] = sbj_get_str(device, "id", ""); keys[device_count++] = sbj_get_str(device, "password", "");
        }
    }
    if (valid) valid = distinct(user_ids, count) && distinct(lease_ids, count) &&
        distinct(device_ids, device_count) && distinct(keys, device_count);
    free(device_ids); free(keys); return valid;
}
sb_proxy_runtime *sb_proxy_runtime_new(const char *host_id, const sb_proxy_bridge *bridge,
    sb_proxy_exchange_fn exchange, void *context, sb_err *err) {
    sb_proxy_bridge selected = {0};
    if (bridge) selected = *bridge;
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1)
    else selected = (sb_proxy_bridge){NULL, native_begin, native_apply, native_stats, native_acknowledge, native_stop};
#endif
    sbj *host = sbj_str(host_id ? host_id : "");
    bool valid_host = !host_id || !*host_id || identifier(host); sbj_free(host);
    if (!valid_host || !exchange || !selected.begin || !selected.apply || !selected.stats || !selected.acknowledge || !selected.stop) {
        sb_fail(err, SB_ERR_VALIDATION, "Proxy runtime is unavailable or its host identity is invalid"); return NULL;
    }
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1)
    if (!bridge) {
        pthread_mutex_lock(&native_owner_mutex);
        if (native_owned) {
            pthread_mutex_unlock(&native_owner_mutex);
            sb_fail(err, SB_ERR_CONFLICT, "The embedded proxy runtime already has an owner"); return NULL;
        }
        native_owned = true; pthread_mutex_unlock(&native_owner_mutex);
        /* Only a new owner generation clears the singleton protocol state.
         * Ordinary core reload and worker stop/start retain boot/seq/counters. */
        if (bridge_result(SBEasyProxyReset(), err)) {
            pthread_mutex_lock(&native_owner_mutex); native_owned = false; pthread_mutex_unlock(&native_owner_mutex); return NULL;
        }
    }
#endif
    sb_proxy_runtime *runtime = sb_xcalloc(1, sizeof(*runtime));
    runtime->native_owner = bridge == NULL;
    runtime->host = sb_strdup(host_id ? host_id : ""); runtime->boot = sb_uuid_v4(); runtime->sequence = 1;
    runtime->bridge = selected; runtime->exchange = exchange; runtime->context = context;
    pthread_mutex_init(&runtime->operation, NULL); pthread_mutex_init(&runtime->mutex, NULL);
    pthread_condattr_t attributes; pthread_condattr_init(&attributes); pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    pthread_cond_init(&runtime->wakeup, &attributes); pthread_condattr_destroy(&attributes);
    return runtime;
}
static bool stopping(sb_proxy_runtime *runtime) {
    pthread_mutex_lock(&runtime->mutex); bool stopped = runtime->stopping; pthread_mutex_unlock(&runtime->mutex); return stopped;
}
static void outcome(sb_proxy_runtime *runtime, const char *issue, bool accepted) {
    pthread_mutex_lock(&runtime->mutex);
    snprintf(runtime->issue, sizeof(runtime->issue), "%s", issue);
    if (accepted) runtime->last_accepted_at = sb_unix_now();
    pthread_mutex_unlock(&runtime->mutex);
}
static int pending_request(sb_proxy_runtime *runtime, sb_err *err) {
    if (runtime->pending) return 0;
    if (runtime->sequence > SAFE_INTEGER) return failure(err, "Proxy lease sequence exhausted; restart is required");
    char *raw = NULL; size_t length = 0; sb_err ignored = {0};
    int rc = runtime->bridge.stats(runtime->bridge.context, &raw, &length, &ignored);
    sbj *reports = !rc && raw && length <= SB_PROXY_REQUEST_LIMIT ? sbj_parse_strict(raw, length, NULL, 0) : NULL;
    secret_free(raw, length);
    if (!reports_valid(reports)) {
        sbj_free(reports); runtime->bridge.stop(runtime->bridge.context);
        return failure(err, "Proxy engine counters are invalid");
    }
    sbj *request = sbj_object(); sbj_set_int(request, "version", 1); sbj_set_str(request, "boot_id", runtime->boot);
    sbj_set_int(request, "request_seq", runtime->sequence); sbj_set(request, "reports", reports);
    runtime->reports = sbj_dump(reports, -1); runtime->pending = sbj_dump(request, -1); sbj_free(request);
    runtime->pending_length = strlen(runtime->pending);
    if (runtime->pending_length > SB_PROXY_REQUEST_LIMIT) {
        free(runtime->reports); runtime->reports = NULL; free(runtime->pending); runtime->pending = NULL;
        runtime->pending_length = 0; return failure(err, "Proxy lease request exceeded the limit");
    }
    return 0;
}
int sb_proxy_runtime_step(sb_proxy_runtime *runtime, sb_err *err) {
    if (!runtime) return failure(err, "Proxy runtime is unavailable");
    if (pthread_mutex_trylock(&runtime->operation) != 0)
        return sb_fail(err, SB_ERR_CONFLICT, "Proxy lease exchange is already in progress");
    int rc = -1; char *raw = NULL; size_t length = 0; sbj *policy = NULL; sb_err ignored = {0};
    if (stopping(runtime)) { failure(err, "Proxy runtime is stopping"); goto done; }
    if (pending_request(runtime, err)) { outcome(runtime, "counters_failed", false); goto done; }
    if (!runtime->begun) {
        runtime->began_ms = request_time_ms();
        if (runtime->began_ms < 0) {
            runtime->bridge.stop(runtime->bridge.context);
            failure(err, "Proxy authorization clock is unavailable"); outcome(runtime, "clock_failed", false); goto done;
        }
        if (runtime->bridge.begin(runtime->bridge.context, runtime->pending, &ignored)) {
            failure(err, "Proxy request initialization failed"); outcome(runtime, "begin_failed", false); goto done;
        }
        runtime->begun = true;
    }
    if (runtime->exchange(runtime->context, runtime->pending, runtime->pending_length, &raw, &length, &ignored)) {
        failure(err, "Proxy lease exchange failed"); outcome(runtime, "exchange_failed", false); goto done;
    }
    if (stopping(runtime)) { failure(err, "Proxy runtime is stopping"); goto done; }
    policy = raw && length <= SB_PROXY_POLICY_LIMIT ? sbj_parse_strict(raw, length, NULL, 0) : NULL;
    if (!policy_valid(runtime, policy)) {
        runtime->bridge.stop(runtime->bridge.context); failure(err, "Proxy lease response was rejected");
        outcome(runtime, "response_rejected", false); goto done;
    }
    if (!*runtime->host) sb_str_set(&runtime->host, sbj_get_str(policy, "host_id", ""));
    int64_t received_ms = request_time_ms();
    if (received_ms < runtime->began_ms) {
        runtime->bridge.stop(runtime->bridge.context);
        failure(err, "Proxy authorization clock is unavailable"); outcome(runtime, "clock_failed", false); goto done;
    }
    int64_t ttl_ms = (sbj_get_int(policy, "expires_at", 0) - sbj_get_int(policy, "generated_at", 0) - 1) * 1000;
    bool expired = received_ms - runtime->began_ms >= ttl_ms;
    /* A matching server response has consumed this sequence even if the
     * local listener fails. Apply before acknowledgment lets the engine retire
     * removed leases; only the exact already-submitted report bytes are acked. */
    int applied = runtime->bridge.apply(runtime->bridge.context, raw, &ignored);
    int acknowledged = runtime->bridge.acknowledge(runtime->bridge.context, runtime->reports, &ignored);
    ++runtime->sequence; runtime->begun = false; runtime->began_ms = 0;
    free(runtime->pending); runtime->pending = NULL; runtime->pending_length = 0;
    free(runtime->reports); runtime->reports = NULL;
    if (applied) { failure(err, "Proxy lease accepted but local ingress could not be applied"); outcome(runtime, "apply_failed", true); }
    else if (acknowledged) { failure(err, "Proxy lease accepted but report acknowledgment failed"); outcome(runtime, "acknowledgment_failed", true); }
    else { outcome(runtime, expired ? "expired" : "", true); rc = 0; }
    if (expired) rc = 1;
done:
    sbj_free(policy); secret_free(raw, length); pthread_mutex_unlock(&runtime->operation); return rc;
}
static void *worker(void *context) {
    sb_proxy_runtime *runtime = context;
    while (!stopping(runtime)) {
        int64_t began = sb_monotonic_ms(); sb_err error = {0};
        if (sb_proxy_runtime_step(runtime, &error) == 1 && !stopping(runtime)) (void)sb_proxy_runtime_step(runtime, &error);
        int64_t wait_ms = SB_PROXY_POLL_MILLIS - (sb_monotonic_ms() - began);
        if (wait_ms < 1000) wait_ms = 1000;
        struct timespec deadline; clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += wait_ms / 1000; deadline.tv_nsec += (wait_ms % 1000) * 1000000;
        if (deadline.tv_nsec >= 1000000000L) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000L; }
        pthread_mutex_lock(&runtime->mutex);
        while (!runtime->stopping && pthread_cond_timedwait(&runtime->wakeup, &runtime->mutex, &deadline) != ETIMEDOUT) {}
        pthread_mutex_unlock(&runtime->mutex);
    }
    return NULL;
}
int sb_proxy_runtime_start(sb_proxy_runtime *runtime, sb_err *err) {
    if (!runtime) return failure(err, "Proxy runtime is unavailable");
    pthread_mutex_lock(&runtime->mutex);
    if (runtime->started) { pthread_mutex_unlock(&runtime->mutex); return 0; }
    runtime->stopping = false;
    if (pthread_create(&runtime->thread, NULL, worker, runtime)) {
        pthread_mutex_unlock(&runtime->mutex); return failure(err, "Proxy lease worker could not start");
    }
    runtime->started = true; pthread_mutex_unlock(&runtime->mutex); return 0;
}
void sb_proxy_runtime_request_stop(sb_proxy_runtime *runtime) {
    if (!runtime) return;
    pthread_mutex_lock(&runtime->mutex); runtime->stopping = true;
    pthread_cond_broadcast(&runtime->wakeup); pthread_mutex_unlock(&runtime->mutex);
}
void sb_proxy_runtime_stop(sb_proxy_runtime *runtime) {
    if (!runtime) return;
    sb_proxy_runtime_request_stop(runtime);
    pthread_mutex_lock(&runtime->mutex); bool join = runtime->started; pthread_t thread = runtime->thread;
    pthread_mutex_unlock(&runtime->mutex);
    if (join) pthread_join(thread, NULL);
    pthread_mutex_lock(&runtime->operation); runtime->bridge.stop(runtime->bridge.context); pthread_mutex_unlock(&runtime->operation);
    if (runtime->self_database) {
        sbj *empty = sbj_array(); (void)sb_proxy_runtime_report(runtime->self_database, "self", empty, sb_unix_now(), NULL); sbj_free(empty);
    }
    pthread_mutex_lock(&runtime->mutex); runtime->started = false; pthread_mutex_unlock(&runtime->mutex);
}
void sb_proxy_runtime_free(sb_proxy_runtime *runtime) {
    if (!runtime) return;
    sb_proxy_runtime_stop(runtime); free(runtime->host); free(runtime->boot); free(runtime->pending); free(runtime->reports);
#if defined(SB_EASY_EMBED_SINGBOX) && defined(SB_EASY_PROXY_USERS_V1)
    if (runtime->native_owner) { pthread_mutex_lock(&native_owner_mutex); native_owned = false; pthread_mutex_unlock(&native_owner_mutex); }
#endif
    pthread_cond_destroy(&runtime->wakeup); pthread_mutex_destroy(&runtime->operation); pthread_mutex_destroy(&runtime->mutex); free(runtime);
}
sbj *sb_proxy_runtime_status(sb_proxy_runtime *runtime) {
    sbj *out = sbj_object(); sbj_set_bool(out, "supported", runtime != NULL);
    if (!runtime) return out;
    pthread_mutex_lock(&runtime->mutex); sbj_set_bool(out, "worker_running", runtime->started && !runtime->stopping);
    sbj_set_str(out, "issue", runtime->issue); sbj_set_int(out, "last_accepted_at", runtime->last_accepted_at);
    pthread_mutex_unlock(&runtime->mutex); return out;
}
static int self_exchange(void *context, const char *request, size_t length, char **response, size_t *size, sb_err *err) {
    sb_proxy_runtime *runtime = context; *response = NULL; *size = 0;
    sbj *capabilities = sbj_array(); sbj_arr_push(capabilities, sbj_str("proxy_users_v1"));
    int reported = sb_proxy_runtime_report(runtime->self_database, "self", capabilities, sb_unix_now(), err);
    sbj_free(capabilities); if (reported) return -1;
    sbj *body = sbj_parse_strict(request, length, NULL, 0);
    sbj *out = body ? sb_proxy_lease_exchange(runtime->self_database, "self", body, sb_unix_now(), err) : NULL;
    sbj_free(body); if (!out) return -1;
    *response = sbj_dump(out, -1); *size = strlen(*response); sbj_free(out); return 0;
}
sb_proxy_runtime *sb_proxy_runtime_new_self(sb_database *database, const sb_proxy_bridge *bridge, sb_err *err) {
    if (!database) { sb_fail(err, SB_ERR_VALIDATION, "Proxy self runtime database is required"); return NULL; }
    sb_proxy_runtime *runtime = sb_proxy_runtime_new("self", bridge, self_exchange, NULL, err);
    if (runtime) { runtime->context = runtime; runtime->self_database = database; }
    return runtime;
}
