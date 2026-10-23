#include "sb/subscription_service.h"
#include "sb/proxy_parser.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct sb_subscription_service {
    sb_store *store;
    sb_subscription_fetcher *fetcher;
    pthread_mutex_t refresh_mutex;
    pthread_mutex_t lifecycle_mutex;
    pthread_cond_t wakeup;
    pthread_t thread;
    bool running;
    bool stopping;
};

sb_subscription_service *sb_subscription_service_new(sb_store *store,
                                                     sb_subscription_fetcher *fetcher) {
    sb_subscription_service *service = sb_xcalloc(1, sizeof *service);
    service->store = store;
    service->fetcher = fetcher;
    pthread_mutex_init(&service->refresh_mutex, NULL);
    pthread_mutex_init(&service->lifecycle_mutex, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&service->wakeup, &attr);
    pthread_condattr_destroy(&attr);
    return service;
}

static bool stopping(sb_subscription_service *service) {
    pthread_mutex_lock(&service->lifecycle_mutex);
    bool result = service->stopping;
    pthread_mutex_unlock(&service->lifecycle_mutex);
    return result;
}

static int fetch_locked(sb_subscription_service *service, const char *id, bool only_due,
                         int64_t now, sb_subscription_fetch_result *result, sb_err *err) {
    sb_subscription sub;
    sb_subscription_init(&sub);
    sb_proxy_import parsed;
    sb_proxy_import_init(&parsed);
    sbj *usage = NULL;
    char *body = NULL;
    int found = sb_store_find_subscription(service->store, id, &sub, err);
    int rc = found == 1 ? 0 : -1;
    if (found == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
    if (rc != 0) goto done;
    if (only_due && (!sub.enabled || sub.next_refresh_at > now)) { rc = 1; goto done; }
    size_t length = 0;
    sb_err fetch_error = {0};
    body = sb_subscription_fetcher_fetch_metadata(service->fetcher, sub.url, sub.url_len,
                                                   &length, &usage, &fetch_error);
    if (!body) {
        rc = sb_fail(err, SB_ERR_VALIDATION, "Failed to fetch subscription: %s", fetch_error.msg);
        goto failed;
    }
    rc = sb_parse_subscription_report(body, length, &parsed, err);
    if (rc != 0) goto failed;
    sb_subscription_fetch_result_free(result);
    result->skipped = parsed.skipped.len;
    result->errors = parsed.skipped;
    memset(&parsed.skipped, 0, sizeof parsed.skipped);
    result->usage = usage;
    usage = NULL;
    rc = sb_store_apply_subscription_fetch(service->store, &sub, parsed.nodes.items,
                                           parsed.nodes.len, result, now, err);
    if (rc == 0) goto done;
failed:
    /* The transport may include the URL (and its access token) in an error.
     * Persist only a bounded category; the explicit request gets its error. */
    sb_store_record_subscription_failure(service->store, &sub,
        body ? "Subscription refresh failed: incompatible response or storage conflict"
             : "Subscription download failed; check source availability and credentials",
        now, NULL);
done:
    free(body);
    sbj_free(usage);
    sb_proxy_import_free(&parsed);
    sb_subscription_free(&sub);
    return rc;
}

int sb_subscription_service_fetch(sb_subscription_service *service, const char *id,
                                   sb_subscription_fetch_result *result, sb_err *err) {
    pthread_mutex_lock(&service->refresh_mutex);
    int rc = fetch_locked(service, id, false, (int64_t)time(NULL), result, err);
    pthread_mutex_unlock(&service->refresh_mutex);
    return rc;
}

int sb_subscription_service_refresh_due(sb_subscription_service *service, int64_t now,
                                         sb_err *err) {
    sb_subscription_vec subscriptions = {0};
    if (sb_store_list_subscriptions(service->store, &subscriptions, err) != 0) return -1;
    int attempted = 0;
    for (size_t i = 0; i < subscriptions.len && !stopping(service); ++i) {
        const sb_subscription *sub = &subscriptions.items[i];
        if (!sub->enabled || sub->next_refresh_at > now) continue;
        /* UI/manual refresh has priority over the periodic sweep. */
        if (pthread_mutex_trylock(&service->refresh_mutex) != 0) break;
        sb_subscription_fetch_result result;
        sb_subscription_fetch_result_init(&result);
        sb_err ignored = {0};
        int rc = fetch_locked(service, sub->id, true, now, &result, &ignored);
        if (rc != 1) ++attempted;
        sb_subscription_fetch_result_free(&result);
        pthread_mutex_unlock(&service->refresh_mutex);
    }
    sb_subscription_vec_free(&subscriptions);
    return attempted;
}

static void *refresh_worker(void *user) {
    sb_subscription_service *service = user;
    while (!stopping(service)) {
        sb_subscription_service_refresh_due(service, (int64_t)time(NULL), NULL);
        pthread_mutex_lock(&service->lifecycle_mutex);
        if (!service->stopping) {
            struct timespec deadline;
            clock_gettime(CLOCK_MONOTONIC, &deadline);
            deadline.tv_sec += 5;
            pthread_cond_timedwait(&service->wakeup, &service->lifecycle_mutex, &deadline);
        }
        pthread_mutex_unlock(&service->lifecycle_mutex);
    }
    return NULL;
}

int sb_subscription_service_start(sb_subscription_service *service, sb_err *err) {
    pthread_mutex_lock(&service->lifecycle_mutex);
    int rc = 0;
    if (!service->running) {
        service->stopping = false;
        if (pthread_create(&service->thread, NULL, refresh_worker, service) != 0)
            rc = sb_fail(err, SB_ERR_IO, "Unable to start subscription refresh worker");
        else service->running = true;
    }
    pthread_mutex_unlock(&service->lifecycle_mutex);
    return rc;
}

void sb_subscription_service_stop(sb_subscription_service *service) {
    if (!service) return;
    pthread_mutex_lock(&service->lifecycle_mutex);
    bool join = service->running;
    service->stopping = true;
    pthread_cond_broadcast(&service->wakeup);
    pthread_mutex_unlock(&service->lifecycle_mutex);
    if (join) pthread_join(service->thread, NULL);
    service->running = false;
}

void sb_subscription_service_free(sb_subscription_service *service) {
    if (!service) return;
    sb_subscription_service_stop(service);
    pthread_mutex_destroy(&service->refresh_mutex);
    pthread_mutex_destroy(&service->lifecycle_mutex);
    pthread_cond_destroy(&service->wakeup);
    free(service);
}
