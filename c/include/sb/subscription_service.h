#ifndef SB_SUBSCRIPTION_SERVICE_H
#define SB_SUBSCRIPTION_SERVICE_H

#include "sb/store.h"
#include "sb/subscription_fetcher.h"

typedef struct sb_subscription_service sb_subscription_service;
/* Borrows store and fetcher. Serializes automatic and manual refreshes. */
sb_subscription_service *sb_subscription_service_new(sb_store *store,
                                                     sb_subscription_fetcher *fetcher);
int sb_subscription_service_start(sb_subscription_service *service, sb_err *err);
void sb_subscription_service_stop(sb_subscription_service *service);
void sb_subscription_service_free(sb_subscription_service *service);
int sb_subscription_service_fetch(sb_subscription_service *service, const char *id,
                                   sb_subscription_fetch_result *result, sb_err *err);
/* Runs due enabled sources once, using Unix seconds. Returns attempted count.
 * Per-source failure remains in the subscription status; listing failure is -1.
 * Useful for deterministic scheduler/restore tests without sleeping. */
int sb_subscription_service_refresh_due(sb_subscription_service *service, int64_t now,
                                         sb_err *err);
#endif
