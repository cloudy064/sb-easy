#ifndef SB_PROXY_USERS_H
#define SB_PROXY_USERS_H
#include "sb/database.h"
#include "sb/json.h"
/* Authenticated runtime status only. Missing capabilities clear support.
 * Admin-editable host.capabilities never authorize managed proxy listeners. */
int sb_proxy_runtime_report(sb_database *database, const char *host_id, const sbj *capabilities, int64_t now,
                            sb_err *err);
/* Monotonic clock dependency injection for deterministic tests/embedding.
 * Must be installed before any proxy-user epoch observation, lease or reset;
 * shared database connections inherit it. Never exposed as a runtime setting. */
typedef int64_t (*sb_proxy_monotonic_fn)(void *context);
int sb_proxy_clock_set_source(sb_database *database, sb_proxy_monotonic_fn source, void *context, sb_err *err);
/* All returned JSON is caller-owned. now is Unix seconds; injected for tests. */
sbj *sb_proxy_users_list(sb_database *database, sb_err *err);
sbj *sb_proxy_user_get(sb_database *database, const char *id, sb_err *err);
sbj *sb_proxy_user_save(sb_database *database, const char *id, const sbj *body, int64_t now, sb_err *err);
int sb_proxy_user_remove(sb_database *database, const char *id, int64_t now, sb_err *err);
sbj *sb_proxy_user_reset(sb_database *database, const char *id, int64_t now, sb_err *err);
sbj *sb_proxy_claim_rotate(sb_database *database, const char *id, int64_t now, sb_err *err);
char *sb_proxy_claim_resolve(sb_database *database, const char *token, int64_t now, sb_err *err);
sbj *sb_proxy_device_create(sb_database *database, const char *user_id, const sbj *body, int64_t now,
                            sb_err *err);
int sb_proxy_device_revoke(sb_database *database, const char *user_id, const char *device_id, int64_t now,
                           sb_err *err);
sbj *sb_proxy_ingress_list(sb_database *database, sb_err *err);
sbj *sb_proxy_ingress_save(sb_database *database, const char *host_id, const sbj *body, int64_t now,
                           sb_err *err);
sbj *sb_proxy_subscription(sb_database *database, const char *token, int64_t now, sb_err *err);
/* Only call for an authenticated enabled host. The business layer rechecks it.
 * Request/response: docs/proxy-user-leases-v1.md. BEGIN IMMEDIATE reserves bytes
 * across every node, boot and device; grants are never reclaimed automatically. */
sbj *sb_proxy_lease_exchange(sb_database *database, const char *host_id, const sbj *request, int64_t now,
                             sb_err *err);
#endif
