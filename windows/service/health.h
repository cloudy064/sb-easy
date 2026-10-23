#ifndef SBW_HEALTH_H
#define SBW_HEALTH_H
#include "../common.h"

typedef struct sbw_health sbw_health;
typedef struct sbw_health_transport {
    void *context;
    int (*proxies)(void *context, sbj **out, sbw_error *error);
    int (*probe)(void *context, const char *target, const char *url, DWORD timeout_ms,
                  int64_t *delay_ms, sbw_error *error);
    int (*select)(void *context, const char *selector, const char *target, sbw_error *error);
} sbw_health_transport;
/* All policy/result objects are owned by the caller. No credentials or remote
 * response bodies enter results. Windows field names match Android health. */
sbj *sbw_health_policy(const sbj *identity);
bool sbw_health_policy_valid(const sbj *policy);
sbj *sbw_health_change(const sbj *identity, const sbj *policy, sbw_error *error);
/* Candidate membership is an explicit user constraint. NULL means none passed;
 * callers retain the current selection and never fall back to direct. */
const char *sbw_health_choose(const char *current, const sbj *candidates,
                               const sbj *results, const sbj *policy);
sbw_health *sbw_health_new(void);
void sbw_health_free(sbw_health *health);
void sbw_health_reset(sbw_health *health);
/* Serialized by the controller mutation lock. A step does at most one node
 * probe or one selector mutation. PID/network/policy/group changes discard
 * incomplete cycles, so stale probes cannot select a different generation. */
void sbw_health_step(sbw_health *health, const sbj *groups, const sbj *policy,
                      DWORD pid, LONG network_generation, uint64_t now_ms,
                      const sbw_health_transport *transport);
sbj *sbw_health_snapshot(const sbw_health *health);
#endif
