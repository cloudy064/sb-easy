/* Agent-side access to the Clash API exposed by the locally running sing-box
 * (C++ agent_clash.hpp).
 *
 * The controller and secret are read from the installed sing-box config for
 * every operation, so config reloads do not leave the agent with stale
 * credentials. All functions are safe to call from several threads at once
 * (the agent loop samples telemetry while the local UI selects proxies). */
#ifndef SB_AGENT_CLASH_H
#define SB_AGENT_CLASH_H

#include <stddef.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_agent_clash sb_agent_clash;

/* Receives one {"<tag>": <delay number or null>} object per tested proxy
 * (borrowed). Returning -1 (with err set) aborts the test run; the error is
 * propagated by sb_agent_clash_test_proxies (C++ reporter exceptions). */
typedef int (*sb_latency_reporter)(const sbj *latency, void *user, sb_err *err);

/* config_path is copied. Never fails (the C++ constructor cannot throw). */
sb_agent_clash *sb_agent_clash_new(const char *config_path);
void sb_agent_clash_free(sb_agent_clash *clash);

/* Tests all concrete proxies, or only the requested tags, and invokes the
 * reporter once per proxy so the control plane can show progressive results.
 * tags == NULL means "all" (std::nullopt); a non-NULL empty vector tests
 * nothing. On success stores the number of tested proxies in *tested.
 * Errors: SB_ERR_VALIDATION "proxy latency reporter is required",
 * config/Clash failures, or whatever the reporter set. */
int sb_agent_clash_test_proxies(sb_agent_clash *clash, const sb_strvec *tags,
                                sb_latency_reporter reporter, void *user, size_t *tested,
                                sb_err *err);

/* Returns an agent telemetry payload in *out, or sets *out = NULL when the
 * installed config does not expose a Clash controller. -1 on error. */
int sb_agent_clash_sample_telemetry(sb_agent_clash *clash, sbj **out, sb_err *err);

/* Returns the live Clash proxy/group model from the locally running core.
 * Unlike the installed config, this includes each selector's current choice. */
sbj *sb_agent_clash_proxies(sb_agent_clash *clash, sb_err *err);

/* Selects an outbound in a live selector group and returns the chosen pair
 * ({"success":true,"group":...,"name":...}). */
sbj *sb_agent_clash_select_proxy(sb_agent_clash *clash, const char *group, const char *proxy,
                                 sb_err *err);

/* Opens a short-lived CONNECT tunnel through the installed local HTTP/mixed
 * inbound and returns the actual Clash connection chain selected by sing-box.
 * URL validation errors are SB_ERR_VALIDATION (C++ std::invalid_argument). */
sbj *sb_agent_clash_test_route(sb_agent_clash *clash, const char *url, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
