/* Node-local transform of panel-rendered sing-box configs (C++ agent_config.hpp). */
#ifndef SB_AGENT_CONFIG_H
#define SB_AGENT_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C++ AgentConfigTransformOptions. The std::map members are JSON objects
 * (sbj keeps keys sorted like std::map). All members are owned. */
typedef struct {
    bool local_proxy_egress;           /* default true */
    sbj *outbound_server_overrides;    /* object: tag -> server string */
    sbj *outbound_overrides;           /* object: tag -> outbound object */
    char *default_proxy_outbound;      /* NULL == std::nullopt */
    /* Node-local route rules are prepended after the panel config is rendered.
     * They are intentionally kept outside the Agent UI settings so a panel
     * refresh cannot discard local policy. JSON array. */
    sbj *local_route_rules;
} sb_agent_config_options;

void sb_agent_config_options_init(sb_agent_config_options *o); /* C++ defaults */
void sb_agent_config_options_free(sb_agent_config_options *o);
void sb_agent_config_options_copy(sb_agent_config_options *dst,
                                  const sb_agent_config_options *src); /* dst uninitialised */

/* Apply node-local adjustments to a panel-rendered sing-box configuration.
 *
 * The transformation mirrors the legacy Rust agent mode: proxy transports use
 * the node's own egress instead of the management WireGuard detour, optional
 * node-specific outbound replacements are applied, and proxy DNS is injected
 * for OpenAI domains. Returns the body unchanged (copied) when nothing
 * changed, otherwise the 2-space pretty dump. NULL on error. */
char *sb_prepare_agent_config(const char *body, size_t len,
                              const sb_agent_config_options *options, sb_err *err);

/* Serializes the node-local transform settings used by the Agent UI. */
sbj *sb_agent_config_options_to_json(const sb_agent_config_options *options);

/* Applies a JSON settings object over the supplied defaults (NULL -> C++
 * defaults) and validates every supported value. *out must not be
 * initialised; it is initialised on success only. */
int sb_agent_config_options_from_json(const sbj *value,
                                      const sb_agent_config_options *defaults,
                                      sb_agent_config_options *out, sb_err *err);

/* Loads persisted settings, returning the supplied defaults when the file does
 * not exist. Same *out contract as from_json. */
int sb_agent_config_options_load(const char *path, const sb_agent_config_options *defaults,
                                 sb_agent_config_options *out, sb_err *err);

/* Persists a complete settings object using an atomic replacement. */
int sb_agent_config_options_save(const char *path, const sb_agent_config_options *options,
                                 sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
