#ifndef SBW_ROUTING_H
#define SBW_ROUTING_H
#include "../common.h"
#define SBW_GPT_SELECTOR "sb-easy-local-gpt"
#define SBW_DEFAULT_SELECTOR "sb-easy-local-default"
sbj *sbw_routing_groups(const sbj *source, const sbj *identity);
sbj *sbw_routing_apply(const sbj *source, const sbj *identity, bool runtime, sbw_error *error);
/* Owned identity copy; does not persist or activate. Save validates domains,
 * executable names and overlaps; remove accepts only {id}. Activation must
 * still pass routing_apply and the core's config check before persistence. */
sbj *sbw_routing_change(const sbj *identity, const sbj *params, bool remove, sbw_error *error);
/* Enables automatic selection only for the explicit leaf-node allowlist. */
sbj *sbw_routing_automatic(const sbj *source, const sbj *identity, const sbj *params, sbw_error *error);
char *sbw_routing_target(const sbj *effective);
sbj *sbw_routing_runtime(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error);
/* Returns an owned effective snapshot; never changes the server snapshot. */
sbj *sbw_routing_snapshot_node(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error);
sbj *sbw_routing_snapshot(const sbj *source, bool gpt_default, sbw_error *error);
#endif
