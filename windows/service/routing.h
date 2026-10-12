#ifndef SBW_ROUTING_H
#define SBW_ROUTING_H
#include "../common.h"
#define SBW_GPT_SELECTOR "sb-easy-local-gpt"
#define SBW_DEFAULT_SELECTOR "sb-easy-local-default"
sbj *sbw_routing_groups(const sbj *source, const sbj *identity);
sbj *sbw_routing_apply(const sbj *source, const sbj *identity, bool runtime, sbw_error *error);
char *sbw_routing_target(const sbj *effective);
sbj *sbw_routing_runtime(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error);
/* Returns an owned effective snapshot; never changes the server snapshot. */
sbj *sbw_routing_snapshot_node(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error);
sbj *sbw_routing_snapshot(const sbj *source, bool gpt_default, sbw_error *error);
#endif
