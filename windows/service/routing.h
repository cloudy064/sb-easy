#ifndef SBW_ROUTING_H
#define SBW_ROUTING_H
#include "../common.h"
/* Returns an owned effective snapshot; never changes the server snapshot. */
sbj *sbw_routing_snapshot(const sbj *source, bool gpt_default, sbw_error *error);
#endif
