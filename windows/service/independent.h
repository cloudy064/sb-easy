#ifndef SBW_INDEPENDENT_H
#define SBW_INDEPENDENT_H
#include "../common.h"
bool sbw_identity_is_independent(const sbj *identity);
/* Empty standalone profile, with no server/agent token or managed routes. */
sbj *sbw_independent_identity(void);
/* Fresh immutable base snapshot; local nodes are merged once by routing_apply.
 * Empty profiles are representable for setup, but connection.start should
 * require at least one imported node. */
sbj *sbw_independent_snapshot(const sbj *identity, sbw_error *error);
#endif
