#ifndef SBW_IP_CHECK_H
#define SBW_IP_CHECK_H
#include "../common.h"

/* Read-only discovery and validation. Never calls the active proxy core, changes
 * routes, or returns subscription credentials to the desktop. */
sbj *sbw_ipcheck_nodes(const sbj *config, const sbj *source, const sbj *identity, sbw_error *error);
sbj *sbw_ipcheck_interfaces(void);
int sbw_ipcheck_validate(const sbj *config, const sbj *params, const sbj *interfaces, sbw_error *error);
sbj *sbw_ipcheck_failed_snapshot(const sbj *previous);
#endif
