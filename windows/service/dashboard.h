#ifndef SBW_DASHBOARD_H
#define SBW_DASHBOARD_H
#include "../common.h"
/* Display projections only: no credentials, arbitrary JSON, or API secrets.
 * Collection/string limits keep every result below the IPC frame limit. */
sbj *sbw_config_catalog(const sbj *snapshot);
sbj *sbw_dashboard_snapshot(const sbj *connections, const sbj *proxies);
#endif
