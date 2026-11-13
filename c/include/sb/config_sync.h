#ifndef SB_CONFIG_SYNC_H
#define SB_CONFIG_SYNC_H

#include "sb/database.h"
#include "sb/json.h"

/* JSON Merge Patch: null object members delete; arrays replace as a whole.
 * Both helpers return owned values. Diff cannot represent new literal null
 * object members; migration callers must verify round-trip equality. */
sbj *sb_config_merge_patch(const sbj *base, const sbj *patch);
sbj *sb_config_merge_diff(const sbj *base, const sbj *effective);

/* Source timestamps are assigned by the server, in monotonic milliseconds.
 * Capture before rendering; get/put reject a changed source snapshot. */
int64_t sb_config_sync_source_version(sb_database *db, sb_err *err);
int sb_config_sync_exists(sb_database *db, const char *host_id, sb_err *err);
/* First read preserves the old rendered configuration as a base-relative
 * patch. Pass NULL for legacy to start with an empty patch. */
sbj *sb_config_sync_get(sb_database *db, const char *host_id, const sbj *base,
                        const sbj *legacy, int64_t source_version, sb_err *err);
sbj *sb_config_sync_put(sb_database *db, const char *host_id, const sbj *base,
                        int64_t source_version, int64_t expected_base_version,
                        int64_t expected_patch_version, const sbj *patch,
                        const sbj *agent_settings, sb_err *err);

#endif
