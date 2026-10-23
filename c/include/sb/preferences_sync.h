#ifndef SB_PREFERENCES_SYNC_H
#define SB_PREFERENCES_SYNC_H
#include "sb/database.h"
#include "sb/json.h"
/* Server-side opaque storage: validation never attempts to decrypt. Clients
 * use the fixed envelope documented in docs/preferences-format.md. */
int sb_preferences_validate_envelope(const sbj *envelope, sb_err *err);
sbj *sb_preferences_get(sb_database *database, const char *user_id, const char *slot, sb_err *err);
/* expected_revision=0 creates an absent slot; all replacements/deletions require
 * the last observed revision. Conflicts leave existing data untouched. */
sbj *sb_preferences_put(sb_database *database, const char *user_id, const char *slot,
                        int64_t expected_revision, const sbj *envelope, sb_err *err);
int sb_preferences_delete(sb_database *database, const char *user_id, const char *slot,
                           int64_t expected_revision, sb_err *err);
#endif
