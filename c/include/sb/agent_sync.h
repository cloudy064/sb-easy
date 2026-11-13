#ifndef SB_AGENT_SYNC_H
#define SB_AGENT_SYNC_H
#include "sb/json.h"
#include "sb/util.h"

/* Durable server snapshot and local outbox. Caller serializes all access.
 * Files are identity-scoped; no credentials are persisted in this module. */
typedef struct sb_agent_sync sb_agent_sync;
sb_agent_sync *sb_agent_sync_new(const char *path, const char *scope,
                                const sbj *legacy_settings, sb_err *err);
void sb_agent_sync_free(sb_agent_sync *sync);
bool sb_agent_sync_state_valid(const sbj *state);
/* Snapshot owns all returned fields. patch/settings expose pending edits;
 * server_patch/server_agent_settings and config remain server-confirmed. */
sbj *sb_agent_sync_snapshot(const sb_agent_sync *sync);
/* Observe remote state without losing pending edits. Stale edits become an
 * explicit conflict. Identical server contents acknowledge a lost response. */
int sb_agent_sync_observe(sb_agent_sync *sync, const sbj *state, sb_err *err);
/* Full state edit requires base_version, patch_version and local_version.
 * resolve=use_server discards pending; retry_local explicitly retries it. */
int sb_agent_sync_queue(sb_agent_sync *sync, const sbj *edit, sb_err *err);
sbj *sb_agent_sync_request(const sb_agent_sync *sync);
/* Acknowledges precisely the sent request; newer local edits are retained. */
int sb_agent_sync_acknowledge(sb_agent_sync *sync, const sbj *sent,
                             const sbj *state, sb_err *err);
#endif
