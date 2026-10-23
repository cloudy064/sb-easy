#ifndef SB_OBSERVABILITY_H
#define SB_OBSERVABILITY_H
#include "sb/database.h"
#include "sb/json.h"

/* These functions share the store's database mutex; timestamps are UTC seconds
 * from server receipt. They never persist connection/domain/log payloads. */
typedef struct sb_observability sb_observability;
sb_observability *sb_observability_new(sb_database *database);
int sb_observability_start(sb_observability *monitor, sb_err *err);
void sb_observability_stop(sb_observability *monitor);
void sb_observability_free(sb_observability *monitor);
int sb_observability_sample(sb_database *database, const char *host_id,
                            const sbj *telemetry, int64_t now, sb_err *err);
int sb_observability_target(sb_database *database, const char *host_id,
                            const char *etag, int64_t now, sb_err *err);
int sb_observability_status(sb_database *database, const char *host_id,
                            const sbj *state, int64_t now, sb_err *err);
int sb_observability_evaluate(sb_database *database, int64_t now, sb_err *err);
sbj *sb_observability_settings(sb_database *database, sb_err *err);
int sb_observability_configure(sb_database *database, const sbj *settings, sb_err *err);
sbj *sb_observability_history(sb_database *database, const char *host_id,
                              int64_t from, int64_t to, int64_t step, sb_err *err);
sbj *sb_observability_hosts(sb_database *database, int64_t now, sb_err *err);
sbj *sb_observability_alerts(sb_database *database, const char *host_id, bool active_only, sb_err *err);
int sb_observability_ack(sb_database *database, int64_t alert_id, const char *user_id, sb_err *err);
/* A separate read-only scrape credential. Return plaintext only at rotation;
 * NULL with revoke=true deletes it. Never accepted as a panel/agent token. */
char *sb_observability_rotate_token(sb_database *database, bool revoke, sb_err *err);
bool sb_observability_check_token(sb_database *database, const char *token);
char *sb_observability_prometheus(sb_database *database, int64_t now, sb_err *err);
#endif
