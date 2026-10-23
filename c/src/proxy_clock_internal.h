#ifndef SB_PROXY_CLOCK_INTERNAL_H
#define SB_PROXY_CLOCK_INTERNAL_H

#include "sb/database.h"
#include <stdbool.h>
#include <sqlite3.h>

/* Owned by database handles; file aliases in one process share one clock state. */
typedef struct sb_proxy_clock sb_proxy_clock;
sb_proxy_clock *sb_proxy_clock_attach(sqlite3 *handle, sb_err *err);
void sb_proxy_clock_detach(sb_proxy_clock *clock);
/* Caller holds the database lock. Epoch observation happens inside the same
 * SQLite write transaction that reads/changes the epoch and allocates grants. */
int64_t sb_proxy_clock_wait_ms(sb_database *database, const char *user, int64_t epoch);
void sb_proxy_clock_reset_epoch(sb_database *database, const char *user, int64_t epoch);

#endif
