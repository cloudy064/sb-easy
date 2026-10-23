#ifndef SB_WG_MIGRATION_H
#define SB_WG_MIGRATION_H
#include "sb/json.h"
#include "sb/util.h"
/* Validates a wg-easy v14 wg0.json and produces a private normalized batch.
 * Does not execute commands or access a store. Caller owns the result.
 * options: dns, allowed_ips, persistent_keepalive (v14 stored these in env).
 * Neither this batch nor any private key belongs in preview responses/logs. */
sbj *sb_wg_easy_v14_normalize(const sbj *configuration, const sbj *options,
                              const char *default_dns, sb_err *err);
#endif
