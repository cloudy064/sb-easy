#ifndef SBW_PLUGIN_CATALOG_H
#define SBW_PLUGIN_CATALOG_H
#include "../common.h"

/* Explicit trust is a test/build seam only. RPC never accepts a keyset. */
sbj *sbw_plugin_catalog_verify(const char *envelope, size_t length, const sbj *trusted_keys,
                                int64_t now, bool permit_expired_receipt, char payload_hash[65], sbw_error *error);
sbj *sbw_plugin_catalog_verify_trusted(const char *envelope, size_t length, int64_t now,
                                        bool permit_expired_receipt, char payload_hash[65], sbw_error *error);
/* Produces a new monotonic state with cumulative revocations; caller atomically
 * persists it before any install or activation. Does not mutate previous. */
sbj *sbw_plugin_catalog_accept(const sbj *previous, const sbj *payload, const char *hash, sbw_error *error);
bool sbw_plugin_catalog_revoked(const sbj *state, const char *id, const char *platform, int64_t build);
const sbj *sbw_plugin_catalog_release(const sbj *payload, const char *id, const char *platform,
                                       const char *abi, int64_t build);
int sbw_plugin_catalog_compatible(const sbj *release, const char *host_version,
                                  const char *core_version, int64_t os_version, sbw_error *error);
bool sbw_plugin_catalog_has_trust(void);
#endif
