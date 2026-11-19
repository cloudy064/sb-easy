#ifndef SBW_TAILSCALE_STATUS_H
#define SBW_TAILSCALE_STATUS_H
#include "runtime_config.h"

/* Query only the owned core's private API. The projection deliberately excludes
 * authorization URLs, user profiles, node keys, and all other credentials. */
int sbw_tailscale_status_get(const sbw_runtime_config *config, DWORD expected_pid,
                            HANDLE cancel, sbj **out, sbw_error *error);

/* Decode one complete, uncompressed gRPC-Web data frame. Exposed for bounded
 * decoder tests; callers own *out and must not pass unbounded transport data. */
int sbw_tailscale_status_decode(const unsigned char *frame, size_t length,
                               sbj **out, sbw_error *error);

#define SBW_TAILSCALE_STATUS_LIMIT (512U * 1024U)
#endif
