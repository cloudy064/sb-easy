/* Validated per-host Tailscale settings and sing-box endpoint rendering. */
#ifndef SB_TAILSCALE_H
#define SB_TAILSCALE_H

#include "sb/types.h"

/* Settings are objects. All strings reject embedded NUL bytes. */
int sb_tailscale_validate(const sbj *settings, sb_err *err);
bool sb_tailscale_enabled(const sbj *settings);
/* Merge a partial update. Omitted auth_key preserves it; "" clears it.
 * On failure *settings is unchanged. has_auth_key is read-only. */
int sb_tailscale_update(sbj **settings, const sbj *patch, sb_err *err);
/* Owned public copy, omitting auth_key and reporting has_auth_key. */
sbj *sb_tailscale_public(const sbj *settings);
/* Add the endpoint and protected routes to an initialized request. */
int sb_tailscale_render(sb_render_request *request, const sbj *settings,
                        const char *host_id, sb_err *err);

#endif
