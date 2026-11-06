#ifndef SBW_TRAY_BRIDGE_H
#define SBW_TRAY_BRIDGE_H
#include "../common.h"

/* Parse only the versioned browser RPC contract and explicit operation list.
 * Returned JSON and URL are owned by the caller. No service calls occur here. */
sbj *sbw_tray_request(const char *body, size_t length, sbw_error *error);
wchar_t *sbw_tray_browser_url(unsigned short port, const char *token, sbw_error *error);
bool sbw_tray_arguments(int count, const wchar_t *const *arguments, bool *background);
#endif
