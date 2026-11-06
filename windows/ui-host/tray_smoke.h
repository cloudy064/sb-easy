#ifndef SBW_TRAY_SMOKE_H
#define SBW_TRAY_SMOKE_H
#include "local_web.h"
/* Read-only transport check for an explicitly isolated pipe, never production. */
int sbw_tray_smoke(sbw_local_web *web, const wchar_t *receipt, bool offline);
#endif
