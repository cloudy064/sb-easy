#ifndef SBW_EXTENSIONS_H
#define SBW_EXTENSIONS_H
#include "capture.h"
wchar_t *sbw_extension_path(const wchar_t *relative);
bool sbw_extension_enabled(void);
bool sbw_extension_is_enabled(const char *id);
bool sbw_extension_installed(const char *id);
bool sbw_extension_present(const char *id);
sbj *sbw_extensions_snapshot(sbw_capture *capture,bool statistics_running,bool statistics_failed);
int sbw_extension_change(const char *id,const char *action, sbw_error *error);
bool sbw_capture_worker_running(sbw_capture *capture);
sbj *sbw_capture_worker_validate(sbw_capture *capture, const sbj *config, sbw_error *error);
#endif
