#ifndef SBW_DIAGNOSTICS_H
#define SBW_DIAGNOSTICS_H
#include "../common.h"
typedef struct sbw_diagnostics sbw_diagnostics;
typedef struct sbw_log_stream sbw_log_stream;
/* The caller has already secured and pinned this directory. */
sbw_diagnostics *sbw_diagnostics_new(const wchar_t *directory);
void sbw_diagnostics_free(sbw_diagnostics *log);
void sbw_diagnostics_event(sbw_diagnostics *log, const char *event, const char *result);
/* Takes ownership of reader, including on failure. Never writes raw core text. */
sbw_log_stream *sbw_diagnostics_capture(sbw_diagnostics *log, HANDLE reader, const char *config);
void sbw_diagnostics_finish(sbw_log_stream *stream);
char *sbw_diagnostics_redact(const char *line, const sbj *config);
#endif
