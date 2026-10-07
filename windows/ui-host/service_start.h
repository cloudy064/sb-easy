#ifndef SBW_SERVICE_START_H
#define SBW_SERVICE_START_H
#include "../common.h"

typedef struct sbw_service_start_options {
    const wchar_t *pipe_name;
    const wchar_t *binary;
    /* NULL uses the existing current-user console data directory. */
    const wchar_t *data_directory;
    bool use_scm;
} sbw_service_start_options;

/* Ensure a trusted backend is available before a read-only request. Never
 * replays requests or installs an elevated service. A newly started portable
 * backend outlives the UI; *started_pid is zero when reusing an existing one. */
int sbw_service_ensure(const sbw_service_start_options *options, HANDLE cancel,
                       DWORD timeout_ms, DWORD *started_pid, sbw_error *error);
#endif
