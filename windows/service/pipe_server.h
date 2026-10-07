#ifndef SB_WINDOWS_PIPE_SERVER_H
#define SB_WINDOWS_PIPE_SERVER_H
#include "controller.h"
#define SBW_DEFAULT_PIPE L"\\\\.\\pipe\\sb-easy-control-v1"
typedef struct sbw_pipe_options {
    const wchar_t *pipe_name;
    DWORD io_timeout_ms;
    unsigned worker_count;
    HANDLE ready_event;
    void (*on_ready)(void *);
    void *on_ready_context;
    sbw_controller *controller; /* borrowed for server lifetime */
} sbw_pipe_options;
void sbw_pipe_options_init(sbw_pipe_options *options);
bool sbw_valid_pipe_name(const wchar_t *name);
DWORD sbw_run_pipe_server(const sbw_pipe_options *options, HANDLE stop_event);
#endif
