#ifndef SBW_CORE_PROCESS_H
#define SBW_CORE_PROCESS_H

#include "../common.h"
#include <stdbool.h>
#include <stddef.h>
#include <windows.h>

typedef struct sbw_core sbw_core;

typedef struct sbw_core_options {
    const wchar_t *executable;     /* fixed, absolute local .exe; copied and pinned */
    const wchar_t *work_directory; /* dedicated absolute local directory; copied */
    DWORD check_timeout_ms;        /* 0 => 15000; maximum 60000 */
    DWORD stop_timeout_ms;         /* 0 => 2000; maximum 10000 */
} sbw_core_options;

typedef struct sbw_core_status {
    bool process_running; /* process existence only, never a VPN health claim */
    DWORD process_id;
    bool has_exit_code;
    DWORD exit_code;
    bool last_stop_forced; /* Job termination was needed; OS routing cleanup is not proven. */
} sbw_core_status;

sbw_core *sbw_core_new(const sbw_core_options *options, sbw_error *error);
/* Call after all users have finished; closes the kill-on-close Job Object. */
void sbw_core_free(sbw_core *core);

/* Read-only prerequisite check. The pinned sing-box embeds Wintun; has_tun
 * additionally requires an enabled administrator SID and elevated process token. */
int sbw_core_preflight(sbw_core *core, bool has_tun, sbw_error *error);
/* Call first from the hosting executable's wmain. Returns -1 for ordinary
 * arguments, otherwise the private console-signal helper's exit status. */
int sbw_core_signal_helper(int argc, wchar_t **argv);

/* Runs the pinned executable's check -c PATH with a private temporary config.
 * Success does not start a core or change process_running. Optional exit_code
 * is MAXDWORD until an actual process exit has been observed. */
int sbw_core_config_check(sbw_core *core, const char *json, size_t length, HANDLE cancel,
                          DWORD *exit_code, sbw_error *error);
/* Checks these exact bytes first, reusing a successful config_check only for
 * identical bytes. The cached check is consumed by this attempt. No shell,
 * PATH search, or extra args. */
int sbw_core_start(sbw_core *core, const char *json, size_t length, HANDLE cancel, sbw_error *error);
int sbw_core_stop(sbw_core *core, sbw_error *error);
int sbw_core_poll(sbw_core *core, sbw_core_status *status, sbw_error *error);

/* Concurrent operations fail with CORE_BUSY instead of waiting without a bound.
 * Remote health checks, configuration activation, rollback, and routing cleanup
 * belong to the controller; this adapter provides none of those guarantees. */
#endif
