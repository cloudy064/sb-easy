/* Owns a sing-box runtime and its validated atomic config (C++
 * singbox_supervisor.hpp). Normal builds use a supervised child process;
 * SB_EASY_EMBED_SINGBOX builds run the engine in-process via the Go bridge. */
#ifndef SB_SINGBOX_SUPERVISOR_H
#define SB_SINGBOX_SUPERVISOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *binary;          /* default "sing-box" (copied) */
    const char *config_path;     /* default "data/sing-box.gen.json" (copied) */
    bool validate_config;        /* default true */
    int64_t restart_backoff_ms;  /* default 1000 */
    int64_t shutdown_timeout_ms; /* default 2000 */
} sb_singbox_supervisor_options;

void sb_singbox_supervisor_options_init(sb_singbox_supervisor_options *o);

typedef struct sb_singbox_supervisor sb_singbox_supervisor;

/* SB_ERR_VALIDATION on an empty binary, a config path naming no file or
 * negative durations. */
sb_singbox_supervisor *sb_singbox_supervisor_new(const sb_singbox_supervisor_options *options,
                                                 sb_err *err);
/* Stops the runtime, then releases the supervisor. */
void sb_singbox_supervisor_free(sb_singbox_supervisor *s);

/* Validate and atomically install a config, then SIGHUP a live child or
 * start a new child. */
int sb_singbox_supervisor_apply_config(sb_singbox_supervisor *s, const char *contents,
                                       size_t len, sb_err *err);
/* Reap an exited child and respawn it after the configured crash backoff.
 * Failures are recorded in last_error. */
void sb_singbox_supervisor_ensure_alive(sb_singbox_supervisor *s);
int sb_singbox_supervisor_reload(sb_singbox_supervisor *s, sb_err *err);
int sb_singbox_supervisor_restart(sb_singbox_supervisor *s, sb_err *err);
void sb_singbox_supervisor_stop(sb_singbox_supervisor *s);

bool sb_singbox_supervisor_running(sb_singbox_supervisor *s);
/* Child pid (getpid() for the embedded runtime), or -1 when not running. */
pid_t sb_singbox_supervisor_pid(sb_singbox_supervisor *s);
/* Borrowed; NULL when there is no error. Valid until the next call. */
const char *sb_singbox_supervisor_last_error(const sb_singbox_supervisor *s);

#ifdef __cplusplus
}
#endif

#endif
