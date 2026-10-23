#ifndef SB_WINDOWS_RUNTIME_STATE_H
#define SB_WINDOWS_RUNTIME_STATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sb_windows_phase {
    SB_WINDOWS_UNENROLLED,
    SB_WINDOWS_STOPPED,
    SB_WINDOWS_STARTING,
    SB_WINDOWS_RUNNING,
    SB_WINDOWS_ROLLING_BACK,
    SB_WINDOWS_DEGRADED
} sb_windows_phase;

typedef enum sb_windows_event {
    SB_WINDOWS_ENROLL,
    SB_WINDOWS_FORGET,
    SB_WINDOWS_START,
    SB_WINDOWS_CORE_HEALTHY,
    SB_WINDOWS_STOP,
    SB_WINDOWS_CONFIG_FAILED,
    SB_WINDOWS_ROLLBACK_SUCCEEDED,
    SB_WINDOWS_CORE_FAILED
} sb_windows_event;

/* Pure orchestration state: no credentials, handles, POSIX types or I/O. */
typedef struct sb_windows_runtime_state {
    sb_windows_phase phase;
    bool enrolled;
    bool core_running;
} sb_windows_runtime_state;

void sb_windows_runtime_init(sb_windows_runtime_state *state);
/* Invalid transitions return false and leave state unchanged. */
bool sb_windows_runtime_apply(sb_windows_runtime_state *state, sb_windows_event event);
const char *sb_windows_phase_name(sb_windows_phase phase);

/* Retry scheduling is independent of the clock and platform. A manual stop
 * disables recovery; callers persist that intent separately from core state. */
typedef struct sb_windows_recovery {
    bool desired_connected;
    unsigned attempts;
    uint64_t retry_at_ms, healthy_since_ms;
} sb_windows_recovery;
void sb_windows_recovery_request(sb_windows_recovery *recovery, bool connect, uint64_t now_ms);
void sb_windows_recovery_failed(sb_windows_recovery *recovery, uint64_t now_ms);
void sb_windows_recovery_healthy(sb_windows_recovery *recovery, uint64_t now_ms);
bool sb_windows_recovery_due(const sb_windows_recovery *recovery, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
