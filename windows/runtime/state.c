#include "state.h"
#include <string.h>

void sb_windows_recovery_request(sb_windows_recovery *recovery, bool connect, uint64_t now_ms) {
    memset(recovery, 0, sizeof *recovery);
    recovery->desired_connected = connect;
    recovery->retry_at_ms = now_ms;
}
void sb_windows_recovery_failed(sb_windows_recovery *recovery, uint64_t now_ms) {
    if (!recovery->desired_connected) return;
    /* 2, 4, 8, 16, 32, 60 seconds; sustained health resets flapping history. */
    unsigned shift = recovery->attempts < 5 ? recovery->attempts : 5;
    uint64_t delay = (uint64_t)2000 << shift;
    if (delay > 60000) delay = 60000;
    if (recovery->attempts < 1000000) ++recovery->attempts;
    recovery->retry_at_ms = now_ms + delay;
    recovery->healthy_since_ms = 0;
}
void sb_windows_recovery_healthy(sb_windows_recovery *recovery, uint64_t now_ms) {
    if (!recovery->healthy_since_ms) recovery->healthy_since_ms = now_ms;
    if (now_ms - recovery->healthy_since_ms >= 60000) recovery->attempts = 0;
    recovery->retry_at_ms = 0;
}
bool sb_windows_recovery_due(const sb_windows_recovery *recovery, uint64_t now_ms) {
    return recovery->desired_connected && recovery->retry_at_ms && now_ms >= recovery->retry_at_ms;
}

void sb_windows_runtime_init(sb_windows_runtime_state *state) {
    if (!state) return;
    state->phase = SB_WINDOWS_UNENROLLED;
    state->enrolled = false;
    state->core_running = false;
}

bool sb_windows_runtime_apply(sb_windows_runtime_state *state, sb_windows_event event) {
    if (!state) return false;
    sb_windows_runtime_state next = *state;
    switch (event) {
    case SB_WINDOWS_ENROLL:
        if (state->phase != SB_WINDOWS_UNENROLLED) return false;
        next.enrolled = true;
        next.phase = SB_WINDOWS_STOPPED;
        break;
    case SB_WINDOWS_FORGET:
        if (state->phase != SB_WINDOWS_STOPPED && state->phase != SB_WINDOWS_UNENROLLED)
            return false;
        sb_windows_runtime_init(&next);
        break;
    case SB_WINDOWS_START:
        if (!state->enrolled || (state->phase != SB_WINDOWS_STOPPED &&
                                state->phase != SB_WINDOWS_DEGRADED)) return false;
        next.phase = SB_WINDOWS_STARTING;
        next.core_running = false;
        break;
    case SB_WINDOWS_CORE_HEALTHY:
        if (state->phase != SB_WINDOWS_STARTING) return false;
        next.phase = SB_WINDOWS_RUNNING;
        next.core_running = true;
        break;
    case SB_WINDOWS_STOP:
        if (!state->enrolled) return false;
        next.phase = SB_WINDOWS_STOPPED;
        next.core_running = false;
        break;
    case SB_WINDOWS_CONFIG_FAILED:
        if (state->phase != SB_WINDOWS_RUNNING) return false;
        next.phase = SB_WINDOWS_ROLLING_BACK;
        next.core_running = false;
        break;
    case SB_WINDOWS_ROLLBACK_SUCCEEDED:
        if (state->phase != SB_WINDOWS_ROLLING_BACK) return false;
        next.phase = SB_WINDOWS_RUNNING;
        next.core_running = true;
        break;
    case SB_WINDOWS_CORE_FAILED:
        if (state->phase != SB_WINDOWS_STARTING && state->phase != SB_WINDOWS_RUNNING &&
            state->phase != SB_WINDOWS_ROLLING_BACK) return false;
        next.phase = SB_WINDOWS_DEGRADED;
        next.core_running = false;
        break;
    default:
        return false;
    }
    *state = next;
    return true;
}

const char *sb_windows_phase_name(sb_windows_phase phase) {
    switch (phase) {
    case SB_WINDOWS_UNENROLLED: return "UNENROLLED";
    case SB_WINDOWS_STOPPED: return "STOPPED";
    case SB_WINDOWS_STARTING: return "STARTING";
    case SB_WINDOWS_RUNNING: return "RUNNING";
    case SB_WINDOWS_ROLLING_BACK: return "ROLLING_BACK";
    case SB_WINDOWS_DEGRADED: return "DEGRADED";
    default: return "UNKNOWN";
    }
}
