#include "state.h"

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
