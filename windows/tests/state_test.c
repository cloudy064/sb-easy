#include "../runtime/state.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 1; \
} } while (0)

int main(void) {
    sb_windows_runtime_state state;
    sb_windows_runtime_init(&state);
    CHECK(state.phase == SB_WINDOWS_UNENROLLED && !state.enrolled && !state.core_running);
    CHECK(!sb_windows_runtime_apply(&state, SB_WINDOWS_START));
    CHECK(!sb_windows_runtime_apply(&state, SB_WINDOWS_CORE_HEALTHY));
    CHECK(state.phase == SB_WINDOWS_UNENROLLED && !state.enrolled);
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_ENROLL));
    CHECK(state.phase == SB_WINDOWS_STOPPED && state.enrolled && !state.core_running);
    CHECK(!sb_windows_runtime_apply(&state, SB_WINDOWS_ENROLL));
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_START));
    CHECK(state.phase == SB_WINDOWS_STARTING && !state.core_running);
    CHECK(!sb_windows_runtime_apply(&state, SB_WINDOWS_FORGET));
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_CORE_HEALTHY));
    CHECK(state.phase == SB_WINDOWS_RUNNING && state.core_running);
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_CONFIG_FAILED));
    CHECK(state.phase == SB_WINDOWS_ROLLING_BACK && !state.core_running);
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_ROLLBACK_SUCCEEDED));
    CHECK(state.phase == SB_WINDOWS_RUNNING && state.core_running);
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_CORE_FAILED));
    CHECK(state.phase == SB_WINDOWS_DEGRADED && !state.core_running);
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_START));
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_CORE_FAILED));
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_STOP));
    CHECK(sb_windows_runtime_apply(&state, SB_WINDOWS_FORGET));
    CHECK(state.phase == SB_WINDOWS_UNENROLLED && !state.enrolled && !state.core_running);
    CHECK(strcmp(sb_windows_phase_name(state.phase), "UNENROLLED") == 0);
    CHECK(!sb_windows_runtime_apply(&state, (sb_windows_event)999));
    CHECK(!sb_windows_runtime_apply(NULL, SB_WINDOWS_START));
    puts("Portable runtime state tests passed.");
    return 0;
}
