#include "../service/core_process.h"
#include "../service/updater.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int wmain(int argc, wchar_t **argv) {
    assert(argc == 2); sbw_error error = {0};
    sbw_updater *updater = sbw_updater_new(NULL, NULL, false, &error); assert(updater);
    sbj *status = sbw_updater_status(updater); assert(!sbj_get_bool(status, "supported", true) && !sbj_get_bool(status, "installed_service", true));
    assert(sbj_string_is(sbj_get(status, "phase"), "unavailable")); sbj_free(status);
    assert(sbw_updater_check(updater, "https://invalid.example/release.json", &error) < 0);
    assert(sbw_updater_download(updater, "arbitrary", &error) < 0);
    assert(sbw_updater_install(updater, "arbitrary", true, &error) < 0);
    assert(sbw_updater_cancel(updater, &error) < 0 && !sbw_updater_installing(updater)); sbw_updater_free(updater);
    wchar_t temporary[MAX_PATH], name[96]; assert(GetTempPathW(MAX_PATH, temporary));
    swprintf_s(name, 96, L"sbeasy-version-%lu-%llu", GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    wchar_t *directory = sbw_path_join(temporary, name); sbw_core_options options = {argv[1], directory, 3000, 2000};
    sbw_core *core = sbw_core_new(&options, &error); assert(core);
    assert(sbw_core_version_check(core, "1.14.3", NULL, &error) == 0);
    memset(&error, 0, sizeof(error)); assert(sbw_core_version_check(core, "1.14.4", NULL, &error) < 0 && !strcmp(error.code, "CORE_VERSION_MISMATCH"));
    HANDLE cancel = CreateEventW(NULL, TRUE, TRUE, NULL); assert(cancel);
    assert(sbw_core_version_check(core, "1.14.3", cancel, &error) < 0 && !strcmp(error.code, "CORE_CANCELLED")); CloseHandle(cancel);
    sbw_core_status process = {0}; assert(sbw_core_poll(core, &process, &error) == 0 && !process.process_running);
    sbw_core_free(core);
    wchar_t *file = sbw_path_join(directory, L"state.lock"); DeleteFileW(file); free(file);
    /* Diagnostics can contain fixture process metadata; remove only this test's
     * known regular files, never recurse through external paths. */
    const wchar_t *logs[] = {L"service-events.log", L"core.log", L"core.log.1", L"diagnostics.log"};
    for (size_t i = 0; i < sizeof(logs) / sizeof(logs[0]); ++i) { file = sbw_path_join(directory, logs[i]); DeleteFileW(file); free(file); }
    RemoveDirectoryW(directory); free(directory); puts("Windows updater availability and actual core-version tests passed"); return 0;
}
