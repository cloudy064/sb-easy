#include "update_transaction.h"
#include "updater.h"
#include "update_files.h"
#include "../ui-host/pipe_client.h"
#include "../ui-host/server_identity.h"
#include <msi.h>
#include <shellapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "0.6.9-dev"
#endif
#ifndef SB_EASY_CORE_VERSION
#define SB_EASY_CORE_VERSION "1.14.3"
#endif
static const wchar_t upgrade_code[] = L"{78E985E7-0CDC-4782-B1EA-52DCE6B3E544}";
static const wchar_t control_pipe[] = L"\\\\.\\pipe\\sb-easy-control-v1";
static int fail(sbw_error *error, const char *code) { return sbw_fail(error, code, "The installer transaction could not be completed safely. Check the update status and private installer log."); }
int sbw_update_registered_version(char output[32], sbw_error *error) {
    output[0] = 0; unsigned found = 0;
    for (DWORD index = 0; index < 16; ++index) {
        wchar_t product[39]; UINT result = MsiEnumRelatedProductsW(upgrade_code, 0, index, product);
        if (result == ERROR_NO_MORE_ITEMS) return found == 1 ? 0 : fail(error, "UPDATE_MSI_REQUIRED");
        if (result != ERROR_SUCCESS) return fail(error, "UPDATE_MSI_REQUIRED");
        if (MsiQueryProductStateW(product) != INSTALLSTATE_DEFAULT) continue;
        wchar_t value[32]; DWORD length = 32;
        if (MsiGetProductInfoW(product, INSTALLPROPERTY_VERSIONSTRING, value, &length) != ERROR_SUCCESS || ++found != 1)
            return fail(error, "UPDATE_MSI_REQUIRED");
        char *version = sbw_utf8(value, error); unsigned parts[3];
        bool valid = version && sbw_release_version(version, parts) && strlen(version) < 32;
        if (valid) strcpy_s(output, 32, version);
        free(version); if (!valid) return fail(error, "UPDATE_MSI_REQUIRED");
    }
    return fail(error, "UPDATE_MSI_REQUIRED");
}
static wchar_t *service_binary(sbw_error *error) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_CONFIG) : NULL;
    DWORD size = 0; QUERY_SERVICE_CONFIGW *config = NULL; LPWSTR *arguments = NULL; int count = 0; wchar_t *path = NULL;
    if (!service) goto done;
    QueryServiceConfigW(service, NULL, 0, &size); if (!size || size > 65536) goto done;
    config = sb_xcalloc(size, 1);
    if (!QueryServiceConfigW(service, config, size, &size) || config->dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        _wcsicmp(config->lpServiceStartName, L"LocalSystem")) goto done;
    wchar_t expanded[32768]; DWORD length = ExpandEnvironmentStringsW(config->lpBinaryPathName, expanded, 32768);
    if (!length || length > 32768) goto done;
    arguments = CommandLineToArgvW(expanded, &count);
    if (!arguments || count != 1 || wcslen(arguments[0]) < 4 || arguments[0][1] != L':' || arguments[0][2] != L'\\') goto done;
    const wchar_t *leaf = wcsrchr(arguments[0], L'\\');
    if (!leaf || _wcsicmp(leaf + 1, L"sb-easy-service.exe")) goto done;
    path = _wcsdup(arguments[0]);
done:
    if (arguments) LocalFree(arguments);
    free(config); if (service) CloseServiceHandle(service); if (manager) CloseServiceHandle(manager);
    if (!path) fail(error, "UPDATE_SERVICE_IDENTITY");
    return path;
}
static wchar_t *parent_path(const wchar_t *path) {
    wchar_t *directory = _wcsdup(path); wchar_t *slash = wcsrchr(directory, L'\\');
    if (!slash || slash == directory + 2) { free(directory); return NULL; }
    *slash = 0; return directory;
}
static int service_state(bool start, sbw_error *error) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_STATUS | (start ? SERVICE_START : SERVICE_STOP)) : NULL;
    if (!service) { if (manager) CloseServiceHandle(manager); return fail(error, "UPDATE_SERVICE_CONTROL"); }
    SERVICE_STATUS_PROCESS state = {0}; DWORD size = 0; bool requested = false, success = false;
    ULONGLONG deadline = GetTickCount64() + 45000;
    while (GetTickCount64() < deadline) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&state, sizeof(state), &size)) break;
        if (state.dwCurrentState == (start ? SERVICE_RUNNING : SERVICE_STOPPED)) { success = true; break; }
        if (!requested) {
            if (start && state.dwCurrentState == SERVICE_STOPPED) {
                if (!StartServiceW(service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) break;
                requested = true;
            } else if (!start && (state.dwCurrentState == SERVICE_RUNNING || state.dwCurrentState == SERVICE_PAUSED)) {
                SERVICE_STATUS ignored;
                if (!ControlService(service, SERVICE_CONTROL_STOP, &ignored) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) break;
                requested = true;
            }
        }
        Sleep(100);
    }
    CloseServiceHandle(service); CloseServiceHandle(manager); return success ? 0 : fail(error, "UPDATE_SERVICE_CONTROL");
}
static int rpc(const wchar_t *binary, const char *method, const sbj *params, DWORD timeout, sbj **result, sbw_error *error) {
    *result = NULL; sbj *request = sbj_object(); sbj_set_str(request, "id", "installer"); sbj_set_int(request, "version", 1);
    sbj_set_str(request, "method", method); sbj_set(request, "params", params ? sbj_clone(params) : sbj_object());
    char *body = sbj_dump(request, -1), *response = NULL; sbj_free(request);
    HANDLE cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    int status = cancel ? sbw_pipe_request_expected(control_pipe, binary, body, cancel, timeout, &response, error) : -1;
    if (cancel) CloseHandle(cancel);
    free(body);
    if (status) { free(response); return -1; }
    sbj *reply = sbw_json_parse(response, strlen(response), 32, NULL); free(response);
    if (!sbj_string_is(sbj_get(reply, "id"), "installer") || sbj_get_int(reply, "version", 0) != 1 ||
        !sbj_get_bool(reply, "ok", false) || !sbj_is_object(sbj_get(reply, "result"))) status = fail(error, "UPDATE_HEALTH_FAILED");
    else *result = sbj_clone(sbj_get(reply, "result"));
    sbj_free(reply); return status;
}
static int health_rpc(const wchar_t *binary, const char *expected, bool rollback, sbw_error *error) {
    ULONGLONG deadline = GetTickCount64() + 30000; sbj *hello = NULL;
    while (GetTickCount64() < deadline) {
        if (rpc(binary, "protocol.hello", NULL, 3000, &hello, error) == 0) break;
        Sleep(200);
    }
    bool matched = hello && sbj_get_int(hello, "protocol_version", 0) == 1 &&
        !strcmp(sbj_get_str(hello, "service_version", ""), expected);
    sbj_free(hello); if (!matched) return fail(error, "UPDATE_VERSION_MISMATCH");
    wchar_t *data_path = sbw_default_data_directory(false, error), *stage_path = data_path ? sbw_path_join(data_path, L"updates\\staging") : NULL;
    sbw_directory_guard *stage = stage_path ? sbw_secure_directory_open(stage_path, error) : NULL;
    sbj *job = stage ? sbw_update_read_json(stage, L"job.json", false, error) : NULL;
    const char *nonce = sbj_get_str(job, "health_nonce", "");
    if (strlen(nonce) != 64) {
        sbj_free(job); sbw_secure_directory_close(stage); free(stage_path); free(data_path); return fail(error, "UPDATE_JOB_INVALID");
    }
    sbj *params = sbj_object(), *result = NULL; sbj_set_bool(params, "rollback", rollback); sbj_set_str(params, "nonce", nonce);
    sbj_free(job); sbw_secure_directory_close(stage); free(stage_path); free(data_path);
    int status = rpc(binary, "updates.health", params, 90000, &result, error);
    if (!status && (!sbj_get_bool(result, "healthy", false) || !sbj_string_is(sbj_get(result, "version"), expected)))
        status = fail(error, "UPDATE_HEALTH_FAILED");
    sbj_free(params); sbj_free(result); return status;
}
static sbw_directory_guard *fixed_stage(wchar_t **data_path, sbw_directory_guard **root, sbw_error *error) {
    *root = NULL; *data_path = sbw_default_data_directory(false, error); if (!*data_path) return NULL;
    wchar_t *updates = sbw_path_join(*data_path, L"updates"), *stage = sbw_path_join(updates, L"staging");
    *root = sbw_secure_directory_open(updates, error);
    sbw_directory_guard *result = *root ? sbw_secure_directory_open(stage, error) : NULL;
    free(updates); free(stage); return result;
}
int sbw_update_health_check(void) {
    if (!sbw_update_is_system()) return 1;
    sbw_error error = {0}; wchar_t *directory = sbw_executable_directory(&error);
    wchar_t *expected = directory ? sbw_path_join(directory, L"sb-easy-service.exe") : NULL;
    wchar_t *registered = service_binary(&error); int result = 1;
    if (expected && registered && sbw_same_file(expected, registered)) result = health_rpc(expected, SB_EASY_VERSION, false, &error) == 0 ? 0 : 1;
    free(expected); free(registered); free(directory);
    if (result) fprintf(stderr, "%s\n", error.code[0] ? error.code : "UPDATE_HEALTH_FAILED");
    return result;
}
static int write_journal(sbw_directory_guard *stage, const sbw_release *release, const char *phase, bool state_existed,
    UINT installer_code, sbw_error *error) {
    sbj *journal = sbj_object(); sbj_set_int(journal, "schema", 1); sbj_set_str(journal, "release_id", release->id);
    sbj_set_str(journal, "phase", phase); sbj_set_bool(journal, "state_existed", state_existed);
    sbj_set_int(journal, "installer_code", installer_code);
    int result = sbw_update_write_json(stage, L"transaction.json", journal, error); sbj_free(journal); return result;
}
static int write_result(sbw_directory_guard *root, const sbw_release *release, const char *phase, UINT code,
    bool restored, const sbw_error *failure, sbw_error *error) {
    sbj *state = sbj_object(); sbj_set_int(state, "schema", 1); sbj_set_str(state, "release_id", release->id);
    sbj_set_str(state, "version", release->version); sbj_set_str(state, "phase", phase); sbj_set_int(state, "installer_code", code);
    sbj_set_bool(state, "state_restored", restored); sbj_set_bool(state, "reboot_required", code == ERROR_SUCCESS_REBOOT_REQUIRED || code == ERROR_SUCCESS_REBOOT_INITIATED);
    sbj_set_str(state, "error_code", failure ? failure->code : ""); sbj_set_int(state, "finished_at", (int64_t)time(NULL));
    int result = sbw_update_write_json(root, L"current.json", state, error); sbj_free(state); return result;
}
static bool installer_idle(void) {
    HANDLE mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, L"Global\\_MSIExecute");
    if (!mutex) return GetLastError() == ERROR_FILE_NOT_FOUND;
    DWORD waited = WaitForSingleObject(mutex, 0);
    bool idle = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
    if (idle) ReleaseMutex(mutex);
    CloseHandle(mutex); return idle;
}
static int restore_previous(sbw_directory_guard *root, sbw_directory_guard *stage, sbw_directory_guard *data,
    const sbw_release *release, const sbj *job, bool existed, UINT code, const sbw_error *original, sbw_error *error) {
    char installed[32];
    if (sbw_update_registered_version(installed, error) < 0 || strcmp(installed, sbj_get_str(job, "previous_version", "")))
        return fail(error, "UPDATE_ROLLBACK_UNCONFIRMED");
    if (service_state(false, error) < 0 || write_journal(stage, release, "restoring", existed, code, error) < 0) return -1;
    bool copied = false;
    if (existed ? sbw_update_copy(stage, L"device-state.backup", data, L"device-state.dat", 16U * 1024U * 1024U, false, &copied, error) < 0 :
        sbw_update_remove(data, L"device-state.dat", error) < 0) return -1;
    if (service_state(true, error) < 0) return -1;
    wchar_t *binary = service_binary(error);
    int result = binary ? health_rpc(binary, sbj_get_str(job, "previous_version", ""), true, error) : -1;
    free(binary);
    if (!result) result = write_result(root, release, "rolled_back", code, true, original, error);
    if (!result) result = write_journal(stage, release, "complete", existed, code, error);
    return result;
}
static int self_verified(sbw_directory_guard *stage, sbw_error *error) {
    wchar_t self[32768]; DWORD length = GetModuleFileNameW(NULL, self, 32768);
    wchar_t *expected = sbw_secure_directory_path(stage, L"update-helper.exe");
    HANDLE file = sbw_secure_directory_file(stage, L"update-helper.exe", GENERIC_READ, OPEN_EXISTING, error);
    int result = length && length < 32768 && expected && sbw_same_file(self, expected) && file != INVALID_HANDLE_VALUE ?
        sbw_release_verify_file(expected, file, SB_EASY_PUBLISHER_THUMBPRINT, true, error) : fail(error, "UPDATE_HELPER_IDENTITY");
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(expected); return result;
}
int sbw_update_launch_recovery(sbw_error *error) {
    if (!sbw_update_is_system()) return fail(error, "UPDATE_INSTALLED_SERVICE_REQUIRED");
    wchar_t *data = NULL; sbw_directory_guard *root = NULL, *stage = fixed_stage(&data, &root, error);
    HANDLE file = stage ? sbw_secure_directory_file(stage, L"update-helper.exe", GENERIC_READ, OPEN_EXISTING, error) : INVALID_HANDLE_VALUE;
    wchar_t *path = stage ? sbw_secure_directory_path(stage, L"update-helper.exe") : NULL; int result = -1;
    if (file != INVALID_HANDLE_VALUE && path && sbw_release_verify_file(path, file, SB_EASY_PUBLISHER_THUMBPRINT, true, error) == 0) {
        size_t length = wcslen(path) + 32; wchar_t *command = sb_xcalloc(length, sizeof(wchar_t));
        swprintf_s(command, length, L"\"%ls\" --recover", path);
        STARTUPINFOW startup = {0}; startup.cb = sizeof(startup); PROCESS_INFORMATION process = {0};
        if (CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &startup, &process)) {
            CloseHandle(process.hThread); CloseHandle(process.hProcess); result = 0;
        } else fail(error, "UPDATE_HELPER_FAILED");
        free(command);
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(path); free(data); sbw_secure_directory_close(stage); sbw_secure_directory_close(root); return result;
}
int sbw_update_helper_main(int argc, wchar_t **argv) {
    bool recover = argc == 2 && !wcscmp(argv[1], L"--recover");
    if ((!recover && (argc != 2 || wcscmp(argv[1], L"--apply"))) || !sbw_update_is_system()) return 2;
    /* Give the acknowledged desktop response time to close its own WebView. */
    if (!recover) Sleep(2000);
    sbw_error error = {0}, original = {0}; wchar_t *data_path = NULL, *binary = NULL, *install_directory = NULL, *package_path = NULL;
    sbw_directory_guard *root = NULL, *stage = fixed_stage(&data_path, &root, &error), *data = NULL, *installation = NULL;
    HANDLE transaction = INVALID_HANDLE_VALUE, package = INVALID_HANDLE_VALUE; sbj *job = NULL, *journal = NULL;
    sb_buf manifest = {0}, signature = {0}; sbw_release release = {0}; bool existed = false, backup = false, stopped = false, restore_attempted = false;
    int result = 1; UINT code = ERROR_INSTALL_FAILURE;
    if (!stage || self_verified(stage, &error) < 0) goto done;
    transaction = sbw_secure_directory_file(stage, L"transaction.lock", GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING, &error);
    if (transaction == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
        transaction = sbw_secure_directory_file(stage, L"transaction.lock", GENERIC_READ | GENERIC_WRITE, CREATE_NEW, &error);
    if (transaction == INVALID_HANDLE_VALUE) goto done; /* Another helper owns recovery. */
    memset(&error, 0, sizeof(error));
    job = sbw_update_read_json(stage, L"job.json", false, &error);
    if (!job || sbw_update_read(stage, L"release.json", SBW_RELEASE_MANIFEST_LIMIT, false, &manifest, &error) < 0 ||
        sbw_update_read(stage, L"release.p7s", SBW_RELEASE_SIGNATURE_LIMIT, false, &signature, &error) < 0 ||
        sbw_release_verify_manifest(manifest.p, manifest.len, signature.p, signature.len, SB_EASY_PUBLISHER_THUMBPRINT, &release, &error) < 0) goto terminal;
    if (sbj_obj_len(job) != 7 || sbj_get_int(job, "schema", 0) != 1 || !sbj_is_bool(sbj_get(job, "resume_connected")) ||
        !sbw_json_string(sbj_get(job, "health_nonce"), 64, false) || strlen(sbj_get_str(job, "health_nonce", "")) != 64 ||
        !sbj_string_is(sbj_get(job, "release_id"), release.id) || !sbj_string_is(sbj_get(job, "previous_version"), SB_EASY_VERSION) ||
        !sbj_string_is(sbj_get(job, "previous_core_version"), SB_EASY_CORE_VERSION) ||
        (!recover && ((int64_t)time(NULL) - sbj_get_int(job, "created_at", 0) < 0 ||
        (int64_t)time(NULL) - sbj_get_int(job, "created_at", 0) > 300))) { fail(&error, "UPDATE_JOB_INVALID"); goto terminal; }
    data = sbw_secure_directory_open(data_path, &error); if (!data) goto terminal;
    if (recover) {
        /* A previous helper may have died while MSI was still rolling back. */
        ULONGLONG deadline = GetTickCount64() + 600000;
        while (!installer_idle() && GetTickCount64() < deadline) Sleep(1000);
        if (!installer_idle()) { fail(&error, "UPDATE_INSTALLER_BUSY"); goto terminal; }
        journal = sbw_update_read_json(stage, L"transaction.json", true, &error);
        if ((!journal && error.code[0]) || (journal && (sbj_get_int(journal, "schema", 0) != 1 ||
            !sbj_string_is(sbj_get(journal, "release_id"), release.id)))) goto terminal;
        existed = sbj_get_bool(journal, "state_existed", false);
        const char *phase = sbj_get_str(journal, "phase", "not_started");
        backup = !strcmp(phase, "backed_up") || !strcmp(phase, "installing") || !strcmp(phase, "restoring");
        char installed[32]; if (sbw_update_registered_version(installed, &error) < 0) goto terminal;
        if (!strcmp(installed, release.version)) {
            sbj *health = sbw_update_read_json(stage, L"health.json", false, &error);
            bool checked = health && sbj_string_is(sbj_get(health, "release_id"), release.id) &&
                sbj_string_is(sbj_get(health, "version"), release.version) && sbj_get_bool(health, "healthy", false) && !sbj_get_bool(health, "rollback", true);
            sbj_free(health);
            binary = service_binary(&error);
            if (!checked || !binary || service_state(true, &error) < 0 || health_rpc(binary, release.version, false, &error) < 0) goto terminal;
            code = ERROR_SUCCESS; result = write_result(root, &release, "succeeded", code, false, NULL, &error) == 0 ? 0 : 1;
            if (!result) write_journal(stage, &release, "complete", existed, code, &error);
            goto done;
        }
        if (strcmp(installed, SB_EASY_VERSION)) { fail(&error, "UPDATE_ROLLBACK_UNCONFIRMED"); goto terminal; }
        if (backup) {
            fail(&original, "UPDATE_INTERRUPTED");
            restore_attempted = true;
            if (restore_previous(root, stage, data, &release, job, existed, code, &original, &error) == 0) goto done;
            goto terminal;
        }
        /* No durable backup means installation was never allowed to start. */
        if (strcmp(phase, "not_started") && strcmp(phase, "prepared") && strcmp(phase, "service_stopped")) { fail(&error, "UPDATE_JOURNAL_INVALID"); goto terminal; }
        binary = service_binary(&error);
        if (!binary || service_state(true, &error) < 0 || health_rpc(binary, SB_EASY_VERSION, true, &error) < 0) goto terminal;
        fail(&original, "UPDATE_INTERRUPTED"); write_result(root, &release, "failed", code, false, &original, &error); goto done;
    }
    char installed[32];
    if (sbw_update_registered_version(installed, &error) < 0 || strcmp(installed, SB_EASY_VERSION) ||
        sbw_release_compare(release.version, installed) <= 0 || sbw_release_compare(installed, release.minimum_app_version) < 0) {
        fail(&error, "UPDATE_VERSION_MISMATCH"); goto terminal;
    }
    binary = service_binary(&error); install_directory = binary ? parent_path(binary) : NULL;
    installation = install_directory ? sbw_secure_directory_open_readonly(install_directory, &error) : NULL;
    HANDLE service_file = installation ? sbw_secure_directory_file(installation, L"sb-easy-service.exe", GENERIC_READ, OPEN_EXISTING, &error) : INVALID_HANDLE_VALUE;
    bool service_trusted = service_file != INVALID_HANDLE_VALUE && sbw_release_verify_file(binary, service_file, SB_EASY_PUBLISHER_THUMBPRINT, true, &error) == 0;
    if (service_file != INVALID_HANDLE_VALUE) CloseHandle(service_file);
    sbw_secure_directory_close(installation); installation = NULL;
    if (!service_trusted) goto terminal;
    package = sbw_secure_directory_file(stage, L"package.msi", GENERIC_READ, OPEN_EXISTING, &error);
    package_path = sbw_secure_directory_path(stage, L"package.msi");
    if (package == INVALID_HANDLE_VALUE || sbw_release_verify_installer(package_path, package, SB_EASY_PUBLISHER_THUMBPRINT, &release, &error) < 0) goto terminal;
    if (write_journal(stage, &release, "prepared", false, code, &error) < 0 || sbw_update_remove(stage, L"health.json", &error) < 0 ||
        service_state(false, &error) < 0) goto terminal;
    stopped = true;
    if (write_journal(stage, &release, "service_stopped", false, code, &error) < 0 ||
        sbw_update_copy(data, L"device-state.dat", stage, L"device-state.backup", 16U * 1024U * 1024U, true, &existed, &error) < 0) goto terminal;
    if (!existed && sbw_update_remove(stage, L"device-state.backup", &error) < 0) goto terminal;
    if (write_journal(stage, &release, "backed_up", existed, code, &error) < 0) goto terminal;
    backup = true;
    wchar_t *log = sbw_secure_directory_path(stage, L"installer.log");
    if (sbw_update_remove(stage, L"installer.log", &error) < 0) { free(log); goto terminal; }
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    if (MsiEnableLogW(INSTALLLOGMODE_FATALEXIT | INSTALLLOGMODE_ERROR | INSTALLLOGMODE_WARNING | INSTALLLOGMODE_ACTIONSTART | INSTALLLOGMODE_INFO,
        log, INSTALLLOGATTRIBUTES_FLUSHEACHLINE) != ERROR_SUCCESS) { free(log); fail(&error, "UPDATE_LOG_FAILED"); goto terminal; }
    free(log);
    if (write_journal(stage, &release, "installing", existed, code, &error) < 0) goto terminal;
    size_t count = wcslen(install_directory) + 128; wchar_t *properties = sb_xcalloc(count, sizeof(wchar_t));
    swprintf_s(properties, count, L"REBOOT=ReallySuppress SB_EASY_UPDATE=1 INSTALLFOLDER=\"%ls\"", install_directory);
    code = MsiInstallProductW(package_path, properties); free(properties); MsiEnableLogW(0, NULL, 0);
    if (code == ERROR_SUCCESS || code == ERROR_SUCCESS_REBOOT_REQUIRED || code == ERROR_SUCCESS_REBOOT_INITIATED) {
        char active[32]; sbj *health = sbw_update_read_json(stage, L"health.json", false, &error);
        bool healthy = health && sbj_string_is(sbj_get(health, "release_id"), release.id) &&
            sbj_string_is(sbj_get(health, "version"), release.version) && sbj_string_is(sbj_get(health, "core_version"), release.core_version) &&
            sbj_get_bool(health, "healthy", false) && !sbj_get_bool(health, "rollback", true);
        sbj_free(health);
        if (!healthy || sbw_update_registered_version(active, &error) < 0 || strcmp(active, release.version)) { fail(&error, "UPDATE_HEALTH_UNCONFIRMED"); goto terminal; }
        if (write_result(root, &release, "succeeded", code, false, NULL, &error) < 0) goto terminal;
        write_journal(stage, &release, "complete", existed, code, &error); result = 0; goto done;
    }
    fail(&original, "UPDATE_INSTALLER_FAILED");
    restore_attempted = true;
    if (restore_previous(root, stage, data, &release, job, existed, code, &original, &error) == 0) goto done;
terminal:
    if (backup && !restore_attempted && data && job) {
        original = error;
        if (restore_previous(root, stage, data, &release, job, existed, code, &original, &error) == 0) goto done;
    }
    if (!release.id[0] && root) {
        sbj *prior = sbw_update_read_json(root, L"current.json", true, NULL);
        const char *id = sbj_get_str(prior, "release_id", ""), *version = sbj_get_str(prior, "version", ""); unsigned parts[3];
        bool valid = strlen(id) == 64 && sbw_release_version(version, parts);
        for (size_t i = 0; valid && i < 64; ++i) if (!strchr("0123456789abcdef", id[i])) valid = false;
        if (valid) { strcpy_s(release.id, sizeof(release.id), id); strcpy_s(release.version, sizeof(release.version), version); }
        sbj_free(prior);
    }
    if (release.id[0]) {
        sbw_error saved_error = error, ignored = {0};
        if (stopped && !backup && binary) { service_state(true, &ignored); health_rpc(binary, SB_EASY_VERSION, true, &ignored); }
        write_result(root, &release, backup || recover ? "recovery_required" : "failed", code, false, &saved_error, &ignored);
    }
done:
    if (package != INVALID_HANDLE_VALUE) CloseHandle(package);
    if (transaction != INVALID_HANDLE_VALUE) CloseHandle(transaction);
    sbj_free(job); sbj_free(journal); sb_buf_free(&manifest); sb_buf_free(&signature);
    sbw_secure_directory_close(installation); sbw_secure_directory_close(data); sbw_secure_directory_close(stage); sbw_secure_directory_close(root);
    free(data_path); free(binary); free(install_directory); free(package_path); return result;
}
