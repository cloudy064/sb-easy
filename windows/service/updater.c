#include "updater.h"
#include "control_plane.h"
#include "update_files.h"
#include "update_transaction.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "0.6.9-dev"
#endif
#ifndef SB_EASY_CORE_VERSION
#define SB_EASY_CORE_VERSION "1.14.3"
#endif

struct sbw_updater {
    CRITICAL_SECTION mutex;
    HANDLE worker, cancel;
    sbw_directory_guard *root, *stage, *installed;
    wchar_t *data_directory;
    bool supported, installed_service, busy, downloading;
    unsigned cohort;
    char phase[32], current[32];
    char *manifest_url;
    sb_buf manifest, signature;
    sbw_release release;
    uint64_t received;
    sbw_error error;
    sbj *last_result;
};
static int unavailable(sbw_updater *updater, sbw_error *error) {
    if (updater && updater->error.code[0]) { if (error) *error = updater->error; return -1; }
    return sbw_fail(error, "UPDATE_UNAVAILABLE", "Updates require a signed release installed as the Windows service.");
}
static void set_phase(sbw_updater *updater, const char *phase, const sbw_error *error) {
    EnterCriticalSection(&updater->mutex);
    strcpy_s(updater->phase, sizeof(updater->phase), phase);
    memset(&updater->error, 0, sizeof(updater->error)); if (error) updater->error = *error;
    LeaveCriticalSection(&updater->mutex);
}
static bool id_valid(const char *id) {
    if (!id || strlen(id) != 64) return false;
    for (size_t i = 0; i < 64; ++i) if (!strchr("0123456789abcdef", id[i])) return false;
    return true;
}
static bool verified_service_process(void) {
    if (!sbw_update_is_system()) return false;
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_STATUS) : NULL;
    SERVICE_STATUS_PROCESS status = {0}; DWORD bytes = 0;
    bool valid = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &bytes) &&
        status.dwProcessId == GetCurrentProcessId() && status.dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
        (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING);
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    return valid;
}
static int cohort_load(sbw_updater *updater, sbw_error *error) {
    sbj *saved = sbw_update_read_json(updater->root, L"cohort.json", true, error);
    if (!saved && error->code[0]) return -1;
    if (saved) {
        int64_t value = sbj_get_int(saved, "cohort", -1);
        bool valid = sbj_obj_len(saved) == 2 && sbj_get_int(saved, "schema", 0) == 1 && value >= 0 && value < 100;
        sbj_free(saved); if (!valid) return sbw_fail(error, "UPDATE_STORAGE_FAILED", "The persisted update rollout group is invalid.");
        updater->cohort = (unsigned)value; return 0;
    }
    BYTE random = 255;
    do { if (BCryptGenRandom(NULL, &random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return sbw_fail(error, "UPDATE_STORAGE_FAILED", "The update rollout group could not be initialized."); } while (random >= 200);
    updater->cohort = random % 100;
    saved = sbj_object(); sbj_set_int(saved, "schema", 1); sbj_set_int(saved, "cohort", updater->cohort);
    int result = sbw_update_write_json(updater->root, L"cohort.json", saved, error); sbj_free(saved); return result;
}
static bool persisted_phase(const char *phase) {
    return !strcmp(phase, "installing") || !strcmp(phase, "succeeded") || !strcmp(phase, "rolled_back") ||
        !strcmp(phase, "failed") || !strcmp(phase, "recovery_required");
}
static void refresh_result_locked(sbw_updater *updater) {
    if (!updater->root || updater->busy) return;
    sbw_error error = {0}; sbj *saved = sbw_update_read_json(updater->root, L"current.json", true, &error);
    if (!saved) return;
    const char *phase = sbj_get_str(saved, "phase", "");
    if (sbj_get_int(saved, "schema", 0) != 1 || !persisted_phase(phase) || !id_valid(sbj_get_str(saved, "release_id", ""))) {
        sbj_free(saved); return;
    }
    sbj_free(updater->last_result); updater->last_result = sbj_object();
    sbj_set_str(updater->last_result, "phase", phase);
    sbj_set_str(updater->last_result, "version", sbj_get_str(saved, "version", ""));
    sbj_set_int(updater->last_result, "installer_code", sbj_get_int(saved, "installer_code", 0));
    sbj_set_bool(updater->last_result, "reboot_required", sbj_get_bool(saved, "reboot_required", false));
    sbj_set_bool(updater->last_result, "state_restored", sbj_get_bool(saved, "state_restored", false));
    sbj_set_str(updater->last_result, "error_code", sbj_get_str(saved, "error_code", ""));
    if (!strcmp(updater->phase, "installing") || !strcmp(updater->phase, "idle")) strcpy_s(updater->phase, sizeof(updater->phase), phase);
    sbj_free(saved);
}
sbw_updater *sbw_updater_new(const wchar_t *install_directory, const wchar_t *data_directory, bool installed_service, sbw_error *error) {
    sbw_updater *updater = sb_xcalloc(1, sizeof(*updater)); InitializeCriticalSection(&updater->mutex);
    strcpy_s(updater->phase, sizeof(updater->phase), "unavailable");
    strcpy_s(updater->current, sizeof(updater->current), SB_EASY_VERSION);
    char *suffix = strchr(updater->current, '-'); if (suffix) *suffix = 0;
    updater->installed_service = installed_service && verified_service_process();
    if (strlen(SB_EASY_PUBLISHER_THUMBPRINT) != 40)
        sbw_fail(&updater->error, "UPDATE_PUBLISHER_UNCONFIGURED", "This build has no trusted release publisher configured.");
    else if (!updater->installed_service || !install_directory || !data_directory)
        sbw_fail(&updater->error, "UPDATE_INSTALLED_SERVICE_REQUIRED", "Install this signed release with its MSI before using updates.");
    else {
        wchar_t *root = sbw_path_join(data_directory, L"updates"), *stage = sbw_path_join(root, L"staging");
        updater->root = sbw_secure_directory_open(root, &updater->error);
        updater->stage = updater->root ? sbw_secure_directory_open(stage, &updater->error) : NULL;
        /* The installation is verified through SCM and its signed helper below.
         * Opening this guard also rejects reparse-point parents. */
        updater->installed = updater->stage ? sbw_secure_directory_open_readonly(install_directory, &updater->error) : NULL;
        free(root); free(stage);
        updater->cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
        updater->data_directory = _wcsdup(data_directory);
        if (updater->installed && updater->cancel && cohort_load(updater, &updater->error) == 0) {
            updater->supported = true; strcpy_s(updater->phase, sizeof(updater->phase), "idle"); refresh_result_locked(updater);
            if (!strcmp(updater->phase, "installing")) {
                sbw_error recovery = {0};
                if (sbw_update_launch_recovery(&recovery) < 0) { updater->error = recovery; strcpy_s(updater->phase, sizeof(updater->phase), "recovery_required"); }
            }
        } else if (!updater->error.code[0]) sbw_fail(&updater->error, "UPDATE_STORAGE_FAILED", "The private updater could not be initialized.");
    }
    if (error) *error = updater->error;
    return updater;
}
void sbw_updater_free(sbw_updater *updater) {
    if (!updater) return;
    if (updater->cancel) SetEvent(updater->cancel);
    if (updater->worker) { WaitForSingleObject(updater->worker, INFINITE); CloseHandle(updater->worker); }
    if (updater->cancel) CloseHandle(updater->cancel);
    sbw_secure_directory_close(updater->stage); sbw_secure_directory_close(updater->root); sbw_secure_directory_close(updater->installed);
    free(updater->data_directory); free(updater->manifest_url); sb_buf_free(&updater->manifest); sb_buf_free(&updater->signature);
    sbj_free(updater->last_result); DeleteCriticalSection(&updater->mutex); free(updater);
}
sbj *sbw_updater_status(sbw_updater *updater) {
    sbj *status = sbj_object();
    sbj_set_bool(status, "publisher_configured", strlen(SB_EASY_PUBLISHER_THUMBPRINT) == 40);
    sbj_set_str(status, "current_version", SB_EASY_VERSION); sbj_set_str(status, "current_core_version", SB_EASY_CORE_VERSION);
    sbj_set_bool(status, "busy", false); sbj_set_bool(status, "cancellable", false); sbj_set_int(status, "received_bytes", 0);
    if (!updater) { sbj_set_bool(status, "supported", false); sbj_set_bool(status, "installed_service", false); sbj_set_str(status, "phase", "unavailable"); return status; }
    EnterCriticalSection(&updater->mutex); refresh_result_locked(updater);
    sbj_set_bool(status, "supported", updater->supported); sbj_set_bool(status, "installed_service", updater->installed_service);
    sbj_set_bool(status, "busy", updater->busy); sbj_set_str(status, "phase", updater->phase);
    sbj_set_bool(status, "cancellable", updater->busy && (!strcmp(updater->phase, "checking") || !strcmp(updater->phase, "downloading")));
    sbj_set_int(status, "received_bytes", (int64_t)updater->received);
    if (updater->release.id[0]) {
        sbj *release = sbj_object(); sbj_set_str(release, "id", updater->release.id);
        sbj_set_str(release, "version", updater->release.version); sbj_set_str(release, "core_version", updater->release.core_version);
        sbj_set_str(release, "channel", "stable"); sbj_set_int(release, "bytes", (int64_t)updater->release.bytes);
        sbj_set_int(release, "rollout_percent", updater->release.rollout_percent); sbj_set(status, "release", release);
    }
    if (updater->error.code[0]) {
        sbj *failure = sbj_object(); sbj_set_str(failure, "code", updater->error.code); sbj_set_str(failure, "message", updater->error.message);
        sbj_set(status, "error", failure);
    }
    if (updater->last_result) sbj_set(status, "last_result", sbj_clone(updater->last_result));
    LeaveCriticalSection(&updater->mutex); return status;
}
static int memory_sink(void *context, const void *data, size_t length, sbw_error *error) {
    (void)error; sb_buf_append(context, data, length); return 0;
}
static char *artifact_url(const char *manifest, const char *name) {
    const char *slash = strrchr(manifest, '/'); if (!slash) return NULL;
    sb_buf result = {0}; sb_buf_append(&result, manifest, (size_t)(slash - manifest) + 1); sb_buf_puts(&result, name); return sb_buf_detach(&result);
}
typedef struct file_sink_state { sbw_updater *updater; HANDLE file; } file_sink_state;
static int file_sink(void *context, const void *data, size_t length, sbw_error *error) {
    file_sink_state *state = context; DWORD written = 0;
    if (length > MAXDWORD || !WriteFile(state->file, data, (DWORD)length, &written, NULL) || written != length)
        return sbw_fail(error, "UPDATE_STORAGE_FAILED", "The installer could not be saved to its private staging directory.");
    EnterCriticalSection(&state->updater->mutex); state->updater->received += length; LeaveCriticalSection(&state->updater->mutex);
    return 0;
}
static int check_release(sbw_updater *updater, sbw_error *error) {
    sb_buf manifest = {0}, signature = {0}; uint64_t received = 0; sbw_release release = {0};
    sb_buf signature_url = {0}; sb_buf_puts(&signature_url, updater->manifest_url); sb_buf_puts(&signature_url, ".p7s");
    int result = sbw_https_download(updater->manifest_url, SBW_RELEASE_MANIFEST_LIMIT, 20000, updater->cancel, memory_sink, &manifest, &received, error);
    if (!result) result = sbw_https_download(signature_url.p, SBW_RELEASE_SIGNATURE_LIMIT, 20000, updater->cancel, memory_sink, &signature, &received, error);
    if (!result) result = sbw_release_verify_manifest(manifest.p, manifest.len, signature.p, signature.len, SB_EASY_PUBLISHER_THUMBPRINT, &release, error);
    if (!result && WaitForSingleObject(updater->cancel, 0) == WAIT_OBJECT_0) result = sbw_fail(error, "cancelled", "The release check was cancelled.");
    if (!result) {
        EnterCriticalSection(&updater->mutex); updater->release = release;
        sb_buf_free(&updater->manifest); updater->manifest = manifest; memset(&manifest, 0, sizeof(manifest));
        sb_buf_free(&updater->signature); updater->signature = signature; memset(&signature, 0, sizeof(signature));
        LeaveCriticalSection(&updater->mutex);
        result = sbw_release_eligible(&release, updater->current, updater->cohort, error);
    }
    sb_buf_free(&manifest); sb_buf_free(&signature); sb_buf_free(&signature_url); return result;
}
static int download_release(sbw_updater *updater, sbw_error *error) {
    /* Re-verify the retained bytes before network or disk work. */
    sbw_release release;
    if (sbw_release_verify_manifest(updater->manifest.p, updater->manifest.len, updater->signature.p, updater->signature.len,
        SB_EASY_PUBLISHER_THUMBPRINT, &release, error) < 0 || sbw_release_eligible(&release, updater->current, updater->cohort, error) < 0) return -1;
    if (sbw_update_write(updater->stage, L"release.json", updater->manifest.p, updater->manifest.len, error) < 0 ||
        sbw_update_write(updater->stage, L"release.p7s", updater->signature.p, updater->signature.len, error) < 0 ||
        sbw_update_remove(updater->stage, L"package.msi", error) < 0) return -1;
    HANDLE file = sbw_secure_directory_file(updater->stage, L"package.msi", GENERIC_READ | GENERIC_WRITE, CREATE_NEW, error);
    if (file == INVALID_HANDLE_VALUE) return -1;
    file_sink_state sink = {updater, file}; uint64_t received = 0;
    char *url = artifact_url(updater->manifest_url, release.installer);
    int result = url ? sbw_https_download(url, release.bytes, 600000, updater->cancel, file_sink, &sink, &received, error) : -1;
    free(url);
    wchar_t *path = sbw_secure_directory_path(updater->stage, L"package.msi");
    if (!result && (!FlushFileBuffers(file) || received != release.bytes)) result = sbw_fail(error, "UPDATE_HASH_MISMATCH", "The installer download is incomplete.");
    if (!result) result = sbw_release_verify_installer(path, file, SB_EASY_PUBLISHER_THUMBPRINT, &release, error);
    if (!result && WaitForSingleObject(updater->cancel, 0) == WAIT_OBJECT_0) result = sbw_fail(error, "cancelled", "The installer download was cancelled.");
    CloseHandle(file); free(path);
    if (result) { sbw_error ignored = {0}; sbw_update_remove(updater->stage, L"package.msi", &ignored); }
    return result;
}
static DWORD WINAPI update_worker(void *context) {
    sbw_updater *updater = context; sbw_error error = {0};
    int result = updater->downloading ? download_release(updater, &error) : check_release(updater, &error);
    const char *phase = updater->downloading ? "ready" : "available";
    if (result) {
        if (!strcmp(error.code, "cancelled")) phase = "cancelled";
        else if (!strcmp(error.code, "UPDATE_NOT_NEWER")) phase = "current";
        else if (!strcmp(error.code, "UPDATE_ROLLOUT_PENDING")) phase = "deferred";
        else phase = "failed";
    }
    set_phase(updater, phase, result ? &error : NULL);
    EnterCriticalSection(&updater->mutex); updater->busy = false; LeaveCriticalSection(&updater->mutex); return 0;
}
static int start_locked(sbw_updater *updater, bool download, sbw_error *error) {
    if (updater->worker) { CloseHandle(updater->worker); updater->worker = NULL; }
    updater->busy = true; updater->downloading = download; updater->received = 0; memset(&updater->error, 0, sizeof(updater->error));
    strcpy_s(updater->phase, sizeof(updater->phase), download ? "downloading" : "checking"); ResetEvent(updater->cancel);
    updater->worker = CreateThread(NULL, 0, update_worker, updater, 0, NULL);
    if (!updater->worker) { updater->busy = false; strcpy_s(updater->phase, sizeof(updater->phase), "failed");
        return sbw_fail(error, "UPDATE_WORKER_FAILED", "The update worker could not be started."); }
    return 0;
}
static bool blocked_locked(sbw_updater *updater) {
    refresh_result_locked(updater);
    return updater->busy || !strcmp(updater->phase, "installing") || !strcmp(updater->phase, "recovery_required");
}
static int registered_current(sbw_updater *updater, sbw_error *error) {
    char version[32];
    if (sbw_update_registered_version(version, error) < 0) return -1;
    return !strcmp(version, updater->current) ? 0 : sbw_fail(error, "UPDATE_VERSION_MISMATCH", "The running service does not match the registered MSI version.");
}
int sbw_updater_check(sbw_updater *updater, const char *manifest_url, sbw_error *error) {
    if (!updater || !updater->supported) return unavailable(updater, error);
    if (registered_current(updater, error) < 0) return -1;
    if (!sbw_https_release_url(manifest_url)) return sbw_fail(error, "UPDATE_URL_INVALID", "Use a direct HTTPS release-manifest URL without credentials, query or fragment.");
    EnterCriticalSection(&updater->mutex);
    if (blocked_locked(updater)) { LeaveCriticalSection(&updater->mutex); return sbw_fail(error, "UPDATE_BUSY", "An update or recovery is already in progress."); }
    free(updater->manifest_url); updater->manifest_url = sb_strdup(manifest_url);
    memset(&updater->release, 0, sizeof(updater->release)); sb_buf_free(&updater->manifest); sb_buf_free(&updater->signature);
    int result = start_locked(updater, false, error); LeaveCriticalSection(&updater->mutex); return result;
}
int sbw_updater_download(sbw_updater *updater, const char *release_id, sbw_error *error) {
    if (!updater || !updater->supported) return unavailable(updater, error);
    EnterCriticalSection(&updater->mutex);
    if (blocked_locked(updater) || strcmp(updater->phase, "available") || !id_valid(release_id) || strcmp(updater->release.id, release_id)) {
        LeaveCriticalSection(&updater->mutex); return sbw_fail(error, "UPDATE_RELEASE_CHANGED", "Check and select the available signed release again.");
    }
    int result = start_locked(updater, true, error); LeaveCriticalSection(&updater->mutex); return result;
}
int sbw_updater_cancel(sbw_updater *updater, sbw_error *error) {
    if (!updater || !updater->supported) return unavailable(updater, error);
    EnterCriticalSection(&updater->mutex);
    if (!updater->busy || (strcmp(updater->phase, "checking") && strcmp(updater->phase, "downloading"))) {
        LeaveCriticalSection(&updater->mutex); return sbw_fail(error, "UPDATE_NOT_CANCELLABLE", "Only a release check or download can be cancelled.");
    }
    SetEvent(updater->cancel); LeaveCriticalSection(&updater->mutex); return 0;
}
bool sbw_updater_installing(sbw_updater *updater) {
    if (!updater) return false;
    EnterCriticalSection(&updater->mutex); refresh_result_locked(updater);
    bool installing = !strcmp(updater->phase, "installing") || !strcmp(updater->phase, "recovery_required");
    LeaveCriticalSection(&updater->mutex); return installing;
}
int sbw_updater_recover(sbw_updater *updater, sbw_error *error) {
    if (!updater || !updater->supported) return unavailable(updater, error);
    if (!sbw_updater_installing(updater)) return sbw_fail(error, "UPDATE_NO_RECOVERY", "There is no interrupted installer transaction to recover.");
    return sbw_update_launch_recovery(error);
}
int sbw_updater_install(sbw_updater *updater, const char *release_id, bool resume_connected, sbw_error *error) {
    if (!updater || !updater->supported) return unavailable(updater, error);
    if (registered_current(updater, error) < 0) return -1;
    EnterCriticalSection(&updater->mutex);
    if (blocked_locked(updater) || strcmp(updater->phase, "ready") || !id_valid(release_id) || strcmp(updater->release.id, release_id)) {
        LeaveCriticalSection(&updater->mutex); return sbw_fail(error, "UPDATE_RELEASE_CHANGED", "Download and verify the selected release before installing it.");
    }
    HANDLE package = INVALID_HANDLE_VALUE, helper = INVALID_HANDLE_VALUE; wchar_t *package_path = NULL, *helper_path = NULL;
    int result = -1; bool copied = false;
    package = sbw_secure_directory_file(updater->stage, L"package.msi", GENERIC_READ, OPEN_EXISTING, error);
    package_path = sbw_secure_directory_path(updater->stage, L"package.msi");
    if (package == INVALID_HANDLE_VALUE || sbw_release_verify_installer(package_path, package, SB_EASY_PUBLISHER_THUMBPRINT, &updater->release, error) < 0) goto done;
    if (sbw_update_copy(updater->installed, L"sb-easy-update.exe", updater->stage, L"update-helper.exe", 32U * 1024U * 1024U, false, &copied, error) < 0) goto done;
    helper = sbw_secure_directory_file(updater->stage, L"update-helper.exe", GENERIC_READ, OPEN_EXISTING, error);
    helper_path = sbw_secure_directory_path(updater->stage, L"update-helper.exe");
    if (helper == INVALID_HANDLE_VALUE || sbw_release_verify_file(helper_path, helper, SB_EASY_PUBLISHER_THUMBPRINT, true, error) < 0) goto done;
    const wchar_t *previous[] = {L"transaction.json", L"device-state.backup", L"health.json"};
    for (size_t i = 0; i < sizeof(previous) / sizeof(previous[0]); ++i)
        if (sbw_update_remove(updater->stage, previous[i], error) < 0) goto done;
    sbj *job = sbj_object(); sbj_set_int(job, "schema", 1); sbj_set_str(job, "release_id", updater->release.id);
    sbj_set_str(job, "previous_version", updater->current); sbj_set_str(job, "previous_core_version", SB_EASY_CORE_VERSION);
    sbj_set_bool(job, "resume_connected", resume_connected); sbj_set_int(job, "created_at", (int64_t)time(NULL));
    BYTE random[32]; char nonce[65];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        sbj_free(job); sbw_fail(error, "UPDATE_RANDOM_FAILED", "The private installer handshake could not be created."); goto done;
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) { nonce[i * 2] = digits[random[i] >> 4]; nonce[i * 2 + 1] = digits[random[i] & 15]; }
    nonce[64] = 0; sbj_set_str(job, "health_nonce", nonce); SecureZeroMemory(nonce, sizeof(nonce)); SecureZeroMemory(random, sizeof(random));
    result = sbw_update_write_json(updater->stage, L"job.json", job, error); sbj_free(job); if (result) goto done;
    sbj *state = sbj_object(); sbj_set_int(state, "schema", 1); sbj_set_str(state, "phase", "installing");
    sbj_set_str(state, "release_id", updater->release.id); sbj_set_str(state, "version", updater->release.version);
    result = sbw_update_write_json(updater->root, L"current.json", state, error); sbj_free(state); if (result) goto done;
    size_t size = wcslen(helper_path) + 32; wchar_t *command = sb_xcalloc(size, sizeof(wchar_t));
    swprintf_s(command, size, L"\"%ls\" --apply", helper_path);
    STARTUPINFOW startup = {0}; startup.cb = sizeof(startup); PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(helper_path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        NULL, NULL, &startup, &process)) result = sbw_fail(error, "UPDATE_HELPER_FAILED", "The signed installer helper could not be started.");
    else { CloseHandle(process.hThread); CloseHandle(process.hProcess); result = 0; strcpy_s(updater->phase, sizeof(updater->phase), "installing"); }
    free(command);
    if (result) { sbw_error ignored = {0}; sbw_update_remove(updater->root, L"current.json", &ignored); }
done:
    if (package != INVALID_HANDLE_VALUE) CloseHandle(package);
    if (helper != INVALID_HANDLE_VALUE) CloseHandle(helper);
    free(package_path); free(helper_path); LeaveCriticalSection(&updater->mutex); return result;
}

static int health_job(sbw_updater *updater, bool rollback, sbj **output, sbw_release *release, sbw_error *error) {
    *output = NULL;
    if (!updater || !updater->supported || !sbw_updater_installing(updater)) return unavailable(updater, error);
    sb_buf manifest = {0}, signature = {0}; sbj *job = sbw_update_read_json(updater->stage, L"job.json", false, error);
    int result = job ? sbw_update_read(updater->stage, L"release.json", SBW_RELEASE_MANIFEST_LIMIT, false, &manifest, error) : -1;
    if (!result) result = sbw_update_read(updater->stage, L"release.p7s", SBW_RELEASE_SIGNATURE_LIMIT, false, &signature, error);
    if (!result) result = sbw_release_verify_manifest(manifest.p, manifest.len, signature.p, signature.len,
        SB_EASY_PUBLISHER_THUMBPRINT, release, error);
    if (!result && (sbj_get_int(job, "schema", 0) != 1 || !sbj_is_bool(sbj_get(job, "resume_connected")) ||
        strcmp(sbj_get_str(job, "release_id", ""), release->id) ||
        strcmp(updater->current, rollback ? sbj_get_str(job, "previous_version", "") : release->version) ||
        strcmp(SB_EASY_CORE_VERSION, rollback ? sbj_get_str(job, "previous_core_version", "") : release->core_version)))
        result = sbw_fail(error, "UPDATE_VERSION_MISMATCH", "The running application and core do not match the installer transaction.");
    sb_buf_free(&manifest); sb_buf_free(&signature);
    if (result) sbj_free(job); else *output = job;
    return result;
}
int sbw_updater_health_parameters(sbw_updater *updater, const char *nonce, bool rollback, bool *resume_connected, sbw_error *error) {
    sbj *job = NULL; sbw_release release; *resume_connected = false;
    int result = health_job(updater, rollback, &job, &release, error);
    if (!result && (!id_valid(nonce) || strcmp(nonce, sbj_get_str(job, "health_nonce", ""))))
        result = sbw_fail(error, "UPDATE_HEALTH_FORBIDDEN", "Only the private installer handshake can run this operation.");
    if (!result) *resume_connected = sbj_get_bool(job, "resume_connected", false);
    sbj_free(job); return result;
}
int sbw_updater_health_record(sbw_updater *updater, bool rollback, sbw_error *error) {
    sbj *job = NULL; sbw_release release;
    if (health_job(updater, rollback, &job, &release, error) < 0) return -1;
    sbj_free(job); sbj *record = sbj_object(); sbj_set_int(record, "schema", 1); sbj_set_str(record, "release_id", release.id);
    sbj_set_str(record, "version", updater->current); sbj_set_str(record, "core_version", SB_EASY_CORE_VERSION);
    sbj_set_bool(record, "healthy", true); sbj_set_bool(record, "rollback", rollback);
    int result = sbw_update_write_json(updater->stage, L"health.json", record, error); sbj_free(record); return result;
}
