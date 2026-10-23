#include "../service/update_files.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    sbw_error error = {0}; wchar_t temporary[MAX_PATH], leaf[96]; assert(GetTempPathW(MAX_PATH, temporary));
    swprintf_s(leaf, 96, L"sbeasy-update-files-%lu-%llu", GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    wchar_t *base = sbw_path_join(temporary, leaf), *source_path = sbw_path_join(base, L"profile"), *stage_path = sbw_path_join(base, L"updates");
    sbw_store *store = sbw_secure_store_new(source_path, &error); assert(store);
    sbw_directory_guard *source = sbw_secure_directory_open(source_path, &error), *stage = sbw_secure_directory_open(stage_path, &error);
    assert(source && stage);
    sbj *original = sbj_object(); sbj_set_int(original, "version", 1); sbj_set_str(original, "private_device_token", "never-plaintext-in-backup");
    assert(store->save(store->context, original, &error) == 0);
    bool existed = false;
    assert(sbw_update_copy(source, L"device-state.dat", stage, L"device-state.backup", 16U * 1024U * 1024U, false, &existed, &error) == 0 && existed);
    sb_buf bytes = {0}; assert(sbw_update_read(stage, L"device-state.backup", 16U * 1024U * 1024U, false, &bytes, &error) == 0);
    assert(bytes.len > 32);
    const char *secret = "never-plaintext-in-backup";
    for (size_t i = 0; i + strlen(secret) <= bytes.len; ++i) assert(memcmp(bytes.p + i, secret, strlen(secret)));
    sb_buf_free(&bytes);
    sbj *changed = sbj_object(); sbj_set_int(changed, "version", 99);
    assert(store->save(store->context, changed, &error) == 0);
    assert(sbw_update_copy(stage, L"device-state.backup", source, L"device-state.dat", 16U * 1024U * 1024U, false, &existed, &error) == 0);
    sbj *restored = NULL; assert(store->load(store->context, &restored, &error) == 0 && sbj_equal(restored, original)); sbj_free(restored);
    assert(sbw_update_copy(source, L"absent.dat", stage, L"absent.backup", 10, true, &existed, &error) == 0 && !existed && !error.code[0]);
    assert(sbw_update_write(stage, L"current.json", "old", 3, &error) == 0);
    HANDLE pinned = sbw_secure_directory_file(stage, L"current.json", GENERIC_READ, OPEN_EXISTING, &error); assert(pinned != INVALID_HANDLE_VALUE);
    assert(sbw_update_write(stage, L"current.json", "new", 3, &error) < 0);
    assert(sbw_update_read(stage, L"current.json", 3, false, &bytes, &error) == 0 && bytes.len == 3 && !memcmp(bytes.p, "old", 3)); sb_buf_free(&bytes);
    CloseHandle(pinned); assert(sbw_update_write(stage, L"current.json", "new", 3, &error) == 0);
    assert(sbw_update_read(stage, L"current.json", 2, false, &bytes, &error) < 0 && !bytes.p);
    assert(!sbw_secure_directory_path(stage, L"..\\device-state.dat"));
    assert(!sbw_secure_directory_path(stage, L"C:\\unexpected.msi"));
    assert(sbw_secure_directory_file(stage, L"x", GENERIC_WRITE, CREATE_ALWAYS, &error) == INVALID_HANDLE_VALUE);
    sbw_directory_guard *readonly = sbw_secure_directory_open_readonly(stage_path, &error); assert(readonly);
    assert(sbw_secure_directory_file(readonly, L"current.json", GENERIC_WRITE, OPEN_EXISTING, &error) == INVALID_HANDLE_VALUE);
    pinned = sbw_secure_directory_file(readonly, L"current.json", GENERIC_READ, OPEN_EXISTING, &error); assert(pinned != INVALID_HANDLE_VALUE); CloseHandle(pinned);
    sbw_secure_directory_close(readonly);
    assert(sbw_update_remove(stage, L"current.json", &error) == 0);
    assert(sbw_update_remove(stage, L"device-state.backup", &error) == 0);
    assert(sbw_update_remove(stage, L"missing.dat", &error) == 0);
    assert(store->clear(store->context, &error) == 0);
    sbj_free(original); sbj_free(changed); sbw_store_free(store);
    assert(sbw_update_remove(source, L"state.lock", &error) == 0);
    sbw_secure_directory_close(source); sbw_secure_directory_close(stage);
    assert(RemoveDirectoryW(source_path)); assert(RemoveDirectoryW(stage_path)); assert(RemoveDirectoryW(base));
    free(source_path); free(stage_path); free(base); puts("Windows update file backup, rollback and path tests passed"); return 0;
}
