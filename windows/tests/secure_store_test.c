#include "../service/secure_store.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s (storage=%s)\n", __FILE__, __LINE__, #condition, error.code); \
    goto done; \
} } while (0)

static bool owner_policy(void) {
    BYTE system[SECURITY_MAX_SID_SIZE], administrators[SECURITY_MAX_SID_SIZE];
    BYTE unrelated[SECURITY_MAX_SID_SIZE], service_user[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(system);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size)) return false;
    size = sizeof(administrators);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size)) return false;
    size = sizeof(unrelated);
    if (!CreateWellKnownSid(WinBuiltinUsersSid, NULL, unrelated, &size)) return false;
    size = sizeof(service_user);
    if (!CreateWellKnownSid(WinInteractiveSid, NULL, service_user, &size)) return false;
    return sbw_trusted_storage_owner(system, service_user) &&
        sbw_trusted_storage_owner(administrators, service_user) &&
        sbw_trusted_storage_owner(service_user, service_user) &&
        !sbw_trusted_storage_owner(unrelated, service_user) &&
        !sbw_trusted_storage_owner(NULL, service_user);
}

static bool restricted_acl(const wchar_t *path) {
    PACL acl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (GetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              NULL, NULL, &acl, NULL, &descriptor) != ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool result = GetSecurityDescriptorControl(descriptor, &control, &revision) && acl &&
        acl->AceCount == 3 && (control & SE_DACL_PROTECTED) != 0;
    if (acl) for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *item = NULL;
        if (!GetAce(acl, i, &item)) { result = false; continue; }
        ACCESS_ALLOWED_ACE *ace = item;
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (IsWellKnownSid(&ace->SidStart, WinWorldSid) || IsWellKnownSid(&ace->SidStart, WinBuiltinUsersSid) ||
             IsWellKnownSid(&ace->SidStart, WinAuthenticatedUserSid) || IsWellKnownSid(&ace->SidStart, WinInteractiveSid)))
            result = false;
    }
    LocalFree(descriptor);
    return result;
}

static BYTE *read_bytes(const wchar_t *path, DWORD *size) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    DWORD length = GetFileSize(file, NULL), read = 0;
    if (length == INVALID_FILE_SIZE || length > 1024 * 1024) { CloseHandle(file); return NULL; }
    BYTE *bytes = sb_xcalloc((size_t)length + 1, 1);
    bool ok = ReadFile(file, bytes, length, &read, NULL) && read == length;
    CloseHandle(file);
    if (!ok) { free(bytes); return NULL; }
    *size = length;
    return bytes;
}

static bool has_bytes(const BYTE *haystack, DWORD length, const char *needle) {
    size_t count = strlen(needle);
    if (count > length) return false;
    for (size_t i = 0; i <= length - count; ++i) if (!memcmp(haystack + i, needle, count)) return true;
    return false;
}

static bool write_bytes(const wchar_t *path, const void *bytes, DWORD size) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, bytes, size, &written, NULL) && written == size && FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static bool write_legacy_envelope(const wchar_t *path, const char *json) {
    DATA_BLOB plain = {(DWORD)strlen(json), (BYTE *)json}, encrypted = {0};
    if (!CryptProtectData(&plain, L"sb-easy device state", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) return false;
    bool result = write_bytes(path, encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    return result;
}

static bool create_junction(const wchar_t *link, const wchar_t *target) {
    if (!CreateDirectoryW(link, NULL)) return false;
    HANDLE directory = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (directory == INVALID_HANDLE_VALUE) return false;
    struct mount_point_buffer {
        DWORD tag;
        WORD data_length, reserved, substitute_offset, substitute_length, print_offset, print_length;
        wchar_t paths[2048];
    } buffer = {0};
    size_t target_length = wcslen(target), substitute_length = target_length + 4;
    bool result = false;
    if (substitute_length + target_length + 2 < 2048) {
        buffer.tag = IO_REPARSE_TAG_MOUNT_POINT;
        buffer.substitute_length = (WORD)(substitute_length * sizeof(wchar_t));
        buffer.print_offset = (WORD)((substitute_length + 1) * sizeof(wchar_t));
        buffer.print_length = (WORD)(target_length * sizeof(wchar_t));
        buffer.data_length = (WORD)(8 + (substitute_length + target_length + 2) * sizeof(wchar_t));
        memcpy(buffer.paths, L"\\??\\", 4 * sizeof(wchar_t));
        memcpy(buffer.paths + 4, target, target_length * sizeof(wchar_t));
        memcpy(buffer.paths + substitute_length + 1, target, target_length * sizeof(wchar_t));
        DWORD returned = 0;
        result = DeviceIoControl(directory, FSCTL_SET_REPARSE_POINT, &buffer,
            (DWORD)(8 + buffer.data_length), NULL, 0, &returned, NULL) != FALSE;
    }
    CloseHandle(directory);
    return result;
}

int main(void) {
    sbw_error error = {0};
    sbw_store *store = NULL, *other = NULL;
    sbj *state = NULL, *loaded = NULL;
    wchar_t temporary[1024] = {0}, name[64] = L"sb-easy-store-test-";
    wchar_t *base = NULL, *data = NULL, *file = NULL, *lock = NULL;
    wchar_t *target = NULL, *junction = NULL, *nested = NULL;
    wchar_t *application = NULL, *console_data = NULL, *console_lock = NULL;
    bool created_base = false;
    BYTE *bytes = NULL;
    DWORD size = 0;
    int result = 1;
    const char legacy_json[] = "{\"version\":1,\"identity\":{\"server\":\"https://example.test/panel\","
        "\"host_id\":\"device-1\",\"host_name\":\"电脑\",\"agent_token\":\"private-agent-token\","
        "\"profile_id\":\"default\",\"profile_name\":\"Default\"},\"candidate\":null}";
    const char damaged[] = "damaged-protected-envelope";
    CHECK(owner_policy());
    DWORD temp_length = GetTempPathW((DWORD)(sizeof(temporary) / sizeof(*temporary)), temporary);
    CHECK(temp_length > 0 && temp_length < sizeof(temporary) / sizeof(*temporary));
    while (temp_length > 3 && temporary[temp_length - 1] == L'\\') temporary[--temp_length] = L'\0';
    BYTE random[16] = {0};
    CHECK(BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0);
    const wchar_t hex[] = L"0123456789abcdef";
    size_t prefix_length = wcslen(name);
    for (size_t i = 0; i < sizeof(random); ++i) {
        name[prefix_length + i * 2] = hex[random[i] >> 4];
        name[prefix_length + i * 2 + 1] = hex[random[i] & 15];
    }
    /* Cleanup uses only exact children of this freshly created, random directory. */
    CHECK(!wcschr(name, L'\\') && !wcschr(name, L'/'));
    base = sbw_path_join(temporary, name);
    CHECK(CreateDirectoryW(base, NULL));
    created_base = true;
    data = sbw_path_join(base, L"data");
    file = sbw_path_join(data, L"device-state.dat");
    lock = sbw_path_join(data, L"state.lock");
    target = sbw_path_join(base, L"target");
    junction = sbw_path_join(base, L"junction");
    nested = sbw_path_join(junction, L"nested");
    application = sbw_path_join(base, L"sb-easy");
    console_data = sbw_path_join(application, L"dev-service");
    console_lock = sbw_path_join(console_data, L"state.lock");
    store = sbw_secure_store_new(data, &error);
    CHECK(store != NULL);
    CHECK(store->load(store->context, &loaded, &error) == 0 && loaded == NULL);
    other = sbw_secure_store_new(data, &error);
    CHECK(other == NULL && !strcmp(error.code, "STORAGE_ERROR"));
    CHECK(write_legacy_envelope(file, legacy_json));
    CHECK(store->load(store->context, &loaded, &error) == 0);
    CHECK(sbj_get_int(loaded, "version", 0) == 1 &&
          sbj_string_is(sbj_get(sbj_get(loaded, "identity"), "host_name"), "电脑"));
    sbj_free(loaded); loaded = NULL;
    state = sbw_json_parse(legacy_json, strlen(legacy_json), 40, &error);
    CHECK(state != NULL);
    sbj_set_str(state, "candidate", "private-proxy-password");
    CHECK(store->save(store->context, state, &error) == 0);
    CHECK(restricted_acl(data) && restricted_acl(file) && restricted_acl(lock));
    bytes = read_bytes(file, &size);
    CHECK(bytes != NULL && !has_bytes(bytes, size, "private-agent-token") && !has_bytes(bytes, size, "private-proxy-password"));
    free(bytes); bytes = NULL;
    sbw_store_free(store); store = NULL;
    store = sbw_secure_store_new(data, &error);
    CHECK(store != NULL && store->load(store->context, &loaded, &error) == 0 && sbj_equal(loaded, state));
    sbj_free(loaded); loaded = NULL;
    sbj_set_int(state, "version", 2);
    CHECK(store->save(store->context, state, &error) == 0);
    CHECK(store->load(store->context, &loaded, &error) == 0 && sbj_get_int(loaded, "version", 0) == 2);
    sbj_free(loaded); loaded = NULL;
    CHECK(store->clear(store->context, &error) == 0);
    CHECK(store->load(store->context, &loaded, &error) == 0 && loaded == NULL);
    CHECK(write_bytes(file, damaged, (DWORD)strlen(damaged)));
    CHECK(store->load(store->context, &loaded, &error) == -1 && !strcmp(error.code, "STORAGE_CORRUPT"));
    CHECK(store->save(store->context, state, &error) == -1 && !strcmp(error.code, "STORAGE_CORRUPT"));
    CHECK(store->clear(store->context, &error) == -1 && !strcmp(error.code, "STORAGE_CORRUPT"));
    bytes = read_bytes(file, &size);
    CHECK(bytes && size == strlen(damaged) && !memcmp(bytes, damaged, size));
    free(bytes); bytes = NULL;
    sbw_store_free(store); store = NULL;
    CHECK(CreateDirectoryW(target, NULL));
    CHECK(create_junction(junction, target));
    other = sbw_secure_store_new(nested, &error);
    CHECK(other == NULL && !strcmp(error.code, "UNSAFE_STORAGE_PATH"));
    wchar_t *uncreated = sbw_path_join(target, L"nested");
    DWORD attributes = GetFileAttributesW(uncreated);
    free(uncreated);
    CHECK(attributes == INVALID_FILE_ATTRIBUTES);
    CHECK(RemoveDirectoryW(junction));
    other = sbw_secure_store_new(L"\\\\server\\share\\state", &error);
    CHECK(other == NULL && !strcmp(error.code, "UNSAFE_STORAGE_PATH"));
    store = sbw_secure_store_new(console_data, &error);
    CHECK(store != NULL && restricted_acl(application) && restricted_acl(console_data));
    puts("C11 secure store: DPAPI compatibility, owner/ACL, atomic persistence, exclusive lock, corruption and junction tests passed.");
    result = 0;
done:
    sbw_store_free(other);
    sbw_store_free(store);
    sbj_free(state);
    sbj_free(loaded);
    free(bytes);
    if (created_base) {
        /* No recursive removal and no filesystem-derived list: exact paths only. */
        if (console_lock) DeleteFileW(console_lock);
        if (console_data) RemoveDirectoryW(console_data);
        if (application) RemoveDirectoryW(application);
        if (file) DeleteFileW(file);
        if (lock) DeleteFileW(lock);
        if (data) RemoveDirectoryW(data);
        if (junction) RemoveDirectoryW(junction);
        if (target) RemoveDirectoryW(target);
        RemoveDirectoryW(base);
    }
    free(base); free(data); free(file); free(lock); free(target); free(junction); free(nested);
    free(application); free(console_data); free(console_lock);
    return result;
}
