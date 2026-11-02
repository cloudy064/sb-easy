#include "../service/secure_store.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (storage=%s)\n", __FILE__, __LINE__, #condition,            \
                    error.code);                                                                   \
            goto done;                                                                             \
        }                                                                                          \
    } while (0)

static bool owner_policy(void) {
    BYTE system[SECURITY_MAX_SID_SIZE], administrators[SECURITY_MAX_SID_SIZE];
    BYTE unrelated[SECURITY_MAX_SID_SIZE], service_user[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(system);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size))
        return false;
    size = sizeof(administrators);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size))
        return false;
    size = sizeof(unrelated);
    if (!CreateWellKnownSid(WinBuiltinUsersSid, NULL, unrelated, &size))
        return false;
    size = sizeof(service_user);
    if (!CreateWellKnownSid(WinInteractiveSid, NULL, service_user, &size))
        return false;
    return sbw_trusted_storage_owner(system, service_user) &&
           sbw_trusted_storage_owner(administrators, service_user) &&
           sbw_trusted_storage_owner(service_user, service_user) &&
           !sbw_trusted_storage_owner(unrelated, service_user) &&
           !sbw_trusted_storage_owner(NULL, service_user);
}

static bool restricted_acl(const wchar_t *path) {
    PACL acl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (GetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL,
                              NULL, &acl, NULL, &descriptor) != ERROR_SUCCESS)
        return false;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool result = GetSecurityDescriptorControl(descriptor, &control, &revision) && acl &&
                  acl->AceCount == 3 && (control & SE_DACL_PROTECTED) != 0;
    if (acl)
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *item = NULL;
            if (!GetAce(acl, i, &item)) {
                result = false;
                continue;
            }
            ACCESS_ALLOWED_ACE *ace = item;
            if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                (IsWellKnownSid(&ace->SidStart, WinWorldSid) ||
                 IsWellKnownSid(&ace->SidStart, WinBuiltinUsersSid) ||
                 IsWellKnownSid(&ace->SidStart, WinAuthenticatedUserSid) ||
                 IsWellKnownSid(&ace->SidStart, WinInteractiveSid)))
                result = false;
        }
    LocalFree(descriptor);
    return result;
}

static BYTE *read_bytes(const wchar_t *path, DWORD *size) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return NULL;
    DWORD length = GetFileSize(file, NULL), read = 0;
    if (length == INVALID_FILE_SIZE || length > 1024 * 1024) {
        CloseHandle(file);
        return NULL;
    }
    BYTE *bytes = sb_xcalloc((size_t)length + 1, 1);
    bool ok = ReadFile(file, bytes, length, &read, NULL) && read == length;
    CloseHandle(file);
    if (!ok) {
        free(bytes);
        return NULL;
    }
    *size = length;
    return bytes;
}

static bool has_bytes(const BYTE *haystack, DWORD length, const char *needle) {
    size_t count = strlen(needle);
    if (count > length)
        return false;
    for (size_t i = 0; i <= length - count; ++i)
        if (!memcmp(haystack + i, needle, count))
            return true;
    return false;
}

static bool write_bytes(const wchar_t *path, const void *bytes, DWORD size) {
    HANDLE file =
        CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    bool ok =
        WriteFile(file, bytes, size, &written, NULL) && written == size && FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static bool write_legacy_envelope(const wchar_t *path, const char *json) {
    DATA_BLOB plain = {(DWORD)strlen(json), (BYTE *)json}, encrypted = {0};
    if (!CryptProtectData(&plain, L"sb-easy device state", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &encrypted))
        return false;
    bool result = write_bytes(path, encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    return result;
}

static bool create_junction(const wchar_t *link, const wchar_t *target) {
    if (!CreateDirectoryW(link, NULL))
        return false;
    HANDLE directory = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (directory == INVALID_HANDLE_VALUE)
        return false;
    struct mount_point_buffer {
        DWORD tag;
        WORD data_length, reserved, substitute_offset, substitute_length, print_offset,
            print_length;
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
        result =
            DeviceIoControl(directory, FSCTL_SET_REPARSE_POINT, &buffer,
                            (DWORD)(8 + buffer.data_length), NULL, 0, &returned, NULL) != FALSE;
    }
    CloseHandle(directory);
    return result;
}

typedef struct test_state {
    sbw_error error;
    sbw_store *store, *other;
    sbj *state, *loaded;
    wchar_t *base, *data, *file, *lock, *target, *junction, *nested;
    wchar_t *application, *console_data, *console_lock;
    bool created_base;
    BYTE *bytes;
    DWORD size;
} test_state;

static const char legacy_json[] =
    "{\"version\":1,\"identity\":{\"server\":\"https://example.test/panel\","
    "\"host_id\":\"device-1\",\"host_name\":\"电脑\",\"agent_token\":\"private-agent-token\","
    "\"profile_id\":\"default\",\"profile_name\":\"Default\"},\"candidate\":null}";
static const char damaged[] = "damaged-protected-envelope";

#define CHECK_T(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: %s (storage=%s)\n", __FILE__, __LINE__, #condition,            \
                    t->error.code);                                                                \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int scenario_open_and_lock(test_state *t) {
    t->store = sbw_secure_store_new(t->data, &t->error);
    CHECK_T(t->store != NULL);
    CHECK_T(t->store->load(t->store->context, &t->loaded, &t->error) == 0 && t->loaded == NULL);
    t->other = sbw_secure_store_new(t->data, &t->error);
    CHECK_T(t->other == NULL && !strcmp(t->error.code, "STORAGE_ERROR"));
    return 0;
}

static int scenario_legacy_load(test_state *t) {
    CHECK_T(write_legacy_envelope(t->file, legacy_json));
    CHECK_T(t->store->load(t->store->context, &t->loaded, &t->error) == 0);
    CHECK_T(sbj_get_int(t->loaded, "version", 0) == 1 &&
            sbj_string_is(sbj_get(sbj_get(t->loaded, "identity"), "host_name"), "电脑"));
    sbj_free(t->loaded);
    t->loaded = NULL;
    return 0;
}

static int scenario_save_and_acl(test_state *t) {
    t->state = sbw_json_parse(legacy_json, strlen(legacy_json), 40, &t->error);
    CHECK_T(t->state != NULL);
    sbj_set_str(t->state, "candidate", "private-proxy-password");
    CHECK_T(t->store->save(t->store->context, t->state, &t->error) == 0);
    CHECK_T(restricted_acl(t->data) && restricted_acl(t->file) && restricted_acl(t->lock));
    t->bytes = read_bytes(t->file, &t->size);
    CHECK_T(t->bytes != NULL && !has_bytes(t->bytes, t->size, "private-agent-token") &&
            !has_bytes(t->bytes, t->size, "private-proxy-password"));
    free(t->bytes);
    t->bytes = NULL;
    return 0;
}

static int scenario_reopen_and_update(test_state *t) {
    sbw_store_free(t->store);
    t->store = NULL;
    t->store = sbw_secure_store_new(t->data, &t->error);
    CHECK_T(t->store != NULL && t->store->load(t->store->context, &t->loaded, &t->error) == 0 &&
            sbj_equal(t->loaded, t->state));
    sbj_free(t->loaded);
    t->loaded = NULL;
    sbj_set_int(t->state, "version", 2);
    CHECK_T(t->store->save(t->store->context, t->state, &t->error) == 0);
    CHECK_T(t->store->load(t->store->context, &t->loaded, &t->error) == 0 &&
            sbj_get_int(t->loaded, "version", 0) == 2);
    sbj_free(t->loaded);
    t->loaded = NULL;
    CHECK_T(t->store->clear(t->store->context, &t->error) == 0);
    CHECK_T(t->store->load(t->store->context, &t->loaded, &t->error) == 0 && t->loaded == NULL);
    return 0;
}

static int scenario_corruption(test_state *t) {
    CHECK_T(write_bytes(t->file, damaged, (DWORD)strlen(damaged)));
    CHECK_T(t->store->load(t->store->context, &t->loaded, &t->error) == -1 &&
            !strcmp(t->error.code, "STORAGE_CORRUPT"));
    CHECK_T(t->store->save(t->store->context, t->state, &t->error) == -1 &&
            !strcmp(t->error.code, "STORAGE_CORRUPT"));
    CHECK_T(t->store->clear(t->store->context, &t->error) == -1 &&
            !strcmp(t->error.code, "STORAGE_CORRUPT"));
    t->bytes = read_bytes(t->file, &t->size);
    CHECK_T(t->bytes && t->size == strlen(damaged) && !memcmp(t->bytes, damaged, t->size));
    free(t->bytes);
    t->bytes = NULL;
    sbw_store_free(t->store);
    t->store = NULL;
    return 0;
}

static int scenario_junction_and_unc(test_state *t) {
    CHECK_T(CreateDirectoryW(t->target, NULL));
    CHECK_T(create_junction(t->junction, t->target));
    t->other = sbw_secure_store_new(t->nested, &t->error);
    CHECK_T(t->other == NULL && !strcmp(t->error.code, "UNSAFE_STORAGE_PATH"));
    wchar_t *uncreated = sbw_path_join(t->target, L"nested");
    DWORD attributes = GetFileAttributesW(uncreated);
    free(uncreated);
    CHECK_T(attributes == INVALID_FILE_ATTRIBUTES);
    CHECK_T(RemoveDirectoryW(t->junction));
    t->other = sbw_secure_store_new(L"\\\\server\\share\\state", &t->error);
    CHECK_T(t->other == NULL && !strcmp(t->error.code, "UNSAFE_STORAGE_PATH"));
    return 0;
}

static int scenario_console_data(test_state *t) {
    t->store = sbw_secure_store_new(t->console_data, &t->error);
    CHECK_T(t->store != NULL && restricted_acl(t->application) && restricted_acl(t->console_data));
    return 0;
}

static const struct {
    const char *name;
    int (*run)(test_state *);
} scenarios[] = {
    {"open_and_lock", scenario_open_and_lock}, {"legacy_load", scenario_legacy_load},
    {"save_and_acl", scenario_save_and_acl},   {"reopen_and_update", scenario_reopen_and_update},
    {"corruption", scenario_corruption},       {"junction_and_unc", scenario_junction_and_unc},
    {"console_data", scenario_console_data},
};

int main(void) {
    sbw_error error = {0};
    test_state t = {0};
    wchar_t temporary[1024] = {0}, name[64] = L"sb-easy-store-test-";
    int result = 1;
    CHECK(owner_policy());
    DWORD temp_length = GetTempPathW((DWORD)(sizeof(temporary) / sizeof(*temporary)), temporary);
    CHECK(temp_length > 0 && temp_length < sizeof(temporary) / sizeof(*temporary));
    while (temp_length > 3 && temporary[temp_length - 1] == L'\\')
        temporary[--temp_length] = L'\0';
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
    t.base = sbw_path_join(temporary, name);
    CHECK(CreateDirectoryW(t.base, NULL));
    t.created_base = true;
    t.data = sbw_path_join(t.base, L"data");
    t.file = sbw_path_join(t.data, L"device-state.dat");
    t.lock = sbw_path_join(t.data, L"state.lock");
    t.target = sbw_path_join(t.base, L"target");
    t.junction = sbw_path_join(t.base, L"junction");
    t.nested = sbw_path_join(t.junction, L"nested");
    t.application = sbw_path_join(t.base, L"sb-easy");
    t.console_data = sbw_path_join(t.application, L"dev-service");
    t.console_lock = sbw_path_join(t.console_data, L"state.lock");
    for (size_t i = 0; i < sizeof scenarios / sizeof *scenarios; ++i) {
        if (scenarios[i].run(&t) != 0) {
            fprintf(stderr, "secure_store_test: scenario '%s' failed\n", scenarios[i].name);
            goto done;
        }
    }
    puts("C11 secure store: DPAPI compatibility, owner/ACL, atomic persistence, exclusive lock, "
         "corruption and junction tests passed.");
    result = 0;
done:
    sbw_store_free(t.other);
    sbw_store_free(t.store);
    sbj_free(t.state);
    sbj_free(t.loaded);
    free(t.bytes);
    if (t.created_base) {
        /* No recursive removal and no filesystem-derived list: exact paths only. */
        if (t.console_lock)
            DeleteFileW(t.console_lock);
        if (t.console_data)
            RemoveDirectoryW(t.console_data);
        if (t.application)
            RemoveDirectoryW(t.application);
        if (t.file)
            DeleteFileW(t.file);
        if (t.lock)
            DeleteFileW(t.lock);
        if (t.data)
            RemoveDirectoryW(t.data);
        if (t.junction)
            RemoveDirectoryW(t.junction);
        if (t.target)
            RemoveDirectoryW(t.target);
        RemoveDirectoryW(t.base);
    }
    free(t.base);
    free(t.data);
    free(t.file);
    free(t.lock);
    free(t.target);
    free(t.junction);
    free(t.nested);
    free(t.application);
    free(t.console_data);
    free(t.console_lock);
    return result;
}
