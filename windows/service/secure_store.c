#include "secure_store.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SBW_MAX_STORE_BYTES (16U * 1024U * 1024U)

typedef struct secure_store {
    wchar_t *directory;
    wchar_t *file;
    HANDLE *parents;
    size_t parent_count;
    HANDLE lock;
    PSECURITY_DESCRIPTOR descriptor;
    PACL acl;
    PSID user_sid;
} secure_store;

static int storage_fail(sbw_error *error, const char *code) {
    const char *message = "Device state could not be securely read or saved.";
    if (!strcmp(code, "STORAGE_CORRUPT"))
        message = "Stored device state is damaged or cannot be decrypted; it was left unchanged.";
    else if (!strcmp(code, "UNSAFE_STORAGE_PATH"))
        message = "The device data location is not a safe local directory.";
    return sbw_fail(error, code, message);
}

bool sbw_trusted_storage_owner(PSID owner, PSID service_user) {
    return owner && service_user && IsValidSid(owner) && IsValidSid(service_user) &&
        (EqualSid(owner, service_user) || IsWellKnownSid(owner, WinLocalSystemSid) ||
         IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
}

static wchar_t *wide_copy(const wchar_t *value) {
    size_t length = wcslen(value);
    wchar_t *copy = sb_xmalloc((length + 1) * sizeof(*copy));
    memcpy(copy, value, (length + 1) * sizeof(*copy));
    return copy;
}

static wchar_t *join_path(const wchar_t *base, const wchar_t *leaf) {
    size_t a = wcslen(base), b = wcslen(leaf);
    bool separator = a > 0 && base[a - 1] != L'\\';
    wchar_t *result = sb_xcalloc(a + b + (separator ? 2 : 1), sizeof(*result));
    memcpy(result, base, a * sizeof(*result));
    if (separator) result[a++] = L'\\';
    memcpy(result + a, leaf, (b + 1) * sizeof(*result));
    return result;
}

static int reject_reparse(HANDLE file, bool directory, sbw_error *error) {
    FILE_ATTRIBUTE_TAG_INFO attributes = {0};
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)))
        return storage_fail(error, "STORAGE_ERROR");
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)
        return storage_fail(error, "UNSAFE_STORAGE_PATH");
    return 0;
}

static int descriptor_init(secure_store *store, sbw_error *error) {
    HANDLE token = NULL;
    BYTE *information = NULL;
    LPWSTR sid_text = NULL;
    wchar_t *sddl = NULL;
    DWORD length = 0;
    BOOL present = FALSE, defaulted = FALSE;
    int result = -1;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &length);
    if (!length) goto done;
    information = sb_xmalloc(length);
    if (!GetTokenInformation(token, TokenUser, information, length, &length)) goto done;
    PSID user = ((TOKEN_USER *)information)->User.Sid;
    DWORD sid_length = GetLengthSid(user);
    store->user_sid = sb_xmalloc(sid_length);
    if (!CopySid(sid_length, store->user_sid, user)) goto done;
    if (!ConvertSidToStringSidW(user, &sid_text)) goto done;
    const wchar_t prefix[] = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;";
    size_t prefix_length = wcslen(prefix), text_length = wcslen(sid_text);
    sddl = sb_xcalloc(prefix_length + text_length + 2, sizeof(*sddl));
    memcpy(sddl, prefix, prefix_length * sizeof(*sddl));
    memcpy(sddl + prefix_length, sid_text, text_length * sizeof(*sddl));
    sddl[prefix_length + text_length] = L')';
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &store->descriptor, NULL)) goto done;
    if (!GetSecurityDescriptorDacl(store->descriptor, &present, &store->acl, &defaulted) || !present) goto done;
    result = 0;
done:
    if (token) CloseHandle(token);
    free(information);
    if (sid_text) LocalFree(sid_text);
    free(sddl);
    return result == 0 ? 0 : storage_fail(error, "STORAGE_ERROR");
}

static int descriptor_apply(const secure_store *store, HANDLE object, sbw_error *error) {
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR current = NULL;
    if (GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &current)
        != ERROR_SUCCESS) return storage_fail(error, "STORAGE_ERROR");
    bool trusted = sbw_trusted_storage_owner(owner, store->user_sid);
    LocalFree(current);
    if (!trusted) return storage_fail(error, "UNSAFE_STORAGE_PATH");
    if (SetSecurityInfo(object, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, store->acl, NULL) != ERROR_SUCCESS)
        return storage_fail(error, "STORAGE_ERROR");
    return 0;
}

static wchar_t *normalized_directory(const wchar_t *input, sbw_error *error) {
    if (!input || !*input) { storage_fail(error, "UNSAFE_STORAGE_PATH"); return NULL; }
    wchar_t *supplied = wide_copy(input);
    for (wchar_t *p = supplied; *p; ++p) if (*p == L'/') *p = L'\\';
    DWORD required = GetFullPathNameW(supplied, 0, NULL, NULL);
    if (!required || required > 32760) {
        free(supplied);
        storage_fail(error, "UNSAFE_STORAGE_PATH");
        return NULL;
    }
    wchar_t *path = sb_xcalloc((size_t)required + 1, sizeof(*path));
    DWORD copied = GetFullPathNameW(supplied, required + 1, path, NULL);
    free(supplied);
    if (!copied || copied > required) goto unsafe;
    size_t length = wcslen(path);
    while (length > 3 && path[length - 1] == L'\\') path[--length] = L'\0';
    if (length < 4 || path[1] != L':' || path[2] != L'\\' || wcschr(path + 2, L':') ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) goto unsafe;
    wchar_t root[] = {path[0], L':', L'\\', L'\0'};
    if (GetDriveTypeW(root) != DRIVE_FIXED) goto unsafe;
    return path;
unsafe:
    free(path);
    storage_fail(error, "UNSAFE_STORAGE_PATH");
    return NULL;
}

static int pin_directories(secure_store *store, sbw_error *error) {
    size_t length = wcslen(store->directory);
    size_t parent_end = (size_t)(wcsrchr(store->directory, L'\\') - store->directory);
    wchar_t *current = wide_copy(store->directory);
    /* Each pinned prefix removes FILE_SHARE_DELETE so ancestors cannot be
     * renamed or replaced between subsequent no-follow opens. */
    store->parents = sb_xcalloc(length + 1, sizeof(*store->parents));
    SECURITY_ATTRIBUTES security = {sizeof(SECURITY_ATTRIBUTES), store->descriptor, FALSE};
    for (size_t i = 3; i <= length; ++i) {
        if (current[i] != L'\\' && current[i] != L'\0') continue;
        wchar_t saved = current[i];
        current[i] = L'\0';
        if (!CreateDirectoryW(current, &security) && GetLastError() != ERROR_ALREADY_EXISTS) {
            free(current);
            return storage_fail(error, "STORAGE_ERROR");
        }
        const wchar_t *component = wcsrchr(current, L'\\') + 1;
        bool managed = i == length ||
            (i == parent_end && CompareStringOrdinal(component, -1, L"sb-easy", -1, TRUE) == CSTR_EQUAL);
        HANDLE directory = CreateFileW(current, FILE_READ_ATTRIBUTES | (managed ? READ_CONTROL | WRITE_DAC : 0),
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (directory == INVALID_HANDLE_VALUE) { free(current); return storage_fail(error, "STORAGE_ERROR"); }
        if (reject_reparse(directory, true, error) != 0 ||
            (managed && descriptor_apply(store, directory, error) != 0)) {
            CloseHandle(directory);
            free(current);
            return -1;
        }
        store->parents[store->parent_count++] = directory;
        current[i] = saved;
    }
    free(current);
    return 0;
}

static int secure_load(void *context, sbj **out, sbw_error *error) {
    secure_store *store = context;
    BYTE *bytes = NULL;
    DATA_BLOB decrypted = {0};
    HANDLE file = INVALID_HANDLE_VALUE;
    int result = -1;
    if (!out) return storage_fail(error, "STORAGE_ERROR");
    *out = NULL;
    file = CreateFileW(store->file, GENERIC_READ | WRITE_DAC, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return 0;
        return storage_fail(error, "STORAGE_ERROR");
    }
    if (reject_reparse(file, false, error) != 0 || descriptor_apply(store, file, error) != 0) goto done;
    LARGE_INTEGER size = {0};
    if (!GetFileSizeEx(file, &size)) { storage_fail(error, "STORAGE_ERROR"); goto done; }
    if (size.QuadPart <= 0 || size.QuadPart > SBW_MAX_STORE_BYTES) { storage_fail(error, "STORAGE_CORRUPT"); goto done; }
    DWORD length = (DWORD)size.QuadPart, read = 0;
    bytes = sb_xmalloc(length);
    if (!ReadFile(file, bytes, length, &read, NULL) || read != length) { storage_fail(error, "STORAGE_ERROR"); goto done; }
    DATA_BLOB encrypted = {length, bytes};
    if (!CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &decrypted)) {
        storage_fail(error, "STORAGE_CORRUPT");
        goto done;
    }
    *out = sbw_json_parse((const char *)decrypted.pbData, decrypted.cbData, 40, error);
    if (!*out) { storage_fail(error, "STORAGE_CORRUPT"); goto done; }
    result = 0;
done:
    if (decrypted.pbData) { SecureZeroMemory(decrypted.pbData, decrypted.cbData); LocalFree(decrypted.pbData); }
    free(bytes);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return result;
}

static int secure_save(void *context, const sbj *state, sbw_error *error) {
    secure_store *store = context;
    sbj *previous = NULL;
    if (secure_load(context, &previous, error) != 0) return -1;
    sbj_free(previous);
    sb_err json_error = {0};
    if (!state || sbj_validate_utf8(state, &json_error) != 0) return storage_fail(error, "STORAGE_ERROR");
    char *plain = sbj_dump(state, -1);
    size_t plain_length = strlen(plain);
    if (plain_length > SBW_MAX_STORE_BYTES - 4096) {
        SecureZeroMemory(plain, plain_length);
        free(plain);
        return storage_fail(error, "STORAGE_ERROR");
    }
    DATA_BLOB input = {(DWORD)plain_length, (BYTE *)plain}, encrypted = {0};
    BOOL protected_ok = CryptProtectData(&input, L"sb-easy device state", NULL, NULL, NULL,
                                         CRYPTPROTECT_UI_FORBIDDEN, &encrypted);
    SecureZeroMemory(plain, plain_length);
    free(plain);
    if (!protected_ok) return storage_fail(error, "STORAGE_ERROR");
    BYTE random[16] = {0};
    wchar_t filename[64] = L"device-state.tmp-";
    const wchar_t hex[] = L"0123456789abcdef";
    wchar_t *temporary = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    bool created = false;
    int result = -1;
    if (BCryptGenRandom(NULL, random, (ULONG)sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) goto done;
    size_t prefix = wcslen(filename);
    for (size_t i = 0; i < sizeof(random); ++i) {
        filename[prefix + i * 2] = hex[random[i] >> 4];
        filename[prefix + i * 2 + 1] = hex[random[i] & 15];
    }
    temporary = join_path(store->directory, filename);
    SECURITY_ATTRIBUTES security = {sizeof(SECURITY_ATTRIBUTES), store->descriptor, FALSE};
    file = CreateFileW(temporary, GENERIC_WRITE, 0, &security, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    created = true;
    DWORD written = 0;
    if (!WriteFile(file, encrypted.pbData, encrypted.cbData, &written, NULL) ||
        written != encrypted.cbData || !FlushFileBuffers(file)) goto done;
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temporary, store->file, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) goto done;
    result = 0;
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (result != 0 && created) DeleteFileW(temporary);
    free(temporary);
    LocalFree(encrypted.pbData);
    return result == 0 ? 0 : storage_fail(error, "STORAGE_ERROR");
}

static int secure_clear(void *context, sbw_error *error) {
    secure_store *store = context;
    sbj *previous = NULL;
    if (secure_load(context, &previous, error) != 0) return -1;
    if (!previous) return 0;
    sbj_free(previous);
    HANDLE file = CreateFileW(store->file, DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC, 0,
                              NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return storage_fail(error, "STORAGE_ERROR");
    int result = -1;
    if (reject_reparse(file, false, error) == 0 && descriptor_apply(store, file, error) == 0) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        result = SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)) ? 0
            : storage_fail(error, "STORAGE_ERROR");
    }
    CloseHandle(file);
    return result;
}

static void secure_destroy(void *context) {
    secure_store *store = context;
    if (!store) return;
    if (store->lock && store->lock != INVALID_HANDLE_VALUE) CloseHandle(store->lock);
    for (size_t i = store->parent_count; i > 0; --i) CloseHandle(store->parents[i - 1]);
    free(store->parents);
    if (store->descriptor) LocalFree(store->descriptor);
    free(store->user_sid);
    free(store->directory);
    free(store->file);
    free(store);
}

void sbw_store_free(sbw_store *store) {
    if (!store) return;
    if (store->destroy) store->destroy(store->context);
    free(store);
}

sbw_store *sbw_secure_store_new(const wchar_t *directory, sbw_error *error) {
    secure_store *context = sb_xcalloc(1, sizeof(*context));
    if (descriptor_init(context, error) != 0) goto failed;
    context->directory = normalized_directory(directory, error);
    if (!context->directory || pin_directories(context, error) != 0) goto failed;
    context->file = join_path(context->directory, L"device-state.dat");
    wchar_t *lock_path = join_path(context->directory, L"state.lock");
    SECURITY_ATTRIBUTES security = {sizeof(SECURITY_ATTRIBUTES), context->descriptor, FALSE};
    context->lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE | WRITE_DAC, 0, &security,
                                 OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(lock_path);
    if (context->lock == INVALID_HANDLE_VALUE) { storage_fail(error, "STORAGE_ERROR"); goto failed; }
    if (reject_reparse(context->lock, false, error) != 0 || descriptor_apply(context, context->lock, error) != 0) goto failed;
    sbw_store *store = sb_xcalloc(1, sizeof(*store));
    store->context = context;
    store->load = secure_load;
    store->save = secure_save;
    store->clear = secure_clear;
    store->destroy = secure_destroy;
    return store;
failed:
    secure_destroy(context);
    return NULL;
}

wchar_t *sbw_default_data_directory(bool console, sbw_error *error) {
    PWSTR folder = NULL;
    if (FAILED(SHGetKnownFolderPath(console ? &FOLDERID_LocalAppData : &FOLDERID_ProgramData, 0, NULL, &folder))) {
        storage_fail(error, "STORAGE_ERROR");
        return NULL;
    }
    wchar_t *result = join_path(folder, console ? L"sb-easy\\dev-service" : L"sb-easy");
    CoTaskMemFree(folder);
    return result;
}
