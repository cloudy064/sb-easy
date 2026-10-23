#include "update_files.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

static int failure(sbw_error *error) { return sbw_fail(error, "UPDATE_STORAGE_FAILED", "The private update files could not be read or saved."); }
bool sbw_update_is_system(void) {
    HANDLE token = NULL; BYTE data[256]; DWORD size = sizeof(data); bool system = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        system = GetTokenInformation(token, TokenUser, data, size, &size) &&
            IsWellKnownSid(((TOKEN_USER *)data)->User.Sid, WinLocalSystemSid);
        CloseHandle(token);
    }
    return system;
}
int sbw_update_read(sbw_directory_guard *directory, const wchar_t *name, size_t limit,
    bool optional, sb_buf *output, sbw_error *error) {
    memset(output, 0, sizeof(*output));
    HANDLE file = sbw_secure_directory_file(directory, name, GENERIC_READ, OPEN_EXISTING, error);
    if (file == INVALID_HANDLE_VALUE) {
        if (optional && GetLastError() == ERROR_FILE_NOT_FOUND) { if (error) memset(error, 0, sizeof(*error)); return 0; }
        return -1;
    }
    LARGE_INTEGER size; bool ok = GetFileSizeEx(file, &size) && size.QuadPart >= 0 && (uint64_t)size.QuadPart <= limit;
    BYTE buffer[16384]; uint64_t total = 0;
    while (ok && total < (uint64_t)size.QuadPart) {
        DWORD read = 0;
        ok = ReadFile(file, buffer, sizeof(buffer), &read, NULL) && read && read <= (uint64_t)size.QuadPart - total;
        if (ok) { sb_buf_append(output, buffer, read); total += read; }
    }
    CloseHandle(file);
    if (!ok) { sb_buf_free(output); return failure(error); }
    return 0;
}
sbj *sbw_update_read_json(sbw_directory_guard *directory, const wchar_t *name, bool optional, sbw_error *error) {
    sb_buf content = {0};
    if (sbw_update_read(directory, name, 65536, optional, &content, error) < 0) return NULL;
    if (!content.p && optional) return NULL;
    sbj *result = sbj_parse_strict(content.p, content.len, NULL, 0); sb_buf_free(&content);
    if (!sbj_is_object(result)) { sbj_free(result); failure(error); return NULL; }
    return result;
}
static HANDLE temporary_file(sbw_directory_guard *directory, wchar_t name[64], sbw_error *error) {
    BYTE random[16]; const wchar_t digits[] = L"0123456789abcdef";
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { failure(error); return INVALID_HANDLE_VALUE; }
    wcscpy_s(name, 64, L"pending-");
    for (size_t i = 0; i < sizeof(random); ++i) { name[8 + i * 2] = digits[random[i] >> 4]; name[9 + i * 2] = digits[random[i] & 15]; }
    name[40] = 0; wcscat_s(name, 64, L".tmp");
    return sbw_secure_directory_file(directory, name, GENERIC_WRITE, CREATE_NEW, error);
}
static int replace_file(sbw_directory_guard *directory, const wchar_t *temporary, const wchar_t *name, sbw_error *error) {
    HANDLE prior = sbw_secure_directory_file(directory, name, GENERIC_READ, OPEN_EXISTING, error);
    if (prior == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) return -1;
    if (prior != INVALID_HANDLE_VALUE) CloseHandle(prior);
    wchar_t *source = sbw_secure_directory_path(directory, temporary), *destination = sbw_secure_directory_path(directory, name);
    bool ok = source && destination && MoveFileExW(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    free(source); free(destination);
    if (!ok) return failure(error);
    if (error) memset(error, 0, sizeof(*error));
    return 0;
}
int sbw_update_remove(sbw_directory_guard *directory, const wchar_t *name, sbw_error *error) {
    HANDLE file = sbw_secure_directory_file(directory, name, DELETE, OPEN_EXISTING, error);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) { if (error) memset(error, 0, sizeof(*error)); return 0; }
        return -1;
    }
    FILE_DISPOSITION_INFO disposition = {TRUE};
    bool ok = SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
    CloseHandle(file); return ok ? 0 : failure(error);
}
int sbw_update_write(sbw_directory_guard *directory, const wchar_t *name, const void *data, size_t length, sbw_error *error) {
    if (length > 16U * 1024U * 1024U) return failure(error);
    wchar_t temporary[64]; HANDLE file = temporary_file(directory, temporary, error);
    if (file == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0; bool ok = WriteFile(file, data, (DWORD)length, &written, NULL) && written == length && FlushFileBuffers(file);
    CloseHandle(file);
    int result = ok ? replace_file(directory, temporary, name, error) : failure(error);
    if (result) { sbw_error ignored = {0}; sbw_update_remove(directory, temporary, &ignored); }
    return result;
}
int sbw_update_write_json(sbw_directory_guard *directory, const wchar_t *name, const sbj *json, sbw_error *error) {
    char *content = sbj_dump(json, -1);
    int result = sbw_update_write(directory, name, content, strlen(content), error); free(content); return result;
}
int sbw_update_copy(sbw_directory_guard *source, const wchar_t *source_name, sbw_directory_guard *destination,
    const wchar_t *destination_name, uint64_t limit, bool optional, bool *existed, sbw_error *error) {
    *existed = false;
    HANDLE input = sbw_secure_directory_file(source, source_name, GENERIC_READ, OPEN_EXISTING, error);
    if (input == INVALID_HANDLE_VALUE) {
        if (optional && GetLastError() == ERROR_FILE_NOT_FOUND) { if (error) memset(error, 0, sizeof(*error)); return 0; }
        return -1;
    }
    *existed = true; LARGE_INTEGER size;
    if (!GetFileSizeEx(input, &size) || size.QuadPart < 0 || (uint64_t)size.QuadPart > limit) { CloseHandle(input); return failure(error); }
    wchar_t temporary[64]; HANDLE output = temporary_file(destination, temporary, error);
    if (output == INVALID_HANDLE_VALUE) { CloseHandle(input); return -1; }
    BYTE buffer[65536]; uint64_t total = 0; bool ok = true;
    while (ok && total < (uint64_t)size.QuadPart) {
        DWORD read = 0, written = 0;
        ok = ReadFile(input, buffer, sizeof(buffer), &read, NULL) && read && read <= (uint64_t)size.QuadPart - total &&
            WriteFile(output, buffer, read, &written, NULL) && written == read;
        if (ok) total += read;
    }
    if (ok) ok = FlushFileBuffers(output) != FALSE;
    CloseHandle(input); CloseHandle(output);
    int result = ok ? replace_file(destination, temporary, destination_name, error) : failure(error);
    if (result) { sbw_error ignored = {0}; sbw_update_remove(destination, temporary, &ignored); }
    return result;
}
