#include "server_identity.h"
#include "../common.h"
#include <stdlib.h>
#include <string.h>

bool sbw_same_file(const wchar_t *first, const wchar_t *second) {
    HANDLE a = CreateFileW(first, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE b = CreateFileW(second, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    FILE_ID_INFO left = {0}, right = {0};
    bool same = a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(a, FileIdInfo, &left, sizeof(left)) &&
        GetFileInformationByHandleEx(b, FileIdInfo, &right, sizeof(right)) &&
        left.VolumeSerialNumber == right.VolumeSerialNumber && memcmp(&left.FileId, &right.FileId, sizeof(left.FileId)) == 0;
    if (a != INVALID_HANDLE_VALUE) CloseHandle(a);
    if (b != INVALID_HANDLE_VALUE) CloseHandle(b);
    return same;
}
static TOKEN_USER *token_user(HANDLE process) {
    HANDLE token = NULL;
    DWORD length = 0;
    TOKEN_USER *user = NULL;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &length);
    if (length && length <= 65536) {
        user = sb_xmalloc(length);
        if (!GetTokenInformation(token, TokenUser, user, length, &length)) { free(user); user = NULL; }
    }
    CloseHandle(token);
    return user;
}
static bool registered_service(DWORD pid) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"sb-easy", SERVICE_QUERY_STATUS) : NULL;
    SERVICE_STATUS_PROCESS status = {0};
    DWORD size = 0;
    bool same = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &size) &&
        (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING) && status.dwProcessId == pid;
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    return same;
}
wchar_t *sbw_expected_service_binary(void) {
    sbw_error error = {0};
    wchar_t *directory = sbw_executable_directory(&error);
    wchar_t *path = directory ? sbw_path_join(directory, L"sb-easy-service.exe") : NULL;
    free(directory);
    return path;
}
bool sbw_verified_pipe_server(HANDLE pipe, const wchar_t *expected_binary) {
    ULONG pid = 0;
    HANDLE process = NULL;
    TOKEN_USER *server = NULL, *client = NULL;
    wchar_t image[32768];
    DWORD length = (DWORD)(sizeof(image) / sizeof(image[0]));
    bool verified = false;
    if (!expected_binary || !*expected_binary || !GetNamedPipeServerProcessId(pipe, &pid) || !pid) return false;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    if (!QueryFullProcessImageNameW(process, 0, image, &length) || !sbw_same_file(image, expected_binary)) goto done;
    if (registered_service(pid)) { verified = true; goto done; }
    server = token_user(process);
    client = token_user(GetCurrentProcess());
    verified = server && client && EqualSid(server->User.Sid, client->User.Sid);
done:
    free(server); free(client); CloseHandle(process);
    return verified;
}
