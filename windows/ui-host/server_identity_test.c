#include "server_identity.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    wchar_t name[128], executable[32768];
    HANDLE server, client;
    wchar_t *expected;
    bool accepted, impostor, missing;
    swprintf_s(name, 128, L"\\\\.\\pipe\\sb-easy-identity-%lu", GetCurrentProcessId());
    server = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 1024, 1000, NULL);
    if (server == INVALID_HANDLE_VALUE) return 1;
    client = CreateFileW(name, FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, 0, NULL,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (client == INVALID_HANDLE_VALUE) { CloseHandle(server); return 2; }
    if (!GetModuleFileNameW(NULL, executable, 32768)) { CloseHandle(client); CloseHandle(server); return 2; }
    expected = sbw_expected_service_binary();
    accepted = sbw_verified_pipe_server(client, executable);
    impostor = sbw_verified_pipe_server(client, expected);
    missing = sbw_verified_pipe_server(client, L"C:\\missing-sb-easy-test.exe");
    free(expected); CloseHandle(client); CloseHandle(server);
    if (!accepted || impostor || missing) return 3;
    puts("Pipe server identity and impostor rejection passed.");
    return 0;
}
