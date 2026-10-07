#ifndef SBW_SERVER_IDENTITY_H
#define SBW_SERVER_IDENTITY_H
#include <windows.h>
#include <stdbool.h>
wchar_t *sbw_expected_service_binary(void);
bool sbw_same_file(const wchar_t *first, const wchar_t *second);
bool sbw_verified_pipe_server(HANDLE pipe, const wchar_t *expected_binary);
#endif
