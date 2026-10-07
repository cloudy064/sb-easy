#ifndef SBW_PIPE_CLIENT_H
#define SBW_PIPE_CLIENT_H
#include "../common.h"
/* One bounded request. On success, *response is caller-owned UTF-8 JSON. */
int sbw_pipe_request(const wchar_t *pipe, const char *body, HANDLE cancel, DWORD timeout_ms,
                     char **response, sbw_error *error);
#endif
