#include "tray_smoke.h"
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static char *http_request(sbw_local_web *web, bool post, DWORD *status) {
    HINTERNET session = WinHttpOpen(L"sb-easy-smoke", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    HINTERNET connection = session ? WinHttpConnect(session, L"127.0.0.1", sbw_local_web_port(web), 0) : NULL;
    HINTERNET request = connection ? WinHttpOpenRequest(connection, post ? L"POST" : L"GET",
        post ? L"/api/rpc" : L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : NULL;
    char *response = NULL;
    if (request) {
        WinHttpSetTimeouts(request, 4000, 4000, 4000, 5000);
        wchar_t headers[256]; sbw_error error = {0}; wchar_t *token = sbw_wide(sbw_local_web_token(web), &error);
        (void)swprintf_s(headers, 256, L"Origin: http://127.0.0.1:%u\r\nAuthorization: Bearer %ls\r\nContent-Type: application/json\r\n",
            sbw_local_web_port(web), token ? token : L"");
        if (token) { SecureZeroMemory(token, wcslen(token) * sizeof *token); free(token); }
        char body[] = "{\"version\":1,\"id\":\"smoke\",\"method\":\"status.get\",\"params\":{}}";
        bool ok = WinHttpSendRequest(request, post ? headers : NULL, post ? (DWORD)-1 : 0,
            post ? body : NULL, post ? (DWORD)strlen(body) : 0, post ? (DWORD)strlen(body) : 0, 0) &&
            WinHttpReceiveResponse(request, NULL);
        SecureZeroMemory(headers, sizeof headers); DWORD size = sizeof *status;
        if (ok) ok = WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, status, &size, NULL) != FALSE;
        if (ok) {
            sb_buf buffer = {0}; char chunk[4096]; DWORD read = 0;
            while (WinHttpReadData(request, chunk, sizeof chunk, &read) && read) {
                if (buffer.len + read > 1024U * 1024U) break;
                sb_buf_append(&buffer, chunk, read);
            }
            response = sb_buf_detach(&buffer);
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
    return response;
}
int sbw_tray_smoke(sbw_local_web *web, const wchar_t *path, bool offline) {
    DWORD static_status = 0, rpc_status = 0;
    char *page = http_request(web, false, &static_status); bool static_ok = page && static_status == 200; free(page);
    char *body = NULL; sbj *answer = NULL; bool available = false;
    for (unsigned i = 0; i < (offline ? 1U : 20U); ++i) {
        free(body); sbj_free(answer); body = http_request(web, true, &rpc_status);
        answer = body ? sbj_parse_cstr(body) : NULL; available = sbj_get_bool(answer, "ok", false);
        if (available || offline) break;
        Sleep(200);
    }
    bool envelope = sbj_get_int(answer, "version", 0) == 1 && sbj_string_is(sbj_get(answer, "id"), "smoke");
    bool ok = static_ok && rpc_status == 200 && envelope && available != offline;
    sbj *receipt = sbj_object(); sbj_set_bool(receipt, "ok", ok); sbj_set_int(receipt, "http_status", rpc_status);
    sbj_set_bool(receipt, "static_ok", static_ok); sbj_set_bool(receipt, "rpc_ok", envelope);
    sbj_set_bool(receipt, "service_available", available);
    sbj_set_str(receipt, "service_phase", sbj_get_str(sbj_get(answer, "result"), "phase", "unavailable"));
    char *serialized = sbj_dump(receipt, 2); FILE *file = NULL;
    if (_wfopen_s(&file, path, L"wb") || !file) ok = false;
    else { size_t n = strlen(serialized); if (fwrite(serialized, 1, n, file) != n) ok = false; if (fclose(file)) ok = false; }
    free(serialized); sbj_free(receipt); free(body); sbj_free(answer); return ok ? 0 : 1;
}
