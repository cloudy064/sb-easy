#include "test_support.h"
#include "../ui-host/tray_bridge.h"

int main(void) {
    sbw_error error = {0};
    const char body[] = "{\"version\":1,\"id\":\"test\",\"method\":\"status.get\",\"params\":{}}";
    sbj *request = sbw_tray_request(body, sizeof body - 1, &error);
    CHECK(request && sbj_string_is(sbj_get(request, "method"), "status.get"));
    sbj_free(request);
    const char unknown[] = "{\"version\":1,\"id\":\"test\",\"method\":\"shell.execute\",\"params\":{}}";
    CHECK(!sbw_tray_request(unknown, sizeof unknown - 1, &error));
    CHECK(!strcmp(error.code, "NOT_IMPLEMENTED"));
    const char invalid[] = "{\"version\":2,\"id\":\"test\",\"method\":\"status.get\",\"params\":{}}";
    CHECK(!sbw_tray_request(invalid, sizeof invalid - 1, &error));
    CHECK(!sbw_tray_request(body, sizeof body, &error));
    char token[65]; memset(token, 'a', 64); token[64] = 0;
    wchar_t *url = sbw_tray_browser_url(23145, token, &error);
    CHECK(url && !wcsncmp(url, L"http://127.0.0.1:23145/#session=", wcslen(L"http://127.0.0.1:23145/#session=")));
    CHECK(!wcschr(url, L'?')); free(url);
    token[0] = '/'; CHECK(!sbw_tray_browser_url(23145, token, &error));
    CHECK(!sbw_tray_browser_url(0, token, &error));
    const wchar_t *plain[] = {L"sb-easy.exe"}, *background[] = {L"sb-easy.exe", L"--background"};
    const wchar_t *open[] = {L"sb-easy.exe", L"--open"}, *bad[] = {L"sb-easy.exe", L"https://evil.invalid"};
    bool silent = true;
    CHECK(sbw_tray_arguments(1, plain, &silent) && !silent);
    CHECK(sbw_tray_arguments(2, background, &silent) && silent);
    CHECK(sbw_tray_arguments(2, open, &silent) && !silent);
    CHECK(!sbw_tray_arguments(2, bad, &silent));
    puts("Tray RPC allowlist, fixed loopback URL and launch arguments passed.");
    return 0;
}
