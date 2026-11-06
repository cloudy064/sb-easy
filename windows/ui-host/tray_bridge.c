#include "tray_bridge.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

sbj *sbw_tray_request(const char *body, size_t length, sbw_error *error) {
    static const char *methods[] = {
        "service.start", "protocol.hello", "status.get", "enrollment.status", "enrollment.apply",
        "updates.status", "updates.check", "updates.download", "updates.install", "updates.cancel", "updates.recover",
        "enrollment.forget", "config.summary", "config.refresh", "config.validate", "config.inspect",
        "routing.gpt_default", "routing.gpt_server", "routing.gpt_node", "routing.set", "routing.group_save",
        "routing.group_remove", "routing.probe", "routing.delay", "routing.health.set", "routing.health.check",
        "routing.automatic.set", "preferences.export", "preferences.preview", "preferences.apply",
        "preferences.cloud.login", "preferences.cloud.mfa", "preferences.cloud.logout", "preferences.cloud.get",
        "preferences.cloud.put", "preferences.cloud.delete", "mode.set", "management.settings.get", "management.settings.set",
        "subscriptions.import", "subscriptions.refresh", "subscriptions.fetch", "subscriptions.save", "subscriptions.remove",
        "connection.start", "connection.stop", "runtime.snapshot", "traffic.snapshot", "traffic.clear", "logs.snapshot",
        "extensions.list", "extensions.change", "extensions.catalog", "extensions.catalog_update", "extensions.rollback",
        "extensions.install", "extensions.progress", "httpdebug.open", "httpdebug.export", "httpdebug.trust",
        "httpdebug.untrust", "httpdebug.start", "httpdebug.stop", "httpdebug.snapshot", "httpdebug.attach", "httpdebug.certificate",
        "capture.snapshot", "capture.validate", "capture.configure", "capture.rotate", "capture.read", "capture.delete", "capture.upload"
    };
    if (!body || !length || length > 1024U * 1024U || memchr(body, '\0', length)) {
        sbw_fail(error, "INVALID_REQUEST", "Invalid local web request.");
        return NULL;
    }
    sbj *request = sbw_json_parse(body, length, 32, error);
    if (!sbj_is_object(request) || !sbw_json_string(sbj_get(request, "id"), 128, false) ||
        !sbj_is_integer(sbj_get(request, "version")) || sbj_get_int(request, "version", 0) != 1 ||
        !sbw_json_string(sbj_get(request, "method"), 128, false) || !sbj_is_object(sbj_get(request, "params"))) {
        sbj_free(request);
        sbw_fail(error, "INVALID_REQUEST", "Invalid local web request.");
        return NULL;
    }
    for (size_t i = 0; i < sizeof methods / sizeof *methods; ++i)
        if (sbj_string_is(sbj_get(request, "method"), methods[i])) return request;
    sbj_free(request);
    sbw_fail(error, "NOT_IMPLEMENTED", "This operation is not available.");
    return NULL;
}

wchar_t *sbw_tray_browser_url(unsigned short port, const char *token, sbw_error *error) {
    if (!port || !token || strlen(token) != 64 || strspn(token, "0123456789abcdef") != 64) {
        sbw_fail(error, "INVALID_SESSION", "Invalid local web session.");
        return NULL;
    }
    char url[128];
    (void)sprintf_s(url, sizeof url, "http://127.0.0.1:%u/#session=%s", port, token);
    return sbw_wide(url, error);
}

bool sbw_tray_arguments(int count, const wchar_t *const *arguments, bool *background) {
    if (!arguments || !background || count < 1 || count > 2) return false;
    *background = false;
    if (count == 1 || !wcscmp(arguments[1], L"--open")) return true;
    if (!wcscmp(arguments[1], L"--background")) { *background = true; return true; }
    return false;
}
