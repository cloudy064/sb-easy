#include "protocol.h"
#include <stdlib.h>
#include <string.h>

static sbj *failure(const sbj *id, const char *code, const char *message) {
    sbj *response = sbj_object(), *error = sbj_object();
    sbj_set(response, "id", id ? sbj_clone(id) : sbj_null());
    sbj_set_int(response, "version", 1); sbj_set_bool(response, "ok", false);
    sbj_set_str(error, "code", code); sbj_set_str(error, "message", message);
    sbj_set(response, "error", error); return response;
}
char *sbw_handle_request(const char *raw, size_t length, sbw_controller *controller, bool authorized) {
    sbw_error error = {0};
    sbj *request = length <= SBW_MAX_FRAME ? sbw_json_parse(raw, length, 32, &error) : NULL;
    const sbj *id = sbj_get(request, "id"), *version = sbj_get(request, "version"), *params = sbj_get(request, "params");
    const sbj *method_value = sbj_get(request, "method");
    sbj *response = NULL, *result = NULL, *empty = NULL;
    if (!sbw_json_string(id, 128, false)) id = NULL;
    if (!sbj_is_object(request) || !id || !sbj_is_integer(version) ||
        !sbw_json_string(method_value, 128, false) || (params && !sbj_is_object(params))) {
        response = failure(id, "INVALID_REQUEST", "Invalid protocol request."); goto done;
    }
    if (sbj_as_int(version, 0) != 1) {
        response = failure(id, "UNSUPPORTED_VERSION", "This service supports protocol version 1."); goto done;
    }
    const char *method = method_value->v.str.ptr;
    if (!params) { empty = sbj_object(); params = empty; }
    if (sb_streq(method, "protocol.hello")) {
        result = sbj_object();
        sbj_set_int(result, "protocol_version", 1); sbj_set_str(result, "service_version", SB_EASY_VERSION);
        sbj *methods = sbj_array(), *features = sbj_object();
        const char *names[] = {"protocol.hello", "status.get", "enrollment.status", "enrollment.apply", "enrollment.forget", "config.refresh", "config.summary", "config.validate", "connection.start", "connection.stop", "config.inspect", "runtime.snapshot"};
        for (size_t i = 0; i < (controller ? sizeof(names) / sizeof(names[0]) : 3U); ++i) sbj_arr_push(methods, sbj_str(names[i]));
        sbj_set(result, "supported_methods", methods);
        sbj_set_bool(features, "enrollment", controller != NULL); sbj_set_bool(features, "config_sync", controller != NULL);
        sbj_set_bool(features, "config_validation", controller != NULL);
        sbj_set_bool(features, "runtime_observability", controller != NULL);
        sbj_set_bool(features, "vpn", controller != NULL);
        sbj_set_bool(features, "connection_control", controller != NULL); sbj_set_bool(features, "proxy_selection", false);
        sbj_set(result, "features", features);
    } else if (controller) result = sbw_controller_dispatch(controller, method, params, authorized, &error);
    else if (sb_streq(method, "status.get") || sb_streq(method, "enrollment.status")) {
        result = sbj_object(); sbj_set_bool(result, "enrolled", false); sbj_set_str(result, "phase", "UNENROLLED");
        if (sb_streq(method, "status.get")) { sbj_set_bool(result, "core_running", false); sbj_set_bool(result, "connection_available", false); }
    } else sbw_fail(&error, "NOT_IMPLEMENTED", "This service build does not implement this operation.");
    if (!result) response = failure(id, error.code[0] ? error.code : "INTERNAL_ERROR", error.message[0] ? error.message : "The operation failed.");
    else {
        response = sbj_object(); sbj_set(response, "id", sbj_clone(id));
        sbj_set_int(response, "version", 1); sbj_set_bool(response, "ok", true); sbj_set(response, "result", result);
    }
done:;
    char *serialized = sbj_dump(response, -1);
    sbj_free(empty); sbj_free(response); sbj_free(request); return serialized;
}
