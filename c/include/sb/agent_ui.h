/* Password-protected local Agent API with an optional external static UI
 * directory (C++ agent_ui.hpp). Served by civetweb. */
#ifndef SB_AGENT_UI_H
#define SB_AGENT_UI_H

#include <stdint.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C++ AgentUiCallbacks. Every callback is required and may run on any
 * civetweb worker thread. JSON callbacks return an owned value, or NULL with
 * err set; the error kind selects the HTTP status like the C++
 * handle_response(): SB_ERR_BAD_JSON (nlohmann json::exception) -> 400
 * "无效的 JSON 请求：<msg>", SB_ERR_VALIDATION (std::invalid_argument) -> 400
 * "<msg>", anything else -> 500 "<msg>". */
typedef struct {
    sbj *(*status)(void *user, sb_err *err);
    sbj *(*settings)(void *user, sb_err *err);
    sbj *(*update_settings)(const sbj *value, void *user, sb_err *err);
    sbj *(*config)(void *user, sb_err *err);
    sbj *(*proxies)(void *user, sb_err *err);
    sbj *(*select_proxy)(const char *group, const char *proxy, void *user, sb_err *err);
    sbj *(*test_route)(const char *url, void *user, sb_err *err);
    int (*request_action)(const char *action, void *user, sb_err *err);
    void *user;
} sb_agent_ui_callbacks;

/* C++ AgentLocalUiOptions. Strings are borrowed for the duration of
 * sb_agent_ui_new (they are copied). */
typedef struct {
    const char *address;      /* default "0.0.0.0" */
    uint16_t port;            /* default 51822; 0 binds an ephemeral port */
    const char *username;     /* default "admin" */
    const char *password;     /* required */
    const char *ui_directory; /* NULL or "" -> JSON API only */
} sb_agent_ui_options;

void sb_agent_ui_options_init(sb_agent_ui_options *options);

typedef struct sb_agent_ui sb_agent_ui;

/* Validates the options (SB_ERR_VALIDATION with the C++ messages), starts
 * the listener and returns once it is bound. SB_ERR_GENERIC "Agent UI HTTP
 * listener did not start" when binding fails. */
sb_agent_ui *sb_agent_ui_new(const sb_agent_ui_options *options,
                             const sb_agent_ui_callbacks *callbacks, sb_err *err);
/* Stops the listener (waits for in-flight requests) and releases it. */
void sb_agent_ui_free(sb_agent_ui *ui);
/* The bound port (useful with port 0). */
uint16_t sb_agent_ui_port(const sb_agent_ui *ui);

#ifdef __cplusplus
}
#endif

#endif
