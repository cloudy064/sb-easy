/* Agent local UI contract (port of cpp/tests/agent_ui_test.cpp) plus the
 * Drogon behaviours the civetweb port reproduces. */
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sb/agent_config.h"
#include "sb/agent_ui.h"
#include "sb/http_client.h"
#include "sb/json.h"
#include "sb/util.h"

/* ---- temporary UI directory ------------------------------------------- */

static char *make_ui_directory(void) {
    char tmpl[] = "/tmp/sb-easy-agent-ui-XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) abort();
    char *path = sb_strdup(dir);
    char *assets = sb_path_join(path, "assets");
    sb_mkdirs(assets, 0755);
    char *index = sb_path_join(path, "index.html");
    const char *html = "<!doctype html><title>External Agent UI</title>"
                       "<main>sb-easy Svelte UI fixture</main>";
    sb_write_file(index, html, strlen(html));
    char *app = sb_path_join(assets, "app.js");
    const char *js = "document.documentElement.dataset.ui='external';";
    sb_write_file(app, js, strlen(js));
    free(app);
    free(index);
    free(assets);
    return path;
}

static void remove_directory(const char *path) {
    char *command = sb_asprintf("rm -rf '%s'", path);
    if (system(command) != 0) {
    }
    free(command);
}

/* ---- fixture callbacks --------------------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    sbj *settings;
    sbj *config;
    char *requested_action;
    char *tested_url;
    char *selected_group;
    char *selected_proxy;
} fixture_state;

static sbj *cb_status(void *user, sb_err *err) {
    (void)user;
    (void)err;
    return sbj_parse_cstr("{\"running\":true,\"server\":\"https://panel.example\","
                          "\"rule_source\":\"quickjs\",\"telemetry\":{\"available\":true,"
                          "\"sampled_at\":\"2026-07-31T10:00:00Z\",\"up\":1024,\"down\":2048,"
                          "\"up_total\":4096,\"down_total\":8192,\"conn_count\":3}}");
}

static sbj *cb_settings(void *user, sb_err *err) {
    (void)err;
    fixture_state *state = user;
    pthread_mutex_lock(&state->mutex);
    sbj *copy = sbj_clone(state->settings);
    pthread_mutex_unlock(&state->mutex);
    return copy;
}

static sbj *cb_update_settings(const sbj *value, void *user, sb_err *err) {
    fixture_state *state = user;
    sb_agent_config_options parsed;
    if (sb_agent_config_options_from_json(value, NULL, &parsed, err) != 0) return NULL;
    sbj *json = sb_agent_config_options_to_json(&parsed);
    sb_agent_config_options_free(&parsed);
    pthread_mutex_lock(&state->mutex);
    sbj_free(state->settings);
    state->settings = sbj_clone(json);
    pthread_mutex_unlock(&state->mutex);
    return json;
}

static sbj *cb_config(void *user, sb_err *err) {
    (void)err;
    fixture_state *state = user;
    return sbj_clone(state->config);
}

static sbj *cb_proxies(void *user, sb_err *err) {
    (void)user;
    (void)err;
    return sbj_parse_cstr(
        "{\"proxies\":{\"Proxy\":{\"type\":\"Selector\",\"now\":\"node-a\","
        "\"all\":[\"node-a\",\"Auto\"]},\"Auto\":{\"type\":\"URLTest\",\"now\":\"node-a\","
        "\"all\":[\"node-a\"]},\"node-a\":{\"type\":\"Shadowsocks\",\"history\":"
        "[{\"time\":\"2026-08-10T00:00:00Z\",\"delay\":36}]}}}");
}

static sbj *cb_select_proxy(const char *group, const char *proxy, void *user, sb_err *err) {
    (void)err;
    fixture_state *state = user;
    pthread_mutex_lock(&state->mutex);
    sb_str_set(&state->selected_group, group);
    sb_str_set(&state->selected_proxy, proxy);
    pthread_mutex_unlock(&state->mutex);
    sbj *result = sbj_object();
    sbj_set_bool(result, "success", true);
    sbj_set_str(result, "group", group);
    sbj_set_str(result, "name", proxy);
    return result;
}

static sbj *cb_test_route(const char *url, void *user, sb_err *err) {
    fixture_state *state = user;
    if (strcmp(url, "explode") == 0) {
        sb_fail(err, SB_ERR_GENERIC, "route test exploded");
        return NULL;
    }
    if (strcmp(url, "invalid") == 0) {
        sb_fail(err, SB_ERR_VALIDATION, "只支持 http:// 或 https:// URL");
        return NULL;
    }
    pthread_mutex_lock(&state->mutex);
    sb_str_set(&state->tested_url, url);
    pthread_mutex_unlock(&state->mutex);
    sbj *result = sbj_parse_cstr(
        "{\"success\":true,\"host\":\"example.com\",\"port\":443,\"kind\":\"proxy\","
        "\"outbound\":\"node-a\",\"chains\":[\"node-a\",\"Proxy\"],"
        "\"rule\":\"domain_suffix=example.com => route(Proxy)\",\"rule_payload\":\"\"}");
    sbj_set_str(result, "url", url);
    return result;
}

static int cb_request_action(const char *action, void *user, sb_err *err) {
    (void)err;
    fixture_state *state = user;
    pthread_mutex_lock(&state->mutex);
    sb_str_set(&state->requested_action, action);
    pthread_mutex_unlock(&state->mutex);
    return 0;
}

static sb_agent_ui_callbacks fixture_callbacks(fixture_state *state) {
    sb_agent_ui_callbacks callbacks = {
        .status = cb_status,
        .settings = cb_settings,
        .update_settings = cb_update_settings,
        .config = cb_config,
        .proxies = cb_proxies,
        .select_proxy = cb_select_proxy,
        .test_route = cb_test_route,
        .request_action = cb_request_action,
        .user = state,
    };
    return callbacks;
}

static void fixture_state_init(fixture_state *state) {
    memset(state, 0, sizeof *state);
    pthread_mutex_init(&state->mutex, NULL);
    sb_agent_config_options defaults;
    sb_agent_config_options_init(&defaults);
    state->settings = sb_agent_config_options_to_json(&defaults);
    sb_agent_config_options_free(&defaults);
    state->config = sbj_parse_cstr(
        "{\"outbounds\":[{\"tag\":\"Proxy\",\"type\":\"selector\",\"outbounds\":[\"node-a\"],"
        "\"default\":\"node-a\"},{\"tag\":\"node-a\",\"type\":\"shadowsocks\"}],"
        "\"route\":{\"final\":\"Proxy\"}}");
}

static void fixture_state_free(fixture_state *state) {
    sbj_free(state->settings);
    sbj_free(state->config);
    free(state->requested_action);
    free(state->tested_url);
    free(state->selected_group);
    free(state->selected_proxy);
    pthread_mutex_destroy(&state->mutex);
}

/* ---- HTTP client with a one-cookie jar ----------------------------------- */

typedef struct {
    uint16_t port;
    char *cookie; /* current sb_easy_agent_session value, "" when none */
} client;

typedef struct {
    long status;
    char *body;
    size_t body_len;
    sbj *json;
    char *content_type;
    char *frame_options;
    char *cache_control;
    char *content_security_policy;
    char *set_cookie; /* raw Set-Cookie header or NULL */
} ui_response;

static void ui_response_free(ui_response *r) {
    free(r->body);
    sbj_free(r->json);
    free(r->content_type);
    free(r->frame_options);
    free(r->cache_control);
    free(r->content_security_policy);
    free(r->set_cookie);
    memset(r, 0, sizeof *r);
}

/* Session cookie value from a Set-Cookie header (NULL if another cookie). */
static char *cookie_value(const char *set_cookie) {
    const char *prefix = "sb_easy_agent_session=";
    if (!set_cookie || !sb_starts_with(set_cookie, prefix)) return NULL;
    const char *value = set_cookie + strlen(prefix);
    return sb_strndup(value, strcspn(value, ";"));
}

enum { MARK_AUTO, MARK_NEVER, MARK_ALWAYS };

static ui_response request_ex(client *c, const char *method, const char *path, const char *body,
                              int mark) {
    ui_response out;
    memset(&out, 0, sizeof out);
    sb_strvec headers = {0};
    bool write = strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0;
    if (mark == MARK_ALWAYS || (mark == MARK_AUTO && write)) sb_strvec_push(&headers, "X-SB-Easy-UI: 1");
    if (body) sb_strvec_push(&headers, "Content-Type: application/json");
    if (c->cookie && *c->cookie)
        sb_strvec_push_take(&headers, sb_asprintf("Cookie: sb_easy_agent_session=%s", c->cookie));
    sb_strvec_push_take(&headers, NULL);
    char *url = sb_asprintf("http://127.0.0.1:%u%s", (unsigned)c->port, path);
    sb_http_request req = {0};
    req.method = method;
    req.url = url;
    req.headers = (const char *const *)headers.items;
    req.body = body;
    req.body_len = body ? strlen(body) : 0;
    req.timeout_ms = 5000;
    sb_http_response resp;
    sb_err err = {0};
    int rc = sb_http_perform(&req, &resp, &err);
    free(url);
    sb_strvec_free(&headers);
    if (rc != 0) {
        fprintf(stderr, "request %s %s failed: %s\n", method, path, err.msg);
        out.status = -1;
        return out;
    }
    out.status = resp.status;
    out.body = resp.body;
    out.body_len = resp.body_len;
    resp.body = NULL;
    out.content_type = sb_http_response_header(&resp, "Content-Type");
    out.frame_options = sb_http_response_header(&resp, "X-Frame-Options");
    out.cache_control = sb_http_response_header(&resp, "Cache-Control");
    out.content_security_policy = sb_http_response_header(&resp, "Content-Security-Policy");
    out.set_cookie = sb_http_response_header(&resp, "Set-Cookie");
    sb_http_response_free(&resp);
    if (out.body_len) out.json = sbj_parse(out.body, out.body_len, NULL, 0);
    char *value = cookie_value(out.set_cookie);
    if (value) {
        free(c->cookie);
        c->cookie = value;
    }
    return out;
}

static ui_response request(client *c, const char *method, const char *path, const char *body) {
    return request_ex(c, method, path, body, MARK_AUTO);
}

/* Sends a literal request (no client-side normalisation) and returns the
 * whole raw response. */
static char *raw_request(uint16_t port, const char *text) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        close(fd);
        return NULL;
    }
    size_t len = strlen(text), sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, text + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    sb_buf out = {0};
    char chunk[4096];
    ssize_t n;
    while ((n = recv(fd, chunk, sizeof chunk, 0)) > 0) sb_buf_append(&out, chunk, (size_t)n);
    close(fd);
    return sb_buf_detach(&out);
}

static const char *json_str(const sbj *value, const char *key) {
    return sbj_get_str(value, key, "(missing)");
}

/* ---- tests -------------------------------------------------------------- */

TEST(agent_ui_contract) {
    char *ui_directory = make_ui_directory();
    fixture_state state;
    fixture_state_init(&state);
    sb_agent_ui_callbacks callbacks = fixture_callbacks(&state);
    sb_agent_ui_options options = {
        .address = "127.0.0.1",
        .port = 0,
        .username = "local-admin",
        .password = "contract-password",
        .ui_directory = ui_directory,
    };
    sb_err err = {0};
    sb_agent_ui *ui = sb_agent_ui_new(&options, &callbacks, &err);
    if (!ui) fprintf(stderr, "sb_agent_ui_new: %s\n", err.msg);
    REQUIRE(ui != NULL);
    REQUIRE(sb_agent_ui_port(ui) != 0);
    client c = {.port = sb_agent_ui_port(ui), .cookie = sb_strdup("")};

    /* Agent UI health endpoint should remain available without credentials. */
    ui_response health = request(&c, "GET", "/health", NULL);
    CHECK_EQ_INT(health.status, 200);
    CHECK_STR(json_str(health.json, "service"), "sb-easy-agent-ui");
    CHECK_STR(json_str(health.json, "status"), "ok");
    ui_response_free(&health);

    /* Agent should serve the external UI shell without embedding it. */
    ui_response unauthorized = request(&c, "GET", "/", NULL);
    CHECK_EQ_INT(unauthorized.status, 200);
    CHECK_CONTAINS(unauthorized.body, "sb-easy Svelte UI fixture");
    ui_response_free(&unauthorized);

    /* Agent APIs should still require a local session. */
    ui_response unauthorized_api = request(&c, "GET", "/api/status", NULL);
    CHECK_EQ_INT(unauthorized_api.status, 401);
    CHECK_STR(json_str(unauthorized_api.json, "error"), "本地管理会话已失效，请重新登录");
    ui_response_free(&unauthorized_api);

    /* SPA routes should fall back to the configured external index. */
    ui_response login_page = request(&c, "GET", "/login", NULL);
    CHECK_EQ_INT(login_page.status, 200);
    CHECK_CONTAINS(login_page.content_type, "text/html");
    CHECK_CONTAINS(login_page.body, "sb-easy Svelte UI fixture");
    ui_response_free(&login_page);

    /* Agent should serve assets from the configured UI path. */
    ui_response static_asset = request(&c, "GET", "/assets/app.js", NULL);
    CHECK_EQ_INT(static_asset.status, 200);
    CHECK_CONTAINS(static_asset.body, "dataset.ui='external'");
    CHECK_STR(static_asset.content_type, "text/javascript; charset=utf-8");
    CHECK_STR(static_asset.cache_control, "public, max-age=31536000, immutable");
    ui_response_free(&static_asset);

    /* Agent UI should reject invalid login credentials. */
    ui_response invalid_login = request(&c, "POST", "/api/login",
                                        "{\"username\":\"local-admin\",\"password\":\"wrong\"}");
    CHECK_EQ_INT(invalid_login.status, 401);
    CHECK(invalid_login.set_cookie == NULL);
    CHECK_STR(json_str(invalid_login.json, "error"), "用户名或密码错误");
    CHECK_STR(c.cookie, "");
    ui_response_free(&invalid_login);

    /* Agent UI login should issue an HttpOnly SameSite session cookie. */
    ui_response login = request(
        &c, "POST", "/api/login",
        "{\"username\":\"local-admin\",\"password\":\"contract-password\"}");
    CHECK_EQ_INT(login.status, 200);
    CHECK(c.cookie && strlen(c.cookie) == 64);
    CHECK_CONTAINS(login.set_cookie, "HttpOnly");
    CHECK_CONTAINS(login.set_cookie, "SameSite=Strict");
    CHECK_CONTAINS(login.set_cookie, "Max-Age=43200");
    CHECK_CONTAINS(login.set_cookie, "Path=/");
    CHECK(sbj_get_bool(login.json, "authenticated", false));
    CHECK_STR(json_str(login.json, "username"), "local-admin");
    ui_response_free(&login);

    /* Authenticated users should receive the secured external UI shell. */
    ui_response root = request(&c, "GET", "/", NULL);
    CHECK_EQ_INT(root.status, 200);
    CHECK_CONTAINS(root.content_type, "text/html");
    CHECK_CONTAINS(root.body, "sb-easy Svelte UI fixture");
    CHECK_STR(root.frame_options, "DENY");
    CHECK_STR(root.cache_control, "no-cache");
    ui_response_free(&root);

    /* Agent UI should expose runtime status. */
    ui_response status = request(&c, "GET", "/api/status", NULL);
    CHECK_EQ_INT(status.status, 200);
    CHECK(sbj_get_bool(status.json, "running", false));
    CHECK_EQ_INT(sbj_get_int(sbj_get(status.json, "telemetry"), "down", 0), 2048);
    CHECK_STR(status.content_type, "application/json; charset=utf-8");
    CHECK_STR(status.cache_control, "no-store");
    CHECK_STR(status.frame_options, "DENY");
    CHECK_STR(status.content_security_policy,
              "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; "
              "img-src 'self' data:; frame-ancestors 'none'");
    ui_response_free(&status);

    /* Agent UI should validate and update local settings. */
    ui_response updated = request(
        &c, "PUT", "/api/settings",
        "{\"local_proxy_egress\":false,\"default_proxy_outbound\":\"node-a\","
        "\"outbound_server_overrides\":{},\"outbound_overrides\":{}}");
    CHECK_EQ_INT(updated.status, 200);
    CHECK(!sbj_get_bool(updated.json, "local_proxy_egress", true));
    CHECK_STR(sbj_get_str(state.settings, "default_proxy_outbound", NULL), "node-a");
    ui_response_free(&updated);

    /* Agent UI should reject invalid setting types. */
    ui_response invalid = request(&c, "PUT", "/api/settings",
                                  "{\"outbound_server_overrides\":{\"node-a\":42}}");
    CHECK_EQ_INT(invalid.status, 400);
    CHECK_STR(json_str(invalid.json, "error"),
              "outbound_server_overrides values must be non-empty strings");
    ui_response_free(&invalid);

    /* Agent UI should queue authenticated runtime actions. */
    ui_response action = request(&c, "POST", "/api/actions/restart", NULL);
    CHECK_EQ_INT(action.status, 200);
    CHECK(sbj_get_bool(action.json, "accepted", false));
    CHECK_STR(json_str(action.json, "action"), "restart");
    CHECK_STR(state.requested_action, "restart");
    ui_response_free(&action);

    /* Agent UI should expose the current local config to authenticated users. */
    ui_response raw_config = request(&c, "GET", "/api/config", NULL);
    CHECK_EQ_INT(raw_config.status, 200);
    CHECK(raw_config.json && sbj_equal(raw_config.json, state.config));
    ui_response_free(&raw_config);

    /* Agent UI should expose live proxy groups and their current selection. */
    ui_response proxies = request(&c, "GET", "/api/proxies", NULL);
    CHECK_EQ_INT(proxies.status, 200);
    CHECK_STR(json_str(sbj_get(sbj_get(proxies.json, "proxies"), "Proxy"), "now"), "node-a");
    ui_response_free(&proxies);

    /* Agent UI should pass proxy group selections to the local Clash callback. */
    ui_response switched =
        request(&c, "PUT", "/api/proxies", "{\"group\":\"Proxy\",\"name\":\"Auto\"}");
    CHECK_EQ_INT(switched.status, 200);
    CHECK(sbj_get_bool(switched.json, "success", false));
    CHECK_STR(state.selected_group, "Proxy");
    CHECK_STR(state.selected_proxy, "Auto");
    ui_response_free(&switched);

    /* Agent UI should reject a proxy switch without a node name. */
    ui_response invalid_switch = request(&c, "PUT", "/api/proxies", "{\"group\":\"Proxy\"}");
    CHECK_EQ_INT(invalid_switch.status, 400);
    CHECK_STR(json_str(invalid_switch.json, "error"), "请选择有效的策略组和节点");
    ui_response_free(&invalid_switch);

    /* Agent UI should return the actual route test callback result. */
    ui_response route_test =
        request(&c, "POST", "/api/route-test", "{\"url\":\"https://example.com/path\"}");
    CHECK_EQ_INT(route_test.status, 200);
    CHECK_STR(json_str(route_test.json, "outbound"), "node-a");
    CHECK_STR(json_str(route_test.json, "kind"), "proxy");
    CHECK_STR(state.tested_url, "https://example.com/path");
    ui_response_free(&route_test);

    /* Agent UI should reject a route test without a URL. */
    ui_response invalid_route_test = request(&c, "POST", "/api/route-test", "{}");
    CHECK_EQ_INT(invalid_route_test.status, 400);
    CHECK_STR(json_str(invalid_route_test.json, "error"), "请输入要测试的 URL");
    ui_response_free(&invalid_route_test);

    /* Agent UI should accept an authenticated logout. */
    ui_response logout = request(&c, "POST", "/api/logout", NULL);
    CHECK_EQ_INT(logout.status, 200);
    CHECK(!sbj_get_bool(logout.json, "authenticated", true));
    CHECK_CONTAINS(logout.set_cookie, "sb_easy_agent_session=; Max-Age=0");
    ui_response_free(&logout);

    /* External UI shell should remain available after logout. */
    ui_response after_logout = request(&c, "GET", "/", NULL);
    CHECK_EQ_INT(after_logout.status, 200);
    ui_response_free(&after_logout);

    /* Agent UI logout should revoke the local API session. */
    ui_response api_after_logout = request(&c, "GET", "/api/status", NULL);
    CHECK_EQ_INT(api_after_logout.status, 401);
    ui_response_free(&api_after_logout);

    free(c.cookie);
    sb_agent_ui_free(ui);
    fixture_state_free(&state);
    remove_directory(ui_directory);
    free(ui_directory);
}

/* Revoked sessions stay revoked even when the old cookie is replayed, and the
 * UI marker / JSON / size / routing rules match the Drogon build. */
TEST(agent_ui_request_rules) {
    char *ui_directory = make_ui_directory();
    fixture_state state;
    fixture_state_init(&state);
    sb_agent_ui_callbacks callbacks = fixture_callbacks(&state);
    sb_agent_ui_options options = {
        .address = "127.0.0.1",
        .port = 0,
        .username = "admin",
        .password = "pw",
        .ui_directory = ui_directory,
    };
    sb_err err = {0};
    sb_agent_ui *ui = sb_agent_ui_new(&options, &callbacks, &err);
    REQUIRE(ui != NULL);
    client c = {.port = sb_agent_ui_port(ui), .cookie = sb_strdup("")};

    /* Login requires the local UI request marker. */
    ui_response unmarked = request_ex(&c, "POST", "/api/login",
                                      "{\"username\":\"admin\",\"password\":\"pw\"}", MARK_NEVER);
    CHECK_EQ_INT(unmarked.status, 403);
    CHECK_STR(json_str(unmarked.json, "error"), "缺少本地管理界面请求标记");
    ui_response_free(&unmarked);

    /* Malformed JSON and non-object bodies. */
    ui_response malformed = request(&c, "POST", "/api/login", "{nope");
    CHECK_EQ_INT(malformed.status, 400);
    CHECK_CONTAINS(json_str(malformed.json, "error"), "无效的 JSON 请求：[json.exception.parse_error.101]");
    ui_response_free(&malformed);
    ui_response empty = request(&c, "POST", "/api/login", NULL);
    CHECK_EQ_INT(empty.status, 400);
    CHECK_STR(json_str(empty.json, "error"),
              "无效的 JSON 请求：[json.exception.parse_error.101] parse error at line 1, column 1: "
              "attempting to parse an empty input; check that your input string or stream "
              "contains the expected JSON");
    ui_response_free(&empty);
    ui_response array = request(&c, "POST", "/api/login", "[]");
    CHECK_EQ_INT(array.status, 400);
    CHECK_STR(json_str(array.json, "error"), "登录请求必须是 JSON 对象");
    ui_response_free(&array);
    ui_response typed = request(&c, "POST", "/api/login", "{\"username\":1}");
    CHECK_EQ_INT(typed.status, 400);
    CHECK_STR(json_str(typed.json, "error"),
              "无效的 JSON 请求：[json.exception.type_error.302] type must be string, but is number");
    ui_response_free(&typed);

    /* The session guard is case-insensitive like Drogon's router. */
    ui_response upper = request(&c, "GET", "/API/STATUS", NULL);
    CHECK_EQ_INT(upper.status, 401);
    ui_response_free(&upper);

    ui_response login =
        request(&c, "POST", "/api/login", "{\"username\":\"admin\",\"password\":\"pw\"}");
    CHECK_EQ_INT(login.status, 200);
    ui_response_free(&login);
    char *old_cookie = sb_strdup(c.cookie);

    ui_response upper_ok = request(&c, "GET", "/API/Status", NULL);
    CHECK_EQ_INT(upper_ok.status, 200);
    ui_response_free(&upper_ok);

    /* Mutating API calls need the marker even with a valid session. */
    ui_response unmarked_action =
        request_ex(&c, "POST", "/api/actions/reload", NULL, MARK_NEVER);
    CHECK_EQ_INT(unmarked_action.status, 403);
    CHECK(state.requested_action == NULL);
    ui_response_free(&unmarked_action);

    /* Wrong method on a known route: 405; unknown API route: JSON 404. */
    ui_response wrong_method = request(&c, "GET", "/api/actions/reload", NULL);
    CHECK_EQ_INT(wrong_method.status, 405);
    ui_response_free(&wrong_method);
    ui_response unknown = request(&c, "GET", "/api/unknown", NULL);
    CHECK_EQ_INT(unknown.status, 404);
    CHECK_STR(json_str(unknown.json, "error"), "API route not found");
    ui_response_free(&unknown);
    ui_response unknown_delete = request(&c, "DELETE", "/api/status/x", NULL);
    CHECK_EQ_INT(unknown_delete.status, 403); /* DELETE without the marker */
    ui_response_free(&unknown_delete);
    ui_response unknown_marked = request_ex(&c, "DELETE", "/api/status/x", NULL, MARK_ALWAYS);
    CHECK_EQ_INT(unknown_marked.status, 404);
    ui_response_free(&unknown_marked);

    /* Callback errors map like the C++ handle_response(). */
    ui_response exploded = request(&c, "POST", "/api/route-test", "{\"url\":\"explode\"}");
    CHECK_EQ_INT(exploded.status, 500);
    CHECK_STR(json_str(exploded.json, "error"), "route test exploded");
    ui_response_free(&exploded);
    ui_response rejected = request(&c, "POST", "/api/route-test", "{\"url\":\"invalid\"}");
    CHECK_EQ_INT(rejected.status, 400);
    ui_response_free(&rejected);

    /* Size limits: 8 KiB for proxy switches, 512 KiB for any body. */
    char *large = sb_xmalloc(9000);
    memset(large, ' ', 8999);
    large[0] = '{';
    large[8997] = '}';
    large[8998] = '\0';
    ui_response too_large = request(&c, "PUT", "/api/proxies", large);
    CHECK_EQ_INT(too_large.status, 413);
    CHECK_STR(json_str(too_large.json, "error"), "节点切换请求过大");
    ui_response_free(&too_large);
    ui_response route_large = request(&c, "POST", "/api/route-test", large);
    CHECK_EQ_INT(route_large.status, 413);
    CHECK_STR(json_str(route_large.json, "error"), "路由测试请求过大");
    ui_response_free(&route_large);
    free(large);
    char *huge = sb_xmalloc(600 * 1024);
    memset(huge, ' ', 600 * 1024 - 1);
    huge[0] = '{';
    huge[600 * 1024 - 2] = '}';
    huge[600 * 1024 - 1] = '\0';
    ui_response settings_huge = request(&c, "PUT", "/api/settings", huge);
    CHECK_EQ_INT(settings_huge.status, 413);
    ui_response_free(&settings_huge);
    free(huge);

    /* HEAD is served like GET without a body. */
    char *head = raw_request(c.port, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(head && sb_starts_with(head, "HTTP/1.1 200 OK\r\n"));
    CHECK_CONTAINS(head, "Content-Type: text/html; charset=utf-8\r\n");
    CHECK(head && sb_ends_with(head, "\r\n\r\n")); /* no body */
    CHECK(head && !strstr(head, "fixture"));
    free(head);

    /* Static resources cannot escape the UI directory (Drogon decodes the
     * path without normalising it, and the handler rejects ".."). */
    char *traversal =
        raw_request(c.port, "GET /assets/%2e%2e/index.html HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(traversal && sb_starts_with(traversal, "HTTP/1.1 404 "));
    CHECK_CONTAINS(traversal, "{\"error\":\"Static resource not found\"}");
    free(traversal);
    char *dotted = raw_request(c.port, "GET /assets/../index.html HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(dotted && sb_starts_with(dotted, "HTTP/1.1 404 "));
    free(dotted);
    ui_response missing_asset = request(&c, "GET", "/assets/missing.js", NULL);
    CHECK_EQ_INT(missing_asset.status, 404);
    ui_response_free(&missing_asset);
    ui_response missing_file = request(&c, "GET", "/favicon.ico", NULL);
    CHECK_EQ_INT(missing_file.status, 404);
    CHECK_STR(json_str(missing_file.json, "error"), "Static resource not found");
    ui_response_free(&missing_file);
    ui_response index = request(&c, "GET", "/index.html", NULL);
    CHECK_EQ_INT(index.status, 200);
    CHECK_STR(index.cache_control, "no-cache");
    ui_response_free(&index);

    /* Cookies are parsed like Drogon: no space after ';', several Cookie
     * headers (last wins), case-sensitive names. */
    char *cookie_request = sb_asprintf(
        "GET /api/status HTTP/1.1\r\nHost: x\r\nCookie: a=1;sb_easy_agent_session=%s\r\n\r\n",
        c.cookie);
    char *cookie_response = raw_request(c.port, cookie_request);
    CHECK(cookie_response && sb_starts_with(cookie_response, "HTTP/1.1 200 "));
    free(cookie_response);
    free(cookie_request);
    cookie_request = sb_asprintf("GET /api/status HTTP/1.1\r\nHost: x\r\n"
                                 "Cookie: sb_easy_agent_session=stale\r\n"
                                 "Cookie: other=2; sb_easy_agent_session=%s \r\n\r\n",
                                 c.cookie);
    cookie_response = raw_request(c.port, cookie_request);
    CHECK(cookie_response && sb_starts_with(cookie_response, "HTTP/1.1 200 "));
    free(cookie_response);
    free(cookie_request);
    cookie_request = sb_asprintf(
        "GET /api/status HTTP/1.1\r\nHost: x\r\nCookie: SB_EASY_AGENT_SESSION=%s\r\n\r\n",
        c.cookie);
    cookie_response = raw_request(c.port, cookie_request);
    CHECK(cookie_response && sb_starts_with(cookie_response, "HTTP/1.1 401 "));
    free(cookie_response);
    free(cookie_request);

    /* Oversized bodies get Drogon's bare parser response. */
    char *oversized = raw_request(c.port, "PUT /api/settings HTTP/1.1\r\nHost: x\r\n"
                                          "Content-Length: 600000\r\n\r\n{}");
    CHECK_STR(oversized, "HTTP/1.1 413 Request Entity Too Large\r\nConnection: close\r\n\r\n");
    free(oversized);

    /* A revoked session cannot be replayed. */
    ui_response logout = request(&c, "POST", "/api/logout", NULL);
    CHECK_EQ_INT(logout.status, 200);
    ui_response_free(&logout);
    sb_str_set(&c.cookie, old_cookie);
    ui_response replay = request(&c, "GET", "/api/status", NULL);
    CHECK_EQ_INT(replay.status, 401);
    ui_response_free(&replay);

    free(old_cookie);
    free(c.cookie);
    sb_agent_ui_free(ui);
    fixture_state_free(&state);
    remove_directory(ui_directory);
    free(ui_directory);
}

TEST(agent_ui_without_static_directory) {
    fixture_state state;
    fixture_state_init(&state);
    sb_agent_ui_callbacks callbacks = fixture_callbacks(&state);
    sb_agent_ui_options options;
    sb_agent_ui_options_init(&options);
    options.address = "127.0.0.1";
    options.port = 0;
    options.password = "pw";
    sb_err err = {0};
    sb_agent_ui *ui = sb_agent_ui_new(&options, &callbacks, &err);
    REQUIRE(ui != NULL);
    client c = {.port = sb_agent_ui_port(ui), .cookie = sb_strdup("")};

    ui_response root = request(&c, "GET", "/", NULL);
    CHECK_EQ_INT(root.status, 404);
    CHECK_STR(json_str(root.json, "error"),
              "No Agent UI path is configured; use the JSON API or set AGENT_UI_PATH");
    ui_response_free(&root);

    ui_response login =
        request(&c, "POST", "/api/login", "{\"username\":\"admin\",\"password\":\"pw\"}");
    CHECK_EQ_INT(login.status, 200);
    ui_response_free(&login);
    ui_response status = request(&c, "GET", "/api/status", NULL);
    CHECK_EQ_INT(status.status, 200);
    ui_response_free(&status);
    ui_response health = request(&c, "GET", "/health", NULL);
    CHECK_EQ_INT(health.status, 200);
    ui_response_free(&health);

    free(c.cookie);
    sb_agent_ui_free(ui);
    fixture_state_free(&state);
}

TEST(agent_ui_option_validation) {
    fixture_state state;
    fixture_state_init(&state);
    sb_agent_ui_callbacks callbacks = fixture_callbacks(&state);
    sb_agent_ui_options options;
    sb_err err = {0};

    sb_agent_ui_options_init(&options);
    CHECK_STR(options.address, "0.0.0.0");
    CHECK_EQ_INT(options.port, 51822);
    CHECK_STR(options.username, "admin");
    options.port = 0;
    CHECK(sb_agent_ui_new(&options, &callbacks, &err) == NULL);
    CHECK_STR(err.msg, "Agent UI password must not be empty");
    CHECK(err.code == SB_ERR_VALIDATION);

    options.password = "pw";
    options.address = "";
    CHECK(sb_agent_ui_new(&options, &callbacks, &err) == NULL);
    CHECK_STR(err.msg, "Agent UI address must not be empty");

    options.address = "127.0.0.1";
    options.username = "";
    CHECK(sb_agent_ui_new(&options, &callbacks, &err) == NULL);
    CHECK_STR(err.msg, "Agent UI username must not be empty");

    options.username = "a:b";
    CHECK(sb_agent_ui_new(&options, &callbacks, &err) == NULL);
    CHECK_STR(err.msg, "Agent UI username must not contain ':'");

    options.username = "admin";
    options.ui_directory = "/nonexistent/sb-easy-agent-ui";
    CHECK(sb_agent_ui_new(&options, &callbacks, &err) == NULL);
    CHECK_STR(err.msg, "Agent UI path must contain a readable index.html: "
                       "/nonexistent/sb-easy-agent-ui");

    options.ui_directory = NULL;
    sb_agent_ui_callbacks incomplete = callbacks;
    incomplete.test_route = NULL;
    CHECK(sb_agent_ui_new(&options, &incomplete, &err) == NULL);
    CHECK_STR(err.msg, "all Agent UI callbacks are required");

    /* A port that is already bound fails cleanly. */
    sb_agent_ui *first = sb_agent_ui_new(&options, &callbacks, &err);
    REQUIRE(first != NULL);
    options.port = sb_agent_ui_port(first);
    sb_agent_ui *second = sb_agent_ui_new(&options, &callbacks, &err);
    CHECK(second == NULL);
    CHECK_STR(err.msg, "Agent UI HTTP listener did not start");
    sb_agent_ui_free(second);
    sb_agent_ui_free(first);
    fixture_state_free(&state);
}
