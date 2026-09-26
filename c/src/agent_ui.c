/* Password-protected local Agent API + optional static UI directory (port of
 * cpp/src/agent_ui.cpp; Drogon replaced by civetweb).
 *
 * Routing mirrors what Drogon does with the C++ registrations:
 *   - HEAD is routed as GET and answered without a body;
 *   - exact routes match the lower-cased path (Drogon is case-insensitive),
 *     a known path with another method is 405 (OPTIONS: 403);
 *   - the regex routes are tried in registration order and only for the
 *     methods they were registered with, case-insensitively;
 *   - nothing matched -> 404 HTML page.
 * The pre-routing session advice deliberately compares the path
 * case-insensitively: Drogon routes /API/status to the status handler while
 * the C++ advice only guards the lower-case "/api/" prefix. */
#include "sb/agent_ui.h"

#include <civetweb.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

#define MAXIMUM_SETTINGS_BODY_SIZE ((size_t)512u * 1024u)
#define MAXIMUM_SMALL_BODY_SIZE ((size_t)8u * 1024u)
#define SESSION_COOKIE_NAME "sb_easy_agent_session"
#define SESSION_DURATION_MS ((int64_t)12 * 60 * 60 * 1000)
#define JSON_CONTENT_TYPE "application/json; charset=utf-8"
#define CONTENT_SECURITY_POLICY                                                    \
    "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; " \
    "img-src 'self' data:; frame-ancestors 'none'"

typedef struct {
    char *token;
    int64_t expires_ms; /* monotonic */
} session;

struct sb_agent_ui {
    struct mg_context *context;
    uint16_t port;
    char *username;
    char *password;
    char *ui_directory; /* NULL -> API only */
    sb_agent_ui_callbacks callbacks;
    pthread_mutex_t mutex; /* guards sessions */
    /* Drogon ran every handler on its single IO thread (setThreadNum(1));
     * civetweb reads requests on several workers but handlers stay serial. */
    pthread_mutex_t handler_mutex;
    session *sessions;
    size_t session_len, session_cap;
};

void sb_agent_ui_options_init(sb_agent_ui_options *options) {
    options->address = "0.0.0.0";
    options->port = 51822;
    options->username = "admin";
    options->password = "";
    options->ui_directory = NULL;
}

/* ---- AuthenticationState ---------------------------------------------- */

static void remove_expired_locked(sb_agent_ui *ui, int64_t now) {
    size_t kept = 0;
    for (size_t i = 0; i < ui->session_len; ++i) {
        if (ui->sessions[i].expires_ms <= now) {
            free(ui->sessions[i].token);
        } else {
            ui->sessions[kept++] = ui->sessions[i];
        }
    }
    ui->session_len = kept;
}

/* Returns a malloc'd session token, or NULL for wrong credentials. */
static char *session_login(sb_agent_ui *ui, const char *username, const char *password) {
    if (!sb_consttime_streq(username, ui->username) ||
        !sb_consttime_streq(password, ui->password))
        return NULL;
    char *token = sb_random_hex(32);
    int64_t expires = sb_monotonic_ms() + SESSION_DURATION_MS;
    pthread_mutex_lock(&ui->mutex);
    remove_expired_locked(ui, sb_monotonic_ms());
    bool replaced = false;
    for (size_t i = 0; i < ui->session_len && !replaced; ++i) {
        if (strcmp(ui->sessions[i].token, token) == 0) {
            ui->sessions[i].expires_ms = expires;
            replaced = true;
        }
    }
    if (!replaced) {
        if (ui->session_len == ui->session_cap) {
            ui->session_cap = ui->session_cap ? ui->session_cap * 2 : 8;
            ui->sessions = sb_xrealloc(ui->sessions, ui->session_cap * sizeof *ui->sessions);
        }
        ui->sessions[ui->session_len].token = sb_strdup(token);
        ui->sessions[ui->session_len].expires_ms = expires;
        ++ui->session_len;
    }
    pthread_mutex_unlock(&ui->mutex);
    return token;
}

static bool session_authenticated(sb_agent_ui *ui, const char *token) {
    if (sb_str_empty(token)) return false;
    int64_t now = sb_monotonic_ms();
    bool found = false;
    pthread_mutex_lock(&ui->mutex);
    remove_expired_locked(ui, now);
    for (size_t i = 0; i < ui->session_len && !found; ++i)
        found = strcmp(ui->sessions[i].token, token) == 0 && ui->sessions[i].expires_ms > now;
    pthread_mutex_unlock(&ui->mutex);
    return found;
}

static void session_logout(sb_agent_ui *ui, const char *token) {
    if (sb_str_empty(token)) return;
    pthread_mutex_lock(&ui->mutex);
    for (size_t i = 0; i < ui->session_len; ++i) {
        if (strcmp(ui->sessions[i].token, token) == 0) {
            free(ui->sessions[i].token);
            ui->sessions[i] = ui->sessions[--ui->session_len];
            break;
        }
    }
    pthread_mutex_unlock(&ui->mutex);
}

/* ---- request / response ----------------------------------------------- */

typedef struct {
    struct mg_connection *conn;
    const char *method; /* HEAD already mapped to GET */
    bool head;
    char *path;         /* Drogon-decoded path; may contain NUL bytes */
    size_t path_len;
    char *lower;        /* lower-cased copy of path */
    const char *body;
    size_t body_len;
} request;

typedef struct {
    int status;
    char *body;
    size_t body_len;
    const char *content_type; /* NULL -> no Content-Type header */
    const char *cache_control; /* non-NULL -> secure_response() headers */
    char *set_cookie;          /* full cookie value, or NULL */
} response;

static void response_json(response *resp, int status, sbj *body) {
    resp->status = status;
    resp->body = sbj_dump(body, -1);
    resp->body_len = strlen(resp->body);
    resp->content_type = JSON_CONTENT_TYPE;
    resp->cache_control = "no-store";
    sbj_free(body);
}

static void response_error(response *resp, int status, const char *message) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", message);
    response_json(resp, status, body);
}

/* Drogon's default error handler: an empty text/html response. */
static void response_plain(response *resp, int status) {
    resp->status = status;
    resp->body = sb_strdup("");
    resp->body_len = 0;
    resp->content_type = "text/html; charset=utf-8";
}

static void response_not_found_page(response *resp) {
    resp->status = 404;
    resp->body = sb_strdup("<html><head><title>404 Not Found</title></head><body bgcolor=\"white\">"
                           "<center><h1>404 Not Found</h1></center></body></html>");
    resp->body_len = strlen(resp->body);
    resp->content_type = "text/html; charset=utf-8";
}

static const char *status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Request Entity Too Large";
    case 500: return "Internal Server Error";
    default: return "Unknown";
    }
}

static void send_response(struct mg_connection *conn, const response *resp, bool head) {
    sb_buf head_buf = {0};
    sb_buf_printf(&head_buf, "HTTP/1.1 %d %s\r\n", resp->status, status_text(resp->status));
    sb_buf_printf(&head_buf, "Content-Length: %zu\r\n", resp->body_len);
    if (resp->content_type) sb_buf_printf(&head_buf, "Content-Type: %s\r\n", resp->content_type);
    if (resp->cache_control) {
        sb_buf_printf(&head_buf, "Cache-Control: %s\r\n", resp->cache_control);
        sb_buf_puts(&head_buf, "X-Content-Type-Options: nosniff\r\n"
                               "X-Frame-Options: DENY\r\n"
                               "Referrer-Policy: no-referrer\r\n"
                               "Content-Security-Policy: " CONTENT_SECURITY_POLICY "\r\n");
    }
    if (resp->set_cookie) sb_buf_printf(&head_buf, "Set-Cookie: %s\r\n", resp->set_cookie);
    sb_buf_puts(&head_buf, "Connection: close\r\n\r\n");
    mg_write(conn, head_buf.p, head_buf.len);
    sb_buf_free(&head_buf);
    if (!head && resp->body_len) mg_write(conn, resp->body, resp->body_len);
}

/* Drogon Cookie::cookieString() for the session cookie. */
static char *session_cookie(const char *value, int maximum_age_seconds) {
    return sb_asprintf(SESSION_COOKIE_NAME "=%s; Max-Age=%d; Path=/; SameSite=Strict; HttpOnly",
                       value, maximum_age_seconds);
}

/* Drogon getCookie(): "" when absent. malloc'd. */
static char *request_cookie(const request *req) {
    const char *header = mg_get_header(req->conn, "Cookie");
    if (!header) return sb_strdup("");
    size_t size = strlen(header) + 1;
    char *value = sb_xmalloc(size);
    if (mg_get_cookie(header, SESSION_COOKIE_NAME, value, size) < 0) value[0] = '\0';
    return value;
}

static bool ui_header_present(const request *req) {
    const char *value = mg_get_header(req->conn, "x-sb-easy-ui");
    return value && strcmp(value, "1") == 0;
}

/* nlohmann json::parse(body) error text (parse_error.101). */
static int parse_json_body(const request *req, sbj **out, sb_err *err) {
    if (req->body_len == 0)
        return sb_fail(err, SB_ERR_BAD_JSON,
                       "[json.exception.parse_error.101] parse error at line 1, column 1: "
                       "attempting to parse an empty input; check that your input string or "
                       "stream contains the expected JSON");
    const char *text = req->body;
    size_t len = req->body_len;
    if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) {
        text += 3;
        len -= 3;
    }
    char message[256] = {0};
    *out = len ? sbj_parse(text, len, message, sizeof message) : NULL;
    if (!*out)
        return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.parse_error.101] parse error: %s",
                       message[0] ? message : "syntax error");
    return 0;
}

/* nlohmann value(key, std::string{}) on an object; borrowed. */
static int value_string(const sbj *object, const char *key, const char **out, sb_err *err) {
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = "";
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_BAD_JSON,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

/* C++ handle_response() exception mapping. */
static void response_from_error(response *resp, const sb_err *err) {
    if (err->code == SB_ERR_BAD_JSON) {
        char *message = sb_asprintf("无效的 JSON 请求：%s", err->msg);
        response_error(resp, 400, message);
        free(message);
    } else if (err->code == SB_ERR_VALIDATION) {
        response_error(resp, 400, err->msg);
    } else {
        response_error(resp, 500, err->msg);
    }
}

/* Wraps a callback result: value -> 200 JSON, NULL -> mapped error. */
static void response_from_result(response *resp, sbj *value, const sb_err *err) {
    if (value) response_json(resp, 200, value);
    else response_from_error(resp, err);
}

/* ---- static files ----------------------------------------------------- */

static const struct {
    const char *extension;
    const char *mime;
} mime_types[] = {
    {"aac", "audio/aac"}, {"ac3", "audio/ac3"}, {"aif", "audio/aiff"}, {"aifc", "audio/aiff"},
    {"aiff", "audio/aiff"}, {"apg", "video/apg"}, {"ape", "audio/x-ape"}, {"apng", "image/apng"},
    {"av1", "video/av01"}, {"avi", "video/x-msvideo"}, {"avif", "image/avif"}, {"bmp", "image/bmp"},
    {"bz", "application/x-bzip"}, {"bz2", "application/x-bzip2"},
    {"css", "text/css; charset=utf-8"}, {"csv", "text/csv; charset=utf-8"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"eot", "application/vnd.ms-fontobject"}, {"flac", "audio/flac"}, {"gif", "image/gif"},
    {"gz", "application/gzip"}, {"htm", "text/html; charset=utf-8"},
    {"html", "text/html; charset=utf-8"}, {"icns", "image/icns"},
    {"ico", "image/vnd.microsoft.icon"}, {"j2k", "image/jp2"}, {"jar", "application/java-archive"},
    {"j2c", "image/jp2"}, {"jp2", "image/jp2"}, {"jpeg", "image/jpeg"}, {"jpc", "image/jp2"},
    {"jpf", "image/jp2"}, {"jpg", "image/jpeg"}, {"jpg2", "image/jp2"}, {"jpm", "image/jp2"},
    {"jpx", "image/jp2"}, {"js", "text/javascript; charset=utf-8"},
    {"json", "application/json; charset=utf-8"}, {"lzma", "application/x-xz"},
    {"m1a", "audio/mpeg"}, {"m1v", "video/mpeg"}, {"m2a", "audio/mpeg"}, {"m2ts", "video/mp2t"},
    {"m2v", "video/mpeg"}, {"m4a", "audio/mp4"}, {"m4v", "video/x-m4v"},
    {"mjs", "text/javascript; charset=utf-8"}, {"mka", "audio/matroska"},
    {"mkv", "video/matroska"}, {"mng", "image/x-mng"}, {"mov", "video/quicktime"},
    {"mp1", "audio/mpeg"}, {"mp2", "audio/mpeg"}, {"mp3", "audio/mpeg"}, {"mp4", "video/mp4"},
    {"mpa", "audio/mpeg"}, {"mpe", "video/mpeg"}, {"mpeg", "video/mpeg"}, {"mpg", "video/mpeg"},
    {"mpv", "video/mpeg"}, {"oga", "audio/ogg"}, {"ogg", "audio/ogg"}, {"ogv", "video/ogg"},
    {"otf", "application/x-font-opentype"}, {"pdf", "application/pdf"},
    {"php", "application/x-httpd-php"}, {"png", "image/png"}, {"rar", "application/vnd.rar"},
    {"svg", "image/svg+xml"}, {"tar", "application/x-tar"}, {"targa", "image/x-tga"},
    {"tif", "image/tiff"}, {"tiff", "image/tiff"}, {"tga", "image/x-tga"},
    {"tgz", "application/x-tgz"}, {"ts", "video/mp2t"}, {"tta", "audio/x-tta"},
    {"ttf", "application/x-font-truetype"}, {"txt", "text/plain; charset=utf-8"},
    {"w64", "audio/wav"}, {"wav", "audio/wav"}, {"wave", "audio/wav"},
    {"wasm", "application/wasm"}, {"weba", "audio/webm"}, {"webm", "video/webm"},
    {"webp", "image/webp"}, {"wma", "audio/x-ms-wma"}, {"woff", "application/font-woff"},
    {"woff2", "application/font-woff2"}, {"wv", "audio/x-wavpack"},
    {"xht", "application/xhtml+xml; charset=utf-8"},
    {"xhtml", "application/xhtml+xml; charset=utf-8"},
    {"xml", "application/xml; charset=utf-8"}, {"xsl", "text/xsl; charset=utf-8"},
    {"xz", "application/x-xz"}, {"zip", "application/zip"}, {"7z", "application/x-7z-compressed"},
};

/* Drogon newFileResponse(): the content type follows the file extension. */
static const char *file_content_type(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *dot = strrchr(slash ? slash : path, '.');
    if (!dot || !dot[1]) return "application/octet-stream";
    char *extension = sb_lower_dup(dot + 1);
    const char *mime = "application/octet-stream";
    for (size_t i = 0; i < sizeof mime_types / sizeof mime_types[0]; ++i) {
        if (strcmp(extension, mime_types[i].extension) == 0) {
            mime = mime_types[i].mime;
            break;
        }
    }
    free(extension);
    return mime;
}

/* C++ safe_static_relative_path(). */
static bool safe_static_relative_path(const char *value, size_t len) {
    if (len == 0 || value[0] == '/' || memchr(value, '\0', len)) return false;
    const char *segment = value;
    const char *end = value + len;
    while (segment <= end) {
        const char *slash = memchr(segment, '/', (size_t)(end - segment));
        const char *segment_end = slash ? slash : end;
        if (segment_end - segment == 2 && segment[0] == '.' && segment[1] == '.') return false;
        if (!slash) break;
        segment = slash + 1;
    }
    return true;
}

static void static_file_response(sb_agent_ui *ui, response *resp, const char *relative,
                                 size_t relative_len, bool immutable) {
    if (!safe_static_relative_path(relative, relative_len)) {
        response_error(resp, 404, "Static resource not found");
        return;
    }
    char *path = sb_path_join(ui->ui_directory, relative);
    struct stat st;
    size_t len = 0;
    char *contents = NULL;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) contents = sb_read_file(path, &len);
    if (!contents) {
        free(path);
        response_error(resp, 404, "Static resource not found");
        return;
    }
    resp->status = 200;
    resp->body = contents;
    resp->body_len = len;
    resp->content_type = file_content_type(path);
    resp->cache_control = immutable ? "public, max-age=31536000, immutable" : "no-cache";
    free(path);
}

/* ---- route handlers ----------------------------------------------------- */

static void handle_health(response *resp) {
    sbj *body = sbj_object();
    sbj_set_str(body, "service", "sb-easy-agent-ui");
    sbj_set_str(body, "version", SB_EASY_VERSION);
    sbj_set_str(body, "status", "ok");
    response_json(resp, 200, body);
}

static void handle_login(sb_agent_ui *ui, const request *req, response *resp) {
    if (!ui_header_present(req)) {
        response_error(resp, 403, "缺少本地管理界面请求标记");
        return;
    }
    sb_err err = {0};
    sbj *value = NULL;
    if (parse_json_body(req, &value, &err) != 0) {
        response_from_error(resp, &err);
        return;
    }
    const char *username = "", *password = "";
    if (!sbj_is_object(value)) {
        sb_fail(&err, SB_ERR_VALIDATION, "登录请求必须是 JSON 对象");
    } else if (value_string(value, "username", &username, &err) == 0 &&
               value_string(value, "password", &password, &err) == 0) {
        char *token = session_login(ui, username, password);
        if (!token) {
            response_error(resp, 401, "用户名或密码错误");
        } else {
            sbj *body = sbj_object();
            sbj_set_bool(body, "authenticated", true);
            sbj_set_str(body, "username", username);
            response_json(resp, 200, body);
            resp->set_cookie = session_cookie(token, 43200);
            free(token);
        }
        sbj_free(value);
        return;
    }
    sbj_free(value);
    response_from_error(resp, &err);
}

static void handle_logout(sb_agent_ui *ui, const request *req, response *resp) {
    char *token = request_cookie(req);
    session_logout(ui, token);
    free(token);
    sbj *body = sbj_object();
    sbj_set_bool(body, "authenticated", false);
    response_json(resp, 200, body);
    resp->set_cookie = session_cookie("", 0);
}

static void handle_update_settings(sb_agent_ui *ui, const request *req, response *resp) {
    if (req->body_len > MAXIMUM_SETTINGS_BODY_SIZE) {
        response_error(resp, 413, "设置内容超过 512 KiB");
        return;
    }
    sb_err err = {0};
    sbj *value = NULL;
    if (parse_json_body(req, &value, &err) != 0) {
        response_from_error(resp, &err);
        return;
    }
    sbj *result = ui->callbacks.update_settings(value, ui->callbacks.user, &err);
    sbj_free(value);
    response_from_result(resp, result, &err);
}

static void handle_select_proxy(sb_agent_ui *ui, const request *req, response *resp) {
    if (req->body_len > MAXIMUM_SMALL_BODY_SIZE) {
        response_error(resp, 413, "节点切换请求过大");
        return;
    }
    sb_err err = {0};
    sbj *value = NULL;
    if (parse_json_body(req, &value, &err) != 0) {
        response_from_error(resp, &err);
        return;
    }
    if (!sbj_is_object(value)) {
        sbj_free(value);
        response_error(resp, 400, "节点切换请求必须是 JSON 对象");
        return;
    }
    const sbj *group = sbj_get(value, "group");
    const sbj *name = sbj_get(value, "name");
    if (!sbj_is_string(group) || !sbj_is_string(name) || group->v.str.len == 0 ||
        name->v.str.len == 0) {
        sbj_free(value);
        response_error(resp, 400, "请选择有效的策略组和节点");
        return;
    }
    sbj *result = ui->callbacks.select_proxy(group->v.str.ptr, name->v.str.ptr,
                                             ui->callbacks.user, &err);
    sbj_free(value);
    response_from_result(resp, result, &err);
}

static void handle_route_test(sb_agent_ui *ui, const request *req, response *resp) {
    if (req->body_len > MAXIMUM_SMALL_BODY_SIZE) {
        response_error(resp, 413, "路由测试请求过大");
        return;
    }
    sb_err err = {0};
    sbj *value = NULL;
    if (parse_json_body(req, &value, &err) != 0) {
        response_from_error(resp, &err);
        return;
    }
    const sbj *found = sbj_get(value, "url");
    if (!sbj_is_object(value) || !sbj_is_string(found)) {
        sbj_free(value);
        response_error(resp, 400, "请输入要测试的 URL");
        return;
    }
    sbj *result = ui->callbacks.test_route(found->v.str.ptr, ui->callbacks.user, &err);
    sbj_free(value);
    response_from_result(resp, result, &err);
}

static void handle_action(sb_agent_ui *ui, const char *action, response *resp) {
    sb_err err = {0};
    if (ui->callbacks.request_action(action, ui->callbacks.user, &err) != 0) {
        response_from_error(resp, &err);
        return;
    }
    sbj *body = sbj_object();
    sbj_set_bool(body, "accepted", true);
    sbj_set_str(body, "action", action);
    response_json(resp, 200, body);
}

/* ---- routing ------------------------------------------------------------ */

enum {
    M_GET = 1 << 0,
    M_POST = 1 << 1,
    M_PUT = 1 << 2,
    M_DELETE = 1 << 3,
    M_PATCH = 1 << 4,
    M_OPTIONS = 1 << 5,
    M_OTHER = 1 << 6,
};

static int method_bit(const char *method) {
    if (strcmp(method, "GET") == 0) return M_GET;
    if (strcmp(method, "POST") == 0) return M_POST;
    if (strcmp(method, "PUT") == 0) return M_PUT;
    if (strcmp(method, "DELETE") == 0) return M_DELETE;
    if (strcmp(method, "PATCH") == 0) return M_PATCH;
    if (strcmp(method, "OPTIONS") == 0) return M_OPTIONS;
    return M_OTHER;
}

typedef enum {
    R_HEALTH,
    R_LOGIN,
    R_LOGOUT,
    R_STATUS,
    R_SETTINGS,
    R_CONFIG,
    R_PROXIES,
    R_ROUTE_TEST,
    R_ACTION_REFRESH,
    R_ACTION_RELOAD,
    R_ACTION_RESTART,
} exact_route;

static const struct {
    const char *path;
    exact_route route;
    int methods;
} exact_routes[] = {
    {"/health", R_HEALTH, M_GET},
    {"/api/login", R_LOGIN, M_POST},
    {"/api/logout", R_LOGOUT, M_POST},
    {"/api/status", R_STATUS, M_GET},
    {"/api/settings", R_SETTINGS, M_GET | M_PUT},
    {"/api/config", R_CONFIG, M_GET},
    {"/api/proxies", R_PROXIES, M_GET | M_PUT},
    {"/api/route-test", R_ROUTE_TEST, M_POST},
    {"/api/actions/refresh", R_ACTION_REFRESH, M_POST},
    {"/api/actions/reload", R_ACTION_RELOAD, M_POST},
    {"/api/actions/restart", R_ACTION_RESTART, M_POST},
};

static bool path_equals(const request *req, const char *lowered_literal) {
    size_t len = strlen(lowered_literal);
    return req->path_len == len && memcmp(req->lower, lowered_literal, len) == 0;
}

static bool lower_starts_with(const request *req, const char *prefix) {
    size_t len = strlen(prefix);
    return req->path_len >= len && memcmp(req->lower, prefix, len) == 0;
}

/* ECMAScript ".*" cannot cross a line terminator. */
static bool dot_star(const char *s, size_t len) {
    for (size_t i = 0; i < len; ++i)
        if (s[i] == '\n' || s[i] == '\r') return false;
    return true;
}

/* (?!name(?:/|$)) evaluated on the lower-cased remainder after the leading '/'. */
static bool segment_is(const request *req, const char *name) {
    size_t len = strlen(name);
    if (req->path_len < 1 + len || memcmp(req->lower + 1, name, len) != 0) return false;
    return req->path_len == 1 + len || req->lower[1 + len] == '/';
}

/* ^/([^/]+\.[A-Za-z0-9]+)$ */
static bool single_file_path(const request *req) {
    if (req->path_len < 2 || req->path[0] != '/') return false;
    const char *rest = req->path + 1;
    size_t len = req->path_len - 1;
    if (memchr(rest, '/', len)) return false;
    size_t dot = len;
    for (size_t i = len; i > 0; --i) {
        if (rest[i - 1] == '.') {
            dot = i - 1;
            break;
        }
    }
    if (dot == len || dot == 0 || dot + 1 == len) return false;
    for (size_t i = dot + 1; i < len; ++i) {
        unsigned char c = (unsigned char)rest[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            return false;
    }
    return true;
}

static void route_regex(sb_agent_ui *ui, const request *req, int method, response *resp) {
    bool rooted = req->path_len >= 1 && req->path[0] == '/';
    if (!ui->ui_directory) {
        /* ^/(?!api(?:/|$)).*$ GET/HEAD */
        if (method == M_GET && rooted && !segment_is(req, "api") &&
            dot_star(req->path + 1, req->path_len - 1)) {
            response_error(resp, 404,
                           "No Agent UI path is configured; use the JSON API or set "
                           "AGENT_UI_PATH");
            return;
        }
        response_not_found_page(resp);
        return;
    }
    /* ^/assets/(.*)$ GET/HEAD */
    if (method == M_GET && lower_starts_with(req, "/assets/") &&
        dot_star(req->path + 8, req->path_len - 8)) {
        size_t relative_len = req->path_len - 8 + 7;
        char *relative = sb_xmalloc(relative_len + 1);
        memcpy(relative, "assets/", 7);
        memcpy(relative + 7, req->path + 8, req->path_len - 8);
        relative[relative_len] = '\0';
        static_file_response(ui, resp, relative, relative_len, true);
        free(relative);
        return;
    }
    /* ^/([^/]+\.[A-Za-z0-9]+)$ GET/HEAD */
    if (method == M_GET && single_file_path(req)) {
        static_file_response(ui, resp, req->path + 1, req->path_len - 1, false);
        return;
    }
    /* ^/api(?:/.*)?$ GET/POST/PUT/DELETE/PATCH/HEAD */
    if ((method & (M_GET | M_POST | M_PUT | M_DELETE | M_PATCH)) &&
        (path_equals(req, "/api") ||
         (lower_starts_with(req, "/api/") && dot_star(req->path + 5, req->path_len - 5)))) {
        response_error(resp, 404, "API route not found");
        return;
    }
    /* ^/(?!api(?:/|$)|assets(?:/|$)).*$ GET/HEAD */
    if (method == M_GET && rooted && !segment_is(req, "api") && !segment_is(req, "assets") &&
        dot_star(req->path + 1, req->path_len - 1)) {
        static_file_response(ui, resp, "index.html", strlen("index.html"), false);
        return;
    }
    response_not_found_page(resp);
}

static void route_request(sb_agent_ui *ui, const request *req, response *resp) {
    int method = method_bit(req->method);

    /* Pre-routing advice: session + UI marker for everything under /api/
     * except the login endpoint. */
    bool exempt = path_equals(req, "/health") || path_equals(req, "/api/login") ||
                  !lower_starts_with(req, "/api/");
    if (!exempt) {
        char *token = request_cookie(req);
        bool authenticated = session_authenticated(ui, token);
        free(token);
        if (!authenticated) {
            response_error(resp, 401, "本地管理会话已失效，请重新登录");
            return;
        }
        if ((method & (M_POST | M_PUT | M_DELETE | M_PATCH)) && !ui_header_present(req)) {
            response_error(resp, 403, "缺少本地管理界面请求标记");
            return;
        }
    }

    for (size_t i = 0; i < sizeof exact_routes / sizeof exact_routes[0]; ++i) {
        if (!path_equals(req, exact_routes[i].path)) continue;
        if (!(exact_routes[i].methods & method)) {
            response_plain(resp, method == M_OPTIONS ? 403 : 405);
            return;
        }
        const sb_agent_ui_callbacks *cb = &ui->callbacks;
        sb_err err = {0};
        switch (exact_routes[i].route) {
        case R_HEALTH:
            handle_health(resp);
            return;
        case R_LOGIN:
            handle_login(ui, req, resp);
            return;
        case R_LOGOUT:
            handle_logout(ui, req, resp);
            return;
        case R_STATUS:
            response_from_result(resp, cb->status(cb->user, &err), &err);
            return;
        case R_SETTINGS:
            if (method == M_GET) response_from_result(resp, cb->settings(cb->user, &err), &err);
            else handle_update_settings(ui, req, resp);
            return;
        case R_CONFIG:
            response_from_result(resp, cb->config(cb->user, &err), &err);
            return;
        case R_PROXIES:
            if (method == M_GET) response_from_result(resp, cb->proxies(cb->user, &err), &err);
            else handle_select_proxy(ui, req, resp);
            return;
        case R_ROUTE_TEST:
            handle_route_test(ui, req, resp);
            return;
        case R_ACTION_REFRESH:
            handle_action(ui, "refresh", resp);
            return;
        case R_ACTION_RELOAD:
            handle_action(ui, "reload", resp);
            return;
        case R_ACTION_RESTART:
            handle_action(ui, "restart", resp);
            return;
        }
    }
    route_regex(ui, req, method, resp);
}

/* Drogon utils::urlDecode(): '+' -> ' ', valid %XX decoded, else kept. */
static char *drogon_url_decode(const char *begin, size_t len, size_t *out_len) {
    char *result = sb_xmalloc(len + 1);
    size_t n = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = begin[i];
        if (c == '+') {
            result[n++] = ' ';
        } else if (c == '%' && i + 2 < len && isxdigit((unsigned char)begin[i + 1]) &&
                   isxdigit((unsigned char)begin[i + 2])) {
            char hex[3] = {begin[i + 1], begin[i + 2], 0};
            result[n++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            result[n++] = c;
        }
    }
    result[n] = '\0';
    *out_len = n;
    return result;
}

static int begin_request(struct mg_connection *conn) {
    const struct mg_request_info *info = mg_get_request_info(conn);
    sb_agent_ui *ui = info->user_data;
    response resp;
    memset(&resp, 0, sizeof resp);
    request req;
    memset(&req, 0, sizeof req);
    req.conn = conn;
    req.head = strcmp(info->request_method, "HEAD") == 0;
    req.method = req.head ? "GET" : info->request_method;

    /* Drogon clientMaxBodySize (512 KiB) is enforced by the parser. */
    if (info->content_length > (long long)MAXIMUM_SETTINGS_BODY_SIZE) {
        mg_send_http_error(conn, 413, "%s", "");
        return 413;
    }
    sb_buf body = {0};
    char chunk[8192];
    int count;
    while ((count = mg_read(conn, chunk, sizeof chunk)) > 0) {
        sb_buf_append(&body, chunk, (size_t)count);
        if (body.len > MAXIMUM_SETTINGS_BODY_SIZE) {
            sb_buf_free(&body);
            mg_send_http_error(conn, 413, "%s", "");
            return 413;
        }
    }
    req.body = body.p ? body.p : "";
    req.body_len = body.len;

    const char *raw = info->local_uri_raw ? info->local_uri_raw : "/";
    if (raw[0] != '/') raw = "/";
    req.path = drogon_url_decode(raw, strlen(raw), &req.path_len);
    req.lower = sb_xmalloc(req.path_len + 1);
    for (size_t i = 0; i <= req.path_len; ++i) {
        char c = req.path[i];
        req.lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }

    pthread_mutex_lock(&ui->handler_mutex);
    route_request(ui, &req, &resp);
    pthread_mutex_unlock(&ui->handler_mutex);
    send_response(conn, &resp, req.head);
    int status = resp.status;
    free(resp.body);
    free(resp.set_cookie);
    free(req.path);
    free(req.lower);
    sb_buf_free(&body);
    return status > 0 ? status : 200;
}

static int log_message(const struct mg_connection *conn, const char *message) {
    (void)conn;
    SB_DEBUG("agent ui: %s", message);
    return 1;
}

/* ---- lifecycle ---------------------------------------------------------- */

static void init_civetweb(void) { (void)mg_init_library(0); }

static bool callbacks_complete(const sb_agent_ui_callbacks *cb) {
    return cb && cb->status && cb->settings && cb->update_settings && cb->config &&
           cb->proxies && cb->select_proxy && cb->test_route && cb->request_action;
}

sb_agent_ui *sb_agent_ui_new(const sb_agent_ui_options *options,
                             const sb_agent_ui_callbacks *callbacks, sb_err *err) {
    sb_agent_ui_options defaults;
    sb_agent_ui_options_init(&defaults);
    if (!options) options = &defaults;
    const char *address = options->address ? options->address : "";
    const char *username = options->username ? options->username : "";
    if (address[0] == '\0') {
        sb_fail(err, SB_ERR_VALIDATION, "Agent UI address must not be empty");
        return NULL;
    }
    if (username[0] == '\0') {
        sb_fail(err, SB_ERR_VALIDATION, "Agent UI username must not be empty");
        return NULL;
    }
    if (strchr(username, ':')) {
        sb_fail(err, SB_ERR_VALIDATION, "Agent UI username must not contain ':'");
        return NULL;
    }
    if (sb_str_empty(options->password)) {
        sb_fail(err, SB_ERR_VALIDATION, "Agent UI password must not be empty");
        return NULL;
    }
    if (!sb_str_empty(options->ui_directory)) {
        char *index = sb_path_join(options->ui_directory, "index.html");
        struct stat st;
        bool regular = stat(index, &st) == 0 && S_ISREG(st.st_mode);
        free(index);
        if (!regular) {
            sb_fail(err, SB_ERR_VALIDATION, "Agent UI path must contain a readable index.html: %s",
                    options->ui_directory);
            return NULL;
        }
    }
    if (!callbacks_complete(callbacks)) {
        sb_fail(err, SB_ERR_VALIDATION, "all Agent UI callbacks are required");
        return NULL;
    }

    sb_agent_ui *ui = sb_xcalloc(1, sizeof *ui);
    ui->username = sb_strdup(username);
    ui->password = sb_strdup(options->password);
    ui->ui_directory = sb_str_empty(options->ui_directory) ? NULL : sb_strdup(options->ui_directory);
    ui->callbacks = *callbacks;
    pthread_mutex_init(&ui->mutex, NULL);
    pthread_mutex_init(&ui->handler_mutex, NULL);

    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, init_civetweb);

    char *ports = strchr(address, ':') ? sb_asprintf("[%s]:%u", address, (unsigned)options->port)
                                       : sb_asprintf("%s:%u", address, (unsigned)options->port);
    const char *mg_options[] = {
        "listening_ports", ports,
        "num_threads", "8",
        "enable_keep_alive", "no",
        "decode_url", "no",
        "request_timeout_ms", "30000",
        "access_control_allow_origin", "",
        "access_control_allow_methods", "",
        "access_control_allow_headers", "",
        NULL,
    };
    struct mg_callbacks mg_callbacks;
    memset(&mg_callbacks, 0, sizeof mg_callbacks);
    mg_callbacks.begin_request = begin_request;
    mg_callbacks.log_message = log_message;
    ui->context = mg_start(&mg_callbacks, ui, mg_options);
    free(ports);
    if (ui->context) {
        struct mg_server_port bound[4];
        int count = mg_get_server_ports(ui->context, 4, bound);
        if (count > 0 && bound[0].port > 0) ui->port = (uint16_t)bound[0].port;
    }
    if (!ui->context || ui->port == 0) {
        sb_agent_ui_free(ui);
        sb_fail(err, SB_ERR_GENERIC, "Agent UI HTTP listener did not start");
        return NULL;
    }
    return ui;
}

void sb_agent_ui_free(sb_agent_ui *ui) {
    if (!ui) return;
    if (ui->context) mg_stop(ui->context);
    pthread_mutex_lock(&ui->mutex);
    for (size_t i = 0; i < ui->session_len; ++i) free(ui->sessions[i].token);
    free(ui->sessions);
    pthread_mutex_unlock(&ui->mutex);
    pthread_mutex_destroy(&ui->mutex);
    pthread_mutex_destroy(&ui->handler_mutex);
    free(ui->username);
    free(ui->password);
    free(ui->ui_directory);
    free(ui);
}

uint16_t sb_agent_ui_port(const sb_agent_ui *ui) { return ui ? ui->port : 0; }
