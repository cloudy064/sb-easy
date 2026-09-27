/* Polling agent (port of cpp/src/agent_main.cpp): enrollment and credential
 * persistence, config polling + atomic install, command execution, status /
 * telemetry / latency reporting and the local Agent UI wiring.
 *
 * Output mirrors the C++ program line for line (stdout for progress, stderr
 * for errors). Like the C++ agent (Drogon's SIGTERM handling is disabled and
 * trantor ignores SIGPIPE), SIGINT/SIGTERM keep their default action and
 * SIGPIPE is ignored. */
#include "agent_main_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sb/agent_clash.h"
#include "sb/agent_client.h"
#include "sb/agent_config.h"
#include "sb/agent_ui.h"
#include "sb/atomic_file.h"
#include "sb/http_client.h"
#include "sb/json.h"
#include "sb/singbox_supervisor.h"
#include "sb/util.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

/* The panel stores these identity strings verbatim; the C port keeps the
 * values of the C++ agent it replaces. */
#define AGENT_SERVICE "sb-easy-cpp-agent"
#define AGENT_VERSION AGENT_SERVICE "/" SB_EASY_VERSION

extern char **environ;

/* ---- environment ------------------------------------------------------ */

/* C++ environment(): the fallback only when the variable is unset. */
static const char *environment(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value ? value : fallback;
}

static bool environment_flag(const char *name, bool fallback) {
    const char *value = getenv(name);
    if (!value || !*value) return fallback;
    char *lower = sb_lower_dup(value);
    bool result = strcmp(lower, "1") == 0 || strcmp(lower, "true") == 0 ||
                  strcmp(lower, "yes") == 0 || strcmp(lower, "on") == 0;
    free(lower);
    return result;
}

static bool c_space(unsigned char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }

/* std::from_chars for an unsigned integer over the whole text. */
static bool parse_unsigned(const char *text, size_t len, uint64_t limit, uint64_t *out) {
    if (len == 0) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        uint64_t digit = (uint64_t)(text[i] - '0');
        if (value > (limit - digit) / 10u) return false; /* result_out_of_range */
        value = value * 10u + digit;
    }
    *out = value;
    return true;
}

static int poll_interval(int64_t *seconds, sb_err *err) {
    const char *value = environment("AGENT_INTERVAL", "10");
    uint64_t parsed = 0;
    if (!parse_unsigned(value, strlen(value), UINT64_MAX, &parsed))
        return sb_fail(err, SB_ERR_VALIDATION, "AGENT_INTERVAL must be an integer");
    if (parsed < 2u) parsed = 2u;
    *seconds = parsed > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)parsed;
    return 0;
}

/* ---- paths ------------------------------------------------------------ */

static char *config_path(void) {
    const char *value = environment("SINGBOX_CONFIG_PATH", "");
    if (!*value) value = environment("SELF_SINGBOX_CONFIG_PATH", "");
    return sb_strdup(*value ? value : "data/sing-box.gen.json");
}

/* std::filesystem::path::parent_path() (libstdc++, POSIX). */
static char *parent_path(const char *path) {
    size_t len = strlen(path);
    size_t root_end = 0;
    while (root_end < len && path[root_end] == '/') ++root_end;
    if (root_end == len) return sb_strdup(path); /* no relative path */
    size_t last_start = len;
    while (last_start > root_end && path[last_start - 1] != '/') --last_start;
    if (last_start == root_end) return sb_strdup(root_end > 0 ? "/" : "");
    size_t end = last_start;
    while (end > root_end && path[end - 1] == '/') --end;
    return sb_strndup(path, end);
}

/* std::filesystem::path operator/ for a relative file name. */
static char *path_append(const char *directory, const char *name) {
    if (!*directory) return sb_strdup(name);
    return sb_asprintf("%s%s%s", directory, sb_ends_with(directory, "/") ? "" : "/", name);
}

/* parent_path() (or "." when empty) / name. */
static char *path_beside(const char *config, const char *name) {
    char *directory = parent_path(config);
    if (!*directory) sb_str_set(&directory, ".");
    char *result = path_append(directory, name);
    free(directory);
    return result;
}

static char *settings_path(const char *singbox_config_path) {
    const char *value = environment("AGENT_UI_SETTINGS_PATH", "");
    return *value ? sb_strdup(value) : path_beside(singbox_config_path, "agent-ui-settings.json");
}

static char *device_credential_path(const char *singbox_config_path) {
    const char *value = environment("AGENT_CREDENTIAL_PATH", "");
    return *value ? sb_strdup(value) : path_beside(singbox_config_path, "device-credential.json");
}

/* std::filesystem::exists(path, error_code): 1 exists, 0 missing, -1 when the
 * status itself failed (error set). */
static int path_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 1;
    return (errno == ENOENT || errno == ENOTDIR) ? 0 : -1;
}

/* Throwing std::filesystem::exists(path). */
static int path_exists_or_fail(const char *path, bool *exists, sb_err *err) {
    int result = path_exists(path);
    if (result < 0)
        return sb_fail(err, SB_ERR_IO, "filesystem error: status: %s [%s]", strerror(errno), path);
    *exists = result == 1;
    return 0;
}

/* std::ifstream + read, as libstdc++ does it: 1 read into *out, 0 when the
 * file cannot be opened, -1 when reading fails (a directory opens but
 * basic_filebuf::underflow throws "... error reading the file: <errno>"). */
static int read_stream(const char *path, char **out, size_t *len, sb_err *err) {
    *out = NULL;
    *len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    sb_buf buffer = {0};
    sb_buf_append(&buffer, "", 0);
    char chunk[65536];
    for (;;) {
        ssize_t count = read(fd, chunk, sizeof chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            int saved = errno;
            close(fd);
            sb_buf_free(&buffer);
            return sb_fail(err, SB_ERR_IO, "basic_filebuf::underflow error reading the file: %s",
                           strerror(saved));
        }
        if (count == 0) break;
        sb_buf_append(&buffer, chunk, (size_t)count);
    }
    close(fd);
    *len = buffer.len;
    *out = sb_buf_detach(&buffer);
    return 1;
}

/* ---- JSON helpers ----------------------------------------------------- */

static const char *skip_bom(const char *text, size_t *len) {
    if (*len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) {
        *len -= 3;
        return text + 3;
    }
    return text;
}

/* json::parse(text): SB_ERR_BAD_JSON (json::exception) on failure. */
static sbj *parse_json(const char *text, size_t len, sb_err *err) {
    text = skip_bom(text, &len);
    if (len == 0) {
        sb_fail(err, SB_ERR_BAD_JSON,
                "[json.exception.parse_error.101] parse error at line 1, column 1: attempting to "
                "parse an empty input; check that your input string or stream contains the "
                "expected JSON");
        return NULL;
    }
    char message[256] = {0};
    sbj *value = sbj_parse(text, len, message, sizeof message);
    if (!value)
        sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.parse_error.101] parse error: %s",
                message[0] ? message : "syntax error");
    return value;
}

/* json::parse(text, nullptr, false): NULL for a discarded value. */
static sbj *parse_json_lenient(const char *text, size_t len) {
    text = skip_bom(text, &len);
    return len ? sbj_parse(text, len, NULL, 0) : NULL;
}

/* nlohmann object.value(key, fallback) for strings; borrowed result. */
static int value_string(const sbj *object, const char *key, const char *fallback,
                        const char **out, sb_err *err) {
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_BAD_JSON,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

/* ---- identity / enrollment -------------------------------------------- */

typedef struct {
    char *server;
    char *token;
    char *host_id;
    char *host_name;
    char *profile_id;
    char *profile_name;
} agent_identity;

static void agent_identity_free(agent_identity *identity) {
    free(identity->server);
    free(identity->token);
    free(identity->host_id);
    free(identity->host_name);
    free(identity->profile_id);
    free(identity->profile_name);
    memset(identity, 0, sizeof *identity);
}

static sbj *local_device_metadata(void) {
    char hostname[256];
    memset(hostname, 0, sizeof hostname);
    const char *hostname_value = "";
    if (gethostname(hostname, sizeof hostname) == 0) {
        hostname[sizeof hostname - 1] = '\0';
        hostname_value = hostname;
    }
    struct utsname system_information;
    const char *operating_system = "linux";
    const char *architecture = "";
    if (uname(&system_information) == 0) {
        operating_system = system_information.sysname;
        architecture = system_information.machine;
    }
    sbj *device = sbj_object();
    sbj_set_str(device, "platform", environment("AGENT_PLATFORM", "linux"));
    sbj_set_str(device, "agent_version", AGENT_VERSION);
    sbj_set_str(device, "hostname", hostname_value);
    sbj_set_str(device, "architecture", architecture);
    sbj_set_str(device, "os", operating_system);
    return device;
}

/* 1 loaded, 0 no credential file, -1 error. */
static int load_device_credential(const char *path, agent_identity *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    size_t len = 0;
    char *text = NULL;
    int opened = read_stream(path, &text, &len, err);
    if (opened < 0) return -1;
    if (opened == 0) {
        if (path_exists(path) == 0) return 0;
        return sb_fail(err, SB_ERR_IO, "cannot read device credential: %s", path);
    }
    sbj *parsed = parse_json_lenient(text, len);
    free(text);
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        return sb_fail(err, SB_ERR_GENERIC, "device credential is not valid JSON: %s", path);
    }
    const char *server = NULL, *token = NULL, *host_id = NULL, *host_name = NULL,
               *profile_id = NULL, *profile_name = NULL;
    if (value_string(parsed, "server", "", &server, err) != 0 ||
        value_string(parsed, "agent_token", "", &token, err) != 0 ||
        value_string(parsed, "host_id", "", &host_id, err) != 0 ||
        value_string(parsed, "host_name", "", &host_name, err) != 0 ||
        value_string(parsed, "profile_id", "", &profile_id, err) != 0 ||
        value_string(parsed, "profile_name", "", &profile_name, err) != 0) {
        sbj_free(parsed);
        return -1;
    }
    if (!*server || !*token) {
        sbj_free(parsed);
        return sb_fail(err, SB_ERR_GENERIC, "device credential is incomplete: %s", path);
    }
    out->server = sb_strdup(server);
    out->token = sb_strdup(token);
    out->host_id = sb_strdup(host_id);
    const sbj *host_name_value = sbj_get(parsed, "host_name");
    out->host_name = sb_strndup(host_name, sbj_is_string(host_name_value) ? host_name_value->v.str.len : 0);
    out->profile_id = sb_strdup(profile_id);
    const sbj *profile_name_value = sbj_get(parsed, "profile_name");
    out->profile_name = sb_strndup(profile_name, sbj_is_string(profile_name_value) ? profile_name_value->v.str.len : 0);
    sbj_free(parsed);
    return 1;
}

static int save_device_credential(const char *path, const sb_device_credential *credential,
                                  sb_err *err) {
    sbj *value = sbj_object();
    sbj_set_str(value, "server", credential->server);
    sbj_set_str(value, "host_id", credential->host_id);
    sbj_set(value, "host_name", sbj_strn(credential->host_name, credential->host_name_len));
    sbj_set_str(value, "agent_token", credential->token);
    sbj_set_str(value, "profile_id", credential->profile_id);
    sbj_set(value, "profile_name", sbj_strn(credential->profile_name, credential->profile_name_len));
    char *dumped = sbj_dump(value, 2);
    sbj_free(value);
    char *serialized = sb_asprintf("%s\n", dumped);
    free(dumped);
    int rc = sb_atomic_replace_file(path, serialized, strlen(serialized), NULL, NULL, err);
    free(serialized);
    if (rc != 0) return -1;
    if (chmod(path, S_IRUSR | S_IWUSR) != 0)
        return sb_fail(err, SB_ERR_IO, "filesystem error: cannot set permissions: %s [%s]",
                       strerror(errno), path);
    return 0;
}

static int resolve_agent_identity(const char *credential_path, agent_identity *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    const char *environment_server = environment("SB_EASY_SERVER", "");
    const char *environment_token = environment("AGENT_TOKEN", "");
    if (*environment_token) {
        if (!*environment_server)
            return sb_fail(err, SB_ERR_VALIDATION,
                           "SB_EASY_SERVER is required when AGENT_TOKEN is set");
        out->server = sb_strdup(environment_server);
        out->token = sb_strdup(environment_token);
        out->host_id = sb_strdup("");
        out->host_name = sb_strdup("");
        out->profile_id = sb_strdup("");
        out->profile_name = sb_strdup("");
        return 0;
    }

    int loaded = load_device_credential(credential_path, out, err);
    if (loaded != 0) return loaded > 0 ? 0 : -1;

    const char *enrollment_code = environment("AGENT_ENROLLMENT_CODE", "");
    if (!*environment_server || !*enrollment_code)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "set SB_EASY_SERVER with AGENT_ENROLLMENT_CODE for first-time "
                       "enrollment, or provide an existing AGENT_TOKEN");
    sbj *device = local_device_metadata();
    sb_device_enrollment_options options = {
        .server = environment_server,
        .code = enrollment_code,
        .device = device,
        .timeout_ms = 15000,
    };
    sb_device_credential credential;
    int rc = sb_enroll_device(&options, &credential, err);
    sbj_free(device);
    if (rc != 0) return -1;
    if (save_device_credential(credential_path, &credential, err) != 0) {
        sb_device_credential_free(&credential);
        return -1;
    }
    fputs("device enrolled as ", stdout);
    fwrite(credential.host_name, 1, credential.host_name_len, stdout);
    printf(" (%s)\n", credential.host_id);
    out->server = credential.server;
    out->token = credential.token;
    out->host_id = credential.host_id;
    out->host_name = credential.host_name;
    out->profile_id = credential.profile_id;
    out->profile_name = credential.profile_name;
    return 0;
}

/* ---- local UI options ------------------------------------------------- */

static int parse_port(const char *value, size_t len, const char *variable, uint16_t *out,
                      sb_err *err) {
    uint64_t port = 0;
    if (!parse_unsigned(value, len, UINT32_MAX, &port) || port == 0u || port > 65535u)
        return sb_fail(err, SB_ERR_VALIDATION, "%s must contain a valid TCP port", variable);
    *out = (uint16_t)port;
    return 0;
}

typedef struct {
    char *address;
    uint16_t port;
    const char *username;     /* borrowed from the environment */
    const char *password;     /* borrowed from the environment */
    const char *ui_directory; /* borrowed from the environment */
} local_ui_config;

static int local_ui_options(local_ui_config *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    const char *bind = environment("AGENT_UI_BIND", "0.0.0.0:51822");
    size_t size = strlen(bind);
    char *address = NULL;
    const char *port;
    if (bind[0] == '[') {
        const char *bracket = strchr(bind, ']');
        size_t index = bracket ? (size_t)(bracket - bind) : 0;
        if (!bracket || index + 2u > size || bind[index + 1u] != ':')
            return sb_fail(err, SB_ERR_VALIDATION,
                           "AGENT_UI_BIND IPv6 addresses must use [address]:port");
        address = sb_strndup(bind + 1, index - 1u);
        port = bind + index + 2u;
    } else {
        const char *colon = strrchr(bind, ':');
        if (!colon) return sb_fail(err, SB_ERR_VALIDATION, "AGENT_UI_BIND must use address:port");
        address = sb_strndup(bind, (size_t)(colon - bind));
        port = colon + 1;
    }
    if (!*address) {
        free(address);
        return sb_fail(err, SB_ERR_VALIDATION, "AGENT_UI_BIND address must not be empty");
    }
    if (parse_port(port, strlen(port), "AGENT_UI_BIND", &out->port, err) != 0) {
        free(address);
        return -1;
    }
    out->address = address;
    out->username = environment("AGENT_UI_USERNAME", "admin");
    out->password = environment("AGENT_UI_PASSWORD", "");
    out->ui_directory = environment("AGENT_UI_PATH", "");
    return 0;
}

static char *current_time_iso8601(void) {
    time_t now = time(NULL);
    struct tm utc;
    if (!gmtime_r(&now, &utc)) return sb_strdup("");
    char buffer[32];
    if (strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) return sb_strdup("");
    return sb_strdup(buffer);
}

/* ---- node-local transform options from the environment ----------------- */

static int outbound_server_overrides(sbj **out, sb_err *err) {
    *out = NULL;
    const char *value = environment("SINGBOX_OUTBOUND_SERVER_OVERRIDES", "");
    if (!*value) {
        *out = sbj_object();
        return 0;
    }
    sbj *parsed = parse_json(value, strlen(value), err);
    if (!parsed) return -1;
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        return sb_fail(err, SB_ERR_VALIDATION,
                       "SINGBOX_OUTBOUND_SERVER_OVERRIDES must be a JSON object");
    }
    const char *tag;
    const sbj *server;
    SBJ_OBJ_FOREACH(parsed, i, tag, server) {
        if (!sbj_is_string(server)) {
            int rc = sb_fail(err, SB_ERR_VALIDATION, "outbound server override for %s must be a string",
                             tag);
            sbj_free(parsed);
            return rc;
        }
    }
    *out = parsed;
    return 0;
}

static int outbound_overrides(sbj **out, sb_err *err) {
    *out = NULL;
    const char *path = environment("SINGBOX_OUTBOUND_OVERRIDE_FILE", "");
    if (!*path) {
        *out = sbj_object();
        return 0;
    }
    size_t len = 0;
    char *text = NULL;
    int opened = read_stream(path, &text, &len, err);
    if (opened < 0) return -1;
    if (opened == 0) return sb_fail(err, SB_ERR_IO, "cannot read outbound override file: %s", path);
    sbj *parsed = parse_json(text, len, err);
    free(text);
    if (!parsed) return -1;
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        return sb_fail(err, SB_ERR_VALIDATION,
                       "SINGBOX_OUTBOUND_OVERRIDE_FILE must contain a JSON object");
    }
    const char *tag;
    const sbj *outbound;
    SBJ_OBJ_FOREACH(parsed, i, tag, outbound) {
        if (!sbj_is_object(outbound)) {
            int rc = sb_fail(err, SB_ERR_VALIDATION, "outbound override for %s must be a JSON object",
                             tag);
            sbj_free(parsed);
            return rc;
        }
    }
    *out = parsed;
    return 0;
}

static int local_route_rules(const char *singbox_config_path, sbj **out, sb_err *err) {
    *out = NULL;
    const char *value = environment("SINGBOX_LOCAL_ROUTE_RULES_FILE", "");
    char *path;
    if (*value) {
        path = sb_strdup(value);
    } else {
        char *directory = parent_path(singbox_config_path);
        path = path_append(directory, "local-route-rules.json");
        free(directory);
    }
    int rc = -1;
    size_t len = 0;
    char *text = NULL;
    int opened = read_stream(path, &text, &len, err);
    if (opened < 0) goto out;
    if (opened == 0) {
        bool exists = false;
        if (path_exists_or_fail(path, &exists, err) != 0) goto out;
        if (!exists) {
            *out = sbj_array();
            rc = 0;
            goto out;
        }
        sb_fail(err, SB_ERR_IO, "cannot read local route rules file: %s", path);
        goto out;
    }
    sbj *parsed = parse_json(text, len, err);
    if (!parsed) goto out;
    if (!sbj_is_array(parsed)) {
        sbj_free(parsed);
        sb_fail(err, SB_ERR_VALIDATION, "SINGBOX_LOCAL_ROUTE_RULES_FILE must contain a JSON array");
        goto out;
    }
    const sbj *rule;
    SBJ_ARR_FOREACH(parsed, i, rule) {
        if (!sbj_is_object(rule)) {
            sbj_free(parsed);
            sb_fail(err, SB_ERR_VALIDATION, "local route rules file must contain JSON objects");
            goto out;
        }
    }
    *out = parsed;
    rc = 0;
out:
    free(text);
    free(path);
    return rc;
}

/* C++ transform_options(); *out is initialised on success only. */
static int transform_options(sb_agent_config_options *out, sb_err *err) {
    const char *default_outbound = environment("SINGBOX_DEFAULT_PROXY_OUTBOUND", "");
    bool local_proxy_egress = environment_flag("SINGBOX_LOCAL_PROXY_EGRESS", true);
    sbj *servers = NULL, *overrides = NULL, *rules = NULL;
    if (outbound_server_overrides(&servers, err) != 0) return -1;
    if (outbound_overrides(&overrides, err) != 0) {
        sbj_free(servers);
        return -1;
    }
    char *path = config_path();
    int rc = local_route_rules(path, &rules, err);
    free(path);
    if (rc != 0) {
        sbj_free(servers);
        sbj_free(overrides);
        return -1;
    }
    sb_agent_config_options_init(out);
    out->local_proxy_egress = local_proxy_egress;
    sbj_free(out->outbound_server_overrides);
    out->outbound_server_overrides = servers;
    sbj_free(out->outbound_overrides);
    out->outbound_overrides = overrides;
    out->default_proxy_outbound = *default_outbound ? sb_strdup(default_outbound) : NULL;
    sbj_free(out->local_route_rules);
    out->local_route_rules = rules;
    return 0;
}

/* ---- external commands ------------------------------------------------ */

static int split_command_line(const char *command, sb_strvec *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    sb_buf current = {0};
    char quote = 0;
    bool escaped = false, started = false;
    for (const char *p = command; *p; ++p) {
        char character = *p;
        if (escaped) {
            sb_buf_putc(&current, character);
            escaped = false;
            started = true;
            continue;
        }
        if (character == '\\' && quote != '\'') {
            escaped = true;
            started = true;
            continue;
        }
        if (quote != 0) {
            if (character == quote) quote = 0;
            else sb_buf_putc(&current, character);
            started = true;
            continue;
        }
        if (character == '\'' || character == '"') {
            quote = character;
            started = true;
            continue;
        }
        if (c_space((unsigned char)character)) {
            if (started) {
                sb_strvec_push_take(out, sb_buf_detach(&current));
                started = false;
            }
            continue;
        }
        sb_buf_putc(&current, character);
        started = true;
    }
    if (escaped || quote != 0) {
        sb_buf_free(&current);
        sb_strvec_free(out);
        return sb_fail(err, SB_ERR_VALIDATION, "unterminated command escape or quote");
    }
    if (started) sb_strvec_push_take(out, sb_buf_detach(&current));
    sb_buf_free(&current);
    return 0;
}

typedef struct {
    bool success;
    char *detail; /* owned */
} process_result;

static process_result run_program(const sb_strvec *arguments) {
    process_result result = {false, NULL};
    if (arguments->len == 0 || arguments->items[0][0] == '\0') {
        result.detail = sb_strdup("command is empty");
        return result;
    }
    char **argv = sb_xcalloc(arguments->len + 1, sizeof *argv);
    for (size_t i = 0; i < arguments->len; ++i) argv[i] = arguments->items[i];
    pid_t process = 0;
    int spawn_error = posix_spawnp(&process, argv[0], NULL, NULL, argv, environ);
    free(argv);
    if (spawn_error != 0) {
        result.detail = sb_asprintf("spawn failed: %s", strerror(spawn_error));
        return result;
    }
    int status = 0;
    while (waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            result.detail = sb_asprintf("wait failed: %s", strerror(errno));
            return result;
        }
    }
    if (WIFEXITED(status)) {
        result.success = WEXITSTATUS(status) == 0;
        result.detail = sb_asprintf("exit code %d", WEXITSTATUS(status));
        return result;
    }
    if (WIFSIGNALED(status)) {
        result.detail = sb_asprintf("terminated by signal %d", WTERMSIG(status));
        return result;
    }
    result.detail = sb_strdup("process ended without an exit status");
    return result;
}

/* 1 read, 0 missing, -1 error. */
static int read_existing(const char *path, char **out, size_t *len, sb_err *err) {
    int opened = read_stream(path, out, len, err);
    if (opened != 0) return opened;
    bool exists = false;
    if (path_exists_or_fail(path, &exists, err) != 0) return -1;
    if (!exists) return 0;
    return sb_fail(err, SB_ERR_IO, "cannot read existing config: %s", path);
}

/* C++ proxy_test_tags(): *all = true for std::nullopt. */
static int proxy_test_tags(const char *command, sb_strvec *tags, bool *all, sb_err *err) {
    static const char prefix[] = "test-proxies";
    const size_t prefix_len = sizeof prefix - 1;
    memset(tags, 0, sizeof *tags);
    *all = true;
    if (strcmp(command, prefix) == 0) return 0;
    if (!sb_starts_with(command, prefix) || strlen(command) <= prefix_len ||
        !c_space((unsigned char)command[prefix_len]))
        return sb_fail(err, SB_ERR_VALIDATION, "not a test-proxies command");
    const char *suffix = command + prefix_len;
    while (*suffix && c_space((unsigned char)*suffix)) ++suffix;
    sbj *parsed = parse_json_lenient(suffix, strlen(suffix));
    if (!sbj_is_array(parsed)) {
        sbj_free(parsed);
        return 0;
    }
    const sbj *value;
    SBJ_ARR_FOREACH(parsed, i, value) {
        if (!sbj_is_string(value)) {
            sb_strvec_free(tags);
            sbj_free(parsed);
            return 0;
        }
        sb_strvec_push(tags, value->v.str.ptr);
    }
    sbj_free(parsed);
    *all = false;
    return 0;
}

/* ---- runtime ---------------------------------------------------------- */

typedef struct {
    char *config_path;
    char *credential_path;
    agent_identity identity;
    char *settings_path;
    char *singbox_bin;
    bool singbox_managed;
    sb_strvec reload_command;
    sb_strvec restart_command;
    bool validate_config;
    sb_singbox_supervisor *supervisor;
    sb_agent_client *client;
    sb_agent_clash *clash;

    pthread_mutex_t state_mutex;
    pthread_cond_t wakeup;
    bool has_transform_options;
    sb_agent_config_options transform_options; /* state_mutex */
    char *last_etag;                           /* NULL == nullopt */
    int running;                               /* -1 == nullopt */
    char *last_cycle;
    char *last_error;
    sbj *last_telemetry;
    char *last_rule_source;
    bool refresh_requested, reload_requested, restart_requested;
} agent_runtime;

static void runtime_free(agent_runtime *rt) {
    sb_agent_clash_free(rt->clash);
    sb_agent_client_free(rt->client);
    sb_singbox_supervisor_free(rt->supervisor); /* stops a managed child */
    if (rt->has_transform_options) sb_agent_config_options_free(&rt->transform_options);
    sb_strvec_free(&rt->reload_command);
    sb_strvec_free(&rt->restart_command);
    free(rt->singbox_bin);
    free(rt->settings_path);
    agent_identity_free(&rt->identity);
    free(rt->credential_path);
    free(rt->config_path);
    free(rt->last_etag);
    free(rt->last_cycle);
    free(rt->last_error);
    sbj_free(rt->last_telemetry);
    free(rt->last_rule_source);
    pthread_cond_destroy(&rt->wakeup);
    pthread_mutex_destroy(&rt->state_mutex);
    memset(rt, 0, sizeof *rt);
}

static sbj *default_telemetry(void) {
    sbj *telemetry = sbj_object();
    sbj_set_bool(telemetry, "available", false);
    sbj_set_null(telemetry, "sampled_at");
    sbj_set_int(telemetry, "up", 0);
    sbj_set_int(telemetry, "down", 0);
    sbj_set_int(telemetry, "up_total", 0);
    sbj_set_int(telemetry, "down_total", 0);
    sbj_set_int(telemetry, "conn_count", 0);
    return telemetry;
}

/* C++ AgentRuntime constructor: members initialise in declaration order. */
static int runtime_init(agent_runtime *rt, sb_err *err) {
    memset(rt, 0, sizeof *rt);
    pthread_mutex_init(&rt->state_mutex, NULL);
    pthread_condattr_t attributes;
    pthread_condattr_init(&attributes);
    pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    pthread_cond_init(&rt->wakeup, &attributes);
    pthread_condattr_destroy(&attributes);
    rt->running = -1;
    rt->last_telemetry = default_telemetry();
    rt->last_rule_source = sb_strdup("profile");

    rt->config_path = config_path();
    rt->credential_path = device_credential_path(rt->config_path);
    if (resolve_agent_identity(rt->credential_path, &rt->identity, err) != 0) goto fail;
    rt->settings_path = settings_path(rt->config_path);
    rt->singbox_bin = sb_strdup(environment("SINGBOX_BIN", "sing-box"));
    rt->singbox_managed = environment_flag("SINGBOX_MANAGED", true);
    if (split_command_line(environment("RELOAD_CMD", "systemctl reload sing-box"),
                           &rt->reload_command, err) != 0)
        goto fail;
    if (split_command_line(environment("RESTART_CMD", "systemctl restart sing-box"),
                           &rt->restart_command, err) != 0)
        goto fail;
    rt->validate_config = environment_flag("SINGBOX_VALIDATE_CONFIG", true);
    {
        sb_agent_config_options defaults;
        if (transform_options(&defaults, err) != 0) goto fail;
        int rc = sb_agent_config_options_load(rt->settings_path, &defaults,
                                              &rt->transform_options, err);
        sb_agent_config_options_free(&defaults);
        if (rc != 0) goto fail;
        rt->has_transform_options = true;
    }
    {
        sb_singbox_supervisor_options options;
        sb_singbox_supervisor_options_init(&options);
        options.binary = rt->singbox_bin;
        options.config_path = rt->config_path;
        options.validate_config = rt->validate_config;
        rt->supervisor = sb_singbox_supervisor_new(&options, err);
        if (!rt->supervisor) goto fail;
    }
    {
        sb_agent_client_options options = {
            .server = rt->identity.server,
            .token = rt->identity.token,
            .timeout_ms = 15000,
        };
        rt->client = sb_agent_client_new(&options, err);
        if (!rt->client) goto fail;
    }
    rt->clash = sb_agent_clash_new(rt->config_path);
    return 0;
fail:
    runtime_free(rt);
    return -1;
}

static void set_etag(agent_runtime *rt, const char *value) {
    pthread_mutex_lock(&rt->state_mutex);
    sb_str_set(&rt->last_etag, value);
    pthread_mutex_unlock(&rt->state_mutex);
}

static char *copy_etag(agent_runtime *rt) {
    pthread_mutex_lock(&rt->state_mutex);
    char *etag = sb_strdup(rt->last_etag);
    pthread_mutex_unlock(&rt->state_mutex);
    return etag;
}

static void set_rule_source(agent_runtime *rt, const char *value) {
    pthread_mutex_lock(&rt->state_mutex);
    sb_str_set(&rt->last_rule_source, sb_streq(value, "quickjs") ? "quickjs" : "profile");
    pthread_mutex_unlock(&rt->state_mutex);
}

static void set_running(agent_runtime *rt, bool value) {
    pthread_mutex_lock(&rt->state_mutex);
    rt->running = value ? 1 : 0;
    pthread_mutex_unlock(&rt->state_mutex);
}

static int get_running(agent_runtime *rt) {
    pthread_mutex_lock(&rt->state_mutex);
    int value = rt->running;
    pthread_mutex_unlock(&rt->state_mutex);
    return value;
}

static void record_error(sb_strvec *errors, const char *operation, const char *message) {
    char *line = sb_asprintf("%s: %s", operation, message);
    fprintf(stderr, "%s\n", line);
    sb_strvec_push_take(errors, line);
}

typedef struct {
    bool reload;
    bool restart;
} queued_actions;

static queued_actions take_queued_actions(agent_runtime *rt) {
    pthread_mutex_lock(&rt->state_mutex);
    if (rt->refresh_requested) sb_str_set(&rt->last_etag, NULL);
    queued_actions actions = {rt->reload_requested, rt->restart_requested};
    rt->refresh_requested = false;
    rt->reload_requested = false;
    rt->restart_requested = false;
    pthread_mutex_unlock(&rt->state_mutex);
    return actions;
}

static void finish_cycle(agent_runtime *rt, const sb_strvec *errors) {
    char *joined = errors->len ? sb_join(errors, "; ") : NULL;
    char *now = current_time_iso8601();
    pthread_mutex_lock(&rt->state_mutex);
    free(rt->last_cycle);
    rt->last_cycle = now;
    free(rt->last_error);
    rt->last_error = joined;
    pthread_mutex_unlock(&rt->state_mutex);
}

static void update_local_telemetry(agent_runtime *rt, const sbj *telemetry) {
    static const char *const fields[] = {"up", "down", "up_total", "down_total", "conn_count"};
    sbj *value = sbj_object();
    sbj_set_bool(value, "available", true);
    sbj_set(value, "sampled_at", sbj_str_take(current_time_iso8601()));
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i) {
        const sbj *found = sbj_get(telemetry, fields[i]);
        sbj_set(value, fields[i], sbj_is_integer(found) ? sbj_clone(found) : sbj_int(0));
    }
    pthread_mutex_lock(&rt->state_mutex);
    sbj_free(rt->last_telemetry);
    rt->last_telemetry = value;
    pthread_mutex_unlock(&rt->state_mutex);
}

static int validate_with_singbox(const char *temporary, void *user, sb_err *err) {
    agent_runtime *rt = user;
    if (!rt->validate_config) return 0;
    sb_strvec arguments = {0};
    sb_strvec_push(&arguments, rt->singbox_bin);
    sb_strvec_push(&arguments, "check");
    sb_strvec_push(&arguments, "-c");
    sb_strvec_push(&arguments, temporary);
    process_result checked = run_program(&arguments);
    sb_strvec_free(&arguments);
    int rc = 0;
    if (!checked.success)
        rc = sb_fail(err, SB_ERR_GENERIC, "sing-box config validation failed: %s", checked.detail);
    free(checked.detail);
    return rc;
}

static int apply_config(agent_runtime *rt, const sb_agent_config_response *config, sb_err *err) {
    sb_agent_config_options options;
    pthread_mutex_lock(&rt->state_mutex);
    sb_agent_config_options_copy(&options, &rt->transform_options);
    pthread_mutex_unlock(&rt->state_mutex);
    char *prepared = sb_prepare_agent_config(config->body, strlen(config->body), &options, err);
    sb_agent_config_options_free(&options);
    if (!prepared) return -1;
    size_t prepared_len = strlen(prepared);
    int rc = -1;
    char *previous = NULL;

    if (rt->singbox_managed) {
        if (sb_singbox_supervisor_apply_config(rt->supervisor, prepared, prepared_len, err) != 0)
            goto out;
        set_running(rt, sb_singbox_supervisor_running(rt->supervisor));
        set_etag(rt, config->etag);
        set_rule_source(rt, config->rule_source);
        printf("applied config %s\n", config->etag);
        rc = 0;
        goto out;
    }

    size_t previous_len = 0;
    int had_previous = read_existing(rt->config_path, &previous, &previous_len, err);
    if (had_previous < 0) goto out;
    if (sb_atomic_replace_file(rt->config_path, prepared, prepared_len, validate_with_singbox, rt,
                               err) != 0)
        goto out;
    process_result reloaded = run_program(&rt->reload_command);
    if (!reloaded.success) {
        if (had_previous > 0) {
            sb_err restore_error = {0};
            if (sb_atomic_replace_file(rt->config_path, previous, previous_len, NULL, NULL,
                                       &restore_error) != 0) {
                /* C++ lets the restore failure escape instead of the reload error. */
                sb_fail(err, restore_error.code, "%s", restore_error.msg);
                free(reloaded.detail);
                goto out;
            }
            process_result ignored = run_program(&rt->reload_command);
            free(ignored.detail);
        }
        sb_fail(err, SB_ERR_GENERIC, "sing-box reload failed: %s", reloaded.detail);
        free(reloaded.detail);
        goto out;
    }
    free(reloaded.detail);
    set_running(rt, true);
    set_etag(rt, config->etag);
    set_rule_source(rt, config->rule_source);
    printf("applied config %s\n", config->etag);
    rc = 0;
out:
    free(previous);
    free(prepared);
    return rc;
}

/* Reload or restart through the supervisor (managed) or the configured
 * command (unmanaged). */
static process_result run_runtime_command(agent_runtime *rt, bool restart) {
    process_result result = {false, NULL};
    if (!rt->singbox_managed)
        return run_program(restart ? &rt->restart_command : &rt->reload_command);
    sb_err error = {0};
    int rc = restart ? sb_singbox_supervisor_restart(rt->supervisor, &error)
                     : sb_singbox_supervisor_reload(rt->supervisor, &error);
    if (rc != 0) {
        result.detail = sb_strdup(error.msg);
        return result;
    }
    result.success = sb_singbox_supervisor_running(rt->supervisor);
    result.detail = sb_strdup(sb_singbox_supervisor_running(rt->supervisor)
                                  ? (restart ? "restarted" : "reloaded")
                                  : "sing-box did not start");
    return result;
}

static int run_local_action(agent_runtime *rt, queued_actions actions, sb_err *err) {
    if (!actions.reload && !actions.restart) return 0;
    bool restart = actions.restart;
    process_result result = run_runtime_command(rt, restart);
    set_running(rt, rt->singbox_managed ? sb_singbox_supervisor_running(rt->supervisor)
                                        : result.success);
    if (!result.success) {
        sb_fail(err, SB_ERR_GENERIC, "%s", result.detail);
        free(result.detail);
        return -1;
    }
    free(result.detail);
    printf("local UI action completed: %s\n", restart ? "restart" : "reload");
    return 0;
}

static int report_latency(const sbj *latency, void *user, sb_err *err) {
    agent_runtime *rt = user;
    size_t updated = 0;
    return sb_agent_client_report_proxy_latencies(rt->client, latency, &updated, err);
}

static int run_commands(agent_runtime *rt, sb_err *err) {
    sb_agent_command_vec commands;
    if (sb_agent_client_pending_commands(rt->client, &commands, err) != 0) return -1;
    int rc = 0;
    for (size_t i = 0; i < commands.len; ++i) {
        const char *command = commands.items[i].command;
        process_result result = {false, NULL};
        bool changes_running_state = false;
        if (strcmp(command, "reload") == 0 || strcmp(command, "restart") == 0) {
            result = run_runtime_command(rt, strcmp(command, "restart") == 0);
            changes_running_state = true;
        } else if (strcmp(command, "test-proxies") == 0 ||
                   sb_starts_with(command, "test-proxies ")) {
            sb_strvec tags;
            bool all = true;
            sb_err error = {0};
            size_t tested = 0;
            if (proxy_test_tags(command, &tags, &all, &error) == 0 &&
                sb_agent_clash_test_proxies(rt->clash, all ? NULL : &tags, report_latency, rt,
                                            &tested, &error) == 0) {
                result.success = true;
                result.detail = sb_asprintf("tested %zu proxies", tested);
            } else {
                result.detail = sb_asprintf("test-proxies: %s", error.msg);
            }
            sb_strvec_free(&tags);
        } else {
            result.detail = sb_asprintf("unknown command: %s", command);
        }
        if (changes_running_state)
            set_running(rt, rt->singbox_managed ? sb_singbox_supervisor_running(rt->supervisor)
                                                : result.success);
        rc = sb_agent_client_acknowledge_command(rt->client, commands.items[i].id, result.success,
                                                 result.detail, err);
        free(result.detail);
        if (rc != 0) break;
    }
    sb_agent_command_vec_free(&commands);
    return rc;
}

static bool run_cycle(agent_runtime *rt) {
    sb_strvec errors = {0};
    queued_actions actions = take_queued_actions(rt);
    {
        sb_err error = {0};
        char *etag = copy_etag(rt);
        sb_agent_config_response config;
        int rc = sb_agent_client_poll_config(rt->client, etag, &config, &error);
        free(etag);
        if (rc == 0) {
            if (config.modified) rc = apply_config(rt, &config, &error);
            else set_rule_source(rt, config.rule_source);
            sb_agent_config_response_free(&config);
        }
        if (rc != 0) record_error(&errors, "config poll/apply", error.msg);
    }
    {
        sb_err error = {0};
        if (run_local_action(rt, actions, &error) != 0)
            record_error(&errors, "local action", error.msg);
    }
    if (rt->singbox_managed) {
        sb_singbox_supervisor_ensure_alive(rt->supervisor);
        set_running(rt, sb_singbox_supervisor_running(rt->supervisor));
        const char *last_error = sb_singbox_supervisor_last_error(rt->supervisor);
        if (last_error) {
            char *line = sb_asprintf("managed sing-box: %s", last_error);
            fprintf(stderr, "%s\n", line);
            sb_strvec_push_take(&errors, line);
        }
    }
    {
        sb_err error = {0};
        if (run_commands(rt, &error) != 0) record_error(&errors, "command poll", error.msg);
    }
    {
        /* Telemetry is best effort and must not make an otherwise healthy
         * config/status cycle fail when the local Clash API is disabled. */
        sb_err error = {0};
        sbj *telemetry = NULL;
        int rc = sb_agent_clash_sample_telemetry(rt->clash, &telemetry, &error);
        if (rc == 0 && telemetry) {
            update_local_telemetry(rt, telemetry);
            rc = sb_agent_client_report_telemetry(rt->client, telemetry, &error);
        }
        sbj_free(telemetry);
        if (rc != 0) fprintf(stderr, "telemetry sample failed: %s\n", error.msg);
    }
    {
        sb_err error = {0};
        int running = get_running(rt);
        bool running_value = running > 0;
        char *etag = copy_etag(rt);
        if (sb_agent_client_report_status(rt->client, AGENT_VERSION,
                                          running < 0 ? NULL : &running_value, etag, &error) != 0)
            record_error(&errors, "status report", error.msg);
        free(etag);
    }
    finish_cycle(rt, &errors);
    bool ok = errors.len == 0;
    sb_strvec_free(&errors);
    return ok;
}

static void wait_for_work(agent_runtime *rt, int64_t seconds) {
    /* Cap absurd intervals at ~100 years so the deadline cannot overflow. */
    const int64_t maximum = (int64_t)100 * 365 * 24 * 60 * 60;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(seconds > maximum ? maximum : seconds);
    pthread_mutex_lock(&rt->state_mutex);
    while (!(rt->refresh_requested || rt->reload_requested || rt->restart_requested)) {
        if (pthread_cond_timedwait(&rt->wakeup, &rt->state_mutex, &deadline) == ETIMEDOUT) break;
    }
    pthread_mutex_unlock(&rt->state_mutex);
}

/* ---- Agent UI callbacks ------------------------------------------------ */

static sbj *ui_status(void *user, sb_err *err) {
    (void)err;
    agent_runtime *rt = user;
    sbj *status = sbj_object();
    pthread_mutex_lock(&rt->state_mutex);
    sbj_set_str(status, "service", AGENT_SERVICE);
    sbj_set_str(status, "version", SB_EASY_VERSION);
    sbj_set_str(status, "server", rt->identity.server);
    sbj_set_str(status, "config_path", rt->config_path);
    sbj_set_str(status, "settings_path", rt->settings_path);
    sbj_set_bool(status, "singbox_managed", rt->singbox_managed);
#if defined(SB_EASY_EMBED_SINGBOX)
    sbj_set_str(status, "singbox_mode", "embedded");
#else
    sbj_set_str(status, "singbox_mode", "external");
#endif
    sbj_set(status, "running", rt->running < 0 ? sbj_null() : sbj_bool(rt->running > 0));
    sbj_set(status, "etag", sbj_str(rt->last_etag));
    sbj_set(status, "last_cycle", sbj_str(rt->last_cycle));
    sbj_set(status, "last_error", sbj_str(rt->last_error));
    sbj_set_str(status, "rule_source", rt->last_rule_source);
    sbj *pending = sbj_object();
    sbj_set_bool(pending, "refresh", rt->refresh_requested);
    sbj_set_bool(pending, "reload", rt->reload_requested);
    sbj_set_bool(pending, "restart", rt->restart_requested);
    sbj_set(status, "pending", pending);
    sbj_set(status, "telemetry", sbj_clone(rt->last_telemetry));
    pthread_mutex_unlock(&rt->state_mutex);
    return status;
}

static sbj *ui_settings(void *user, sb_err *err) {
    (void)err;
    agent_runtime *rt = user;
    pthread_mutex_lock(&rt->state_mutex);
    sbj *settings = sb_agent_config_options_to_json(&rt->transform_options);
    pthread_mutex_unlock(&rt->state_mutex);
    return settings;
}

static sbj *ui_update_settings(const sbj *value, void *user, sb_err *err) {
    agent_runtime *rt = user;
    sb_agent_config_options current;
    pthread_mutex_lock(&rt->state_mutex);
    sb_agent_config_options_copy(&current, &rt->transform_options);
    pthread_mutex_unlock(&rt->state_mutex);
    sb_agent_config_options updated;
    int rc = sb_agent_config_options_from_json(value, &current, &updated, err);
    sb_agent_config_options_free(&current);
    if (rc != 0) return NULL;
    if (sb_agent_config_options_save(rt->settings_path, &updated, err) != 0) {
        sb_agent_config_options_free(&updated);
        return NULL;
    }
    sbj *result = sb_agent_config_options_to_json(&updated);
    pthread_mutex_lock(&rt->state_mutex);
    sb_agent_config_options_free(&rt->transform_options);
    rt->transform_options = updated;
    rt->refresh_requested = true;
    pthread_cond_signal(&rt->wakeup);
    pthread_mutex_unlock(&rt->state_mutex);
    return result;
}

static sbj *ui_config(void *user, sb_err *err) {
    agent_runtime *rt = user;
    char *contents = NULL;
    size_t len = 0;
    int found = read_existing(rt->config_path, &contents, &len, err);
    if (found < 0) return NULL;
    if (found == 0) return sbj_object();
    sbj *config = parse_json(contents, len, err);
    free(contents);
    return config;
}

static sbj *ui_proxies(void *user, sb_err *err) {
    agent_runtime *rt = user;
    sb_err clash_error = {0};
    sbj *live = sb_agent_clash_proxies(rt->clash, &clash_error);
    if (live) return live;
    /* Keep the proxy page useful when the controller is temporarily down:
     * show the configured groups, but surface why live selection is absent. */
    sbj *fallback = sbj_object();
    sbj *proxies = sbj_object();
    sbj_set(fallback, "proxies", proxies);
    sbj_set_str(fallback, "error", clash_error.msg);
    sbj *config = ui_config(rt, err);
    if (!config) {
        sbj_free(fallback);
        return NULL;
    }
    const sbj *outbounds = sbj_get(config, "outbounds");
    const sbj *outbound;
    SBJ_ARR_FOREACH(outbounds, i, outbound) {
        if (!sbj_is_object(outbound)) continue;
        const char *tag = NULL, *type_or_unknown = NULL, *type = NULL;
        if (value_string(outbound, "tag", "", &tag, err) != 0) goto fail;
        if (!*tag) continue;
        if (value_string(outbound, "type", "unknown", &type_or_unknown, err) != 0) goto fail;
        sbj *proxy = sbj_object();
        sbj_set_str(proxy, "type", type_or_unknown);
        if (value_string(outbound, "type", "", &type, err) != 0) {
            sbj_free(proxy);
            goto fail;
        }
        if (strcmp(type, "selector") == 0 || strcmp(type, "urltest") == 0) {
            sbj_set_str(proxy, "type", strcmp(type, "selector") == 0 ? "Selector" : "URLTest");
            const sbj *all = sbj_get(outbound, "outbounds");
            sbj_set(proxy, "all", all ? sbj_clone(all) : sbj_array());
            const char *now = NULL;
            if (value_string(outbound, "default", "", &now, err) != 0) {
                sbj_free(proxy);
                goto fail;
            }
            sbj_set_str(proxy, "now", now);
        }
        sbj_set(proxies, tag, proxy);
    }
    sbj_free(config);
    return fallback;
fail:
    sbj_free(config);
    sbj_free(fallback);
    return NULL;
}

static sbj *ui_select_proxy(const char *group, const char *proxy, void *user, sb_err *err) {
    agent_runtime *rt = user;
    return sb_agent_clash_select_proxy(rt->clash, group, proxy, err);
}

static sbj *ui_test_route(const char *url, void *user, sb_err *err) {
    agent_runtime *rt = user;
    return sb_agent_clash_test_route(rt->clash, url, err);
}

static int ui_request_action(const char *action, void *user, sb_err *err) {
    agent_runtime *rt = user;
    pthread_mutex_lock(&rt->state_mutex);
    if (strcmp(action, "refresh") == 0) {
        rt->refresh_requested = true;
    } else if (strcmp(action, "reload") == 0) {
        rt->reload_requested = true;
    } else if (strcmp(action, "restart") == 0) {
        rt->restart_requested = true;
    } else {
        pthread_mutex_unlock(&rt->state_mutex);
        return sb_fail(err, SB_ERR_VALIDATION, "unsupported Agent UI action");
    }
    pthread_cond_signal(&rt->wakeup);
    pthread_mutex_unlock(&rt->state_mutex);
    return 0;
}

/* ---- entry point ------------------------------------------------------- */

static void usage(const char *executable) {
    fprintf(stderr,
            "Usage: %s [--once]\n"
            "First use: SB_EASY_SERVER, AGENT_ENROLLMENT_CODE\n"
            "Compatibility: SB_EASY_SERVER, AGENT_TOKEN\n"
            "Enrolled credentials default beside the sing-box config; override with "
            "AGENT_CREDENTIAL_PATH\n"
            "Local UI: set AGENT_UI_PASSWORD; bind defaults to 0.0.0.0:51822; set "
            "AGENT_UI_PATH to serve a static app\n",
            executable);
}

int sb_agent_main(int argc, char **argv) {
    /* trantor ignores SIGPIPE in the C++ build; keep broken pipes from
     * killing the agent (and children inherit the disposition, as before). */
    signal(SIGPIPE, SIG_IGN);
    /* Progress lines go out as they happen, also when stdout is a pipe. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    sb_http_global_init();

    bool once = false;
    if (argc == 2 && strcmp(argv[1], "--once") == 0) {
        once = true;
    } else if (argc != 1) {
        usage(argc > 0 ? argv[0] : "sb-easy-c-agent");
        return 2;
    }

    agent_runtime runtime;
    sb_err err = {0};
    if (runtime_init(&runtime, &err) != 0) {
        fprintf(stderr, "error: %s\n", err.msg);
        return 1;
    }
    if (once) {
        bool ok = run_cycle(&runtime);
        runtime_free(&runtime);
        return ok ? 0 : 1;
    }

    sb_agent_ui *local_ui = NULL;
    if (environment_flag("AGENT_UI_ENABLED", true)) {
        local_ui_config options;
        if (local_ui_options(&options, &err) != 0) goto fail;
        if (!*options.password) {
            fprintf(stderr, "Agent UI disabled: set AGENT_UI_PASSWORD to expose the management "
                            "interface\n");
        } else {
            sb_agent_ui_options ui_options = {
                .address = options.address,
                .port = options.port,
                .username = options.username,
                .password = options.password,
                .ui_directory = options.ui_directory,
            };
            sb_agent_ui_callbacks callbacks = {
                .status = ui_status,
                .settings = ui_settings,
                .update_settings = ui_update_settings,
                .config = ui_config,
                .proxies = ui_proxies,
                .select_proxy = ui_select_proxy,
                .test_route = ui_test_route,
                .request_action = ui_request_action,
                .user = &runtime,
            };
            local_ui = sb_agent_ui_new(&ui_options, &callbacks, &err);
            if (!local_ui) {
                free(options.address);
                goto fail;
            }
            printf("Agent UI listening on %s:%u\n", options.address,
                   (unsigned)sb_agent_ui_port(local_ui));
        }
        free(options.address);
    }
    int64_t interval = 0;
    if (poll_interval(&interval, &err) != 0) goto fail;
    for (;;) {
        (void)run_cycle(&runtime);
        wait_for_work(&runtime, interval);
    }

fail:
    fprintf(stderr, "error: %s\n", err.msg);
    sb_agent_ui_free(local_ui);
    runtime_free(&runtime);
    return 1;
}
