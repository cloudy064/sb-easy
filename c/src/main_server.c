/* sb-easy-c-server: the panel HTTP server (port of cpp/src/server_main.cpp).
 * Configuration comes from the same environment variables and positional
 * arguments as the C++ server; exit codes: 0 after SIGINT/SIGTERM, 1 on
 * errors ("error: <message>"), 2 on usage errors. */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb/http_client.h"
#include "sb/http_server.h"
#include "sb/store.h"
#include "sb/util.h"

/* environment(): the variable's value when set (even if empty), else fallback. */
static const char *environment(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value ? value : fallback;
}

static bool environment_flag(const char *name, bool fallback) {
    const char *value = environment(name, "");
    if (!*value) return fallback;
    char *lowered = sb_lower_dup(value);
    bool on = strcmp(lowered, "1") == 0 || strcmp(lowered, "true") == 0 || strcmp(lowered, "yes") == 0 ||
              strcmp(lowered, "on") == 0;
    free(lowered);
    return on;
}

/* std::from_chars for an unsigned type: digits only, full match, no overflow. */
static bool parse_unsigned(const char *text, uint64_t maximum, uint64_t *out) {
    if (!text || !*text) return false;
    uint64_t value = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        uint64_t digit = (uint64_t)(*p - '0');
        if (value > (maximum - digit) / 10) return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

static int environment_integer(const char *name, uint64_t fallback, uint64_t *out, sb_err *err) {
    const char *value = environment(name, "");
    if (!*value) {
        *out = fallback;
        return 0;
    }
    if (!parse_unsigned(value, UINT64_MAX, out)) return sb_fail(err, SB_ERR_VALIDATION, "%s must be an integer", name);
    return 0;
}

static int parse_port(const char *input, const char *source, uint16_t *out, sb_err *err) {
    uint64_t port = 0;
    if (!parse_unsigned(input, UINT32_MAX, &port) || port == 0 || port > 65535)
        return sb_fail(err, SB_ERR_VALIDATION, "%s port is out of range", source);
    *out = (uint16_t)port;
    return 0;
}

static int apply_bind_address(const char *bind, sb_http_server_options *options, sb_err *err) {
    size_t len = strlen(bind);
    if (bind[0] == '[') {
        const char *closing = strchr(bind, ']');
        size_t at = closing ? (size_t)(closing - bind) : 0;
        if (!closing || at + 1 >= len || bind[at + 1] != ':')
            return sb_fail(err, SB_ERR_VALIDATION, "BIND_ADDR must use [IPv6]:port syntax");
        char *address = sb_strndup(bind + 1, at - 1);
        sb_str_set(&options->address, address);
        free(address);
        return parse_port(bind + at + 2, "BIND_ADDR", &options->port, err);
    }
    const char *separator = strrchr(bind, ':');
    size_t at = separator ? (size_t)(separator - bind) : 0;
    if (!separator || at == 0 || at + 1 >= len)
        return sb_fail(err, SB_ERR_VALIDATION, "BIND_ADDR must use address:port syntax");
    char *address = sb_strndup(bind, at);
    sb_str_set(&options->address, address);
    free(address);
    return parse_port(bind + at + 1, "BIND_ADDR", &options->port, err);
}

static char *database_path_from_environment(sb_err *err) {
    const char *url = environment("DATABASE_URL", "sqlite:/app/data/sb-easy.db?mode=rwc");
    if (strncmp(url, "sqlite:", 7) == 0) url += 7;
    const char *query = strchr(url, '?');
    char *path = query ? sb_strndup(url, (size_t)(query - url)) : sb_strdup(url);
    if (!*path) {
        free(path);
        sb_fail(err, SB_ERR_VALIDATION, "DATABASE_URL does not contain a database path");
        return NULL;
    }
    return path;
}

static void set_if_present(char **slot, const char *name) {
    const char *value = getenv(name);
    if (value) sb_str_set(slot, value);
}

static int configure(int argc, char **argv, sb_http_server_options *options, char **database_path,
                     char **migration_directory, sb_err *err) {
    if (argc == 1) {
        if (!(*database_path = database_path_from_environment(err))) return -1;
        *migration_directory = sb_strdup(environment("MIGRATIONS_DIR", "/app/migrations"));
        if (apply_bind_address(environment("BIND_ADDR", "0.0.0.0:51821"), options, err) != 0) return -1;
        sb_str_set(&options->public_server, environment("PUBLIC_SERVER", ""));
    } else {
        *database_path = sb_strdup(argv[1]);
        *migration_directory = sb_strdup(argv[2]);
        if (argc >= 4) sb_str_set(&options->address, argv[3]);
        if (argc >= 5 && parse_port(argv[4], "command-line", &options->port, err) != 0) return -1;
        if (argc >= 6) sb_str_set(&options->public_server, argv[5]);
    }
    set_if_present(&options->config_hash_seed, "CONFIG_HASH_SEED");
    set_if_present(&options->legacy_agent_token, "AGENT_TOKEN");
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) return sb_fail(err, SB_ERR_VALIDATION, "JWT_SECRET must be set");
    sb_str_set(&options->jwt_secret, secret);
    set_if_present(&options->admin_password, "ADMIN_PASSWORD");
    set_if_present(&options->clash_api_url, "SINGBOX_API_URL");
    set_if_present(&options->clash_api_secret, "SINGBOX_API_SECRET");
    options->singbox_managed = environment_flag("SINGBOX_MANAGED", false);
    sb_str_set(&options->singbox_binary, environment("SINGBOX_BIN", "sing-box"));
    sb_str_set(&options->self_singbox_config_path, environment("SELF_SINGBOX_CONFIG_PATH", ""));
    uint64_t interval = 0;
    if (environment_integer("SELF_SINGBOX_INTERVAL", 10, &interval, err) != 0) return -1;
    options->self_singbox_interval_seconds = interval < 2 ? 2 : interval;
    options->singbox_validate_config = environment_flag("SINGBOX_VALIDATE_CONFIG", true);
    options->wireguard_enabled = environment_flag("WG_ENABLED", true);
    sb_str_set(&options->wireguard_interface, environment("WG_INTERFACE", "wg0"));
    uint64_t wireguard_port = 0;
    if (environment_integer("WG_PORT", 51820, &wireguard_port, err) != 0) return -1;
    if (wireguard_port == 0 || wireguard_port > 65535) return sb_fail(err, SB_ERR_VALIDATION, "WG_PORT is out of range");
    options->wireguard_port = (uint16_t)wireguard_port;
    sb_str_set(&options->wireguard_address, environment("WG_ADDRESS", "10.59.32.1/24"));
    sb_str_set(&options->wireguard_dns, environment("WG_DNS", "10.59.32.1"));
    uint64_t wireguard_mtu = 0;
    if (environment_integer("WG_MTU", 1420, &wireguard_mtu, err) != 0) return -1;
    if (wireguard_mtu > UINT32_MAX) return sb_fail(err, SB_ERR_VALIDATION, "WG_MTU is out of range");
    options->wireguard_mtu = (uint32_t)wireguard_mtu;
    sb_str_set(&options->wireguard_egress, environment("WG_EGRESS", "eth0"));
    sb_str_set(&options->external_hostname, environment("EXTERNAL_HOSTNAME", "127.0.0.1"));
    if (sb_str_empty(options->public_server))
        sb_str_set(&options->public_server, environment("PUBLIC_SERVER", options->external_hostname));
    sb_str_set(&options->wireguard_config_directory, environment("WG_CONFIG_DIRECTORY", "/etc/wireguard"));
    sb_str_set(&options->static_directory, environment("STATIC_DIR", "frontend/dist"));
    sb_str_set(&options->cors_origins, environment("CORS_ORIGINS", ""));
    sb_str_set(&options->log_level, environment("LOG_LEVEL", "info"));
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 1 && (argc < 3 || argc > 6)) {
        fprintf(stderr,
                "Usage: %s <database.db> <migration-directory> [address] [port] [public-server]\n"
                "   or: configure DATABASE_URL, MIGRATIONS_DIR, and BIND_ADDR, then run without arguments\n",
                argv[0]);
        return 2;
    }
    sb_http_global_init();
    sb_http_server_options options;
    sb_http_server_options_init(&options);
    char *database_path = NULL, *migration_directory = NULL;
    sb_err err = {0};
    int rc = 1;
    if (configure(argc, argv, &options, &database_path, &migration_directory, &err) == 0) {
        sb_store *store = sb_store_open(database_path, migration_directory, &err);
        if (store) {
            if (sb_http_server_run(store, &options, &err) == 0) rc = 0;
            sb_store_free(store);
        }
    }
    if (rc != 0) fprintf(stderr, "error: %s\n", err.msg);
    free(database_path);
    free(migration_directory);
    sb_http_server_options_free(&options);
    return rc;
}
