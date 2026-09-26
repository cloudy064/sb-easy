/* In-process sing-box via the Go bridge (C++ singbox_supervisor_embedded.cpp).
 * Only compiled with -DSB_EASY_EMBED_SINGBOX. */
#include "sb/singbox_supervisor.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libsb_easy_singbox.h"
#include "sb/atomic_file.h"

struct sb_singbox_supervisor {
    char *config_path;
    bool validate_config;
    int64_t restart_backoff_ms;
    int64_t shutdown_timeout_ms;
    bool running;
    bool has_started;
    int64_t next_start_ms;
    char *last_error;
};

void sb_singbox_supervisor_options_init(sb_singbox_supervisor_options *o) {
    o->binary = "sing-box";
    o->config_path = "data/sing-box.gen.json";
    o->validate_config = true;
    o->restart_backoff_ms = 1000;
    o->shutdown_timeout_ms = 2000;
}

static void set_last_error(sb_singbox_supervisor *s, char *message) {
    free(s->last_error);
    s->last_error = message;
}

/* Takes ownership of a bridge-allocated error string; NULL when no error. */
static char *bridge_error(char *value) {
    if (!value) return NULL;
    char *message = sb_strdup(value);
    SBEasySingBoxFree(value);
    return message;
}

static int fail_bridge_error(const char *operation, char *value, sb_err *err) {
    char *error = bridge_error(value);
    if (!error) return 0;
    sb_fail(err, SB_ERR_GENERIC, "%s: %s", operation, error);
    free(error);
    return -1;
}

sb_singbox_supervisor *sb_singbox_supervisor_new(const sb_singbox_supervisor_options *options,
                                                 sb_err *err) {
    sb_singbox_supervisor_options o;
    if (options) o = *options;
    else sb_singbox_supervisor_options_init(&o);
    if (sb_str_empty(o.config_path) || sb_ends_with(o.config_path, "/")) {
        sb_fail(err, SB_ERR_VALIDATION, "sing-box config path must name a file");
        return NULL;
    }
    if (o.restart_backoff_ms < 0 || o.shutdown_timeout_ms < 0) {
        sb_fail(err, SB_ERR_VALIDATION, "sing-box process durations cannot be negative");
        return NULL;
    }
    sb_singbox_supervisor *s = sb_xcalloc(1, sizeof *s);
    s->config_path = sb_strdup(o.config_path);
    s->validate_config = o.validate_config;
    s->restart_backoff_ms = o.restart_backoff_ms;
    s->shutdown_timeout_ms = o.shutdown_timeout_ms;
    return s;
}

void sb_singbox_supervisor_free(sb_singbox_supervisor *s) {
    if (!s) return;
    sb_singbox_supervisor_stop(s);
    free(s->config_path);
    free(s->last_error);
    free(s);
}

static int validate(const char *path, void *user, sb_err *err) {
    sb_singbox_supervisor *s = user;
    if (!s->validate_config) return 0;
    return fail_bridge_error("sing-box config validation failed",
                             SBEasySingBoxCheck((char *)path), err);
}

static void reap(sb_singbox_supervisor *s) {
    if (s->running && SBEasySingBoxRunning() == 0) {
        s->running = false;
        set_last_error(s, sb_strdup("embedded sing-box stopped unexpectedly"));
        s->next_start_ms = sb_monotonic_ms() + s->restart_backoff_ms;
    }
}

static bool is_regular_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int start(sb_singbox_supervisor *s, bool ignore_backoff, sb_err *err) {
    reap(s);
    if (s->running) return 0;
    if (!ignore_backoff && sb_monotonic_ms() < s->next_start_ms) return 0;
    if (!is_regular_file(s->config_path)) return 0;
    s->has_started = true;
    char *error = bridge_error(SBEasySingBoxStart(s->config_path));
    if (error) {
        s->next_start_ms = sb_monotonic_ms() + s->restart_backoff_ms;
        set_last_error(s, sb_asprintf("start embedded sing-box failed: %s", error));
        free(error);
        return sb_fail(err, SB_ERR_GENERIC, "%s", s->last_error);
    }
    s->running = true;
    s->next_start_ms = 0;
    set_last_error(s, NULL);
    return 0;
}

static int reload_running(sb_singbox_supervisor *s, sb_err *err) {
    if (fail_bridge_error("reload embedded sing-box failed",
                          SBEasySingBoxReload(s->config_path), err) != 0)
        return -1;
    s->running = true;
    set_last_error(s, NULL);
    return 0;
}

int sb_singbox_supervisor_apply_config(sb_singbox_supervisor *s, const char *contents,
                                       size_t len, sb_err *err) {
    if (sb_atomic_replace_file(s->config_path, contents, len, validate, s, err) != 0) return -1;
    if (!sb_singbox_supervisor_running(s)) return start(s, true, err);
    return reload_running(s, err);
}

void sb_singbox_supervisor_ensure_alive(sb_singbox_supervisor *s) {
    reap(s);
    if (s->has_started && !s->running) {
        sb_err error = {0};
        if (start(s, false, &error) != 0) set_last_error(s, sb_strdup(error.msg));
    }
}

int sb_singbox_supervisor_reload(sb_singbox_supervisor *s, sb_err *err) {
    if (!sb_singbox_supervisor_running(s)) return start(s, true, err);
    return reload_running(s, err);
}

int sb_singbox_supervisor_restart(sb_singbox_supervisor *s, sb_err *err) {
    sb_singbox_supervisor_stop(s);
    s->has_started = true;
    return start(s, true, err);
}

void sb_singbox_supervisor_stop(sb_singbox_supervisor *s) {
    if (!s->running && SBEasySingBoxRunning() == 0) return;
    char *error = bridge_error(SBEasySingBoxStop());
    if (error) {
        set_last_error(s, sb_asprintf("stop embedded sing-box failed: %s", error));
        free(error);
    }
    s->running = false;
    s->has_started = false;
}

bool sb_singbox_supervisor_running(sb_singbox_supervisor *s) {
    reap(s);
    return s->running;
}

pid_t sb_singbox_supervisor_pid(sb_singbox_supervisor *s) {
    return sb_singbox_supervisor_running(s) ? getpid() : -1;
}

const char *sb_singbox_supervisor_last_error(const sb_singbox_supervisor *s) {
    return s->last_error;
}
