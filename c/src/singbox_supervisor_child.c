/* Supervised sing-box child process (C++ singbox_supervisor.cpp). */
#include "sb/singbox_supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sb/atomic_file.h"

extern char **environ;

struct sb_singbox_supervisor {
    char *binary;
    char *config_path;
    bool validate_config;
    int64_t restart_backoff_ms;
    int64_t shutdown_timeout_ms;
    pid_t child;
    bool has_started;
    int64_t next_start_ms; /* monotonic; 0 == time_point{} */
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

/* run_program(): returns true on exit code 0; *detail receives the outcome. */
static bool run_program(char *const argv[], char **detail) {
    pid_t process = 0;
    int spawn_error = posix_spawnp(&process, argv[0], NULL, NULL, argv, environ);
    if (spawn_error != 0) {
        *detail = sb_asprintf("spawn failed: %s", strerror(spawn_error));
        return false;
    }
    int status = 0;
    while (waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            *detail = sb_asprintf("wait failed: %s", strerror(errno));
            return false;
        }
    }
    if (WIFEXITED(status)) {
        *detail = sb_asprintf("exit code %d", WEXITSTATUS(status));
        return WEXITSTATUS(status) == 0;
    }
    if (WIFSIGNALED(status)) {
        *detail = sb_asprintf("terminated by signal %d", WTERMSIG(status));
        return false;
    }
    *detail = sb_strdup("process ended without an exit status");
    return false;
}

static char *child_exit_detail(int status) {
    if (WIFEXITED(status)) return sb_asprintf("sing-box exited with code %d", WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        return sb_asprintf("sing-box terminated by signal %d", WTERMSIG(status));
    return sb_strdup("sing-box exited without a status");
}

sb_singbox_supervisor *sb_singbox_supervisor_new(const sb_singbox_supervisor_options *options,
                                                 sb_err *err) {
    sb_singbox_supervisor_options o;
    if (options) o = *options;
    else sb_singbox_supervisor_options_init(&o);
    if (sb_str_empty(o.binary)) {
        sb_fail(err, SB_ERR_VALIDATION, "sing-box binary is required");
        return NULL;
    }
    if (sb_str_empty(o.config_path) || sb_ends_with(o.config_path, "/")) {
        sb_fail(err, SB_ERR_VALIDATION, "sing-box config path must name a file");
        return NULL;
    }
    if (o.restart_backoff_ms < 0 || o.shutdown_timeout_ms < 0) {
        sb_fail(err, SB_ERR_VALIDATION, "sing-box process durations cannot be negative");
        return NULL;
    }
    sb_singbox_supervisor *s = sb_xcalloc(1, sizeof *s);
    s->binary = sb_strdup(o.binary);
    s->config_path = sb_strdup(o.config_path);
    s->validate_config = o.validate_config;
    s->restart_backoff_ms = o.restart_backoff_ms;
    s->shutdown_timeout_ms = o.shutdown_timeout_ms;
    s->child = -1;
    return s;
}

void sb_singbox_supervisor_free(sb_singbox_supervisor *s) {
    if (!s) return;
    sb_singbox_supervisor_stop(s);
    free(s->binary);
    free(s->config_path);
    free(s->last_error);
    free(s);
}

static int validate(const char *path, void *user, sb_err *err) {
    sb_singbox_supervisor *s = user;
    if (!s->validate_config) return 0;
    char *argv[] = {s->binary, "check", "-c", (char *)path, NULL};
    char *detail = NULL;
    bool ok = run_program(argv, &detail);
    int rc = ok ? 0
                : sb_fail(err, SB_ERR_GENERIC, "sing-box config validation failed: %s", detail);
    free(detail);
    return rc;
}

static void reap(sb_singbox_supervisor *s) {
    if (s->child <= 0) return;
    int status = 0;
    pid_t result = waitpid(s->child, &status, WNOHANG);
    if (result == 0) return;
    if (result == s->child) {
        s->child = -1;
        set_last_error(s, child_exit_detail(status));
        s->next_start_ms = sb_monotonic_ms() + s->restart_backoff_ms;
        return;
    }
    if (result < 0 && errno == EINTR) return;
    if (result < 0 && errno == ECHILD) {
        s->child = -1;
        set_last_error(s, sb_strdup("sing-box child could not be reaped"));
        s->next_start_ms = sb_monotonic_ms() + s->restart_backoff_ms;
        return;
    }
    if (result < 0) set_last_error(s, sb_asprintf("sing-box wait failed: %s", strerror(errno)));
}

static bool is_regular_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int start(sb_singbox_supervisor *s, bool ignore_backoff, sb_err *err) {
    reap(s);
    if (s->child > 0) return 0;
    if (!ignore_backoff && sb_monotonic_ms() < s->next_start_ms) return 0;
    if (!is_regular_file(s->config_path)) return 0;

    char *argv[] = {s->binary, "run", "-c", s->config_path, NULL};
    posix_spawn_file_actions_t actions;
    int actions_error = posix_spawn_file_actions_init(&actions);
    if (actions_error != 0)
        return sb_fail(err, SB_ERR_IO, "initialize sing-box spawn actions failed: %s",
                       strerror(actions_error));
    int stdin_error =
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (stdin_error != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return sb_fail(err, SB_ERR_IO, "configure sing-box stdin failed: %s",
                       strerror(stdin_error));
    }
    pid_t process = 0;
    int spawn_error = posix_spawnp(&process, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        s->child = -1;
        s->has_started = true;
        s->next_start_ms = sb_monotonic_ms() + s->restart_backoff_ms;
        set_last_error(s, sb_asprintf("start sing-box failed: %s", strerror(spawn_error)));
        return sb_fail(err, SB_ERR_IO, "%s", s->last_error);
    }
    s->child = process;
    s->has_started = true;
    s->next_start_ms = 0;
    set_last_error(s, NULL);
    return 0;
}

int sb_singbox_supervisor_apply_config(sb_singbox_supervisor *s, const char *contents,
                                       size_t len, sb_err *err) {
    if (sb_atomic_replace_file(s->config_path, contents, len, validate, s, err) != 0) return -1;
    reap(s);
    if (s->child > 0) {
        if (kill(s->child, SIGHUP) == 0) {
            set_last_error(s, NULL);
            return 0;
        }
        if (errno != ESRCH)
            return sb_fail(err, SB_ERR_IO, "reload sing-box failed: %s", strerror(errno));
        reap(s);
    }
    return start(s, true, err);
}

void sb_singbox_supervisor_ensure_alive(sb_singbox_supervisor *s) {
    pid_t previous = s->child;
    reap(s);
    if (previous > 0 && s->child <= 0) s->has_started = true;
    if (s->has_started && s->child <= 0) {
        sb_err error = {0};
        if (start(s, false, &error) != 0) set_last_error(s, sb_strdup(error.msg));
    }
}

int sb_singbox_supervisor_reload(sb_singbox_supervisor *s, sb_err *err) {
    reap(s);
    if (s->child <= 0) return start(s, true, err);
    if (kill(s->child, SIGHUP) != 0) {
        if (errno == ESRCH) {
            reap(s);
            return start(s, true, err);
        }
        return sb_fail(err, SB_ERR_IO, "reload sing-box failed: %s", strerror(errno));
    }
    set_last_error(s, NULL);
    return 0;
}

int sb_singbox_supervisor_restart(sb_singbox_supervisor *s, sb_err *err) {
    sb_singbox_supervisor_stop(s);
    s->has_started = true;
    return start(s, true, err);
}

void sb_singbox_supervisor_stop(sb_singbox_supervisor *s) {
    if (s->child <= 0) return;
    pid_t process = s->child;
    if (kill(process, SIGTERM) != 0 && errno != ESRCH)
        set_last_error(s, sb_asprintf("stop sing-box failed: %s", strerror(errno)));
    int64_t deadline = sb_monotonic_ms() + s->shutdown_timeout_ms;
    int status = 0;
    while (sb_monotonic_ms() < deadline) {
        pid_t result = waitpid(process, &status, WNOHANG);
        if (result == process || (result < 0 && errno == ECHILD)) {
            s->child = -1;
            s->has_started = false;
            return;
        }
        if (result < 0 && errno != EINTR) break;
        sb_sleep_ms(10);
    }
    (void)kill(process, SIGKILL);
    while (waitpid(process, &status, 0) < 0 && errno == EINTR) {
    }
    s->child = -1;
    s->has_started = false;
}

bool sb_singbox_supervisor_running(sb_singbox_supervisor *s) {
    reap(s);
    return s->child > 0;
}

pid_t sb_singbox_supervisor_pid(sb_singbox_supervisor *s) {
    reap(s);
    return s->child > 0 ? s->child : -1;
}

const char *sb_singbox_supervisor_last_error(const sb_singbox_supervisor *s) {
    return s->last_error;
}
