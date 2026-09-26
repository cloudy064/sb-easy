#include "test.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sb/singbox_supervisor.h"

static const char *fake_singbox =
    "#!/bin/sh\n"
    "if [ \"$1\" = \"check\" ]; then\n"
    "    if grep -q INVALID \"$3\"; then\n"
    "        exit 23\n"
    "    fi\n"
    "    exit 0\n"
    "fi\n"
    "if [ \"$1\" = \"run\" ]; then\n"
    "    config=\"$3\"\n"
    "    echo \"$$\" > \"${config}.pid\"\n"
    "    trap 'echo hup >> \"${config}.events\"' HUP\n"
    "    trap 'exit 0' TERM INT\n"
    "    while :; do\n"
    "        sleep 0.05\n"
    "    done\n"
    "fi\n"
    "exit 2\n";

static char *read_text(const char *path) {
    char *text = sb_read_file(path, NULL);
    return text ? text : sb_strdup("");
}

static pid_t read_pid(const char *path) {
    char *text = read_text(path);
    pid_t pid = (pid_t)strtoll(text, NULL, 10);
    free(text);
    return pid;
}

#define WAIT_UNTIL(cond, ok)                                   \
    do {                                                       \
        int64_t _deadline = sb_monotonic_ms() + 3000;          \
        ok = false;                                            \
        while (sb_monotonic_ms() < _deadline) {                \
            if (cond) { ok = true; break; }                    \
            sb_sleep_ms(10);                                   \
        }                                                      \
    } while (0)

static bool events_have_hup(const char *path) {
    char *text = read_text(path);
    bool found = strstr(text, "hup") != NULL;
    free(text);
    return found;
}

static bool replaced(sb_singbox_supervisor *s, pid_t old, pid_t *out) {
    sb_singbox_supervisor_ensure_alive(s);
    pid_t current = sb_singbox_supervisor_pid(s);
    if (current > 0 && current != old) {
        *out = current;
        return true;
    }
    return false;
}

TEST(managed_singbox_validates_reloads_restarts_and_respawns) {
    char directory[] = "/tmp/sb-easy-supervisor-XXXXXX";
    REQUIRE(mkdtemp(directory));
    char *binary = sb_asprintf("%s/fake-sing-box", directory);
    char *config = sb_asprintf("%s/sing-box.json", directory);
    char *pid_file = sb_asprintf("%s.pid", config);
    char *events_file = sb_asprintf("%s.events", config);
    REQUIRE(sb_write_file(binary, fake_singbox, strlen(fake_singbox)) == 0);
    REQUIRE(chmod(binary, 0700) == 0);

    sb_singbox_supervisor_options options;
    sb_singbox_supervisor_options_init(&options);
    options.binary = binary;
    options.config_path = config;
    options.validate_config = true;
    options.restart_backoff_ms = 30;
    options.shutdown_timeout_ms = 1000;
    sb_err err = {0};
    sb_singbox_supervisor *s = sb_singbox_supervisor_new(&options, &err);
    REQUIRE(s);
    bool ok;

    REQUIRE(sb_singbox_supervisor_apply_config(s, "{\"version\":1}", 13, &err) == 0);
    WAIT_UNTIL(sb_file_exists(pid_file), ok);
    REQUIRE(ok);
    /* the pid file may be observed before the shell wrote it */
    WAIT_UNTIL(read_pid(pid_file) > 0, ok);
    pid_t first_pid = read_pid(pid_file);
    CHECK(sb_singbox_supervisor_running(s));
    CHECK_EQ_INT(sb_singbox_supervisor_pid(s), first_pid);

    CHECK(sb_singbox_supervisor_apply_config(s, "INVALID", 7, &err) != 0);
    CHECK_STR(err.msg, "sing-box config validation failed: exit code 23");
    char *text = read_text(config);
    CHECK_STR(text, "{\"version\":1}");
    free(text);
    CHECK_EQ_INT(sb_singbox_supervisor_pid(s), first_pid);

    REQUIRE(sb_singbox_supervisor_apply_config(s, "{\"version\":2}", 13, &err) == 0);
    WAIT_UNTIL(events_have_hup(events_file), ok);
    CHECK(ok);
    CHECK_EQ_INT(sb_singbox_supervisor_pid(s), first_pid);

    REQUIRE(kill(first_pid, SIGKILL) == 0);
    pid_t replacement = -1;
    WAIT_UNTIL(replaced(s, first_pid, &replacement), ok);
    CHECK(ok);
    CHECK(sb_singbox_supervisor_last_error(s) == NULL); /* cleared by the respawn */

    REQUIRE(sb_singbox_supervisor_restart(s, &err) == 0);
    WAIT_UNTIL(sb_singbox_supervisor_pid(s) > 0 && sb_singbox_supervisor_pid(s) != replacement, ok);
    CHECK(ok);

    sb_singbox_supervisor_stop(s);
    CHECK(!sb_singbox_supervisor_running(s));
    sb_singbox_supervisor_free(s);

    char *command = sb_asprintf("rm -rf '%s'", directory);
    if (system(command) != 0) fprintf(stderr, "cleanup failed\n");
    free(command);
    free(binary);
    free(config);
    free(pid_file);
    free(events_file);
}

TEST(supervisor_option_validation) {
    sb_err err = {0};
    sb_singbox_supervisor_options options;
    sb_singbox_supervisor_options_init(&options);
    options.binary = "";
    CHECK(sb_singbox_supervisor_new(&options, &err) == NULL);
    CHECK_STR(err.msg, "sing-box binary is required");
    options.binary = "sing-box";
    options.config_path = "dir/";
    CHECK(sb_singbox_supervisor_new(&options, &err) == NULL);
    CHECK_STR(err.msg, "sing-box config path must name a file");
    options.config_path = "x.json";
    options.restart_backoff_ms = -1;
    CHECK(sb_singbox_supervisor_new(&options, &err) == NULL);
    CHECK_STR(err.msg, "sing-box process durations cannot be negative");
}

TEST(supervisor_missing_binary_reports_spawn_failure) {
    char directory[] = "/tmp/sb-easy-supervisor-XXXXXX";
    REQUIRE(mkdtemp(directory));
    char *config = sb_asprintf("%s/c.json", directory);
    sb_singbox_supervisor_options options;
    sb_singbox_supervisor_options_init(&options);
    options.binary = "/nonexistent/sing-box";
    options.config_path = config;
    sb_err err = {0};
    sb_singbox_supervisor *s = sb_singbox_supervisor_new(&options, &err);
    REQUIRE(s);
    CHECK(sb_singbox_supervisor_apply_config(s, "{}", 2, &err) != 0);
    CHECK_STR(err.msg, "sing-box config validation failed: spawn failed: No such file or directory");
    sb_singbox_supervisor_free(s);
    free(config);
    rmdir(directory);
}
