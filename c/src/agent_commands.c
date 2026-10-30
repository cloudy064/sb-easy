/* Agent external command helpers. Moved verbatim from agent_main.c. */
#include "agent_main_internal.h"

#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int split_command_line(const char *command, sb_strvec *out, sb_err *err) {
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


process_result run_program(const sb_strvec *arguments) {
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
int read_existing(const char *path, char **out, size_t *len, sb_err *err) {
    int opened = read_stream(path, out, len, err);
    if (opened != 0) return opened;
    bool exists = false;
    if (path_exists_or_fail(path, &exists, err) != 0) return -1;
    if (!exists) return 0;
    return sb_fail(err, SB_ERR_IO, "cannot read existing config: %s", path);
}

/* C++ proxy_test_tags(): *all = true for std::nullopt. */
int proxy_test_tags(const char *command, sbj **tags, bool *all, sb_err *err) {
    static const char prefix[] = "test-proxies";
    const size_t prefix_len = sizeof prefix - 1;
    *tags = NULL;
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
            sbj_free(parsed);
            return 0;
        }
    }
    *tags = parsed;
    *all = false;
    return 0;
}
