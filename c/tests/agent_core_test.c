#include "test.h"

#include <dirent.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sb/agent_config.h"
#include "sb/atomic_file.h"

static char *make_temp_dir(void) {
    char *path = sb_strdup("/tmp/sb-easy-atomic-XXXXXX");
    if (!mkdtemp(path)) abort();
    return path;
}

static void remove_tree(const char *path) {
    char *command = sb_asprintf("rm -rf '%s'", path);
    if (system(command) != 0) fprintf(stderr, "cleanup failed: %s\n", path);
    free(command);
}

static char *read_text(const char *path) {
    char *text = sb_read_file(path, NULL);
    return text ? text : sb_strdup("");
}

typedef struct {
    const char *destination;
    bool validated;
    bool saw_new;
    bool destination_old;
} validator_state;

static int inspecting_validator(const char *temporary, void *user, sb_err *err) {
    validator_state *state = user;
    state->validated = true;
    char *tmp = read_text(temporary);
    char *dst = read_text(state->destination);
    state->saw_new = strcmp(tmp, "new") == 0;
    state->destination_old = strcmp(dst, "old") == 0;
    free(tmp);
    free(dst);
    return 0;
}

static int rejecting_validator(const char *temporary, void *user, sb_err *err) {
    return sb_fail(err, SB_ERR_GENERIC, "rejected");
}

TEST(atomic_config_replacement_validates_before_rename) {
    char *directory = make_temp_dir();
    char *destination = sb_asprintf("%s/nested/config.json", directory);
    sb_err err = {0};

    REQUIRE(sb_atomic_replace_file(destination, "old", 3, NULL, NULL, &err) == 0);
    validator_state state = {destination, false, false, false};
    REQUIRE(sb_atomic_replace_file(destination, "new", 3, inspecting_validator, &state, &err) == 0);
    CHECK(state.validated);
    CHECK(state.saw_new);      /* validator should inspect complete temp content */
    CHECK(state.destination_old); /* destination unchanged during validation */
    char *text = read_text(destination);
    CHECK_STR(text, "new");
    free(text);

    sb_err_clear(&err);
    CHECK(sb_atomic_replace_file(destination, "invalid", 7, rejecting_validator, NULL, &err) != 0);
    CHECK_STR(err.msg, "rejected");
    text = read_text(destination);
    CHECK_STR(text, "new"); /* validator failure must preserve the last good config */
    free(text);

    char *parent = sb_asprintf("%s/nested", directory);
    DIR *dir = opendir(parent);
    REQUIRE(dir);
    int temporary_files = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            strcmp(entry->d_name, "config.json"))
            ++temporary_files;
    }
    closedir(dir);
    CHECK_EQ_INT(temporary_files, 0);

    free(parent);
    free(destination);
    remove_tree(directory);
    free(directory);
}

TEST(atomic_replace_rejects_paths_without_filename) {
    sb_err err = {0};
    CHECK(sb_atomic_replace_file("", "x", 1, NULL, NULL, &err) != 0);
    CHECK_STR(err.msg, "config destination must name a file");
    CHECK(sb_atomic_replace_file("/tmp/dir/", "x", 1, NULL, NULL, &err) != 0);
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
}

TEST(agent_config_returns_body_verbatim_without_changes) {
    sb_agent_config_options options;
    sb_agent_config_options_init(&options);
    const char *body = "{\"outbounds\":[{\"tag\":\"direct\",\"type\":\"direct\"}]}";
    sb_err err = {0};
    char *out = sb_prepare_agent_config(body, strlen(body), &options, &err);
    CHECK_STR(out, body);
    free(out);
    options.local_proxy_egress = false;
    out = sb_prepare_agent_config("not json", 8, &options, &err);
    CHECK_STR(out, "not json");
    free(out);
    sb_agent_config_options_free(&options);
}

TEST(agent_config_options_validation_messages) {
    sb_err err = {0};
    sb_agent_config_options out;
    sbj *v = sbj_parse_cstr("[]");
    CHECK(sb_agent_config_options_from_json(v, NULL, &out, &err) != 0);
    CHECK_STR(err.msg, "agent settings must be a JSON object");
    sbj_free(v);
    v = sbj_parse_cstr("{\"local_proxy_egress\":1}");
    CHECK(sb_agent_config_options_from_json(v, NULL, &out, &err) != 0);
    CHECK_STR(err.msg, "local_proxy_egress must be a boolean");
    sbj_free(v);
    v = sbj_parse_cstr("{\"default_proxy_outbound\":1}");
    CHECK(sb_agent_config_options_from_json(v, NULL, &out, &err) != 0);
    CHECK_STR(err.msg, "default_proxy_outbound must be a string or null");
    sbj_free(v);
    v = sbj_parse_cstr("{\"outbound_overrides\":{\"a\":1}}");
    CHECK(sb_agent_config_options_from_json(v, NULL, &out, &err) != 0);
    CHECK_STR(err.msg, "outbound_overrides values must be JSON objects");
    sbj_free(v);
    v = sbj_parse_cstr("{\"outbound_server_overrides\":[]}");
    CHECK(sb_agent_config_options_from_json(v, NULL, &out, &err) != 0);
    CHECK_STR(err.msg, "outbound_server_overrides must be a JSON object");
    CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    sbj_free(v);
    v = sbj_parse_cstr("{\"default_proxy_outbound\":\"\",\"local_proxy_egress\":false}");
    REQUIRE(sb_agent_config_options_from_json(v, NULL, &out, &err) == 0);
    CHECK(out.default_proxy_outbound == NULL);
    CHECK(!out.local_proxy_egress);
    sb_agent_config_options_free(&out);
    sbj_free(v);

    char *directory = make_temp_dir();
    char *missing = sb_asprintf("%s/missing.json", directory);
    REQUIRE(sb_agent_config_options_load(missing, NULL, &out, &err) == 0);
    CHECK(out.local_proxy_egress);
    sb_agent_config_options_free(&out);
    char *bad = sb_asprintf("%s/bad.json", directory);
    sb_write_file(bad, "{\"local_proxy_egress\":\"x\"}", 26);
    CHECK(sb_agent_config_options_load(bad, NULL, &out, &err) != 0);
    char *expected = sb_asprintf("invalid agent settings %s: local_proxy_egress must be a boolean", bad);
    CHECK_STR(err.msg, expected);
    free(expected);
    free(bad);
    free(missing);
    remove_tree(directory);
    free(directory);
}
