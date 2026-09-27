/* sb-easy-c-render: offline renderer CLI (port of cpp/src/main.cpp). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb/config_renderer.h"
#include "sb/json.h"
#include "sb/types.h"
#include "sb/util.h"

#include "sb/database.h"
#include "sb/store.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

/* nlohmann value(key, "fallback") for strings. */
static int get_string(const sbj *object, const char *key, const char *fallback, const char **out,
                      sb_err *err) {
    if (!sbj_is_object(object))
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.306] cannot use value() with %s",
                       sbj_type_name(object));
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

static int require_array(const sbj *value, sb_err *err) {
    if (sbj_is_array(value)) return 0;
    return sb_fail(err, SB_ERR_GENERIC,
                   "[json.exception.type_error.302] type must be array, but is %s",
                   sbj_type_name(value));
}

static int parse_request(const sbj *value, sb_render_request *request, sb_err *err) {
    const char *mode = NULL;
    if (get_string(value, "mode", "managed", &mode, err) != 0) return -1;
    request->mode = strcmp(mode, "full") == 0 ? SB_PROFILE_FULL : SB_PROFILE_MANAGED;

    const sbj *profile = sbj_get(value, "profile");
    if (!profile)
        return sb_fail(err, SB_ERR_GENERIC, "[json.exception.out_of_range.403] key 'profile' not found");
    sbj_free(request->profile);
    request->profile = sbj_clone(profile);

    const sbj *nodes = sbj_get(value, "nodes");
    if (nodes) {
        if (require_array(nodes, err) != 0) return -1;
        const sbj *item;
        SBJ_ARR_FOREACH(nodes, i, item) {
            sb_proxy_node node;
            if (sb_proxy_node_from_json(item, &node, err) != 0) return -1;
            sb_proxy_node *slot = sb_proxy_node_vec_push(&request->nodes);
            sb_proxy_node_free(slot);
            *slot = node;
        }
    }

    const sbj *host = sbj_get(value, "host");
    if (host) {
        sbj_free(request->host_context);
        request->host_context = sbj_clone(host);
    }

    const sbj *tags = sbj_get(value, "external_route_tags");
    if (tags) {
        if (require_array(tags, err) != 0) return -1;
        const sbj *tag;
        SBJ_ARR_FOREACH(tags, i, tag) {
            if (!sbj_is_string(tag))
                return sb_fail(err, SB_ERR_GENERIC,
                               "[json.exception.type_error.302] type must be string, but is %s",
                               sbj_type_name(tag));
            sb_strvec_push(&request->external_route_tags, tag->v.str.ptr);
        }
    }

    const char *control = NULL;
    if (get_string(value, "control_plane_server", "", &control, err) != 0) return -1;
    sb_str_set(&request->control_plane_server, control);

    const sbj *script = sbj_get(value, "rule_script");
    if (sbj_is_string(script)) {
        sb_str_setn(&request->rule_script, script->v.str.ptr, script->v.str.len);
        request->rule_script_len = script->v.str.len;
    }

    const sbj *clash = sbj_get(value, "clash");
    if (sbj_is_object(clash)) {
        const char *controller = NULL, *secret = NULL;
        if (get_string(clash, "controller", "", &controller, err) != 0 ||
            get_string(clash, "secret", "", &secret, err) != 0)
            return -1;
        sb_str_set(&request->clash_controller, controller);
        sb_str_set(&request->clash_secret, secret);
    }
    return 0;
}

static void usage(const char *executable) {
    fprintf(stderr,
            "Usage:\n  %s render <request.json>\n  %s migrate <database.db> <migration-directory>\n"
            "  %s render-host <database.db> <host-id> <migration-directory>\n  %s --version\n",
            executable, executable, executable, executable);
}

static int print_config(const sb_config_renderer *renderer, const sb_render_request *request,
                        sb_err *err) {
    sbj *config = sb_config_renderer_render(renderer, request, err);
    if (!config) return -1;
    char *text = sbj_dump(config, 2);
    printf("%s\n", text);
    free(text);
    sbj_free(config);
    return 0;
}

static int cmd_render(const char *path, sb_err *err) {
    size_t len = 0;
    char *text = sb_read_file(path, &len);
    if (!text) return sb_fail(err, SB_ERR_IO, "cannot open request file: %s", path);
    char parse_error[256] = {0};
    sbj *value = sbj_parse(text, len, parse_error, sizeof parse_error);
    free(text);
    if (!value)
        return sb_fail(err, SB_ERR_VALIDATION, "[json.exception.parse_error.101] parse error: %s",
                       parse_error);

    sb_config_renderer renderer;
    sb_render_request request;
    sb_render_request_init(&request);
    int rc = -1;
    if (sb_config_renderer_init(&renderer, NULL, err) == 0 &&
        parse_request(value, &request, err) == 0)
        rc = print_config(&renderer, &request, err);
    sb_render_request_free(&request);
    sbj_free(value);
    return rc;
}

static int cmd_migrate(const char *db_path, const char *migrations, sb_err *err) {
    sb_database *db = sb_database_open(db_path, err);
    if (!db) return -1;
    int rc = sb_database_migrate(db, migrations, err);
    if (rc == 0) {
        int64_t count = sb_database_applied_migration_count(db, err);
        if (count < 0) rc = -1;
        else printf("applied migrations: %lld\n", (long long)count);
    }
    sb_database_free(db);
    return rc;
}

static int cmd_render_host(const char *db_path, const char *host_id, const char *migrations,
                           sb_err *err) {
    sb_store *store = sb_store_open(db_path, migrations, err);
    if (!store) return -1;
    sb_config_renderer renderer;
    sb_render_request request;
    sb_render_request_init(&request);
    int rc = -1;
    if (sb_config_renderer_init(&renderer, NULL, err) == 0 &&
        sb_store_render_request_for_host(store, host_id, &request, err) == 0)
        rc = print_config(&renderer, &request, err);
    sb_render_request_free(&request);
    sb_store_free(store);
    return rc;
}

int main(int argc, char **argv) {
    sb_err err = {0};
    int rc;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("sb-easy-c %s\n", SB_EASY_VERSION);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "render") == 0) {
        rc = cmd_render(argv[2], &err);
    }
    else if (argc == 4 && strcmp(argv[1], "migrate") == 0) {
        rc = cmd_migrate(argv[2], argv[3], &err);
    } else if (argc == 5 && strcmp(argv[1], "render-host") == 0) {
        rc = cmd_render_host(argv[2], argv[3], argv[4], &err);
    } else {
        usage(argv[0]);
        return 2;
    }
    if (rc != 0) {
        fprintf(stderr, "error: %s\n", err.msg);
        return 1;
    }
    return 0;
}
