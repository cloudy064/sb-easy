/* Port of cpp/tests/store_test.cpp (+ C-specific parity checks). */
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sb/auth.h"
#include "sb/config_renderer.h"
#include "sb/proxy_parser.h"
#include "sb/store.h"
#include "test.h"

typedef struct {
    char path[256];
} temp_db;

static void temp_db_init(temp_db *t) {
    unsigned char r[8];
    sb_random_bytes(r, sizeof r);
    char *hex = sb_hex_encode(r, sizeof r);
    snprintf(t->path, sizeof t->path, "/tmp/sb-easy-c-%s.db", hex);
    free(hex);
}
static void temp_db_free(temp_db *t) {
    char buf[300];
    unlink(t->path);
    snprintf(buf, sizeof buf, "%s-shm", t->path);
    unlink(buf);
    snprintf(buf, sizeof buf, "%s-wal", t->path);
    unlink(buf);
}
static const char *migrations(void) { return sb_getenv_or("SB_EASY_MIGRATIONS", "migrations"); }

static sb_store *open_store(temp_db *t) {
    temp_db_init(t);
    sb_err err = {0};
    sb_store *s = sb_store_open(t->path, migrations(), &err);
    if (!s) fprintf(stderr, "open failed: %s\n", err.msg);
    return s;
}
static void exec_sql(sb_store *s, const char *sql) {
    sb_err err = {0};
    if (sb_database_execute(sb_store_database(s), sql, &err) != 0) fprintf(stderr, "exec: %s\n", err.msg);
}

TEST(user_repository_preserves_roles_passwords_and_audit_invariants) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    CHECK_EQ_INT(sb_store_ensure_default_admin(s, "initial-password", &err), 0);
    CHECK_EQ_INT(sb_store_ensure_default_admin(s, "ignored-password", &err), 0);
    sb_user_account admin;
    sb_user_account_init(&admin);
    REQUIRE(sb_store_find_user_by_username(s, "admin", &admin, &err) == 1);
    CHECK_STR(admin.role, "admin");
    CHECK(sb_verify_password("initial-password", admin.password_hash));
    CHECK(!sb_verify_password("ignored-password", admin.password_hash));

    char *hash = sb_hash_password("viewer-password", NULL);
    sb_user_account viewer;
    sb_user_account_init(&viewer);
    CHECK_EQ_INT(sb_store_create_user(s, "viewer", hash, "viewer", &viewer, &err), 0);
    free(hash);
    sb_user_account_vec users = {0};
    CHECK_EQ_INT(sb_store_list_users(s, &users, &err), 0);
    CHECK_EQ_INT(users.len, 2);
    sb_user_account_vec_free(&users);
    CHECK_STR(viewer.role, "viewer");
    sbj *vj = sb_user_account_to_json(&viewer);
    CHECK(!sbj_has(vj, "password_hash"));
    sbj_free(vj);

    hash = sb_hash_password("different-password", NULL);
    sb_user_account dup;
    sb_user_account_init(&dup);
    CHECK_EQ_INT(sb_store_create_user(s, "viewer", hash, "viewer", &dup, &err), -1);
    CHECK(err.code == SB_ERR_CONFLICT);
    CHECK_STR(err.msg, "Username already exists");
    sb_user_account_free(&dup);
    free(hash);
    CHECK_EQ_INT(sb_store_create_user(s, "x", "h", "root", &dup, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_EQ_INT(sb_store_delete_user(s, admin.id, admin.id, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_EQ_INT(sb_store_delete_user(s, "someone", admin.id, &err), -1);
    CHECK_STR(err.msg, "Cannot delete the last admin");

    hash = sb_hash_password("replacement-password", NULL);
    CHECK_EQ_INT(sb_store_reset_user_password(s, viewer.id, hash, &err), 0);
    CHECK_EQ_INT(sb_store_reset_user_password(s, "missing", hash, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    free(hash);
    sb_user_account reloaded;
    sb_user_account_init(&reloaded);
    REQUIRE(sb_store_find_user_by_username(s, "viewer", &reloaded, &err) == 1);
    CHECK(sb_verify_password("replacement-password", reloaded.password_hash));
    sb_user_account_free(&reloaded);
    CHECK_EQ_INT(sb_store_delete_user(s, admin.id, viewer.id, &err), 0);
    CHECK_EQ_INT(sb_store_list_users(s, &users, &err), 0);
    CHECK_EQ_INT(users.len, 1);
    sb_user_account_vec_free(&users);

    CHECK_EQ_INT(sb_store_record_audit(s, "admin", "POST", "/api/users", &err), 0);
    sb_audit_entry_vec audit = {0};
    CHECK_EQ_INT(sb_store_list_audit(s, 200, &audit, &err), 0);
    REQUIRE(audit.len == 1);
    CHECK_STR(audit.items[0].actor, "admin");
    CHECK_STR(audit.items[0].action, "POST");
    CHECK_STR(audit.items[0].target, "/api/users");
    sbj *aj = sb_audit_entry_to_json(&audit.items[0]);
    CHECK(sbj_has(aj, "ts") && sbj_has(aj, "target"));
    sbj_free(aj);
    sb_audit_entry_vec_free(&audit);

    sbj *settings = sb_store_app_settings(s, &err);
    REQUIRE(settings);
    CHECK_STR(sbj_get_str(sbj_get(settings, "general"), "app_name", NULL), "sb-easy");
    sbj_free(settings);
    sbj *update = sbj_parse_cstr("{\"general\":{\"app_name\":\"contract-name\"},\"ignored\":{\"value\":true}}");
    CHECK_EQ_INT(sb_store_update_app_settings(s, update, &err), 0);
    sbj_free(update);
    settings = sb_store_app_settings(s, &err);
    REQUIRE(settings);
    CHECK_STR(sbj_get_str(sbj_get(settings, "general"), "app_name", NULL), "contract-name");
    CHECK(!sbj_has(settings, "ignored"));
    sbj_free(settings);

    sbj *one = NULL;
    sbj *val = sbj_parse_cstr("{\"k\":[1,2]}");
    CHECK_EQ_INT(sb_store_set_app_setting(s, "custom", val, &err), 0);
    CHECK_EQ_INT(sb_store_app_setting(s, "custom", &one, &err), 1);
    CHECK(sbj_equal(one, val));
    sbj_free(one);
    sbj_free(val);
    CHECK_EQ_INT(sb_store_app_setting(s, "nope", &one, &err), 0);
    CHECK_EQ_INT(sb_store_set_app_setting(s, "", NULL, &err), -1);

    sb_user_account_free(&admin);
    sb_user_account_free(&viewer);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(sqlite_runner_applies_canonical_migrations_idempotently) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    CHECK_EQ_INT(sb_database_applied_migration_count(sb_store_database(s), &err), 11);
    sb_config_profile p;
    sb_config_profile_init(&p);
    REQUIRE(sb_store_find_profile(s, "android-client", &p, &err) == 1);
    CHECK_STR(p.name, "Managed Device");
    CHECK_STR(sbj_get_str(sbj_get(p.profile, "dns"), "final", NULL), "secure-dns");
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(p.profile, "route"), "default_domain_resolver"), "server", NULL),
              "bootstrap-dns");
    sb_config_profile_free(&p);
    CHECK_EQ_INT(sb_database_migrate(sb_store_database(s), migrations(), &err), 0);
    CHECK_EQ_INT(sb_database_applied_migration_count(sb_store_database(s), &err), 11);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(sqlite_runner_rejects_dirty_missing_and_changed_migrations) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    exec_sql(s, "INSERT INTO _sqlx_migrations "
                "(version, description, success, checksum, execution_time) "
                "VALUES (999, 'dirty', FALSE, X'00', 0)");
    CHECK_EQ_INT(sb_database_migrate(sb_store_database(s), migrations(), &err), -1);
    CHECK_STR(err.msg, "migration 999 is partially applied");
    exec_sql(s, "UPDATE _sqlx_migrations SET success = TRUE WHERE version = 999");
    CHECK_EQ_INT(sb_database_migrate(sb_store_database(s), migrations(), &err), -1);
    CHECK_STR(err.msg, "applied migration 999 is missing from the migration directory");
    sb_store_free(s);
    temp_db_free(&t);

    s = open_store(&t);
    REQUIRE(s);
    exec_sql(s, "UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = 6");
    CHECK_EQ_INT(sb_database_migrate(sb_store_database(s), migrations(), &err), -1);
    CHECK_STR(err.msg, "migration 6 checksum differs from the applied sqlx migration");
    sb_store_free(s);
    temp_db_free(&t);

    CHECK(sb_store_open("/tmp/sb-easy-c-nodir.db", "/nonexistent-dir", &err) == NULL);
    CHECK_STR(err.msg, "migration directory does not exist: /nonexistent-dir");
    unlink("/tmp/sb-easy-c-nodir.db");
    unlink("/tmp/sb-easy-c-nodir.db-wal");
    unlink("/tmp/sb-easy-c-nodir.db-shm");
}

TEST(profile_scripts_persist_and_render_through_the_host_repository) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_config_profile p, saved;
    sb_config_profile_init(&p);
    sb_config_profile_init(&saved);
    REQUIRE(sb_store_find_profile(s, "default", &p, &err) == 1);
    sb_str_set(&p.rule_script,
               "\nfunction buildRules(context) {\n"
               "  if (context.host.id !== \"self\") {\n"
               "    throw new Error(\"unexpected host\");\n"
               "  }\n"
               "  return [{ domain_suffix: [\".example.com\"], outbound: \"direct\" }];\n"
               "}\n");
    p.rule_script_len = strlen(p.rule_script);
    p.rule_script_enabled = true;
    REQUIRE(sb_store_update_profile(s, &p, &saved, &err) == 0);
    CHECK(saved.rule_script_enabled);

    sb_render_request req;
    sb_render_request_init(&req);
    REQUIRE(sb_store_render_request_for_host(s, "self", &req, &err) == 0);
    CHECK(req.rule_script != NULL);
    CHECK_STR(sbj_get_str(req.host_context, "id", NULL), "self");
    CHECK_STR(req.clash_controller, "0.0.0.0:9090");

    sb_config_renderer renderer;
    REQUIRE(sb_config_renderer_init(&renderer, NULL, &err) == 0);
    sbj *rendered = sb_config_renderer_render(&renderer, &req, &err);
    if (!rendered) fprintf(stderr, "render: %s\n", err.msg);
    REQUIRE(rendered);
    CHECK_STR(sbj_get_str(sbj_arr_at(sbj_get(sbj_get(rendered, "route"), "rules"), 0), "outbound", NULL),
              "direct");
    CHECK_STR(sbj_get_str(sbj_get(sbj_get(rendered, "experimental"), "clash_api"), "external_controller",
                          NULL),
              "0.0.0.0:9090");
    sbj_free(rendered);
    sb_render_request_free(&req);
    CHECK_EQ_INT(sb_store_render_request_for_host(s, "missing", &req, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sb_config_profile_free(&p);
    sb_config_profile_free(&saved);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(diagnostic_reports_are_host_scoped_and_retain_the_latest_twenty) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, "Diagnostic device");
    host.name_len = strlen(host.name);
    REQUIRE(sb_store_create_host(s, &host, &created, &err) == 0);
    for (int i = 0; i < 21; ++i) {
        char *text = sb_asprintf("{\"reason\":\"manual\",\"app_version\":\"%d\",\"core_version\":\"1.13.12\","
                                 "\"logs\":[\"%d\"]}",
                                 i, i);
        sbj *report = sbj_parse_cstr(text);
        char *id = sb_store_save_diagnostic_report(s, created.id, report, &err);
        CHECK(id != NULL);
        free(id);
        sbj_free(report);
        free(text);
    }
    sbj *reports = sb_store_list_diagnostic_reports(s, created.id, 20, &err);
    REQUIRE(reports);
    CHECK_EQ_INT(sbj_arr_len(reports), 20);
    CHECK_STR(sbj_get_str(sbj_arr_at(reports, 0), "app_version", NULL), "20");
    CHECK_STR(sbj_get_str(sbj_arr_at(reports, 19), "app_version", NULL), "1");
    CHECK(sbj_has(sbj_arr_at(reports, 0), "report_id"));
    sbj_free(reports);
    CHECK(sb_store_list_diagnostic_reports(s, "missing", 20, &err) == NULL);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sbj *arr = sbj_array();
    CHECK(sb_store_save_diagnostic_report(s, created.id, arr, &err) == NULL);
    CHECK(err.code == SB_ERR_VALIDATION);
    sbj_free(arr);
    sb_host_free(&host);
    sb_host_free(&created);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(profile_crud_uses_the_existing_config_profiles_schema) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_config_profile p, created, saved;
    sb_config_profile_init(&p);
    sb_config_profile_init(&created);
    sb_config_profile_init(&saved);
    sb_str_set(&p.name, "Full profile");
    p.name_len = strlen(p.name);
    sbj_free(p.profile);
    p.profile = sbj_parse_cstr("{\"log\":{\"level\":\"warn\"}}");
    p.mode = SB_PROFILE_FULL;
    REQUIRE(sb_store_create_profile(s, &p, &created, &err) == 0);
    CHECK(!sb_str_empty(created.id));
    CHECK(created.mode == SB_PROFILE_FULL);
    sbj *pj = sb_config_profile_to_json(&created);
    CHECK_STR(sbj_get_str(pj, "template", NULL), "{\"log\":{\"level\":\"warn\"}}");
    CHECK_STR(sbj_get_str(pj, "mode", NULL), "full");
    sbj_free(pj);

    char *sql = sb_asprintf("UPDATE hosts SET profile_id = '%s' WHERE id = 'self'", created.id);
    exec_sql(s, sql);
    free(sql);
    exec_sql(s, "INSERT INTO proxy_nodes "
                "(id, tag, node_type, enabled, server, server_port, "
                "protocol_config, fingerprint) VALUES "
                "('bad-port', 'bad-port', 'shadowsocks', TRUE, "
                "'127.0.0.1', 70000, '{}', 'bad-port')");
    sb_render_request req;
    sb_render_request_init(&req);
    REQUIRE(sb_store_render_request_for_host(s, "self", &req, &err) == 0);
    CHECK_EQ_INT(req.nodes.len, 0);
    sb_render_request_free(&req);

    sb_config_profile_copy(&p, &created);
    sb_str_set(&p.name, "Renamed profile");
    p.name_len = strlen(p.name);
    REQUIRE(sb_store_update_profile(s, &p, &saved, &err) == 0);
    CHECK_STR(saved.name, "Renamed profile");
    sb_str_set(&p.id, "missing");
    CHECK_EQ_INT(sb_store_update_profile(s, &p, &saved, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sb_config_profile_vec all = {0};
    CHECK_EQ_INT(sb_store_list_profiles(s, &all, &err), 0);
    CHECK(all.len >= 3);
    sb_config_profile_vec_free(&all);
    sb_config_profile_free(&p);
    sb_config_profile_free(&created);
    sb_config_profile_free(&saved);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(host_crud_hides_secrets_and_manages_outbound_assignments) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, "Remote node");
    host.name_len = strlen(host.name);
    sbj_set_bool(host.capabilities, "runs_singbox", true);
    sbj_set_bool(host.capabilities, "is_wg_member", false);
    sb_str_set(&host.clash_secret, "do-not-serialize");
    REQUIRE(sb_store_create_host(s, &host, &created, &err) == 0);
    CHECK(!sb_str_empty(created.id));
    CHECK_EQ_INT(strlen(created.agent_token), 64);
    CHECK_STR(created.profile_id, "default");

    sbj *pub = sb_host_to_json(&created);
    CHECK(!sbj_has(pub, "agent_token"));
    CHECK(!sbj_has(pub, "clash_secret"));
    CHECK(sbj_get_bool(pub, "has_token", false));
    sbj_free(pub);

    exec_sql(s, "INSERT INTO proxy_nodes "
                "(id, tag, node_type, enabled, server, server_port, "
                "protocol_config, fingerprint) VALUES "
                "('node-a', 'a', 'shadowsocks', TRUE, '127.0.0.1', 1001, "
                "'{\"method\":\"aes-128-gcm\",\"password\":\"a\"}', 'node-a'),"
                "('node-b', 'b', 'trojan', TRUE, '127.0.0.1', 1002, "
                "'{\"password\":\"b\"}', 'node-b')");
    sb_strvec ids = {0};
    sb_strvec_push(&ids, "node-b");
    sb_strvec_push(&ids, "node-a");
    sb_strvec_push(&ids, "node-a");
    CHECK_EQ_INT(sb_store_set_host_outbounds(s, created.id, &ids, &err), 0);
    sb_strvec_free(&ids);
    sb_strvec assigned = {0};
    CHECK_EQ_INT(sb_store_host_outbounds(s, created.id, &assigned, &err), 0);
    REQUIRE(assigned.len == 2);
    CHECK_STR(assigned.items[0], "node-a");
    CHECK_STR(assigned.items[1], "node-b");
    sb_strvec_free(&assigned);

    /* managed render uses only the assigned nodes */
    sb_render_request req;
    sb_render_request_init(&req);
    REQUIRE(sb_store_render_request_for_host(s, created.id, &req, &err) == 0);
    CHECK_EQ_INT(req.nodes.len, 2);
    sb_render_request_free(&req);

    sb_host found;
    sb_host_init(&found);
    REQUIRE(sb_store_find_host(s, created.id, &found, &err) == 1);
    CHECK_EQ_INT(found.assigned_outbounds, 2);
    char *old_token = sb_strdup(found.agent_token);
    char *new_token = sb_store_rotate_agent_token(s, created.id, &err);
    REQUIRE(new_token);
    CHECK_EQ_INT(strlen(new_token), 64);
    CHECK(strcmp(new_token, old_token) != 0);
    free(old_token);
    free(new_token);
    CHECK(sb_store_rotate_agent_token(s, "missing", &err) == NULL);

    REQUIRE(sb_store_find_host(s, created.id, &found, &err) == 1);
    sb_str_set(&found.name, "Renamed remote");
    found.name_len = strlen(found.name);
    found.enabled = false;
    sb_host updated;
    sb_host_init(&updated);
    REQUIRE(sb_store_update_host(s, &found, &updated, &err) == 0);
    CHECK_STR(updated.name, "Renamed remote");
    CHECK(!updated.enabled);

    sb_host_vec hosts = {0};
    CHECK_EQ_INT(sb_store_list_hosts(s, &hosts, &err), 0);
    CHECK_EQ_INT(hosts.len, 2);
    sb_host_vec_free(&hosts);

    CHECK_EQ_INT(sb_store_delete_host(s, created.id, &err), 0);
    CHECK_EQ_INT(sb_store_find_host(s, created.id, &found, &err), 0);
    CHECK_EQ_INT(sb_store_host_outbounds(s, created.id, &assigned, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    CHECK_EQ_INT(sb_store_delete_host(s, "self", &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    sb_host_free(&host);
    sb_host_free(&created);
    sb_host_free(&found);
    sb_host_free(&updated);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(profile_deletion_resets_assigned_hosts_to_default) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_config_profile p, cp;
    sb_config_profile_init(&p);
    sb_config_profile_init(&cp);
    sb_str_set(&p.name, "Temporary profile");
    p.name_len = strlen(p.name);
    REQUIRE(sb_store_create_profile(s, &p, &cp, &err) == 0);
    sb_host host, ch;
    sb_host_init(&host);
    sb_host_init(&ch);
    sb_str_set(&host.name, "Profile consumer");
    host.name_len = strlen(host.name);
    host.profile_id = sb_strdup(cp.id);
    REQUIRE(sb_store_create_host(s, &host, &ch, &err) == 0);
    CHECK_EQ_INT(sb_store_delete_profile(s, cp.id, &err), 0);
    sb_host reloaded;
    sb_host_init(&reloaded);
    REQUIRE(sb_store_find_host(s, ch.id, &reloaded, &err) == 1);
    CHECK_STR(reloaded.profile_id, "default");
    CHECK_EQ_INT(sb_store_find_profile(s, cp.id, &p, &err), 0);
    CHECK_EQ_INT(sb_store_delete_profile(s, "default", &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_EQ_INT(sb_store_delete_profile(s, "missing", &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sb_config_profile_free(&p);
    sb_config_profile_free(&cp);
    sb_host_free(&host);
    sb_host_free(&ch);
    sb_host_free(&reloaded);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(device_enrollment_codes_are_platform_neutral_expiring_and_single_use) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, "Managed device");
    host.name_len = strlen(host.name);
    host.profile_id = sb_strdup("android-client");
    sbj_set_bool(host.capabilities, "runs_singbox", true);
    sbj_set_bool(host.capabilities, "is_wg_member", false);
    REQUIRE(sb_store_create_host(s, &host, &created, &err) == 0);
    sb_agent_enrollment e;
    sb_agent_enrollment_init(&e);
    REQUIRE(sb_store_create_agent_enrollment(s, created.id, &e, &err) == 0);
    CHECK_EQ_INT(strlen(e.code), 64);
    CHECK(!sb_str_empty(e.expires_at));

    sbj *device = sbj_parse_cstr("{\"platform\":\"linux\",\"agent_version\":\"sb-easy-cpp-agent/test\","
                                 "\"core_version\":\"1.13.12\",\"install_id\":\"store-contract\","
                                 "\"hostname\":\"contract-device\",\"architecture\":\"x86_64\",\"os\":\"Linux\"}");
    sb_agent_enrollment_result r;
    sb_agent_enrollment_result_init(&r);
    REQUIRE(sb_store_redeem_agent_enrollment(s, e.code, device, &r, &err) == 0);
    sbj_free(device);
    CHECK_STR(r.host_id, created.id);
    CHECK_STR(r.agent_token, created.agent_token);
    CHECK_STR(r.profile_id, "android-client");
    CHECK_STR(r.profile_name, "Managed Device");
    sb_host reloaded;
    sb_host_init(&reloaded);
    REQUIRE(sb_store_find_host(s, created.id, &reloaded, &err) == 1);
    CHECK_STR(sbj_get_str(reloaded.capabilities, "platform", NULL), "linux");
    CHECK_STR(sbj_get_str(reloaded.capabilities, "install_id", NULL), "store-contract");
    CHECK_STR(sbj_get_str(reloaded.capabilities, "hostname", NULL), "contract-device");
    CHECK(sbj_get_bool(reloaded.capabilities, "runs_singbox", false));

    sbj *empty = sbj_object();
    CHECK_EQ_INT(sb_store_redeem_agent_enrollment(s, e.code, empty, &r, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_STR(err.msg, "Enrollment code is invalid or expired");

    sb_agent_enrollment expired;
    sb_agent_enrollment_init(&expired);
    REQUIRE(sb_store_create_agent_enrollment(s, created.id, &expired, &err) == 0);
    char *sql = sb_asprintf("UPDATE agent_enrollments SET expires_at = "
                            "datetime('now', '-1 minute') WHERE id = '%s'",
                            expired.id);
    exec_sql(s, sql);
    free(sql);
    CHECK_EQ_INT(sb_store_redeem_agent_enrollment(s, expired.code, empty, &r, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);

    sb_agent_enrollment disabled_code;
    sb_agent_enrollment_init(&disabled_code);
    REQUIRE(sb_store_create_agent_enrollment(s, created.id, &disabled_code, &err) == 0);
    REQUIRE(sb_store_find_host(s, created.id, &reloaded, &err) == 1);
    reloaded.enabled = false;
    sb_host upd;
    sb_host_init(&upd);
    REQUIRE(sb_store_update_host(s, &reloaded, &upd, &err) == 0);
    CHECK_EQ_INT(sb_store_redeem_agent_enrollment(s, disabled_code.code, empty, &r, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_EQ_INT(sb_store_create_agent_enrollment(s, "self", &expired, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    CHECK_EQ_INT(sb_store_create_agent_enrollment(s, "missing", &expired, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    CHECK_EQ_INT(sb_store_redeem_agent_enrollment(s, "short", empty, &r, &err), -1);
    CHECK_STR(err.msg, "A valid enrollment code and device are required");
    sbj_free(empty);

    sb_agent_enrollment_free(&e);
    sb_agent_enrollment_free(&expired);
    sb_agent_enrollment_free(&disabled_code);
    sb_agent_enrollment_result_free(&r);
    sb_host_free(&host);
    sb_host_free(&created);
    sb_host_free(&reloaded);
    sb_host_free(&upd);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(agent_repository_isolates_tokens_status_commands_and_latency) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_host host, created, found;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_host_init(&found);
    sb_str_set(&host.name, "Agent repository host");
    host.name_len = strlen(host.name);
    REQUIRE(sb_store_create_host(s, &host, &created, &err) == 0);
    REQUIRE(sb_store_find_enabled_host_by_token(s, created.agent_token, &found, &err) == 1);
    CHECK_STR(found.id, created.id);
    CHECK_EQ_INT(sb_store_find_enabled_host_by_token(s, "", &found, &err), 0);
    CHECK_EQ_INT(sb_store_find_enabled_host_by_token(s, "wrong", &found, &err), 0);

    sbj *state = sbj_parse_cstr("{\"version\":\"1.12.0\",\"running\":true,\"etag\":\"\\\"etag\\\"\"}");
    CHECK_EQ_INT(sb_store_update_agent_status(s, created.id, state, &err), 0);
    CHECK_EQ_INT(sb_store_update_agent_status(s, "missing", state, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sbj_free(state);
    REQUIRE(sb_store_find_host(s, created.id, &found, &err) == 1);
    CHECK(found.last_seen != NULL);
    CHECK(found.singbox_state != NULL);
    CHECK_EQ_INT(sb_store_touch_host(s, created.id, &err), 0);
    CHECK_EQ_INT(sb_store_touch_host(s, "missing", &err), -1);

    sb_host_command cmd;
    sb_host_command_init(&cmd);
    REQUIRE(sb_store_enqueue_host_command(s, created.id, "reload", &cmd, &err) == 0);
    CHECK_STR(cmd.status, "pending");
    CHECK_EQ_INT(sb_store_enqueue_host_command(s, created.id, "", &cmd, &err), -1);
    sb_host_command_vec cmds = {0};
    CHECK_EQ_INT(sb_store_list_host_commands(s, created.id, true, &cmds, &err), 0);
    CHECK_EQ_INT(cmds.len, 1);
    sb_host_command_vec_free(&cmds);
    CHECK_EQ_INT(sb_store_acknowledge_host_command(s, "self", cmd.id, "done", "wrong host", &err), 0);
    CHECK_EQ_INT(sb_store_acknowledge_host_command(s, created.id, cmd.id, "done", "reloaded", &err), 1);
    CHECK_EQ_INT(sb_store_list_host_commands(s, created.id, false, &cmds, &err), 0);
    REQUIRE(cmds.len == 1);
    CHECK_STR(cmds.items[0].status, "done");
    CHECK_STR(cmds.items[0].result, "reloaded");
    CHECK(cmds.items[0].acked_at != NULL);
    sbj *cj = sb_host_command_to_json(&cmds.items[0]);
    CHECK_STR(sbj_get_str(cj, "result", NULL), "reloaded");
    sbj_free(cj);
    sb_host_command_vec_free(&cmds);

    exec_sql(s, "INSERT INTO proxy_nodes "
                "(id, tag, node_type, enabled, server, server_port, "
                "protocol_config, fingerprint) VALUES "
                "('latency-node', 'latency-node', 'shadowsocks', TRUE, "
                "'127.0.0.1', 8388, "
                "'{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                "'latency-node')");
    sbj *results = sbj_parse_cstr("{\"latency-node\":12.5,\"missing-node\":null}");
    size_t updated = 99;
    CHECK_EQ_INT(sb_store_update_proxy_latencies(s, results, &updated, &err), 0);
    CHECK_EQ_INT(updated, 1);
    sbj_free(results);
    results = sbj_parse_cstr("{\"latency-node\":\"x\"}");
    CHECK_EQ_INT(sb_store_update_proxy_latencies(s, results, &updated, &err), -1);
    CHECK_STR(err.msg, "proxy latency values must be numbers or null");
    sbj_free(results);
    double lat = 7.25;
    CHECK_EQ_INT(sb_store_update_proxy_latency(s, "latency-node", &lat, &err), 0);
    sb_proxy_record rec;
    sb_proxy_record_init(&rec);
    REQUIRE(sb_store_find_proxy_node(s, "latency-node", &rec, &err) == 1);
    CHECK(rec.has_latency && rec.latency == 7.25);
    CHECK(rec.last_latency_test != NULL);
    sb_proxy_record_free(&rec);
    CHECK_EQ_INT(sb_store_update_proxy_latency(s, "missing-node", NULL, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);

    REQUIRE(sb_store_find_host(s, created.id, &found, &err) == 1);
    found.enabled = false;
    sb_host upd;
    sb_host_init(&upd);
    REQUIRE(sb_store_update_host(s, &found, &upd, &err) == 0);
    CHECK_EQ_INT(sb_store_find_enabled_host_by_token(s, created.agent_token, &found, &err), 0);
    sb_host_free(&upd);
    sb_host_command_free(&cmd);
    sb_host_free(&host);
    sb_host_free(&created);
    sb_host_free(&found);
    sb_store_free(s);
    temp_db_free(&t);
}

static sb_parsed_node_vec parse_body(const char *body) {
    return sb_parse_subscription_body(body, strlen(body));
}

TEST(proxy_repository_crud_and_imports_preserve_rust_api_shape) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_proxy_record manual, created, saved;
    sb_proxy_record_init(&manual);
    sb_proxy_record_init(&created);
    sb_proxy_record_init(&saved);
    sb_str_set(&manual.tag, "Manual SS");
    manual.tag_len = strlen(manual.tag);
    sb_str_set(&manual.node_type, "shadowsocks");
    manual.node_type_len = strlen(manual.node_type);
    sb_str_set(&manual.server, "manual.example.com");
    manual.server_len = strlen(manual.server);
    manual.server_port = 8388;
    sbj_set_str(manual.protocol_config, "method", "aes-256-gcm");
    sbj_set_str(manual.protocol_config, "password", "manual-secret");
    REQUIRE(sb_store_create_proxy_node(s, &manual, &created, &err) == 0);
    CHECK_EQ_INT(strlen(created.fingerprint), 64);
    sbj *ser = sb_proxy_record_to_json(&created);
    CHECK_STR(sbj_get_str(ser, "node_type", NULL), "shadowsocks");
    CHECK(sbj_is_string(sbj_get(ser, "protocol_config")));
    CHECK(sbj_is_null(sbj_get(ser, "latency")));
    sbj_free(ser);
    CHECK_EQ_INT(sb_store_create_proxy_node(s, &manual, &saved, &err), -1);
    CHECK_STR(err.msg, "A proxy with the same tag or fingerprint already exists");
    sb_str_set(&manual.node_type, "wireguard");
    manual.node_type_len = strlen(manual.node_type);
    CHECK_EQ_INT(sb_store_create_proxy_node(s, &manual, &saved, &err), -1);
    CHECK_STR(err.msg, "Unsupported proxy type: wireguard");

    sb_proxy_record upd;
    sb_proxy_record_init(&upd);
    sb_proxy_record_copy(&upd, &created);
    sb_str_set(&upd.tag, "Manual SS renamed");
    upd.tag_len = strlen(upd.tag);
    upd.enabled = false;
    REQUIRE(sb_store_update_proxy_node(s, &upd, &saved, &err) == 0);
    CHECK_STR(saved.tag, "Manual SS renamed");
    CHECK(!saved.enabled);
    sb_proxy_record_free(&upd);

    sb_parsed_node_vec imported = parse_body("ss://YWVzLTI1Ni1nY206c2VjcmV0@rotate.example.com:443#Provider");
    REQUIRE(imported.len == 1);
    sb_proxy_upsert_result first;
    sb_proxy_upsert_result_init(&first);
    REQUIRE(sb_store_upsert_proxy_nodes(s, imported.items, imported.len, NULL, &first, &err) == 0);
    CHECK_EQ_INT(first.added, 1);
    CHECK_EQ_INT(first.updated, 0);
    CHECK_EQ_INT(first.errors.len, 0);
    sb_proxy_upsert_result_free(&first);
    sb_parsed_node_vec_free(&imported);

    sb_parsed_node_vec rotated = parse_body("ss://YWVzLTI1Ni1nY206c2VjcmV0@new.example.com:443#Provider");
    sb_proxy_upsert_result second;
    sb_proxy_upsert_result_init(&second);
    REQUIRE(sb_store_upsert_proxy_nodes(s, rotated.items, rotated.len, NULL, &second, &err) == 0);
    CHECK_EQ_INT(second.added, 0);
    CHECK_EQ_INT(second.updated, 1);
    CHECK_EQ_INT(second.errors.len, 0);
    sb_proxy_upsert_result_free(&second);
    CHECK_EQ_INT(sb_store_upsert_proxy_nodes(s, rotated.items, rotated.len, "nope", &second, &err), -1);
    CHECK_STR(err.msg, "Subscription not found");
    /* invalid node lands in errors */
    sb_str_set(&rotated.items[0].node_type, "bogus");
    rotated.items[0].node_type_len = strlen(rotated.items[0].node_type);
    sb_proxy_upsert_result_init(&second);
    REQUIRE(sb_store_upsert_proxy_nodes(s, rotated.items, rotated.len, NULL, &second, &err) == 0);
    REQUIRE(second.errors.len == 1);
    CHECK_STR(second.errors.items[0], "Failed to import Provider: Unsupported proxy type: bogus");
    sb_proxy_upsert_result_free(&second);
    sb_parsed_node_vec_free(&rotated);

    sb_proxy_record_vec nodes = {0};
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), 0);
    REQUIRE(nodes.len == 2);
    CHECK_STR(nodes.items[1].server, "new.example.com");
    sb_proxy_record_vec_free(&nodes);

    CHECK_EQ_INT(sb_store_delete_proxy_node(s, created.id, &err), 0);
    CHECK_EQ_INT(sb_store_find_proxy_node(s, created.id, &saved, &err), 0);
    CHECK_EQ_INT(sb_store_delete_proxy_node(s, created.id, &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);
    sb_proxy_record_free(&manual);
    sb_proxy_record_free(&created);
    sb_proxy_record_free(&saved);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(subscription_repository_records_source_attribution_and_fetch_results) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    sb_subscription sub, created, reloaded, saved;
    sb_subscription_init(&sub);
    sb_subscription_init(&created);
    sb_subscription_init(&reloaded);
    sb_subscription_init(&saved);
    sb_str_set(&sub.name, "Provider");
    sub.name_len = strlen(sub.name);
    sb_str_set(&sub.url, "https://provider.example/sub");
    sub.url_len = strlen(sub.url);
    sub.refresh_interval = 1800;
    REQUIRE(sb_store_create_subscription(s, &sub, &created, &err) == 0);
    sb_parsed_node_vec parsed = parse_body("proxies:\n"
                                           "  - name: Provider HTTP\n"
                                           "    type: http\n"
                                           "    server: http.example.com\n"
                                           "    port: 443\n"
                                           "    tls: true\n");
    sb_proxy_upsert_result imported;
    sb_proxy_upsert_result_init(&imported);
    REQUIRE(sb_store_upsert_proxy_nodes(s, parsed.items, parsed.len, created.id, &imported, &err) == 0);
    CHECK_EQ_INT(imported.added, 1);

    sb_subscription_fetch_result result;
    sb_subscription_fetch_result_init(&result);
    result.added = imported.added;
    result.updated = imported.updated;
    result.found = parsed.len;
    CHECK_EQ_INT(sb_store_record_subscription_fetch(s, created.id, &result, &err), 0);
    CHECK_EQ_INT(sb_store_record_subscription_fetch(s, "missing", &result, &err), -1);
    sbj *rj = sb_subscription_fetch_result_to_json(&result);
    CHECK_EQ_INT(sbj_get_int(rj, "found", -1), 1);
    sbj_free(rj);
    sb_subscription_fetch_result_free(&result);
    REQUIRE(sb_store_find_subscription(s, created.id, &reloaded, &err) == 1);
    CHECK(reloaded.last_fetched_at != NULL);
    REQUIRE(reloaded.last_fetch_result != NULL);
    sbj *meta = sbj_parse_cstr(reloaded.last_fetch_result);
    CHECK_EQ_INT(sbj_get_int(meta, "total", -1), 1);
    sbj_free(meta);
    CHECK_STR(reloaded.last_fetch_result, "{\"added\":1,\"errors\":[],\"skipped\":0,\"total\":1,\"updated\":0}");

    sb_proxy_record_vec nodes = {0};
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), 0);
    REQUIRE(nodes.len == 1);
    CHECK_STR(nodes.items[0].subscription_id, created.id);
    CHECK_STR(nodes.items[0].node_type, "http");
    sb_proxy_record_vec_free(&nodes);

    reloaded.enabled = false;
    reloaded.refresh_interval = 7200;
    REQUIRE(sb_store_update_subscription(s, &reloaded, &saved, &err) == 0);
    CHECK(!saved.enabled);
    CHECK_EQ_INT(saved.refresh_interval, 7200);
    reloaded.refresh_interval = 0;
    CHECK_EQ_INT(sb_store_update_subscription(s, &reloaded, &saved, &err), -1);
    CHECK(err.code == SB_ERR_VALIDATION);
    sb_subscription_vec subs = {0};
    CHECK_EQ_INT(sb_store_list_subscriptions(s, &subs, &err), 0);
    CHECK_EQ_INT(subs.len, 1);
    sb_subscription_vec_free(&subs);
    CHECK_EQ_INT(sb_store_delete_subscription(s, created.id, &err), 0);
    CHECK_EQ_INT(sb_store_find_subscription(s, created.id, &saved, &err), 0);
    CHECK_EQ_INT(sb_store_delete_subscription(s, created.id, &err), -1);

    sb_proxy_upsert_result_free(&imported);
    sb_parsed_node_vec_free(&parsed);
    sb_subscription_free(&sub);
    sb_subscription_free(&created);
    sb_subscription_free(&reloaded);
    sb_subscription_free(&saved);
    sb_store_free(s);
    temp_db_free(&t);
}

/* C-specific: WireGuard repository and backup round-trip (no C++ test). */
TEST(wireguard_peers_and_backup_round_trip) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    char *addr = sb_store_next_wireguard_address(s, "10.59.32.1/24", &err);
    CHECK_STR(addr, "10.59.32.2/24");
    sb_wireguard_peer peer, created, updated;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&created);
    sb_wireguard_peer_init(&updated);
    sb_str_set(&peer.name, "phone");
    peer.name_len = strlen(peer.name);
    sb_str_set(&peer.private_key, "priv");
    sb_str_set(&peer.public_key, "pub");
    sb_str_set(&peer.address, addr);
    free(addr);
    REQUIRE(sb_store_create_wireguard_peer(s, &peer, &created, &err) == 0);
    CHECK_STR(created.dns, "10.59.32.1");
    CHECK_EQ_INT(created.persistent_keepalive, 25);
    CHECK_EQ_INT(sb_store_create_wireguard_peer(s, &peer, &updated, &err), -1);
    CHECK(err.code == SB_ERR_CONFLICT);
    addr = sb_store_next_wireguard_address(s, "10.59.32.1/24", &err);
    CHECK_STR(addr, "10.59.32.3/24");
    free(addr);
    sb_str_setn(&created.name, "tablet\0tail", 11);
    created.name_len = 11;
    sb_str_setn(&created.notes, "note\0tail", 9);
    created.notes_len = 9;
    REQUIRE(sb_store_update_wireguard_peer(s, &created, &updated, &err) == 0);
    CHECK_STR(updated.name, "tablet");
    CHECK_EQ_INT(updated.notes_len, 9);
    CHECK(memcmp(updated.notes, "note\0tail", 9) == 0);
    CHECK_EQ_INT(sb_store_set_wireguard_peer_enabled(s, created.id, false, &err), 0);
    CHECK_EQ_INT(sb_store_set_wireguard_peer_enabled(s, "missing", false, &err), -1);
    CHECK_EQ_INT(sb_store_create_one_time_link(s, "tok", created.id, "2099-01-01 00:00:00", &err), 0);
    CHECK_EQ_INT(sb_store_create_one_time_link(s, "tok2", "missing", "2099-01-01 00:00:00", &err), -1);
    CHECK(err.code == SB_ERR_NOT_FOUND);

    sbj *backup = sb_store_export_backup(s, &err);
    REQUIRE(backup);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(backup, "wireguard_peers")), 1);
    CHECK(sbj_is_object(sbj_get(backup, "app_settings")));
    CHECK_EQ_INT(sb_store_delete_wireguard_peer(s, created.id, &err), 0);
    CHECK_EQ_INT(sb_store_delete_wireguard_peer(s, created.id, &err), -1);
    sbj *counts = sb_store_restore_backup(s, backup, &err);
    REQUIRE(counts);
    CHECK_EQ_INT(sbj_get_int(counts, "wireguard_peers", -1), 1);
    sb_wireguard_peer_vec peers = {0};
    CHECK_EQ_INT(sb_store_list_wireguard_peers(s, &peers, &err), 0);
    REQUIRE(peers.len == 1);
    CHECK_STR(peers.items[0].name, "tablet");
    CHECK_EQ_INT(peers.items[0].name_len, 11);
    CHECK(memcmp(peers.items[0].name, "tablet\0tail", 11) == 0);
    CHECK_EQ_INT(peers.items[0].notes_len, 9);
    CHECK(memcmp(peers.items[0].notes, "note\0tail", 9) == 0);
    CHECK(!peers.items[0].enabled);
    sb_wireguard_peer_vec_free(&peers);
    sbj_free(counts);
    sbj_free(backup);
    sbj *bad = sbj_parse_cstr("{\"subscriptions\":{}}");
    CHECK(sb_store_restore_backup(s, bad, &err) == NULL);
    CHECK_STR(err.msg, "backup row sections must be arrays");
    sbj_free(bad);
    bad = sbj_parse_cstr("{\"subscriptions\":[{\"id\":\"a\",\"url\":\"u\",\"enabled\":1}]}");
    CHECK(sb_store_restore_backup(s, bad, &err) == NULL);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be boolean, but is number");
    sbj_free(bad);

    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_free(&created);
    sb_wireguard_peer_free(&updated);
    sb_store_free(s);
    temp_db_free(&t);
}

/* Parity: open a database produced by the C++/Rust builds if one is given. */
TEST(opens_foreign_database_copy) {
    const char *path = getenv("SB_TEST_FOREIGN_DB");
    if (!path) return;
    sb_err err = {0};
    sb_store *s = sb_store_open(path, migrations(), &err);
    if (!s) fprintf(stderr, "foreign open: %s\n", err.msg);
    REQUIRE(s);
    sb_host_vec hosts = {0};
    sb_config_profile_vec profiles = {0};
    sb_proxy_record_vec nodes = {0};
    sb_subscription_vec subs = {0};
    CHECK_EQ_INT(sb_store_list_hosts(s, &hosts, &err), 0);
    CHECK_EQ_INT(sb_store_list_profiles(s, &profiles, &err), 0);
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), 0);
    CHECK_EQ_INT(sb_store_list_subscriptions(s, &subs, &err), 0);
    printf("  foreign: %zu hosts, %zu profiles, %zu proxies, %zu subscriptions\n", hosts.len,
           profiles.len, nodes.len, subs.len);
    for (size_t i = 0; i < hosts.len; ++i) {
        sb_render_request req;
        sb_render_request_init(&req);
        int rc = sb_store_render_request_for_host(s, hosts.items[i].id, &req, &err);
        if (rc != 0) fprintf(stderr, "render %s: %s\n", hosts.items[i].id, err.msg);
        CHECK_EQ_INT(rc, 0);
        printf("  host %s: %zu nodes, mode %s\n", hosts.items[i].id, req.nodes.len,
               sb_profile_mode_name(req.mode));
        sb_render_request_free(&req);
    }
    sbj *backup = sb_store_export_backup(s, &err);
    CHECK(backup != NULL);
    sbj_free(backup);
    sb_host_vec_free(&hosts);
    sb_config_profile_vec_free(&profiles);
    sb_proxy_record_vec_free(&nodes);
    sb_subscription_vec_free(&subs);
    sb_store_free(s);
}

/* C-specific: nlohmann exceptions that escape the C++ store (json::value() type
 * errors, json::dump() of invalid UTF-8) surface as SB_ERR_BAD_JSON with the
 * identical what() text, and list results are untouched on failure. */
TEST(json_exception_parity_and_list_failure_semantics) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};

    sbj *backup = sbj_parse_cstr("{\"wireguard_peers\":[{\"id\":\"w\",\"address\":\"a\",\"enabled\":1}]}");
    CHECK(sb_store_restore_backup(s, backup, &err) == NULL);
    CHECK(err.code == SB_ERR_BAD_JSON);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be boolean, but is number");
    sbj_free(backup);
    backup = sbj_parse_cstr("{\"subscriptions\":[{\"id\":\"s\",\"url\":\"u\",\"refresh_interval\":true}]}");
    CHECK(sb_store_restore_backup(s, backup, &err) == NULL);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be number, but is boolean");
    sbj_free(backup);
    sb_wireguard_peer_vec peers = {0};
    CHECK_EQ_INT(sb_store_list_wireguard_peers(s, &peers, &err), 0);
    CHECK_EQ_INT(peers.len, 0); /* the failed restore rolled back */
    sb_wireguard_peer_vec_free(&peers);

    sbj *bad = sbj_str("\xff");
    CHECK_EQ_INT(sb_store_set_app_setting(s, "k", bad, &err), -1);
    CHECK(err.code == SB_ERR_BAD_JSON);
    CHECK_STR(err.msg, "[json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF");
    sbj_free(bad);
    bad = sbj_array();
    sbj_arr_push(bad, sbj_str("ok"));
    sbj_arr_push(bad, sbj_str("a\xe4\xb8"));
    CHECK_EQ_INT(sb_store_set_app_setting(s, "k", bad, &err), -1);
    CHECK_STR(err.msg, "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0xB8");
    sbj_free(bad);
    bad = sbj_parse_cstr("{\"general\":{}}");
    sbj_set_str(sbj_get(bad, "general"), "\xed\xa0\x80", "surrogate key");
    CHECK_EQ_INT(sb_store_update_app_settings(s, bad, &err), -1);
    CHECK_STR(err.msg, "[json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xA0");
    sbj_free(bad);
    sbj *good = sbj_str("\xf0\x9f\x98\x80 ok");
    CHECK_EQ_INT(sb_store_set_app_setting(s, "k", good, &err), 0);
    sbj_free(good);

    /* ParsedProxyNode::fingerprint() reads its key material with json::value() */
    sb_proxy_record node, out;
    sb_proxy_record_init(&node);
    sb_proxy_record_init(&out);
    sb_str_set(&node.tag, "T");
    node.tag_len = strlen(node.tag);
    sb_str_set(&node.node_type, "trojan");
    node.node_type_len = strlen(node.node_type);
    sb_str_set(&node.server, "s");
    node.server_len = strlen(node.server);
    node.server_port = 1;
    sbj_set_int(node.protocol_config, "password", 7);
    CHECK_EQ_INT(sb_store_create_proxy_node(s, &node, &out, &err), -1);
    CHECK(err.code == SB_ERR_BAD_JSON);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be string, but is number");
    sb_proxy_record_free(&node);
    sb_proxy_record_free(&out);

    /* save_diagnostic_report reads reason/app_version/core_version with value() */
    sb_host h;
    sb_host_init(&h);
    sbj *report = sbj_parse_cstr("{\"reason\":null}");
    CHECK(sb_store_save_diagnostic_report(s, "self", report, &err) == NULL);
    CHECK_STR(err.msg, "[json.exception.type_error.302] type must be string, but is null");
    sbj_free(report);
    sb_host_free(&h);

    /* a failing list call leaves the caller's vector untouched */
    exec_sql(s, "INSERT INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, "
                "protocol_config, fingerprint) VALUES ('p1','p1','trojan',1,'s',1,'{}','p1'),"
                "('p2','p2','trojan',1,'s',70000,'{}','p2')");
    sb_proxy_record_vec nodes = {0};
    sb_proxy_record *keep = sb_proxy_record_vec_push(&nodes);
    sb_str_set(&keep->id, "caller-row");
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), -1);
    CHECK_STR(err.msg, "proxy server_port is out of range for node p2");
    REQUIRE(nodes.len == 1);
    CHECK_STR(nodes.items[0].id, "caller-row");
    exec_sql(s, "DELETE FROM proxy_nodes WHERE id = 'p2'");
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), 0);
    REQUIRE(nodes.len == 2); /* appended after the caller's row */
    CHECK_STR(nodes.items[1].id, "p1");
    sb_proxy_record_vec_free(&nodes);

    sb_store_free(s);
    temp_db_free(&t);
}

static char *make_migration_dir(const char *const *extra_names, const char *const *extra_sql,
                                size_t extra) {
    unsigned char r[6];
    sb_random_bytes(r, sizeof r);
    char *hex = sb_hex_encode(r, sizeof r);
    char *dir = sb_asprintf("/tmp/sb-easy-c-mig-%s", hex);
    free(hex);
    mkdir(dir, 0700);
    DIR *src = opendir(migrations());
    struct dirent *e;
    while (src && (e = readdir(src)) != NULL) {
        if (!sb_ends_with(e->d_name, ".sql")) continue;
        char *from = sb_path_join(migrations(), e->d_name), *to = sb_path_join(dir, e->d_name);
        size_t n = 0;
        char *text = sb_read_file(from, &n);
        if (text) sb_write_file(to, text, n);
        free(text);
        free(from);
        free(to);
    }
    if (src) closedir(src);
    for (size_t i = 0; i < extra; ++i) {
        char *to = sb_path_join(dir, extra_names[i]);
        sb_write_file(to, extra_sql[i], strlen(extra_sql[i]));
        free(to);
    }
    return dir;
}

static void remove_migration_dir(char *dir) {
    DIR *d = opendir(dir);
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char *p = sb_path_join(dir, e->d_name);
        unlink(p);
        free(p);
    }
    if (d) closedir(d);
    rmdir(dir);
    free(dir);
}

/* C-specific: migration runner rules of cpp/src/database.cpp beyond the C++ tests. */
TEST(migration_runner_edge_cases) {
    sb_err err = {0};
    temp_db t;
    temp_db_init(&t);

    /* names outside ^([0-9]+)_(.+)\.sql$ are ignored */
    const char *ignored_names[] = {"README.md", "abc.sql", "12.sql", "_x.sql", "13_.sql", "14_a.SQL"};
    const char *ignored_sql[] = {"x", "BOGUS", "BOGUS", "BOGUS", "BOGUS", "BOGUS"};
    char *dir = make_migration_dir(ignored_names, ignored_sql, 6);
    sb_store *s = sb_store_open(t.path, dir, &err);
    if (!s) fprintf(stderr, "open: %s\n", err.msg);
    REQUIRE(s);
    CHECK_EQ_INT(sb_database_applied_migration_count(sb_store_database(s), &err), 11);
    sb_store_free(s);
    remove_migration_dir(dir);

    /* a failing migration is rolled back and not recorded */
    const char *bad_names[] = {"12_add_things.sql"};
    const char *bad_sql[] = {"CREATE TABLE later_things (id TEXT);\nBOGUS STATEMENT;\n"};
    dir = make_migration_dir(bad_names, bad_sql, 1);
    CHECK(sb_store_open(t.path, dir, &err) == NULL);
    CHECK_STR(err.msg, "execute SQL failed (1): near \"BOGUS\": syntax error");
    remove_migration_dir(dir);
    s = sb_store_open(t.path, migrations(), &err);
    REQUIRE(s);
    CHECK_EQ_INT(sb_database_applied_migration_count(sb_store_database(s), &err), 11);
    CHECK_EQ_INT(sb_database_execute(sb_store_database(s), "SELECT * FROM later_things", &err), -1);
    sb_store_free(s);

    /* description and non-transactional migrations */
    const char *nt_names[] = {"12_no_tx.sql"};
    const char *nt_sql[] = {"-- no-transaction\nSELECT 1;\n"};
    dir = make_migration_dir(nt_names, nt_sql, 1);
    CHECK(sb_store_open(t.path, dir, &err) == NULL);
    CHECK_STR(err.msg, "non-transactional migrations are not supported");
    remove_migration_dir(dir);

    /* duplicate versions and std::stoll overflow */
    const char *dup_names[] = {"0001_again.sql"};
    const char *dup_sql[] = {"SELECT 1;"};
    dir = make_migration_dir(dup_names, dup_sql, 1);
    CHECK(sb_store_open(t.path, dir, &err) == NULL);
    CHECK_STR(err.msg, "duplicate migration version: 1");
    remove_migration_dir(dir);
    const char *big_names[] = {"99999999999999999999_big.sql"};
    dir = make_migration_dir(big_names, dup_sql, 1);
    CHECK(sb_store_open(t.path, dir, &err) == NULL);
    CHECK_STR(err.msg, "stoll");
    remove_migration_dir(dir);

    /* a new migration is applied with the SQLx description (underscores -> spaces) */
    const char *ok_names[] = {"12_add_more_things.sql"};
    const char *ok_sql[] = {"CREATE TABLE more_things (id TEXT);\n"};
    dir = make_migration_dir(ok_names, ok_sql, 1);
    s = sb_store_open(t.path, dir, &err);
    REQUIRE(s);
    CHECK_EQ_INT(sb_database_applied_migration_count(sb_store_database(s), &err), 12);
    CHECK_EQ_INT(sb_database_execute(sb_store_database(s),
                                     "CREATE TEMP TABLE probe AS SELECT description FROM _sqlx_migrations "
                                     "WHERE version = 12 AND description = 'add more things'",
                                     &err),
                 0);
    sb_store_free(s);
    remove_migration_dir(dir);
    temp_db_free(&t);
}

typedef struct {
    sb_store *store;
    int index;
    int failures;
} worker_arg;

#define WORKERS 8
#define ITERATIONS 25

static void *store_worker(void *p) {
    worker_arg *w = p;
    for (int j = 0; j < ITERATIONS; ++j) {
        sb_err err = {0};
        sb_host host, created, found;
        sb_host_init(&host);
        sb_host_init(&created);
        sb_host_init(&found);
        char *name = sb_asprintf("worker-%d-%d", w->index, j);
        sb_str_set(&host.name, name);
        host.name_len = strlen(host.name);
        if (sb_store_create_host(w->store, &host, &created, &err) != 0) ++w->failures;
        if (sb_store_find_host(w->store, created.id, &found, &err) != 1 || !sb_streq(found.name, name))
            ++w->failures;
        if (sb_store_record_audit(w->store, name, "POST", NULL, &err) != 0) ++w->failures;

        sb_proxy_record node, saved;
        sb_proxy_record_init(&node);
        sb_proxy_record_init(&saved);
        sb_str_set(&node.tag, name);
        node.tag_len = strlen(node.tag);
        sb_str_set(&node.node_type, "trojan");
        node.node_type_len = strlen(node.node_type);
        sb_str_set(&node.server, "concurrent.example");
        node.server_len = strlen(node.server);
        node.server_port = (uint16_t)(1000 + w->index * 100 + j);
        sbj_set_str(node.protocol_config, "password", name);
        if (sb_store_create_proxy_node(w->store, &node, &saved, &err) != 0) ++w->failures;
        sb_strvec ids = {0};
        sb_strvec_push(&ids, saved.id);
        if (sb_store_set_host_outbounds(w->store, created.id, &ids, &err) != 0) ++w->failures;
        sb_strvec_free(&ids);
        sb_render_request req;
        sb_render_request_init(&req);
        if (sb_store_render_request_for_host(w->store, created.id, &req, &err) != 0 || req.nodes.len != 1)
            ++w->failures;
        sb_render_request_free(&req);

        sb_host_vec hosts = {0};
        if (sb_store_list_hosts(w->store, &hosts, &err) != 0 || hosts.len < 2) ++w->failures;
        sb_host_vec_free(&hosts);
        sbj *settings = sb_store_app_settings(w->store, &err);
        if (!settings) ++w->failures;
        sbj_free(settings);

        sb_proxy_record_free(&node);
        sb_proxy_record_free(&saved);
        free(name);
        sb_host_free(&host);
        sb_host_free(&created);
        sb_host_free(&found);
    }
    return NULL;
}

/* C-specific: the store is shared by civetweb worker threads. */
TEST(store_is_safe_under_concurrent_access) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    pthread_t threads[WORKERS];
    worker_arg args[WORKERS];
    for (int i = 0; i < WORKERS; ++i) {
        args[i] = (worker_arg){.store = s, .index = i, .failures = 0};
        REQUIRE(pthread_create(&threads[i], NULL, store_worker, &args[i]) == 0);
    }
    int failures = 0;
    for (int i = 0; i < WORKERS; ++i) {
        pthread_join(threads[i], NULL);
        failures += args[i].failures;
    }
    CHECK_EQ_INT(failures, 0);
    sb_err err = {0};
    sb_host_vec hosts = {0};
    CHECK_EQ_INT(sb_store_list_hosts(s, &hosts, &err), 0);
    CHECK_EQ_INT(hosts.len, 1 + WORKERS * ITERATIONS);
    sb_host_vec_free(&hosts);
    sb_proxy_record_vec nodes = {0};
    CHECK_EQ_INT(sb_store_list_proxy_nodes(s, &nodes, &err), 0);
    CHECK_EQ_INT(nodes.len, WORKERS * ITERATIONS);
    sb_proxy_record_vec_free(&nodes);
    sb_audit_entry_vec audit = {0};
    CHECK_EQ_INT(sb_store_list_audit(s, 1000, &audit, &err), 0);
    CHECK_EQ_INT(audit.len, WORKERS * ITERATIONS);
    sb_audit_entry_vec_free(&audit);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(proxy_bytes_survive_import_latency_and_backup) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_err err = {0};
    const char *body = "[{\"type\":\"shadowsocks\",\"tag\":\"tag\\u0000one\","
        "\"server\":\"host\\u0000one\",\"server_port\":443,\"method\":\"aes-256-gcm\",\"password\":\"pw\\u0000one\"},"
        "{\"type\":\"shadowsocks\",\"tag\":\"tag\\u0000two\","
        "\"server\":\"host\\u0000one\",\"server_port\":443,\"method\":\"aes-256-gcm\",\"password\":\"pw\\u0000two\"}]";
    sbj *config = sbj_object();
    sbj_set(config, "outbounds", sbj_parse_cstr(body));
    sb_proxy_import imported;
    REQUIRE(sb_parse_outbound_config(config, &imported, &err) == 0);
    REQUIRE(imported.nodes.len == 2);
    sb_proxy_upsert_result result;
    sb_proxy_upsert_result_init(&result);
    REQUIRE(sb_store_upsert_proxy_nodes(s, imported.nodes.items, imported.nodes.len, NULL, &result, &err) == 0);
    CHECK_EQ_INT(result.added, 2);
    CHECK_EQ_INT(result.errors.len, 0);
    sb_proxy_upsert_result_free(&result);
    sbj *latencies = sbj_object();
    sbj_setn(latencies, "tag\0two", 7, sbj_int(123));
    size_t updated = 0;
    REQUIRE(sb_store_update_proxy_latencies(s, latencies, &updated, &err) == 0);
    CHECK_EQ_INT(updated, 1);
    sbj_free(latencies);
    sb_proxy_record_vec records = {0};
    REQUIRE(sb_store_list_proxy_nodes(s, &records, &err) == 0);
    REQUIRE(records.len == 2);
    for (size_t i = 0; i < records.len; ++i) {
        CHECK_EQ_INT(records.items[i].tag_len, 7);
        CHECK_EQ_INT(records.items[i].server_len, 8);
        CHECK(memcmp(records.items[i].server, "host\0one", 8) == 0);
    }
    CHECK(strcmp(records.items[0].fingerprint, records.items[1].fingerprint) != 0);
    sb_proxy_record *two = memcmp(records.items[0].tag, "tag\0two", 7) == 0 ? &records.items[0] : &records.items[1];
    CHECK(two->has_latency && two->latency == 123);
    sbj *backup = sb_store_export_backup(s, &err);
    REQUIRE(backup);
    for (size_t i = 0; i < records.len; ++i)
        REQUIRE(sb_store_delete_proxy_node(s, records.items[i].id, &err) == 0);
    sb_proxy_record_vec_free(&records);
    sbj *counts = sb_store_restore_backup(s, backup, &err);
    REQUIRE(counts);
    sbj_free(counts);
    REQUIRE(sb_store_list_proxy_nodes(s, &records, &err) == 0);
    REQUIRE(records.len == 2);
    for (size_t i = 0; i < records.len; ++i) {
        CHECK_EQ_INT(records.items[i].tag_len, 7);
        CHECK_EQ_INT(records.items[i].server_len, 8);
    }
    sb_proxy_record_vec_free(&records);
    sbj_free(backup);
    sb_proxy_import_free(&imported);
    sbj_free(config);
    sb_store_free(s);
    temp_db_free(&t);
}

TEST(subscription_bytes_survive_copy_updates_and_backup) {
    temp_db t;
    sb_store *s = open_store(&t);
    REQUIRE(s);
    sb_subscription sub, created, updated;
    sb_subscription_init(&sub);
    sb_subscription_init(&created);
    sb_subscription_init(&updated);
    const char name[] = "\0provider";
    const char url[] = "https://example.invalid/sub\0tail";
    sb_str_setn(&sub.name, name, sizeof name - 1);
    sub.name_len = sizeof name - 1;
    sb_str_setn(&sub.url, url, sizeof url - 1);
    sub.url_len = sizeof url - 1;
    sb_err err = {0};
    REQUIRE(sb_store_create_subscription(s, &sub, &created, &err) == 0);
    CHECK_EQ_INT(created.name_len, sizeof name - 1);
    CHECK_EQ_INT(created.url_len, sizeof url - 1);
    CHECK(memcmp(created.name, name, sizeof name - 1) == 0);
    CHECK(memcmp(created.url, url, sizeof url - 1) == 0);
    sb_subscription_copy(&sub, &created);
    sub.enabled = false;
    REQUIRE(sb_store_update_subscription(s, &sub, &updated, &err) == 0);
    CHECK_EQ_INT(updated.url_len, sizeof url - 1);
    CHECK(memcmp(updated.url, url, sizeof url - 1) == 0);
    sbj *backup = sb_store_export_backup(s, &err);
    REQUIRE(backup);
    REQUIRE(sb_store_delete_subscription(s, created.id, &err) == 0);
    sbj *counts = sb_store_restore_backup(s, backup, &err);
    REQUIRE(counts);
    sbj_free(counts);
    REQUIRE(sb_store_find_subscription(s, created.id, &updated, &err) == 1);
    sbj *encoded = sb_subscription_to_json(&updated);
    CHECK_EQ_INT(sbj_get(encoded, "name")->v.str.len, sizeof name - 1);
    CHECK_EQ_INT(sbj_get(encoded, "url")->v.str.len, sizeof url - 1);
    CHECK(memcmp(updated.url, url, sizeof url - 1) == 0);
    sbj_free(encoded);
    sbj_free(backup);
    sb_subscription_free(&sub);
    sb_subscription_free(&created);
    sb_subscription_free(&updated);
    sb_store_free(s);
    temp_db_free(&t);
}
