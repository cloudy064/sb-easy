#include "sb/auth_security.h"
#include "../src/auth_security_internal.h"
#include <pthread.h>
#include "test.h"

typedef struct { sb_database *db; sb_auth_security *auth; } security_fixture;
static security_fixture fixture(void) {
    security_fixture f = {0}; sb_err err = {0};
    f.db = sb_database_open(":memory:", &err);
    if (!f.db || sb_database_migrate(f.db, sb_getenv_or("SB_EASY_MIGRATIONS", "migrations"), &err)) {
        fprintf(stderr, "fixture: %s\n", err.msg); sb_database_free(f.db); return (security_fixture){0};
    }
    if (sb_database_execute(f.db,
        "INSERT INTO users(id,username,password_hash,role) VALUES"
        "('a','admin','unused','admin'),('v','viewer','unused','viewer'),('o','operator','unused','operator');"
        "INSERT INTO hosts(id,name) VALUES('h1','first'),('h2','second'),('h3','third');", &err)) {
        fprintf(stderr, "fixture: %s\n", err.msg); sb_database_free(f.db); return (security_fixture){0};
    }
    f.auth = sb_auth_security_new(f.db, "unit-test-secret-with-adequate-entropy", false, &err);
    return f;
}
static void fixture_free(security_fixture *f) { sb_auth_security_free(f->auth); sb_database_free(f->db); }
static char *query_text(sb_database *db, const char *sql) {
    sb_database_lock(db);
    sqlite3_stmt *st = sbq_prepare(sb_database_handle(db), sql, NULL);
    char *text = st && sbq_step_row(st, NULL) == 1 ? sbq_text(st, 0) : NULL;
    sqlite3_finalize(st); sb_database_unlock(db); return text;
}
static sbj *enroll(security_fixture *f, const char *keep, char **secret_out) {
    sb_err err = {0}; sbj *pending = sb_auth_mfa_begin(f->auth, "a", &err);
    if (!pending) { fprintf(stderr, "begin: %s\n", err.msg); return NULL; }
    char *secret = sb_strdup(sbj_get_str(pending, "secret", "")); sbj_free(pending);
    char code[9];
    sb_auth_totp_code(secret, sb_unix_now(), 6, code, NULL);
    sbj *result = sb_auth_mfa_confirm(f->auth, "a", code, keep, &err);
    if (!result) fprintf(stderr, "confirm: %s\n", err.msg);
    if (secret_out) *secret_out = secret; else sb_auth_sec_secret_free(secret);
    return result;
}

TEST(totp_matches_all_rfc6238_sha1_vectors) {
    const int64_t times[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000LL};
    const char *expected[] = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};
    const char *secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    for (unsigned i = 0; i < 6; ++i) {
        char code[9]; CHECK_EQ_INT(sb_auth_totp_code(secret, times[i], 8, code, NULL), 0); CHECK_STR(code, expected[i]);
    }
    char code[9]; CHECK_EQ_INT(sb_auth_totp_code(secret, 59, 6, code, NULL), 0); CHECK_STR(code, "287082");
    CHECK_EQ_INT(sb_auth_totp_code("bad-secret", 59, 6, code, NULL), -1);
    CHECK_EQ_INT(sb_auth_totp_code(secret, -1, 6, code, NULL), -1);
    CHECK_EQ_INT(sb_auth_totp_code(secret, 59, 7, code, NULL), -1);
}

TEST(encrypted_secrets_bind_purpose_key_and_authenticate_every_byte) {
    security_fixture f = fixture(); REQUIRE(f.auth);
    char *one = sb_auth_sec_encrypt(f.auth, "user:a", "secret-value", NULL);
    char *two = sb_auth_sec_encrypt(f.auth, "user:a", "secret-value", NULL);
    REQUIRE(one && two); CHECK(strcmp(one, two)); CHECK(!strstr(one, "secret-value"));
    char *plain = sb_auth_sec_decrypt(f.auth, "user:a", one, NULL); CHECK_STR(plain, "secret-value"); sb_auth_sec_secret_free(plain);
    CHECK(!sb_auth_sec_decrypt(f.auth, "user:b", one, NULL));
    sb_auth_security *other = sb_auth_security_new(f.db, "a-different-server-secret", false, NULL);
    CHECK(!sb_auth_sec_decrypt(other, "user:a", one, NULL)); sb_auth_security_free(other);
    size_t n = 0; unsigned char *raw = sb_base64url_decode_strict(one, strlen(one), &n); REQUIRE(raw);
    raw[13] ^= 1; char *tampered = sb_base64url_encode(raw, n); free(raw);
    CHECK(!sb_auth_sec_decrypt(f.auth, "user:a", tampered, NULL)); free(tampered);
    free(one); free(two); fixture_free(&f);
}

TEST(sessions_are_unique_registered_revocable_and_read_current_roles) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    char *first = sb_auth_security_issue(f.auth, "a", "password", "browser one", &err);
    char *second = sb_auth_security_issue(f.auth, "a", "password", "browser two", &err);
    REQUIRE(first && second); CHECK(strcmp(first, second));
    char *legacy = sb_auth_create_token("unit-test-secret-with-adequate-entropy", "a", "admin", "admin");
    CHECK(!sb_auth_security_verify(f.auth, legacy, NULL, &err)); free(legacy);
    sb_auth_claims claims = {0}; REQUIRE(sb_auth_security_verify(f.auth, first, &claims, &err));
    CHECK_STR(claims.subject, "a"); CHECK_STR(claims.role, "admin"); sb_auth_claims_free(&claims);
    CHECK_EQ_INT(sb_database_execute(f.db, "UPDATE users SET role='viewer' WHERE id='a'", NULL), 0);
    REQUIRE(sb_auth_security_verify(f.auth, first, &claims, &err)); CHECK_STR(claims.role, "viewer"); sb_auth_claims_free(&claims);
    sbj *sessions = sb_auth_security_sessions(f.auth, "a", first, &err); REQUIRE(sessions);
    CHECK_EQ_INT(sbj_arr_len(sessions), 2);
    const sbj *current = sbj_get_bool(sbj_arr_at(sessions, 0), "current", false) ? sbj_arr_at(sessions, 0) : sbj_arr_at(sessions, 1);
    const char *id = sbj_get_str(current, "id", "");
    CHECK_EQ_INT(sb_auth_security_revoke(f.auth, "v", id, NULL, &err), 0);
    CHECK(sb_auth_security_verify(f.auth, first, NULL, &err));
    CHECK_EQ_INT(sb_auth_security_revoke(f.auth, "a", id, NULL, &err), 0);
    CHECK(!sb_auth_security_verify(f.auth, first, NULL, &err));
    CHECK(sb_auth_security_verify(f.auth, second, NULL, &err));
    CHECK_EQ_INT(sb_auth_security_logout(f.auth, second, &err), 0);
    CHECK(!sb_auth_security_verify(f.auth, second, NULL, &err)); sbj_free(sessions);
    char *third = sb_auth_security_issue(f.auth, "a", "password", NULL, &err); REQUIRE(third);
    CHECK_EQ_INT(sb_database_execute(f.db, "UPDATE auth_sessions SET expires_at=0", NULL), 0);
    CHECK(!sb_auth_security_verify(f.auth, third, NULL, &err));
    char *fourth = sb_auth_security_issue(f.auth, "a", "password", NULL, &err); REQUIRE(fourth);
    CHECK_EQ_INT(sb_database_execute(f.db, "DELETE FROM users WHERE id='a'", NULL), 0);
    CHECK(!sb_auth_security_verify(f.auth, fourth, NULL, &err));
    free(first); free(second); free(third); free(fourth); fixture_free(&f);
}

TEST(role_changes_preserve_an_administrator_and_revoke_sessions) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    char *token = sb_auth_security_issue(f.auth, "a", "password", NULL, &err); REQUIRE(token);
    CHECK_EQ_INT(sb_auth_security_change_role(f.auth, "a", "viewer", &err), -1);
    CHECK_CONTAINS(err.msg, "last admin"); CHECK(sb_auth_security_verify(f.auth, token, NULL, &err));
    CHECK_EQ_INT(sb_auth_security_change_role(f.auth, "v", "admin", &err), 0);
    CHECK_EQ_INT(sb_auth_security_change_role(f.auth, "a", "operator", &err), 0);
    CHECK(!sb_auth_security_verify(f.auth, token, NULL, &err));
    CHECK_EQ_INT(sb_auth_security_change_role(f.auth, "v", "root", &err), -1);
    free(token); fixture_free(&f);
}

TEST(mfa_secrets_encrypted_recovery_one_use_and_session_changes_atomic) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    char *current = sb_auth_security_issue(f.auth, "a", "password", "current", NULL);
    char *other = sb_auth_security_issue(f.auth, "a", "password", "other", NULL); REQUIRE(current && other);
    sbj *pending = sb_auth_mfa_begin(f.auth, "a", &err); REQUIRE(pending);
    const char *secret = sbj_get_str(pending, "secret", ""); CHECK_EQ_INT(strlen(secret), 32);
    CHECK_CONTAINS(sbj_get_str(pending, "otpauth_uri", ""), "otpauth://totp/sb-easy:");
    char *stored = query_text(f.db, "SELECT pending_enc FROM auth_mfa WHERE user_id='a'"); REQUIRE(stored);
    CHECK(!strstr(stored, secret)); free(stored);
    sbj *status = sb_auth_mfa_status(f.auth, "a", &err); REQUIRE(status);
    CHECK(!sbj_get_bool(status, "enabled", true)); CHECK(sbj_get_bool(status, "pending", false)); sbj_free(status);
    char code[9]; sb_auth_totp_code(secret, sb_unix_now(), 6, code, NULL);
    sbj *confirmed = sb_auth_mfa_confirm(f.auth, "a", code, current, &err); REQUIRE(confirmed);
    sbj *codes = sbj_get(confirmed, "recovery_codes"); CHECK_EQ_INT(sbj_arr_len(codes), 10);
    CHECK(sb_auth_security_verify(f.auth, current, NULL, &err)); CHECK(!sb_auth_security_verify(f.auth, other, NULL, &err));
    CHECK(!sb_auth_mfa_verify(f.auth, "a", code, &err));
    const char *recovery = sbj_as_str(sbj_arr_at(codes, 0), "");
    CHECK(sb_auth_mfa_verify(f.auth, "a", recovery, &err)); CHECK(!sb_auth_mfa_verify(f.auth, "a", recovery, &err));
    status = sb_auth_mfa_status(f.auth, "a", &err); REQUIRE(status);
    CHECK(sbj_get_bool(status, "enabled", false)); CHECK(!sbj_has(status, "secret"));
    CHECK_EQ_INT(sbj_get_int(status, "recovery_codes_remaining", -1), 9); sbj_free(status);
    stored = query_text(f.db, "SELECT group_concat(code_hash) FROM auth_recovery_codes WHERE user_id='a'");
    REQUIRE(stored); CHECK(!strstr(stored, recovery)); free(stored);
    CHECK_EQ_INT(sb_auth_mfa_disable(f.auth, "a", current, &err), 0);
    CHECK(sb_auth_security_verify(f.auth, current, NULL, &err));
    CHECK(!sb_auth_mfa_verify(f.auth, "a", sbj_as_str(sbj_arr_at(codes, 1), ""), &err));
    status = sb_auth_mfa_status(f.auth, "a", &err); REQUIRE(status);
    CHECK(!sbj_get_bool(status, "enabled", true)); CHECK_EQ_INT(sbj_get_int(status, "recovery_codes_remaining", -1), 0);
    sbj_free(status); sbj_free(confirmed); sbj_free(pending); free(current); free(other); fixture_free(&f);
}

TEST(browser_bound_challenge_and_recovery_code_are_consumed_together) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    sbj *confirmed = enroll(&f, NULL, NULL); REQUIRE(confirmed);
    const char *recovery = sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 0), "");
    char *challenge = sb_auth_security_challenge_bound(f.auth, "a", "password", "browser-nonce", &err); REQUIRE(challenge);
    CHECK(!sb_auth_security_complete_bound(f.auth, challenge, recovery, "browser", "wrong-nonce", &err));
    CHECK(!sb_auth_security_complete(f.auth, challenge, recovery, "browser", &err));
    char *token = sb_auth_security_complete_bound(f.auth, challenge, recovery, "browser", "browser-nonce", &err); REQUIRE(token);
    CHECK(sb_auth_security_verify(f.auth, token, NULL, &err));
    CHECK(!sb_auth_security_complete_bound(f.auth, challenge, recovery, "browser", "browser-nonce", &err));
    CHECK(!sb_auth_mfa_verify(f.auth, "a", recovery, &err));
    sbj *sessions = sb_auth_security_sessions(f.auth, "a", token, &err); REQUIRE(sessions);
    CHECK_STR(sbj_get_str(sbj_arr_at(sessions, 0), "method", ""), "password+mfa"); sbj_free(sessions);
    char *expired = sb_auth_security_challenge(f.auth, "a", "oidc", &err); REQUIRE(expired);
    CHECK_EQ_INT(sb_database_execute(f.db, "UPDATE auth_login_challenges SET expires_at=0", NULL), 0);
    CHECK(!sb_auth_security_complete(f.auth, expired, sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 1), ""), NULL, &err));
    free(expired); free(challenge); free(token); sbj_free(confirmed); fixture_free(&f);
}

TEST(mfa_lockout_and_pending_expiry_persist) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    sbj *confirmed = enroll(&f, NULL, NULL); REQUIRE(confirmed);
    for (unsigned i = 0; i < 5; ++i) CHECK(!sb_auth_mfa_verify(f.auth, "a", "definitely-invalid", &err));
    const char *code = sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 0), "");
    CHECK(!sb_auth_mfa_verify(f.auth, "a", code, &err)); CHECK_CONTAINS(err.msg, "locked");
    sb_auth_security_free(f.auth); f.auth = sb_auth_security_new(f.db, "unit-test-secret-with-adequate-entropy", false, NULL);
    CHECK(!sb_auth_mfa_verify(f.auth, "a", code, &err));
    CHECK_EQ_INT(sb_database_execute(f.db, "UPDATE auth_mfa SET locked_until=0 WHERE user_id='a'", NULL), 0);
    CHECK(sb_auth_mfa_verify(f.auth, "a", code, &err));
    sbj *pending = sb_auth_mfa_begin(f.auth, "v", &err); REQUIRE(pending);
    char totp[9]; sb_auth_totp_code(sbj_get_str(pending, "secret", ""), sb_unix_now(), 6, totp, NULL);
    CHECK_EQ_INT(sb_database_execute(f.db, "UPDATE auth_mfa SET pending_until=0 WHERE user_id='v'", NULL), 0);
    CHECK(!sb_auth_mfa_confirm(f.auth, "v", totp, NULL, &err)); CHECK_CONTAINS(err.msg, "expired");
    sbj_free(pending); sbj_free(confirmed); fixture_free(&f);
}

TEST(revoke_all_invalidates_unfinished_primary_authentication_challenges) {
    security_fixture f = fixture(); REQUIRE(f.auth);
    sbj *confirmed = enroll(&f, NULL, NULL); REQUIRE(confirmed);
    char *challenge = sb_auth_security_challenge(f.auth, "a", "password", NULL); REQUIRE(challenge);
    const char *code = sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 0), "");
    CHECK_EQ_INT(sb_auth_security_revoke(f.auth, "a", NULL, NULL, NULL), 0);
    CHECK(!sb_auth_security_complete(f.auth, challenge, code, NULL, NULL));
    /* An invalidated challenge must not burn a recovery code. */
    CHECK(sb_auth_mfa_verify(f.auth, "a", code, NULL));
    free(challenge); sbj_free(confirmed); fixture_free(&f);
}

TEST(mfa_enable_blocks_stale_primary_login_issuance_even_with_a_spoofed_method) {
    security_fixture f = fixture(); REQUIRE(f.auth);
    sbj *before = sb_auth_mfa_status(f.auth, "a", NULL); REQUIRE(before);
    CHECK(!sbj_get_bool(before, "enabled", true)); sbj_free(before);
    sbj *confirmed = enroll(&f, NULL, NULL); REQUIRE(confirmed);
    CHECK(!sb_auth_security_issue(f.auth, "a", "password", NULL, NULL));
    CHECK(!sb_auth_security_issue(f.auth, "a", "oidc", NULL, NULL));
    CHECK(!sb_auth_security_issue(f.auth, "a", "password+mfa", NULL, NULL));
    char *challenge = sb_auth_security_challenge(f.auth, "a", "password", NULL); REQUIRE(challenge);
    char *token = sb_auth_security_complete(f.auth, challenge,
        sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 0), ""), NULL, NULL);
    REQUIRE(token); CHECK(sb_auth_security_verify(f.auth, token, NULL, NULL));
    free(token); free(challenge); sbj_free(confirmed); fixture_free(&f);
}

typedef struct { sb_auth_security *auth; const char *challenge, *code; char *token; } complete_task;
static void *complete_thread(void *context) {
    complete_task *task = context;
    task->token = sb_auth_security_complete(task->auth, task->challenge, task->code, NULL, NULL); return NULL;
}
TEST(concurrent_challenge_completion_issues_exactly_one_session) {
    security_fixture f = fixture(); REQUIRE(f.auth);
    sbj *confirmed = enroll(&f, NULL, NULL); REQUIRE(confirmed);
    char *challenge = sb_auth_security_challenge(f.auth, "a", "password", NULL); REQUIRE(challenge);
    const char *code = sbj_as_str(sbj_arr_at(sbj_get(confirmed, "recovery_codes"), 0), "");
    complete_task tasks[2] = {{f.auth, challenge, code, NULL}, {f.auth, challenge, code, NULL}};
    pthread_t threads[2]; REQUIRE(!pthread_create(&threads[0], NULL, complete_thread, &tasks[0]));
    REQUIRE(!pthread_create(&threads[1], NULL, complete_thread, &tasks[1]));
    pthread_join(threads[0], NULL); pthread_join(threads[1], NULL);
    CHECK_EQ_INT((tasks[0].token != NULL) + (tasks[1].token != NULL), 1);
    free(tasks[0].token); free(tasks[1].token); free(challenge); sbj_free(confirmed); fixture_free(&f);
}

TEST(device_scope_defaults_deny_and_enforces_role_grant_and_group_membership) {
    security_fixture f = fixture(); REQUIRE(f.auth); sb_err err = {0};
    CHECK(sb_auth_device_allowed(f.auth, "a", "h1", true, &err));
    CHECK(!sb_auth_device_allowed(f.auth, "v", "h1", false, &err));
    CHECK(!sb_auth_device_allowed(f.auth, "o", "h1", true, &err));
    sbj *group = sbj_parse_cstr("{\"id\":\"g1\",\"name\":\"one\",\"host_ids\":[\"h1\",\"h2\"]}");
    REQUIRE(!sb_auth_device_group_save(f.auth, group, &err)); sbj_free(group);
    sbj *policy = sbj_parse_cstr("{\"scope\":\"groups\",\"grants\":[{\"group_id\":\"g1\",\"permission\":\"operate\"}]}");
    REQUIRE(!sb_auth_user_scope_set(f.auth, "v", policy, &err));
    REQUIRE(!sb_auth_user_scope_set(f.auth, "o", policy, &err)); sbj_free(policy);
    CHECK(sb_auth_device_allowed(f.auth, "v", "h1", false, &err)); CHECK(!sb_auth_device_allowed(f.auth, "v", "h1", true, &err));
    CHECK(sb_auth_device_allowed(f.auth, "o", "h2", true, &err)); CHECK(!sb_auth_device_allowed(f.auth, "o", "h3", false, &err));
    policy = sbj_parse_cstr("{\"scope\":\"groups\",\"grants\":[{\"group_id\":\"g1\",\"permission\":\"view\"}]}");
    REQUIRE(!sb_auth_user_scope_set(f.auth, "o", policy, &err)); sbj_free(policy);
    CHECK(sb_auth_device_allowed(f.auth, "o", "h1", false, &err)); CHECK(!sb_auth_device_allowed(f.auth, "o", "h1", true, &err));
    group = sbj_parse_cstr("{\"id\":\"g1\",\"name\":\"bad edit\",\"host_ids\":[\"unknown\"]}");
    CHECK_EQ_INT(sb_auth_device_group_save(f.auth, group, &err), -1); sbj_free(group);
    CHECK(sb_auth_device_allowed(f.auth, "o", "h1", false, &err));
    sbj *groups = sb_auth_device_groups(f.auth, &err); REQUIRE(groups); CHECK_EQ_INT(sbj_arr_len(groups), 1);
    CHECK_STR(sbj_get_str(sbj_arr_at(groups, 0), "name", ""), "one"); CHECK_EQ_INT(sbj_arr_len(sbj_get(sbj_arr_at(groups, 0), "host_ids")), 2); sbj_free(groups);
    policy = sbj_parse_cstr("{\"scope\":\"groups\",\"grants\":[{\"group_id\":\"missing\",\"permission\":\"view\"}]}");
    CHECK_EQ_INT(sb_auth_user_scope_set(f.auth, "o", policy, &err), -1); sbj_free(policy);
    CHECK(sb_auth_device_allowed(f.auth, "o", "h1", false, &err));
    CHECK_EQ_INT(sb_auth_device_group_remove(f.auth, "g1", &err), 0);
    CHECK(!sb_auth_device_allowed(f.auth, "o", "h1", false, &err));
    policy = sbj_parse_cstr("{\"scope\":\"all\",\"grants\":[]}");
    REQUIRE(!sb_auth_user_scope_set(f.auth, "o", policy, &err)); sbj_free(policy);
    CHECK(sb_auth_device_allowed(f.auth, "o", "h3", true, &err));
    CHECK(!sb_auth_device_allowed(f.auth, "o", "unknown", false, &err));
    CHECK(!sb_auth_device_allowed(f.auth, "unknown", "h1", false, &err)); fixture_free(&f);
}

TEST(device_policy_rejects_ambiguous_strings_and_duplicate_grants) {
    security_fixture f = fixture(); REQUIRE(f.auth);
    sbj *group = sbj_parse_cstr("{\"id\":\"g1\",\"name\":\"one\\u0000two\",\"host_ids\":[]}");
    CHECK_EQ_INT(sb_auth_device_group_save(f.auth, group, NULL), -1); sbj_free(group);
    group = sbj_parse_cstr("{\"id\":\"g1\",\"name\":\"one\",\"host_ids\":[\"h1\",\"h1\"]}");
    CHECK_EQ_INT(sb_auth_device_group_save(f.auth, group, NULL), -1); sbj_free(group);
    sbj *policy = sbj_parse_cstr("{\"scope\":\"all\\u0000\",\"grants\":[]}");
    CHECK_EQ_INT(sb_auth_user_scope_set(f.auth, "v", policy, NULL), -1); sbj_free(policy);
    policy = sbj_parse_cstr("{\"scope\":\"groups\",\"grants\":[{\"group_id\":\"g1\",\"permission\":\"view\"},{\"group_id\":\"g1\",\"permission\":\"operate\"}]}");
    CHECK_EQ_INT(sb_auth_user_scope_set(f.auth, "v", policy, NULL), -1); sbj_free(policy); fixture_free(&f);
}
