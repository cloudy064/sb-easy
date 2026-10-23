#include "test.h"
#include "http_test_support.h"
#include "sb/preferences_sync.h"

static sbj *envelope_fixture(void) {
    size_t len = 0; char *text = sb_read_file("testdata/preferences-v1.json", &len);
    if (!text) abort(); sbj *vector = sbj_parse(text, len, NULL, 0); free(text);
    if (!vector) abort(); sbj *envelope = sbj_clone(sbj_get(vector, "envelope")); sbj_free(vector); return envelope;
}
static sb_auth_claims admin_claims(sb_test_server *t) {
    sb_auth_claims claims = {0}; if (!sb_auth_verify_token(t->jwt_secret, t->token, &claims)) abort(); return claims;
}
TEST(envelope_validation) {
    sbj *envelope = envelope_fixture(); sb_err err = {0};
    CHECK_EQ_INT(sb_preferences_validate_envelope(envelope, &err), 0);
    sbj *bad = sbj_clone(envelope); sbj_set_str(bad, "plaintext", "not allowed");
    CHECK_EQ_INT(sb_preferences_validate_envelope(bad, &err), -1); sbj_free(bad);
    bad = sbj_clone(envelope); sbj_set_int(bad, "iterations", 599999);
    CHECK_EQ_INT(sb_preferences_validate_envelope(bad, &err), -1); sbj_free(bad);
    bad = sbj_clone(envelope); sbj_set_str(bad, "salt", "AAAAAAAAAAAAAAAAAAAAAB==");
    CHECK_EQ_INT(sb_preferences_validate_envelope(bad, &err), -1); sbj_free(bad);
    bad = sbj_clone(envelope); sbj_set_str(bad, "format", "sb-easy.backup");
    CHECK_EQ_INT(sb_preferences_validate_envelope(bad, &err), -1); sbj_free(bad);
    sbj_free(envelope);
}
typedef struct { sb_database *db; const char *user; const sbj *envelope; pthread_barrier_t *barrier; int64_t revision; sb_err error; } concurrent_put;
static void *put_thread(void *arg) {
    concurrent_put *p = arg; pthread_barrier_wait(p->barrier);
    sbj *result = sb_preferences_put(p->db, p->user, "personal", 1, p->envelope, &p->error);
    p->revision = result ? sbj_get_int(result, "revision", 0) : 0; sbj_free(result); return NULL;
}
TEST(revisions_concurrency_tombstones_and_limits) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sb_auth_claims claims = admin_claims(&t); sb_database *db = sb_store_database(t.store);
    sbj *envelope = envelope_fixture(); sb_err err = {0};
    CHECK(sb_preferences_get(db, claims.subject, "personal", &err) == NULL); CHECK_EQ_INT(err.code, SB_ERR_NOT_FOUND);
    sbj *result = sb_preferences_put(db, claims.subject, "personal", 0, envelope, &err);
    REQUIRE(result); CHECK_EQ_INT(sbj_get_int(result, "revision", 0), 1); sbj_free(result);
    CHECK(sb_preferences_put(db, claims.subject, "personal", 0, envelope, &err) == NULL); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    pthread_barrier_t barrier; pthread_barrier_init(&barrier, NULL, 2);
    concurrent_put left = {db, claims.subject, envelope, &barrier, 0, {0}}, right = left;
    pthread_t a, b; REQUIRE(pthread_create(&a, NULL, put_thread, &left) == 0); REQUIRE(pthread_create(&b, NULL, put_thread, &right) == 0);
    pthread_join(a, NULL); pthread_join(b, NULL); pthread_barrier_destroy(&barrier);
    CHECK((left.revision == 2) != (right.revision == 2));
    CHECK_EQ_INT(left.revision ? right.error.code : left.error.code, SB_ERR_CONFLICT);
    CHECK_EQ_INT(sb_preferences_delete(db, claims.subject, "personal", 1, &err), -1);
    CHECK_EQ_INT(sb_preferences_delete(db, claims.subject, "personal", 2, &err), 0);
    result = sb_preferences_get(db, claims.subject, "personal", &err); REQUIRE(result);
    CHECK_EQ_INT(sbj_get_int(result, "revision", 0), 3); CHECK(sbj_is_null(sbj_get(result, "envelope"))); CHECK(sbj_get_bool(result, "deleted", false)); sbj_free(result);
    CHECK(sb_preferences_put(db, claims.subject, "personal", 0, envelope, &err) == NULL);
    CHECK(sb_preferences_put(db, claims.subject, "personal", 2, envelope, &err) == NULL);
    result = sb_preferences_put(db, claims.subject, "personal", 3, envelope, &err); REQUIRE(result); CHECK_EQ_INT(sbj_get_int(result, "revision", 0), 4); sbj_free(result);
    for (int i = 1; i < 16; ++i) {
        char name[20]; snprintf(name, sizeof name, "slot-%d", i);
        result = sb_preferences_put(db, claims.subject, name, 0, envelope, &err); REQUIRE(result); sbj_free(result);
    }
    CHECK(sb_preferences_put(db, claims.subject, "seventeenth", 0, envelope, &err) == NULL); CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    CHECK(sb_preferences_put(db, claims.subject, "../another-user", 0, envelope, &err) == NULL); CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
    sbj_free(envelope); sb_auth_claims_free(&claims); sb_test_server_stop(&t);
}
TEST(http_account_isolation_and_compare_and_swap) {
    sb_test_server t; REQUIRE(sb_test_server_start(&t) == 0);
    sbj *envelope = envelope_fixture(); char *body = sbj_dump(envelope, -1); sb_test_response r = {0};
    const char *create[] = {"If-Match: \"0\"", NULL}, *update[] = {"If-Match: 1", NULL};
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, "", create, &r); CHECK_EQ_INT(r.status, 401); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, NULL, NULL, &r); CHECK_EQ_INT(r.status, 400); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, NULL, create, &r); CHECK_EQ_INT(r.status, 200); CHECK_STR(r.etag, "\"1\""); CHECK_STR(r.cache_control, "no-store"); sb_test_response_free(&r);
    char *viewer = sb_test_token(&t, "ignored", "private-viewer", "viewer"); REQUIRE(viewer);
    sb_test_request_ex(&t, "GET", "/api/auth/preferences/personal", NULL, viewer, NULL, &r); CHECK_EQ_INT(r.status, 404); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, viewer, create, &r); CHECK_EQ_INT(r.status, 200); sb_test_response_free(&r);
    sb_test_request_ex(&t, "DELETE", "/api/auth/preferences/personal", NULL, viewer, update, &r); CHECK_EQ_INT(r.status, 200); CHECK(sbj_get_bool(r.json, "deleted", false)); CHECK_EQ_INT(sbj_get_int(r.json, "revision", 0), 2); sb_test_response_free(&r);
    sb_test_request_ex(&t, "GET", "/api/auth/preferences/personal", NULL, NULL, NULL, &r); CHECK_EQ_INT(r.status, 200); CHECK_EQ_INT(sbj_get_int(r.json, "revision", 0), 1); CHECK(sbj_is_object(sbj_get(r.json, "envelope"))); sb_test_response_free(&r);
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, NULL, create, &r); CHECK_EQ_INT(r.status, 409); sb_test_response_free(&r);
    const char *malformed[] = {"If-Match: 1junk", NULL};
    sb_test_request_ex(&t, "PUT", "/api/auth/preferences/personal", body, NULL, malformed, &r); CHECK_EQ_INT(r.status, 400); sb_test_response_free(&r);
    free(viewer); free(body); sbj_free(envelope); sb_test_server_stop(&t);
}
