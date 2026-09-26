#include <stdlib.h>
#include <string.h>

#include "sb/auth.h"
#include "test.h"

TEST(argon2id_hashes_round_trip_with_rust_compatible_defaults) {
    char *first = sb_hash_password("correct horse battery staple", NULL);
    char *second = sb_hash_password("correct horse battery staple", NULL);
    REQUIRE(first && second);
    CHECK(strcmp(first, second) != 0);
    CHECK(strncmp(first, "$argon2id$v=19$m=19456,t=2,p=1$", 31) == 0);
    CHECK(sb_verify_password("correct horse battery staple", first));
    CHECK(!sb_verify_password("wrong", first));
    CHECK(!sb_verify_password("x", ""));
    free(first);
    free(second);
}

/* Produced by the C++ implementation (sbeasy::hash_password("cpp-password")). */
TEST(argon2id_verifies_cpp_generated_hash) {
    const char *cpp_hash = getenv("SB_TEST_CPP_HASH");
    if (!cpp_hash) cpp_hash = "$argon2id$v=19$m=19456,t=2,p=1$5hLAkmyJPYvvTX1Y5wOuqA$"
                              "0x5YVDTGPMA5rf8TmO+irwY0VpL/rXw6+5LiYHL0g28";
    CHECK(sb_verify_password("cpp-password", cpp_hash));
    CHECK(!sb_verify_password("other", cpp_hash));
}

TEST(hs256_sessions_reject_wrong_secrets_and_tampering) {
    char *token = sb_auth_create_token("jwt-test-secret", "user-1", "alice", "viewer");
    REQUIRE(token);
    sb_auth_claims claims = {0};
    REQUIRE(sb_auth_verify_token("jwt-test-secret", token, &claims));
    CHECK_STR(claims.subject, "user-1");
    CHECK_STR(claims.username, "alice");
    CHECK_STR(claims.role, "viewer");
    CHECK(claims.expires_at > claims.issued_at);
    sb_auth_claims_free(&claims);
    CHECK(!sb_auth_verify_token("other-secret", token, NULL));
    char *tampered = sb_strdup(token);
    size_t n = strlen(tampered);
    tampered[n - 1] = tampered[n - 1] == 'a' ? 'b' : 'a';
    CHECK(!sb_auth_verify_token("jwt-test-secret", tampered, NULL));
    CHECK(!sb_auth_verify_token("", token, NULL));
    CHECK(!sb_auth_create_token("", "u", "n", "r"));
    free(tampered);
    free(token);
}
