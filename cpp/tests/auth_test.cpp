#include <string>

#include "sbeasy/auth.hpp"
#include "test_support.hpp"

SB_EASY_TEST("Argon2id password hashes round-trip with Rust-compatible defaults") {
    const auto first = sbeasy::hash_password("correct horse battery staple");
    const auto second = sbeasy::hash_password("correct horse battery staple");
    sbeasy::test::require(first != second,
                          "password hashes must use independent random salts");
    sbeasy::test::require(first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
                          "password hash parameters must match argon2 0.5 defaults");
    sbeasy::test::require(
        sbeasy::verify_password("correct horse battery staple", first),
        "the original password must verify");
    sbeasy::test::require(!sbeasy::verify_password("wrong", first),
                          "an incorrect password must not verify");
}

SB_EASY_TEST("HS256 sessions reject wrong secrets and tampering") {
    const sbeasy::AuthService issuer{"jwt-test-secret"};
    const auto token = issuer.create_token("user-1", "alice", "viewer");
    const auto claims = issuer.verify_token(token);
    sbeasy::test::require(claims.has_value() && claims->subject == "user-1" &&
                              claims->username == "alice" && claims->role == "viewer" &&
                              claims->expires_at > claims->issued_at,
                          "issued JWTs must preserve identity and role claims");
    sbeasy::test::require(
        !sbeasy::AuthService{"other-secret"}.verify_token(token).has_value(),
        "JWTs must be bound to the configured signing secret");
    auto tampered = token;
    tampered.back() = tampered.back() == 'a' ? 'b' : 'a';
    sbeasy::test::require(!issuer.verify_token(tampered).has_value(),
                          "modified JWTs must fail signature validation");
}
