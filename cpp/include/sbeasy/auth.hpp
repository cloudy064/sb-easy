#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace sbeasy {

struct AuthClaims {
    std::string subject;
    std::string username;
    std::string role;
    std::int64_t expires_at{};
    std::int64_t issued_at{};
};

/// Argon2id password hashing compatible with Rust's argon2 0.5 defaults.
[[nodiscard]] std::string hash_password(const std::string& password);
[[nodiscard]] bool verify_password(const std::string& password,
                                   const std::string& encoded_hash);

/// Minimal HS256 JWT issuer/verifier for the panel session contract.
class AuthService final {
  public:
    explicit AuthService(std::string secret);

    [[nodiscard]] std::string create_token(const std::string& user_id,
                                           const std::string& username,
                                           const std::string& role) const;
    [[nodiscard]] std::optional<AuthClaims>
    verify_token(const std::string& token) const;

  private:
    std::string secret_;
};

} // namespace sbeasy
