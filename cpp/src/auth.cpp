#include "sbeasy/auth.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <argon2.h>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace sbeasy {
namespace {

using nlohmann::json;

constexpr std::uint32_t argon_time_cost{2U};
constexpr std::uint32_t argon_memory_cost{19U * 1024U};
constexpr std::uint32_t argon_parallelism{1U};
constexpr std::size_t argon_salt_bytes{16U};
constexpr std::size_t argon_hash_bytes{32U};
constexpr std::int64_t token_lifetime_seconds{72 * 60 * 60};

[[nodiscard]] std::string base64url_encode(const unsigned char* data,
                                           std::size_t size) {
    if (size > static_cast<std::size_t>((std::numeric_limits<int>::max() / 4) * 3)) {
        throw std::invalid_argument("value is too large to base64 encode");
    }
    std::string encoded(4U * ((size + 2U) / 3U), '\0');
    const auto written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()), data, static_cast<int>(size));
    if (written < 0) {
        throw std::runtime_error("base64 encoding failed");
    }
    encoded.resize(static_cast<std::size_t>(written));
    std::ranges::replace(encoded, '+', '-');
    std::ranges::replace(encoded, '/', '_');
    while (encoded.ends_with('=')) {
        encoded.pop_back();
    }
    return encoded;
}

[[nodiscard]] std::optional<std::vector<unsigned char>>
base64url_decode(std::string value) {
    const auto canonical = value;
    std::ranges::replace(value, '-', '+');
    std::ranges::replace(value, '_', '/');
    const auto remainder = value.size() % 4U;
    if (remainder == 1U) {
        return std::nullopt;
    }
    if (remainder != 0U) {
        value.append(4U - remainder, '=');
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    std::vector<unsigned char> decoded((value.size() / 4U) * 3U);
    const auto written = EVP_DecodeBlock(
        decoded.data(), reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (written < 0) {
        return std::nullopt;
    }
    auto actual = static_cast<std::size_t>(written);
    if (value.ends_with("==")) {
        actual -= 2U;
    } else if (value.ends_with('=')) {
        actual -= 1U;
    }
    decoded.resize(actual);
    if (base64url_encode(decoded.data(), decoded.size()) != canonical) {
        return std::nullopt;
    }
    return decoded;
}

[[nodiscard]] std::array<unsigned char, 32U> signature(std::string_view input,
                                                       const std::string& secret) {
    std::array<unsigned char, 32U> digest{};
    unsigned int size{};
    const auto* result =
        HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
             reinterpret_cast<const unsigned char*>(input.data()), input.size(),
             digest.data(), &size);
    if (result == nullptr || size != digest.size()) {
        throw std::runtime_error("JWT signature generation failed");
    }
    return digest;
}

[[nodiscard]] std::int64_t unix_time() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::optional<json> decode_json_segment(std::string_view segment) {
    auto decoded = base64url_decode(std::string{segment});
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    const std::string text{decoded->begin(), decoded->end()};
    auto value = json::parse(text, nullptr, false);
    if (!value.is_object()) {
        return std::nullopt;
    }
    return value;
}

} // namespace

std::string hash_password(const std::string& password) {
    std::array<unsigned char, argon_salt_bytes> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("password salt generation failed");
    }
    const auto encoded_size =
        argon2_encodedlen(argon_time_cost, argon_memory_cost, argon_parallelism,
                          salt.size(), argon_hash_bytes, Argon2_id);
    std::string encoded(encoded_size, '\0');
    const auto result = argon2id_hash_encoded(
        argon_time_cost, argon_memory_cost, argon_parallelism, password.data(),
        password.size(), salt.data(), salt.size(), argon_hash_bytes, encoded.data(),
        encoded.size());
    if (result != ARGON2_OK) {
        throw std::runtime_error("password hashing failed: " +
                                 std::string{argon2_error_message(result)});
    }
    encoded.resize(std::char_traits<char>::length(encoded.c_str()));
    return encoded;
}

bool verify_password(const std::string& password, const std::string& encoded_hash) {
    if (encoded_hash.empty()) {
        return false;
    }
    return argon2id_verify(encoded_hash.c_str(), password.data(), password.size()) ==
           ARGON2_OK;
}

AuthService::AuthService(std::string secret) : secret_(std::move(secret)) {}

std::string AuthService::create_token(const std::string& user_id,
                                      const std::string& username,
                                      const std::string& role) const {
    if (secret_.empty()) {
        throw std::runtime_error("JWT secret is not configured");
    }
    const auto issued_at = unix_time();
    const auto header = json{{"alg", "HS256"}, {"typ", "JWT"}}.dump();
    const auto payload =
        json{
            {"sub", user_id},   {"username", username},
            {"role", role},     {"exp", issued_at + token_lifetime_seconds},
            {"iat", issued_at},
        }
            .dump();
    auto token =
        base64url_encode(reinterpret_cast<const unsigned char*>(header.data()),
                         header.size()) +
        "." +
        base64url_encode(reinterpret_cast<const unsigned char*>(payload.data()),
                         payload.size());
    const auto digest = signature(token, secret_);
    token += "." + base64url_encode(digest.data(), digest.size());
    return token;
}

std::optional<AuthClaims> AuthService::verify_token(const std::string& token) const {
    if (secret_.empty()) {
        return std::nullopt;
    }
    const auto first = token.find('.');
    const auto second =
        first == std::string::npos ? std::string::npos : token.find('.', first + 1U);
    if (first == std::string::npos || second == std::string::npos ||
        token.find('.', second + 1U) != std::string::npos) {
        return std::nullopt;
    }

    const auto header = decode_json_segment(std::string_view{token}.substr(0U, first));
    const auto payload = decode_json_segment(
        std::string_view{token}.substr(first + 1U, second - first - 1U));
    const auto supplied = base64url_decode(token.substr(second + 1U));
    if (!header.has_value() || !payload.has_value() || !supplied.has_value() ||
        header->value("alg", "") != "HS256" || supplied->size() != 32U) {
        return std::nullopt;
    }
    const auto expected =
        signature(std::string_view{token}.substr(0U, second), secret_);
    if (CRYPTO_memcmp(expected.data(), supplied->data(), expected.size()) != 0) {
        return std::nullopt;
    }

    const auto subject = payload->find("sub");
    const auto username = payload->find("username");
    const auto role = payload->find("role");
    const auto expires = payload->find("exp");
    const auto issued = payload->find("iat");
    if (subject == payload->end() || !subject->is_string() ||
        username == payload->end() || !username->is_string() ||
        role == payload->end() || !role->is_string() || expires == payload->end() ||
        !expires->is_number_integer() || issued == payload->end() ||
        !issued->is_number_integer()) {
        return std::nullopt;
    }
    const auto expires_at = expires->get<std::int64_t>();
    if (expires_at <= unix_time()) {
        return std::nullopt;
    }
    return AuthClaims{
        .subject = subject->get<std::string>(),
        .username = username->get<std::string>(),
        .role = role->get<std::string>(),
        .expires_at = expires_at,
        .issued_at = issued->get<std::int64_t>(),
    };
}

} // namespace sbeasy
