#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct ClashClientOptions {
    std::chrono::milliseconds timeout{std::chrono::seconds{10}};
    std::size_t maximum_body_bytes{8U * 1024U * 1024U};
};

struct ClashTarget {
    std::string base_url;
    std::string secret;
};

struct ClashResponse {
    int status{};
    nlohmann::json body;
};

class ClashRequestError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

/// Synchronous facade over a private Drogon event loop used to reach a Clash
/// control API without blocking the panel's own network loop.
class ClashClient final {
  public:
    explicit ClashClient(ClashClientOptions options = {});
    ~ClashClient();

    ClashClient(const ClashClient&) = delete;
    ClashClient& operator=(const ClashClient&) = delete;
    ClashClient(ClashClient&&) noexcept;
    ClashClient& operator=(ClashClient&&) noexcept;

    [[nodiscard]] ClashResponse get(const ClashTarget& target, const std::string& path);
    [[nodiscard]] ClashResponse remove(const ClashTarget& target,
                                       const std::string& path);
    [[nodiscard]] ClashResponse put(const ClashTarget& target, const std::string& path,
                                    const nlohmann::json& body);

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy
