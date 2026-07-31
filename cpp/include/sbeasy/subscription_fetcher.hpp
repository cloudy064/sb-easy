#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace sbeasy {

struct SubscriptionFetcherOptions {
    std::chrono::milliseconds timeout{std::chrono::seconds{30}};
    std::size_t maximum_body_bytes{8U * 1024U * 1024U};
    std::size_t maximum_redirects{5};
};

/// Blocking facade over a private Drogon event loop. This keeps upstream
/// subscription I/O off the server's own event loop and preserves TLS
/// certificate verification.
class SubscriptionFetcher final {
  public:
    explicit SubscriptionFetcher(SubscriptionFetcherOptions options = {});
    ~SubscriptionFetcher();

    SubscriptionFetcher(const SubscriptionFetcher&) = delete;
    SubscriptionFetcher& operator=(const SubscriptionFetcher&) = delete;
    SubscriptionFetcher(SubscriptionFetcher&&) noexcept;
    SubscriptionFetcher& operator=(SubscriptionFetcher&&) noexcept;

    [[nodiscard]] std::string fetch(const std::string& url);

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy
