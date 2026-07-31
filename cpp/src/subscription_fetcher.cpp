#include "sbeasy/subscription_fetcher.hpp"

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
#include <drogon/drogon.h>
#include <trantor/net/EventLoopThread.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

namespace sbeasy {
namespace {

struct HttpAddress {
    std::string scheme;
    std::string origin;
    std::string target;
};

[[nodiscard]] HttpAddress parse_url(const std::string& url) {
    const auto separator = url.find("://");
    if (separator == std::string::npos) {
        throw std::invalid_argument(
            "subscription URL must include http:// or https://");
    }
    const auto scheme = url.substr(0, separator);
    if (scheme != "http" && scheme != "https") {
        throw std::invalid_argument("subscription URL must use HTTP or HTTPS");
    }
    if (url.find('#', separator + 3U) != std::string::npos) {
        throw std::invalid_argument("subscription URL must not contain a fragment");
    }
    const auto authority_start = separator + 3U;
    const auto path = url.find_first_of("/?", authority_start);
    const auto authority =
        url.substr(authority_start, path == std::string::npos ? std::string::npos
                                                              : path - authority_start);
    if (authority.empty() || authority.find('@') != std::string::npos) {
        throw std::invalid_argument(
            "subscription URL authority is empty or contains credentials");
    }
    auto target = path == std::string::npos ? std::string{"/"} : url.substr(path);
    if (target.starts_with('?')) {
        target.insert(target.begin(), '/');
    }
    return {
        .scheme = scheme,
        .origin = scheme + "://" + authority,
        .target = std::move(target),
    };
}

[[nodiscard]] bool redirect_status(drogon::HttpStatusCode status) {
    const auto value = static_cast<int>(status);
    return value == 301 || value == 302 || value == 303 || value == 307 || value == 308;
}

[[nodiscard]] std::string resolve_redirect(const HttpAddress& current,
                                           const std::string& location) {
    if (location.starts_with("http://") || location.starts_with("https://")) {
        return location;
    }
    if (location.starts_with("//")) {
        return current.scheme + ":" + location;
    }
    if (location.starts_with('/')) {
        return current.origin + location;
    }
    auto base = current.target;
    if (const auto question = base.find('?'); question != std::string::npos) {
        base.erase(question);
    }
    const auto slash = base.rfind('/');
    base = slash == std::string::npos ? "/" : base.substr(0, slash + 1U);
    return current.origin + base + location;
}

[[nodiscard]] double timeout_seconds(std::chrono::milliseconds timeout) {
    return std::chrono::duration<double>{timeout}.count();
}

} // namespace

class SubscriptionFetcher::Impl final {
  public:
    explicit Impl(SubscriptionFetcherOptions options)
        : options_(options), event_loop_("sb-easy-subscription-http") {
        if (options_.timeout <= std::chrono::milliseconds::zero() ||
            options_.maximum_body_bytes == 0U) {
            throw std::invalid_argument(
                "subscription timeout and body limit must be positive");
        }
        event_loop_.run();
    }

    [[nodiscard]] std::string fetch(std::string url) {
        for (std::size_t redirects = 0;; ++redirects) {
            const auto address = parse_url(url);
            auto client = drogon::HttpClient::newHttpClient(address.origin,
                                                            event_loop_.getLoop());
            client->setUserAgent("sb-easy-cpp/0.1.0");
            auto request = drogon::HttpRequest::newHttpRequest();
            request->setMethod(drogon::Get);
            request->setPath(address.target);
            request->addHeader("Accept",
                               "text/plain, application/yaml, application/json");

            const auto [result, response] =
                client->sendRequest(request, timeout_seconds(options_.timeout));
            if (result != drogon::ReqResult::Ok || !response) {
                throw std::runtime_error("subscription HTTP request failed: " +
                                         std::string{drogon::to_string_view(result)});
            }
            if (redirect_status(response->statusCode())) {
                if (redirects >= options_.maximum_redirects) {
                    throw std::runtime_error(
                        "subscription exceeded the redirect limit");
                }
                const auto location = response->getHeader("location");
                if (location.empty()) {
                    throw std::runtime_error(
                        "subscription redirect is missing Location");
                }
                url = resolve_redirect(address, location);
                continue;
            }
            const auto status = static_cast<int>(response->statusCode());
            if (status < 200 || status >= 300) {
                throw std::runtime_error("subscription returned HTTP " +
                                         std::to_string(status));
            }
            if (response->body().size() > options_.maximum_body_bytes) {
                throw std::runtime_error(
                    "subscription response exceeds the configured size limit");
            }
            return std::string{response->body()};
        }
    }

  private:
    SubscriptionFetcherOptions options_;
    trantor::EventLoopThread event_loop_;
};

SubscriptionFetcher::SubscriptionFetcher(SubscriptionFetcherOptions options)
    : implementation_(std::make_unique<Impl>(options)) {}

SubscriptionFetcher::~SubscriptionFetcher() = default;
SubscriptionFetcher::SubscriptionFetcher(SubscriptionFetcher&&) noexcept = default;
SubscriptionFetcher&
SubscriptionFetcher::operator=(SubscriptionFetcher&&) noexcept = default;

std::string SubscriptionFetcher::fetch(const std::string& url) {
    return implementation_->fetch(url);
}

} // namespace sbeasy
