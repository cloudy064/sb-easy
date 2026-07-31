#include "sbeasy/clash_client.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
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

using nlohmann::json;

struct HttpAddress {
    std::string origin;
    std::string path_prefix;
};

[[nodiscard]] HttpAddress parse_base_url(std::string url) {
    while (url.ends_with('/')) {
        url.pop_back();
    }
    const auto separator = url.find("://");
    if (separator == std::string::npos ||
        (url.substr(0, separator) != "http" && url.substr(0, separator) != "https")) {
        throw ClashRequestError("Clash API URL must include http:// or https://");
    }
    if (url.find_first_of("?#", separator + 3U) != std::string::npos) {
        throw ClashRequestError(
            "Clash API base URL must not contain a query or fragment");
    }
    const auto path = url.find('/', separator + 3U);
    HttpAddress address;
    if (path == std::string::npos) {
        address.origin = std::move(url);
    } else {
        address.origin = url.substr(0, path);
        address.path_prefix = url.substr(path);
    }
    if (address.origin.empty() || address.origin.ends_with("://")) {
        throw ClashRequestError("Clash API URL has an empty authority");
    }
    return address;
}

[[nodiscard]] double timeout_seconds(std::chrono::milliseconds timeout) {
    return std::chrono::duration<double>{timeout}.count();
}

[[nodiscard]] std::string request_failure(drogon::ReqResult result) {
    return "Clash API request failed: " + std::string{drogon::to_string_view(result)};
}

} // namespace

class ClashClient::Impl final {
  public:
    explicit Impl(ClashClientOptions options)
        : options_(options), event_loop_("sb-easy-clash-http") {
        if (options_.timeout <= std::chrono::milliseconds::zero() ||
            options_.maximum_body_bytes == 0U) {
            throw std::invalid_argument(
                "Clash timeout and response limit must be positive");
        }
        event_loop_.run();
    }

    [[nodiscard]] ClashResponse request(drogon::HttpMethod method,
                                        const ClashTarget& target,
                                        const std::string& path,
                                        const std::optional<json>& body) {
        const auto address = parse_base_url(target.base_url);
        auto client = drogon::HttpClient::newHttpClient(
            address.origin, event_loop_.getLoop(), false, true);
        client->setUserAgent("sb-easy-cpp/0.1.0");

        auto request = drogon::HttpRequest::newHttpRequest();
        request->setMethod(method);
        request->setPath(address.path_prefix + path);
        request->setPathEncode(false);
        request->addHeader("Accept", "application/json");
        if (!target.secret.empty()) {
            request->addHeader("Authorization", "Bearer " + target.secret);
        }
        if (body.has_value()) {
            request->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            request->setBody(body->dump());
        }

        const auto [result, response] =
            client->sendRequest(request, timeout_seconds(options_.timeout));
        if (result != drogon::ReqResult::Ok || !response) {
            throw ClashRequestError(request_failure(result));
        }
        if (response->body().size() > options_.maximum_body_bytes) {
            throw ClashRequestError(
                "Clash API response exceeds the configured size limit");
        }
        const std::string response_body{response->body()};
        auto parsed = response_body.empty()
                          ? json::object()
                          : json::parse(response_body, nullptr, false);
        if (parsed.is_discarded()) {
            parsed = json::object();
        }
        return {
            .status = static_cast<int>(response->statusCode()),
            .body = std::move(parsed),
        };
    }

  private:
    ClashClientOptions options_;
    trantor::EventLoopThread event_loop_;
};

ClashClient::ClashClient(ClashClientOptions options)
    : implementation_(std::make_unique<Impl>(options)) {}

ClashClient::~ClashClient() = default;
ClashClient::ClashClient(ClashClient&&) noexcept = default;
ClashClient& ClashClient::operator=(ClashClient&&) noexcept = default;

ClashResponse ClashClient::get(const ClashTarget& target, const std::string& path) {
    return implementation_->request(drogon::Get, target, path, std::nullopt);
}

ClashResponse ClashClient::remove(const ClashTarget& target, const std::string& path) {
    return implementation_->request(drogon::Delete, target, path, std::nullopt);
}

ClashResponse ClashClient::put(const ClashTarget& target, const std::string& path,
                               const nlohmann::json& body) {
    return implementation_->request(drogon::Put, target, path, body);
}

} // namespace sbeasy
