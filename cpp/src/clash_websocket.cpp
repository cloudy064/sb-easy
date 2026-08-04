#include "sbeasy/clash_websocket.hpp"

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
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
#include <drogon/WebSocketClient.h>
#include <drogon/WebSocketController.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include <nlohmann/json.hpp>

#include "sbeasy/store.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;

constexpr std::string_view websocket_prefix{"/api/sing-box/ws/"};

struct ClashTarget {
    std::string base_url;
    std::string secret;
};

struct UpstreamWebSocketTarget {
    std::string origin;
    std::string path;
    std::string secret;
};

struct WebSocketBridge {
    drogon::WebSocketClientPtr upstream;
};

[[nodiscard]] std::string trim(std::string value) {
    const auto first = std::ranges::find_if_not(value, [](unsigned char character) {
        return std::isspace(character) != 0;
    });
    const auto last = std::ranges::find_if_not(
                          std::ranges::reverse_view(value),
                          [](unsigned char character) {
                              return std::isspace(character) != 0;
                          })
                          .base();
    if (first >= last) {
        return {};
    }
    return {first, last};
}

[[nodiscard]] std::string trim_trailing_slashes(std::string value) {
    value = trim(std::move(value));
    while (value.ends_with('/')) {
        value.pop_back();
    }
    return value;
}

[[nodiscard]] std::optional<std::string>
stream_kind(std::string_view path) {
    if (!path.starts_with(websocket_prefix)) {
        return std::nullopt;
    }
    const auto kind = path.substr(websocket_prefix.size());
    if (kind == "traffic" || kind == "logs" || kind == "connections" ||
        kind == "memory") {
        return std::string{kind};
    }
    return std::nullopt;
}

[[nodiscard]] ClashTarget resolve_target(Store& store,
                                         std::string host_id,
                                         const std::string& local_url,
                                         const std::string& local_secret) {
    host_id = trim(std::move(host_id));
    if (!host_id.empty() && host_id != "self") {
        if (const auto host = store.find_host(host_id);
            host.has_value() && host->clash_api.has_value()) {
            auto url = trim_trailing_slashes(*host->clash_api);
            if (!url.empty()) {
                return {
                    .base_url = std::move(url),
                    .secret = host->clash_secret,
                };
            }
        }
    }
    return {
        .base_url = trim_trailing_slashes(local_url),
        .secret = local_secret,
    };
}

[[nodiscard]] UpstreamWebSocketTarget
upstream_target(const ClashTarget& target, std::string_view kind) {
    auto url = target.base_url;
    if (url.starts_with("http://")) {
        url.replace(0, 7, "ws://");
    } else if (url.starts_with("https://")) {
        url.replace(0, 8, "wss://");
    } else if (!url.starts_with("ws://") && !url.starts_with("wss://")) {
        throw std::invalid_argument(
            "Clash API URL must use http, https, ws, or wss");
    }

    const auto scheme_end = url.find("://");
    const auto path_start = url.find('/', scheme_end + 3);
    auto origin = path_start == std::string::npos ? url : url.substr(0, path_start);
    auto path = path_start == std::string::npos ? std::string{} :
                                                   url.substr(path_start);
    path = trim_trailing_slashes(std::move(path));
    path += '/';
    path += kind;
    return {
        .origin = std::move(origin),
        .path = std::move(path),
        .secret = target.secret,
    };
}

void close_with_error(const drogon::WebSocketConnectionPtr& connection,
                      std::string message) {
    if (!connection || connection->disconnected()) {
        return;
    }
    connection->send(json{{"error", std::move(message)}}.dump());
    connection->shutdown(drogon::CloseCode::kUnexpectedCondition,
                         "upstream unavailable");
}

class ClashWebSocketController final
    : public drogon::WebSocketController<ClashWebSocketController, false> {
  public:
    ClashWebSocketController(std::shared_ptr<Store> store,
                             std::string local_url,
                             std::string local_secret)
        : store_(std::move(store)),
          local_url_(std::move(local_url)),
          local_secret_(std::move(local_secret)) {}

    void handleNewConnection(
        const drogon::HttpRequestPtr& request,
        const drogon::WebSocketConnectionPtr& browser) override {
        const auto kind = stream_kind(request->path());
        if (!kind.has_value()) {
            browser->shutdown(drogon::CloseCode::kViolation,
                              "unsupported stream");
            return;
        }

        UpstreamWebSocketTarget target;
        try {
            const auto resolved =
                resolve_target(*store_, request->getParameter("host"),
                               local_url_, local_secret_);
            if (resolved.base_url.empty()) {
                throw std::invalid_argument(
                    "No sing-box Clash API URL is configured");
            }
            target = upstream_target(resolved, *kind);
        } catch (const std::exception& error) {
            close_with_error(browser, error.what());
            return;
        }

        auto upstream = drogon::WebSocketClient::newWebSocketClient(
            target.origin, nullptr, false, true);
        auto bridge = std::make_shared<WebSocketBridge>();
        bridge->upstream = upstream;
        browser->setContext(bridge);
        const std::weak_ptr<drogon::WebSocketConnection> weak_browser{browser};

        upstream->setMessageHandler(
            [weak_browser](std::string&& message,
                           const drogon::WebSocketClientPtr&,
                           const drogon::WebSocketMessageType& type) {
                if (const auto connection = weak_browser.lock();
                    connection && connection->connected()) {
                    connection->send(message, type);
                }
            });
        upstream->setConnectionClosedHandler(
            [weak_browser](const drogon::WebSocketClientPtr&) {
                if (const auto connection = weak_browser.lock();
                    connection && connection->connected()) {
                    connection->shutdown(drogon::CloseCode::kEndpointGone,
                                         "upstream closed");
                }
            });

        auto upstream_request = drogon::HttpRequest::newHttpRequest();
        upstream_request->setPath(std::move(target.path));
        if (!target.secret.empty()) {
            upstream_request->setParameter("token", std::move(target.secret));
        }
        if (*kind == "logs") {
            const auto level = trim(request->getParameter("level"));
            if (!level.empty()) {
                upstream_request->setParameter("level", level);
            }
        }
        upstream->connectToServer(
            upstream_request,
            [weak_browser](drogon::ReqResult result,
                           const drogon::HttpResponsePtr&,
                           const drogon::WebSocketClientPtr& client) {
                if (result == drogon::ReqResult::Ok) {
                    return;
                }
                close_with_error(
                    weak_browser.lock(),
                    "Could not connect to sing-box Clash WebSocket: " +
                        std::string{drogon::to_string_view(result)});
                client->stop();
            });
    }

    void handleNewMessage(
        const drogon::WebSocketConnectionPtr&,
        std::string&&,
        const drogon::WebSocketMessageType&) override {
        // Clash telemetry streams are downstream-only. Drogon handles ping/pong.
    }

    void handleConnectionClosed(
        const drogon::WebSocketConnectionPtr& browser) override {
        if (browser->hasContext()) {
            const auto bridge = browser->getContext<WebSocketBridge>();
            if (bridge && bridge->upstream) {
                bridge->upstream->stop();
            }
            browser->clearContext();
        }
    }

    WS_PATH_LIST_BEGIN
    WS_ADD_PATH_VIA_REGEX(
        "/api/sing-box/ws/(traffic|logs|connections|memory)", drogon::Get);
    WS_PATH_LIST_END

  private:
    std::shared_ptr<Store> store_;
    std::string local_url_;
    std::string local_secret_;
};

} // namespace

void register_clash_websocket_routes(const std::shared_ptr<Store>& store,
                                     const std::string& local_clash_api,
                                     const std::string& local_clash_secret) {
    if (!store) {
        throw std::invalid_argument("WebSocket store is required");
    }
    drogon::app().registerController(std::make_shared<ClashWebSocketController>(
        store, local_clash_api, local_clash_secret));
}

} // namespace sbeasy
