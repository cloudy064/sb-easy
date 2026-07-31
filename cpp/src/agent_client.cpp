#include "sbeasy/agent_client.hpp"
#include "sbeasy/version.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

struct ServerAddress {
    std::string origin;
    std::string path_prefix;
};

[[nodiscard]] ServerAddress parse_server(std::string server) {
    while (server.ends_with('/')) {
        server.pop_back();
    }
    if (!server.starts_with("http://") && !server.starts_with("https://")) {
        throw std::invalid_argument("agent server must include http:// or https://");
    }
    if (server.find_first_of("?#") != std::string::npos) {
        throw std::invalid_argument(
            "agent server must not contain a query or fragment");
    }
    const auto scheme = server.find("://");
    const auto path = server.find('/', scheme + 3U);
    ServerAddress address;
    if (path == std::string::npos) {
        address.origin = std::move(server);
    } else {
        address.origin = server.substr(0, path);
        address.path_prefix = server.substr(path);
    }
    if (address.origin.empty() || address.origin.ends_with("://")) {
        throw std::invalid_argument("invalid agent server URL");
    }
    return address;
}

[[nodiscard]] double timeout_seconds(std::chrono::milliseconds timeout) {
    return std::chrono::duration<double>{timeout}.count();
}

[[nodiscard]] std::string request_failure(drogon::ReqResult result) {
    return "agent HTTP request failed: " + std::string{drogon::to_string_view(result)};
}

[[nodiscard]] json parse_response_json(const drogon::HttpResponsePtr& response) {
    auto body = json::parse(response->body(), nullptr, false);
    if (body.is_discarded()) {
        throw std::runtime_error("agent endpoint returned invalid JSON");
    }
    return body;
}

} // namespace

class AgentClient::Impl final {
  public:
    explicit Impl(AgentClientOptions options)
        : options_(std::move(options)), address_(parse_server(options_.server)),
          event_loop_("sb-easy-agent-http") {
        if (options_.token.empty()) {
            throw std::invalid_argument("agent token is required");
        }
        if (options_.timeout <= std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("agent HTTP timeout must be positive");
        }
        event_loop_.run();
        client_ =
            drogon::HttpClient::newHttpClient(address_.origin, event_loop_.getLoop());
        client_->setUserAgent("sb-easy-cpp-agent/" +
                              std::string{application_version});
    }

    [[nodiscard]] drogon::HttpResponsePtr
    send(drogon::HttpMethod method, const std::string& path,
         const std::optional<json>& body = std::nullopt,
         const std::optional<std::string>& etag = std::nullopt) {
        auto request = drogon::HttpRequest::newHttpRequest();
        request->setMethod(method);
        request->setPath(address_.path_prefix + path);
        request->addHeader("Authorization", "Bearer " + options_.token);
        if (etag.has_value()) {
            request->addHeader("If-None-Match", *etag);
        }
        if (body.has_value()) {
            request->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            request->setBody(body->dump());
        }

        auto [result, response] =
            client_->sendRequest(request, timeout_seconds(options_.timeout));
        if (result != drogon::ReqResult::Ok || !response) {
            throw std::runtime_error(request_failure(result));
        }
        return response;
    }

    [[nodiscard]] static json
    require_success_json(const drogon::HttpResponsePtr& response) {
        const auto status = static_cast<int>(response->statusCode());
        if (status < 200 || status >= 300) {
            throw std::runtime_error("agent endpoint returned HTTP " +
                                     std::to_string(status));
        }
        return parse_response_json(response);
    }

    AgentClientOptions options_;
    ServerAddress address_;
    trantor::EventLoopThread event_loop_;
    drogon::HttpClientPtr client_;
};

AgentClient::AgentClient(AgentClientOptions options)
    : implementation_(std::make_unique<Impl>(std::move(options))) {}

AgentClient::~AgentClient() = default;
AgentClient::AgentClient(AgentClient&&) noexcept = default;
AgentClient& AgentClient::operator=(AgentClient&&) noexcept = default;

AgentConfigResponse AgentClient::poll_config(const std::optional<std::string>& etag) {
    const auto response =
        implementation_->send(drogon::Get, "/api/agent/config", std::nullopt, etag);
    const auto response_etag = response->getHeader("etag");
    if (response->statusCode() == drogon::k304NotModified) {
        return {
            .modified = false,
            .etag = response_etag.empty() ? etag.value_or("") : response_etag,
            .body = {},
        };
    }
    if (response->statusCode() != drogon::k200OK) {
        throw std::runtime_error(
            "agent config endpoint returned HTTP " +
            std::to_string(static_cast<int>(response->statusCode())));
    }
    if (response_etag.empty()) {
        throw std::runtime_error("agent config response is missing ETag");
    }
    const std::string body{response->body()};
    const auto parsed = json::parse(body, nullptr, false);
    if (!parsed.is_object()) {
        throw std::runtime_error("agent config response must be a JSON object");
    }
    return {
        .modified = true,
        .etag = response_etag,
        .body = body,
    };
}

std::vector<AgentCommand> AgentClient::pending_commands() {
    const auto body = Impl::require_success_json(
        implementation_->send(drogon::Get, "/api/agent/commands"));
    if (!body.is_array()) {
        throw std::runtime_error("agent commands response must be an array");
    }
    std::vector<AgentCommand> commands;
    commands.reserve(body.size());
    for (const auto& value : body) {
        if (!value.is_object() || !value.contains("id") || !value["id"].is_string() ||
            !value.contains("command") || !value["command"].is_string()) {
            throw std::runtime_error("agent command has an invalid shape");
        }
        commands.push_back({
            .id = value["id"].get<std::string>(),
            .command = value["command"].get<std::string>(),
        });
    }
    return commands;
}

void AgentClient::acknowledge_command(const std::string& id, bool success,
                                      const std::optional<std::string>& result) {
    static_cast<void>(Impl::require_success_json(implementation_->send(
        drogon::Post, "/api/agent/commands/" + id + "/ack",
        json{{"status", success ? "done" : "failed"}, {"result", result}})));
}

void AgentClient::report_status(const std::string& version,
                                const std::optional<bool>& running,
                                const std::optional<std::string>& etag) {
    static_cast<void>(Impl::require_success_json(
        implementation_->send(drogon::Post, "/api/agent/status",
                              json{{"singbox_version", version},
                                   {"singbox_running", running},
                                   {"config_etag", etag}})));
}

void AgentClient::report_telemetry(const nlohmann::json& telemetry) {
    if (!telemetry.is_object()) {
        throw std::invalid_argument("agent telemetry must be a JSON object");
    }
    static_cast<void>(Impl::require_success_json(
        implementation_->send(drogon::Post, "/api/agent/telemetry", telemetry)));
}

std::size_t AgentClient::report_proxy_latencies(const nlohmann::json& results) {
    if (!results.is_object()) {
        throw std::invalid_argument(
            "agent proxy latency results must be a JSON object");
    }
    const auto response = Impl::require_success_json(implementation_->send(
        drogon::Post, "/api/agent/proxy-latency", json{{"results", results}}));
    return response.at("updated").get<std::size_t>();
}

} // namespace sbeasy
