#include <cstdint>
#include <iostream>
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
#include <drogon/utils/Utilities.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <nlohmann/json.hpp>

#include "sbeasy/agent_config.hpp"
#include "sbeasy/agent_ui.hpp"

namespace {

using json = nlohmann::json;

struct Response {
    drogon::HttpStatusCode status;
    std::string body;
    std::string content_type;
    std::string authenticate;
    std::string frame_options;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] Response request(const drogon::HttpClientPtr& client,
                               drogon::HttpMethod method, std::string path,
                               std::string authorization = {}, std::string body = {}) {
    auto value = drogon::HttpRequest::newHttpRequest();
    value->setMethod(method);
    value->setPath(std::move(path));
    if (!authorization.empty()) {
        value->addHeader("Authorization", std::move(authorization));
    }
    if (!body.empty()) {
        value->setContentTypeString("application/json");
        value->setBody(std::move(body));
    }
    if (method == drogon::Post || method == drogon::Put) {
        value->addHeader("X-SB-Easy-UI", "1");
    }
    auto [result, response] = client->sendRequest(value, 2.0);
    if (result != drogon::ReqResult::Ok || !response) {
        throw std::runtime_error("Agent UI HTTP request failed");
    }
    return {
        .status = response->statusCode(),
        .body = std::string{response->body()},
        .content_type = response->getHeader("content-type"),
        .authenticate = response->getHeader("www-authenticate"),
        .frame_options = response->getHeader("x-frame-options"),
    };
}

void run_contract() {
    auto settings = sbeasy::agent_config_transform_options_to_json({});
    std::string requested_action;
    const json config{
        {"outbounds", json::array({
                          {{"tag", "Proxy"},
                           {"type", "selector"},
                           {"outbounds", json::array({"node-a"})},
                           {"default", "node-a"}},
                          {{"tag", "node-a"}, {"type", "shadowsocks"}},
                      })},
        {"route", {{"final", "Proxy"}}},
    };
    sbeasy::AgentUiCallbacks callbacks{
        .status =
            [] {
                return json{
                    {"running", true},
                    {"server", "https://panel.example"},
                };
            },
        .settings = [&settings] { return settings; },
        .update_settings =
            [&settings](const json& value) {
                const auto parsed =
                    sbeasy::agent_config_transform_options_from_json(value);
                settings = sbeasy::agent_config_transform_options_to_json(parsed);
                return settings;
            },
        .config = [&config] { return config; },
        .proxies =
            [] {
                return json::array(
                    {{{"tag", "node-a"}, {"type", "shadowsocks"}, {"default", true}}});
            },
        .request_action = [&requested_action](
                              const std::string& action) { requested_action = action; },
    };
    sbeasy::AgentLocalUi ui(
        {
            .address = "127.0.0.1",
            .port = 0,
            .username = "local-admin",
            .password = "contract-password",
        },
        std::move(callbacks));
    require(ui.port() != 0, "Agent UI should expose its bound ephemeral port");
    const auto client = drogon::HttpClient::newHttpClient("http://127.0.0.1:" +
                                                          std::to_string(ui.port()));
    const auto authorization =
        "Basic " + drogon::utils::base64Encode("local-admin:contract-password");

    const auto health = request(client, drogon::Get, "/health");
    require(health.status == drogon::k200OK &&
                json::parse(health.body).at("service") == "sb-easy-agent-ui",
            "Agent UI health endpoint should remain available without credentials");

    const auto unauthorized = request(client, drogon::Get, "/");
    require(unauthorized.status == drogon::k401Unauthorized &&
                unauthorized.authenticate.find("Basic") != std::string::npos,
            "Agent UI should require Basic authentication");

    const auto root = request(client, drogon::Get, "/", authorization);
    require(root.status == drogon::k200OK &&
                root.content_type.find("text/html") != std::string::npos &&
                root.body.find("sb-easy Agent") != std::string::npos &&
                root.frame_options == "DENY",
            "authenticated users should receive the secured Agent UI");

    const auto status = request(client, drogon::Get, "/api/status", authorization);
    require(status.status == drogon::k200OK &&
                json::parse(status.body).at("running") == true,
            "Agent UI should expose runtime status");

    const auto updated = request(client, drogon::Put, "/api/settings", authorization,
                                 json{{"local_proxy_egress", false},
                                      {"default_proxy_outbound", "node-a"},
                                      {"outbound_server_overrides", json::object()},
                                      {"outbound_overrides", json::object()}}
                                     .dump());
    require(updated.status == drogon::k200OK &&
                json::parse(updated.body).at("local_proxy_egress") == false &&
                settings.at("default_proxy_outbound") == "node-a",
            "Agent UI should validate and update local settings");

    const auto invalid =
        request(client, drogon::Put, "/api/settings", authorization,
                R"JSON({"outbound_server_overrides":{"node-a":42}})JSON");
    require(invalid.status == drogon::k400BadRequest,
            "Agent UI should reject invalid setting types");

    const auto action =
        request(client, drogon::Post, "/api/actions/restart", authorization);
    require(action.status == drogon::k200OK &&
                json::parse(action.body).at("accepted") == true &&
                requested_action == "restart",
            "Agent UI should queue authenticated runtime actions");

    const auto raw_config = request(client, drogon::Get, "/api/config", authorization);
    require(raw_config.status == drogon::k200OK &&
                json::parse(raw_config.body) == config,
            "Agent UI should expose the current local config to authenticated users");
}

} // namespace

int main() {
    try {
        run_contract();
        std::cout << "[pass] C++ Agent local UI contract\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] C++ Agent local UI contract: " << error.what() << '\n';
        return 1;
    }
}
