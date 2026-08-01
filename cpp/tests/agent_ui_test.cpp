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
    std::string location;
    std::string frame_options;
    std::string session_cookie;
    bool session_cookie_http_only{false};
    drogon::Cookie::SameSite session_cookie_same_site{drogon::Cookie::SameSite::kNull};
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] Response request(const drogon::HttpClientPtr& client,
                               drogon::HttpMethod method, std::string path,
                               std::string body = {}) {
    auto value = drogon::HttpRequest::newHttpRequest();
    value->setMethod(method);
    value->setPath(std::move(path));
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
        .location = response->getHeader("location"),
        .frame_options = response->getHeader("x-frame-options"),
        .session_cookie = response->getCookie("sb_easy_agent_session").value(),
        .session_cookie_http_only =
            response->getCookie("sb_easy_agent_session").isHttpOnly(),
        .session_cookie_same_site =
            response->getCookie("sb_easy_agent_session").sameSite(),
    };
}

void run_contract() {
    auto settings = sbeasy::agent_config_transform_options_to_json({});
    std::string requested_action;
    std::string tested_url;
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
                    {"rule_source", "quickjs"},
                    {"telemetry",
                     {{"available", true},
                      {"sampled_at", "2026-07-31T10:00:00Z"},
                      {"up", 1024},
                      {"down", 2048},
                      {"up_total", 4096},
                      {"down_total", 8192},
                      {"conn_count", 3}}},
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
        .test_route =
            [&tested_url](const std::string& url) {
                tested_url = url;
                return json{
                    {"success", true},
                    {"url", url},
                    {"host", "example.com"},
                    {"port", 443},
                    {"kind", "proxy"},
                    {"outbound", "node-a"},
                    {"chains", json::array({"node-a", "Proxy"})},
                    {"rule", "domain_suffix=example.com => route(Proxy)"},
                    {"rule_payload", ""},
                };
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
    client->enableCookies(true);

    const auto health = request(client, drogon::Get, "/health");
    require(health.status == drogon::k200OK &&
                json::parse(health.body).at("service") == "sb-easy-agent-ui",
            "Agent UI health endpoint should remain available without credentials");

    const auto unauthorized = request(client, drogon::Get, "/");
    require(unauthorized.status == drogon::k303SeeOther &&
                unauthorized.location == "/login" && unauthorized.authenticate.empty(),
            "Agent UI should redirect browsers to a dedicated login page");

    const auto login_page = request(client, drogon::Get, "/login");
    require(login_page.status == drogon::k200OK &&
                login_page.content_type.find("text/html") != std::string::npos &&
                login_page.body.find("欢迎回来") != std::string::npos,
            "Agent UI should render its standalone login form");

    const auto invalid_login =
        request(client, drogon::Post, "/api/login",
                json{{"username", "local-admin"}, {"password", "wrong"}}.dump());
    require(invalid_login.status == drogon::k401Unauthorized &&
                invalid_login.session_cookie.empty(),
            "Agent UI should reject invalid login credentials");

    const auto login = request(
        client, drogon::Post, "/api/login",
        json{{"username", "local-admin"}, {"password", "contract-password"}}.dump());
    require(login.status == drogon::k200OK && !login.session_cookie.empty() &&
                login.session_cookie_http_only &&
                login.session_cookie_same_site == drogon::Cookie::SameSite::kStrict,
            "Agent UI login should issue an HttpOnly SameSite session cookie");

    const auto root = request(client, drogon::Get, "/");
    require(root.status == drogon::k200OK &&
                root.content_type.find("text/html") != std::string::npos &&
                root.body.find("sb-easy Agent") != std::string::npos &&
                root.body.find("data-view=\"proxies\"") != std::string::npos &&
                root.body.find("/api/proxies") != std::string::npos &&
                root.body.find("/api/settings") != std::string::npos &&
                root.body.find("traffic-chart") != std::string::npos &&
                root.body.find("data-config-mode=\"overview\"") != std::string::npos &&
                root.body.find("data-config-mode=\"network\"") != std::string::npos &&
                root.body.find("data-config-mode=\"routing\"") != std::string::npos &&
                root.body.find("data-config-mode=\"quickjs\"") != std::string::npos &&
                root.body.find("data-config-mode=\"outbounds\"") != std::string::npos &&
                root.body.find("config-route-rules") != std::string::npos &&
                root.body.find("URL 实际路由测试") != std::string::npos &&
                root.body.find("/api/route-test") != std::string::npos &&
                root.body.find("config-quickjs-panel") != std::string::npos &&
                root.body.find("前往中心端配置 QuickJS") != std::string::npos &&
                root.frame_options == "DENY",
            "authenticated users should receive the secured Agent UI");

    const auto status = request(client, drogon::Get, "/api/status");
    require(status.status == drogon::k200OK &&
                json::parse(status.body).at("running") == true &&
                json::parse(status.body).at("telemetry").at("down") == 2048,
            "Agent UI should expose runtime status");

    const auto updated = request(client, drogon::Put, "/api/settings",
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
        request(client, drogon::Put, "/api/settings",
                R"JSON({"outbound_server_overrides":{"node-a":42}})JSON");
    require(invalid.status == drogon::k400BadRequest,
            "Agent UI should reject invalid setting types");

    const auto action = request(client, drogon::Post, "/api/actions/restart");
    require(action.status == drogon::k200OK &&
                json::parse(action.body).at("accepted") == true &&
                requested_action == "restart",
            "Agent UI should queue authenticated runtime actions");

    const auto raw_config = request(client, drogon::Get, "/api/config");
    require(raw_config.status == drogon::k200OK &&
                json::parse(raw_config.body) == config,
            "Agent UI should expose the current local config to authenticated users");

    const auto route_test = request(client, drogon::Post, "/api/route-test",
                                    json{{"url", "https://example.com/path"}}.dump());
    require(route_test.status == drogon::k200OK &&
                json::parse(route_test.body).at("outbound") == "node-a" &&
                json::parse(route_test.body).at("kind") == "proxy" &&
                tested_url == "https://example.com/path",
            "Agent UI should return the actual route test callback result");

    const auto invalid_route_test =
        request(client, drogon::Post, "/api/route-test", json::object().dump());
    require(invalid_route_test.status == drogon::k400BadRequest,
            "Agent UI should reject a route test without a URL");

    const auto logout = request(client, drogon::Post, "/api/logout");
    require(logout.status == drogon::k200OK,
            "Agent UI should accept an authenticated logout");
    const auto after_logout = request(client, drogon::Get, "/");
    require(after_logout.status == drogon::k303SeeOther &&
                after_logout.location == "/login",
            "Agent UI logout should revoke the local session");
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
