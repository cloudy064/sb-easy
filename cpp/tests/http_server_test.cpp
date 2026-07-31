#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

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

#include "sbeasy/http_server.hpp"
#include "sbeasy/store.hpp"

namespace {

using nlohmann::json;

class TemporaryDatabase final {
  public:
    TemporaryDatabase()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-http-" + std::to_string(std::random_device{}()) + ".db")) {}

    ~TemporaryDatabase() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        std::filesystem::remove(path_.string() + "-shm", ignored);
        std::filesystem::remove(path_.string() + "-wal", ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

class RunningServer final {
  public:
    RunningServer() : thread_([] { drogon::app().run(); }) {}

    ~RunningServer() {
        if (drogon::app().isRunning()) {
            drogon::app().quit();
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    RunningServer(const RunningServer&) = delete;
    RunningServer& operator=(const RunningServer&) = delete;

    [[nodiscard]] std::uint16_t wait_for_port() const {
        for (int attempt = 0; attempt < 200; ++attempt) {
            if (drogon::app().isRunning()) {
                const auto listeners = drogon::app().getListeners();
                if (!listeners.empty() && listeners.front().toPort() != 0) {
                    return listeners.front().toPort();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        throw std::runtime_error("HTTP server did not start");
    }

  private:
    std::thread thread_;
};

struct ApiResponse {
    drogon::HttpStatusCode status;
    json body;
    std::string raw_body;
    std::string etag;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] ApiResponse
request(const drogon::HttpClientPtr& client, drogon::HttpMethod method,
        std::string path, std::optional<json> body = std::nullopt,
        const std::vector<std::pair<std::string, std::string>>& headers = {}) {
    auto http_request = drogon::HttpRequest::newHttpRequest();
    http_request->setMethod(method);
    http_request->setPath(std::move(path));
    if (body.has_value()) {
        http_request->setContentTypeString("application/json");
        http_request->setBody(body->dump());
    }
    for (const auto& [name, value] : headers) {
        http_request->addHeader(name, value);
    }

    auto [result, response] = client->sendRequest(http_request, 2.0);
    if (result != drogon::ReqResult::Ok || !response) {
        throw std::runtime_error("HTTP request failed: " +
                                 std::string{drogon::to_string_view(result)});
    }

    const std::string raw_body{response->body()};
    auto parsed =
        raw_body.empty() ? json{nullptr} : json::parse(raw_body, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("HTTP response is not JSON");
    }
    return {
        .status = response->statusCode(),
        .body = std::move(parsed),
        .raw_body = raw_body,
        .etag = response->getHeader("etag"),
    };
}

void run_contract() {
    const TemporaryDatabase database;
    auto store = std::make_shared<sbeasy::Store>(
        database.path(), std::filesystem::path{SB_EASY_MIGRATIONS_DIR});

    sbeasy::HttpServerOptions options;
    options.public_server = "https://panel.example.com";
    options.config_hash_seed = "contract-seed";
    options.legacy_agent_token = "legacy-self-token";
    sbeasy::register_http_routes(store, options);
    drogon::app()
        .setLogLevel(trantor::Logger::kWarn)
        .addListener("127.0.0.1", 0)
        .setThreadNum(1);
    const RunningServer server;
    const auto port = server.wait_for_port();
    const auto client =
        drogon::HttpClient::newHttpClient("http://127.0.0.1:" + std::to_string(port));

    const auto health = request(client, drogon::Get, "/api/health");
    require(health.status == drogon::k200OK &&
                health.body.at("service") == "sb-easy-cpp",
            "health endpoint should identify the C++ service");

    const auto profiles = request(client, drogon::Get, "/api/hosts/profiles");
    require(profiles.status == drogon::k200OK && profiles.body.is_array() &&
                !profiles.body.empty(),
            "profile list should include the seeded default");
    require(profiles.body.at(0).at("template").is_string(),
            "profile template must preserve the Rust string contract");

    const std::string rule_script = R"JS(
function buildRules(context) {
  return [{
    domain_suffix: [".example.com"],
    outbound: context.outboundTags.includes("direct") ? "direct" : "block"
  }];
}
)JS";
    const auto created_profile = request(client, drogon::Post, "/api/hosts/profiles",
                                         json{
                                             {"name", "Scripted profile"},
                                             {"template",
                                              {
                                                  {"route",
                                                   {
                                                       {"rules", json::array()},
                                                       {"final", "direct"},
                                                   }},
                                              }},
                                             {"rule_script", rule_script},
                                             {"rule_script_enabled", true},
                                         });
    require(created_profile.status == drogon::k200OK,
            "profile creation should succeed");
    const auto profile_id = created_profile.body.at("id").get<std::string>();

    const auto updated_profile =
        request(client, drogon::Put, "/api/hosts/profiles/" + profile_id,
                json{
                    {"name", "Renamed scripted profile"},
                    {"template",
                     {
                         {"route",
                          {
                              {"rules", json::array()},
                              {"final", "direct"},
                          }},
                     }},
                });
    require(updated_profile.status == drogon::k200OK &&
                updated_profile.body.at("rule_script_enabled") == true &&
                updated_profile.body.at("rule_script") == rule_script,
            "profile updates should preserve omitted script fields");

    const auto created_host = request(client, drogon::Post, "/api/hosts",
                                      json{
                                          {"name", "HTTP test host"},
                                          {"capabilities",
                                           {
                                               {"runs_singbox", true},
                                               {"is_wg_member", false},
                                               {"is_wg_hub", false},
                                               {"is_self", false},
                                           }},
                                          {"profile_id", profile_id},
                                          {"clash_secret", "hidden"},
                                      });
    require(created_host.status == drogon::k200OK, "host creation should succeed");
    require(created_host.body.at("agent_token").get_ref<const std::string&>().size() ==
                64,
            "host creation should return the one-time token");
    require(!created_host.body.contains("clash_secret"),
            "host creation must not expose the Clash secret");
    const auto host_id = created_host.body.at("id").get<std::string>();
    const auto original_token = created_host.body.at("agent_token").get<std::string>();

    const auto hosts = request(client, drogon::Get, "/api/hosts");
    require(hosts.status == drogon::k200OK && hosts.body.is_array(),
            "host list should succeed");
    bool found_public_host = false;
    for (const auto& host : hosts.body) {
        if (host.at("id") == host_id) {
            found_public_host = true;
            require(!host.contains("agent_token"),
                    "host list must hide the agent token");
            require(host.at("capabilities").is_object(),
                    "host capabilities must be a JSON object");
        }
    }
    require(found_public_host, "created host should appear in the list");

    store->database().execute("INSERT INTO proxy_nodes "
                              "(id, tag, node_type, enabled, server, server_port, "
                              "protocol_config, fingerprint) VALUES "
                              "('http-node', 'http-node', 'shadowsocks', TRUE, "
                              "'127.0.0.1', 8388, "
                              "'{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                              "'http-node')");
    const auto set_outbounds =
        request(client, drogon::Put, "/api/hosts/" + host_id + "/outbounds",
                json{{"node_ids", json::array({"http-node"})}});
    require(set_outbounds.status == drogon::k200OK,
            "outbound assignment should succeed");
    const auto get_outbounds =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/outbounds");
    require(get_outbounds.body.at("node_ids") == json::array({"http-node"}),
            "outbound assignment should round-trip");

    const auto config =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/config");
    require(config.status == drogon::k200OK &&
                config.body.at("route").at("rules").at(0).at("outbound") == "direct",
            "config preview should execute the profile rule script");

    const auto agent_health = request(client, drogon::Get, "/api/agent/health");
    require(agent_health.status == drogon::k200OK,
            "agent health should remain unauthenticated");
    require(request(client, drogon::Get, "/api/agent/config").status ==
                drogon::k401Unauthorized,
            "agent config should reject missing bearer credentials");
    const std::vector<std::pair<std::string, std::string>> agent_auth{
        {"Authorization", "Bearer " + original_token},
    };
    const auto agent_config =
        request(client, drogon::Get, "/api/agent/config", std::nullopt, agent_auth);
    require(agent_config.status == drogon::k200OK && !agent_config.etag.empty() &&
                agent_config.body.at("route").at("rules").at(0).at("outbound") ==
                    "direct",
            "authenticated agents should receive their rendered config and ETag");
    auto cached_headers = agent_auth;
    cached_headers.emplace_back("If-None-Match", agent_config.etag);
    const auto cached_config =
        request(client, drogon::Get, "/api/agent/config", std::nullopt, cached_headers);
    require(cached_config.status == drogon::k304NotModified &&
                cached_config.raw_body.empty() &&
                cached_config.etag == agent_config.etag,
            "matching agent ETags should produce an empty 304 response");
    const auto touched_host = store->find_host(host_id);
    require(touched_host.has_value() && touched_host->last_seen.has_value(),
            "config polls should update host liveness");

    const auto status_report = request(client, drogon::Post, "/api/agent/status",
                                       json{{"singbox_version", "1.12.0"},
                                            {"singbox_running", true},
                                            {"config_etag", agent_config.etag}},
                                       agent_auth);
    require(status_report.status == drogon::k200OK &&
                status_report.body.at("ok") == true,
            "agent status reports should succeed");
    const auto status_host = store->find_host(host_id);
    require(status_host.has_value() && status_host->singbox_state.has_value() &&
                json::parse(*status_host->singbox_state).at("etag") ==
                    agent_config.etag,
            "agent status should persist the reported ETag");

    const auto enqueued =
        request(client, drogon::Post, "/api/hosts/" + host_id + "/commands",
                json{{"command", " RELOAD "}});
    require(enqueued.status == drogon::k200OK &&
                enqueued.body.at("status") == "pending",
            "administrators should enqueue normalized agent commands");
    const auto command_id = enqueued.body.at("id").get<std::string>();
    const auto pending =
        request(client, drogon::Get, "/api/agent/commands", std::nullopt, agent_auth);
    require(pending.status == drogon::k200OK && pending.body.size() == 1U &&
                pending.body.at(0).at("id") == command_id,
            "agents should only pull their pending commands");
    const std::vector<std::pair<std::string, std::string>> legacy_auth{
        {"Authorization", "Bearer legacy-self-token"},
    };
    require(request(client, drogon::Post, "/api/agent/commands/" + command_id + "/ack",
                    json{{"status", "done"}, {"result", "wrong host"}}, legacy_auth)
                    .status == drogon::k200OK,
            "cross-host command acknowledgements should not leak existence");
    require(store->list_host_commands(host_id, true).size() == 1U,
            "a different host token must not acknowledge the command");
    require(request(client, drogon::Post, "/api/agent/commands/" + command_id + "/ack",
                    json{{"status", "done"}, {"result", "reloaded"}}, agent_auth)
                    .status == drogon::k200OK,
            "the owning agent should acknowledge its command");
    const auto command_history =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/commands");
    require(command_history.body.at(0).at("status") == "done" &&
                command_history.body.at(0).at("result") == "reloaded",
            "administrators should see acknowledged command history");
    require(request(client, drogon::Post, "/api/hosts/self/commands",
                    json{{"command", "reload"}})
                    .status == drogon::k400BadRequest,
            "the built-in self host must reject remote commands");

    json logs = json::array();
    for (int index = 0; index < 502; ++index) {
        logs.push_back(std::to_string(index));
    }
    require(request(client, drogon::Post, "/api/agent/telemetry",
                    json{{"up", 10},
                         {"down", 20},
                         {"up_total", 100},
                         {"down_total", 200},
                         {"conn_count", 1},
                         {"connections", json::array({json{{"id", "connection"}}})},
                         {"logs", std::move(logs)}},
                    agent_auth)
                    .status == drogon::k200OK,
            "agents should relay telemetry");
    const auto telemetry =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/telemetry");
    require(telemetry.body.at("up") == 10 && telemetry.body.at("logs").size() == 500U &&
                telemetry.body.at("logs").at(0) == "2",
            "telemetry should retain the latest snapshot and cap logs");

    const auto latency =
        request(client, drogon::Post, "/api/agent/proxy-latency",
                json{{"results", {{"http-node", 42.5}, {"missing-node", nullptr}}}},
                agent_auth);
    require(latency.status == drogon::k200OK && latency.body.at("updated") == 1,
            "agent latency reports should update matching proxy tags");

    const auto revealed =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/token");
    require(revealed.body.at("agent_token") == original_token &&
                revealed.body.at("server") == "https://panel.example.com",
            "token reveal should preserve its response contract");
    const auto rotated =
        request(client, drogon::Post, "/api/hosts/" + host_id + "/rotate-token");
    require(rotated.body.at("agent_token") != original_token,
            "token rotation should return a replacement");
    require(request(client, drogon::Get, "/api/agent/config", std::nullopt, agent_auth)
                    .status == drogon::k401Unauthorized,
            "rotating a token should immediately revoke the old credential");

    const auto updated_host =
        request(client, drogon::Put, "/api/hosts/" + host_id,
                json{{"name", "Disabled preview host"}, {"enabled", false}});
    require(updated_host.body.at("name") == "Disabled preview host" &&
                updated_host.body.at("enabled") == false,
            "partial host updates should preserve the Rust semantics");
    require(request(client, drogon::Get, "/api/hosts/" + host_id + "/config").status ==
                drogon::k200OK,
            "administrative config preview should work for disabled hosts");

    const auto invalid_profile =
        request(client, drogon::Post, "/api/hosts/profiles",
                json{{"name", "invalid"}, {"template", json::array()}});
    require(invalid_profile.status == drogon::k400BadRequest &&
                invalid_profile.body.contains("error"),
            "invalid profile templates should return structured 400 errors");
    require(request(client, drogon::Get, "/api/hosts/missing").status ==
                drogon::k404NotFound,
            "missing hosts should return structured 404 errors");
    require(request(client, drogon::Get, "/api/hosts/missing/config").status ==
                drogon::k404NotFound,
            "missing host config previews should return structured 404 errors");
    require(request(client, drogon::Delete, "/api/hosts/profiles/default").status ==
                drogon::k400BadRequest,
            "the default profile should be protected over HTTP");

    require(
        request(client, drogon::Delete, "/api/hosts/" + host_id).body.at("success") ==
            true,
        "host deletion should succeed");
}

} // namespace

int main() {
    try {
        run_contract();
        std::cout << "[pass] Drogon hosts/profile HTTP contract\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] Drogon hosts/profile HTTP contract: " << error.what()
                  << '\n';
        return 1;
    }
}
