#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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

#include "sbeasy/agent_clash.hpp"
#include "sbeasy/agent_client.hpp"
#include "sbeasy/agent_config.hpp"
#include "sbeasy/atomic_file.hpp"
#include "sbeasy/http_server.hpp"
#include "sbeasy/store.hpp"

namespace {

class TemporaryDirectory final {
  public:
    TemporaryDirectory()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-agent-client-" + std::to_string(std::random_device{}()))) {
        std::filesystem::create_directories(path_);
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
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

class ClashFixture final {
  public:
    ClashFixture() {
        listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener_ < 0) {
            throw std::runtime_error("could not create agent Clash fixture");
        }
        const int reuse = 1;
        if (::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                         static_cast<socklen_t>(sizeof(reuse))) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not configure agent Clash fixture");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<const sockaddr*>(&address),
                   static_cast<socklen_t>(sizeof(address))) != 0 ||
            ::listen(listener_, 8) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not listen for agent Clash fixture");
        }
        socklen_t size = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size) !=
            0) {
            ::close(listener_);
            throw std::runtime_error("could not resolve agent Clash fixture port");
        }
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { serve(); });
    }

    ~ClashFixture() {
        if (listener_ >= 0) {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    ClashFixture(const ClashFixture&) = delete;
    ClashFixture& operator=(const ClashFixture&) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept {
        return port_;
    }

  private:
    static void respond(int client, const std::string& request) {
        std::istringstream line{request.substr(0, request.find("\r\n"))};
        std::string method;
        std::string target;
        line >> method >> target;

        nlohmann::json body = nlohmann::json::object();
        if (target == "/proxies") {
            body["proxies"] = {
                {"Agent Node", {{"type", "Shadowsocks"}}},
                {"Agent Group",
                 {{"type", "Selector"},
                  {"all", nlohmann::json::array({"Agent Node"})}}},
                {"direct", {{"type", "Direct"}}},
            };
        } else if (target.find("/delay?") != std::string::npos) {
            body["delay"] = 33;
        } else if (target == "/connections") {
            body = {
                {"uploadTotal", 4'096},
                {"downloadTotal", 8'192},
                {"connections",
                 nlohmann::json::array({nlohmann::json{{"id", "agent-connection"}}})},
            };
        }
        const auto serialized = body.dump();
        const auto response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              "Content-Length: " +
                              std::to_string(serialized.size()) +
                              "\r\nConnection: close\r\n\r\n" + serialized;
        std::size_t sent{};
        while (sent < response.size()) {
            const auto count = ::send(client, response.data() + sent,
                                      response.size() - sent, MSG_NOSIGNAL);
            if (count <= 0) {
                break;
            }
            sent += static_cast<std::size_t>(count);
        }
    }

    void serve() const {
        while (true) {
            const auto client = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) {
                return;
            }
            std::string request;
            std::array<char, 4'096> buffer{};
            while (request.find("\r\n\r\n") == std::string::npos) {
                const auto count = ::recv(client, buffer.data(), buffer.size(), 0);
                if (count <= 0) {
                    break;
                }
                request.append(buffer.data(), static_cast<std::size_t>(count));
            }
            respond(client, request);
            ::close(client);
        }
    }

    int listener_{-1};
    std::uint16_t port_{};
    std::thread thread_;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void run_config_transform_contract() {
    const auto input = nlohmann::json::parse(R"JSON(
{
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "management-dns",
        "server": "223.5.5.5",
        "detour": "wg-internal"
      }
    ],
    "rules": []
  },
  "outbounds": [
    {
      "type": "selector",
      "tag": "Proxy",
      "outbounds": ["node-a", "node-b"],
      "default": "node-b"
    },
    {
      "type": "shadowsocks",
      "tag": "node-a",
      "server": "old.example",
      "server_port": 443,
      "detour": "wg-internal"
    },
    {
      "type": "shadowsocks",
      "tag": "node-b",
      "server": "remote.example",
      "server_port": 443
    }
  ],
  "route": {
    "final": "Proxy",
    "rules": [
      {"domain_suffix": "example.com", "outbound": "node-b"}
    ]
  }
}
)JSON");
    sbeasy::AgentConfigTransformOptions options{
        .local_proxy_egress = true,
        .outbound_server_overrides = {{"node-a", "local.example"}},
        .outbound_overrides = {{"node-b",
                                {{"type", "socks"},
                                 {"tag", "local-node-b"},
                                 {"server", "127.0.0.1"},
                                 {"server_port", 10'080}}}},
        .default_proxy_outbound = "node-a",
    };
    const auto transformed =
        nlohmann::json::parse(sbeasy::prepare_agent_config(input.dump(), options));
    const auto& outbounds = transformed.at("outbounds");
    require(outbounds.at(0).at("default") == "node-a",
            "agent transform should select the node-local default outbound");
    require(outbounds.at(1).at("server") == "local.example" &&
                !outbounds.at(1).contains("detour"),
            "agent transform should override servers and remove WG detours");
    require(outbounds.at(2).at("tag") == "local-node-b" &&
                outbounds.at(2).at("type") == "socks",
            "agent transform should replace and rename complete outbounds");
    require(transformed.at("route").at("rules").at(0).at("outbound") == "local-node-b",
            "agent transform should rewrite references to renamed outbounds");
    require(!transformed.at("dns").at("servers").at(0).contains("detour"),
            "agent transform should remove management DNS detours");
    require(transformed.at("dns").at("servers").at(1).at("tag") == "proxy-dns" &&
                transformed.at("dns").at("servers").at(1).at("detour") == "Proxy" &&
                transformed.at("dns").at("rules").at(0).at("server") == "proxy-dns",
            "agent transform should install proxy-routed OpenAI DNS");

    auto disabled = options;
    disabled.local_proxy_egress = false;
    require(sbeasy::prepare_agent_config(input.dump(), disabled) == input.dump(),
            "disabled local egress must preserve the panel response byte-for-byte");

    auto invalid_default = options;
    invalid_default.default_proxy_outbound = "missing-node";
    bool rejected = false;
    try {
        static_cast<void>(sbeasy::prepare_agent_config(input.dump(), invalid_default));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "agent transform should reject a default outside the selector");
}

void run_contract() {
    bool rejected_url = false;
    try {
        sbeasy::AgentClient unsupported({
            .server = "ftp://127.0.0.1",
            .token = "token",
        });
        static_cast<void>(unsupported);
    } catch (const std::invalid_argument&) {
        rejected_url = true;
    }
    require(rejected_url, "agent client should reject unsupported server URL schemes");

    const TemporaryDirectory directory;
    const ClashFixture clash_fixture;
    auto store = std::make_shared<sbeasy::Store>(
        directory.path() / "agent.db", std::filesystem::path{SB_EASY_MIGRATIONS_DIR});

    sbeasy::Host host;
    host.name = "C++ agent client";
    host.capabilities = nlohmann::json::object();
    const auto created = store->create_host(std::move(host));

    sbeasy::HttpServerOptions server_options;
    server_options.config_hash_seed = "agent-client-seed";
    sbeasy::register_http_routes(store, server_options);
    drogon::app()
        .setLogLevel(trantor::Logger::kWarn)
        .addListener("127.0.0.1", 0)
        .setThreadNum(1);
    const RunningServer server;
    const auto port = server.wait_for_port();

    sbeasy::AgentClient client({
        .server = "http://127.0.0.1:" + std::to_string(port),
        .token = created.agent_token,
        .timeout = std::chrono::seconds{2},
    });
    const auto config = client.poll_config();
    require(config.modified && !config.etag.empty() && !config.body.empty(),
            "agent client should fetch its first config");
    const auto config_path = directory.path() / "config" / "sing-box.json";
    sbeasy::atomic_replace_file(
        config_path, config.body, [](const std::filesystem::path& temporary) {
            require(std::filesystem::file_size(temporary) > 0U,
                    "agent validator should receive a complete temp file");
        });
    require(std::filesystem::exists(config_path),
            "agent config should be atomically installed");

    const auto clash_config_path = directory.path() / "config" / "clash.json";
    sbeasy::atomic_replace_file(
        clash_config_path,
        nlohmann::json{
            {"experimental",
             {{"clash_api",
               {{"external_controller",
                 "0.0.0.0:" + std::to_string(clash_fixture.port())},
                {"secret", "fixture-secret"}}}}},
        }
            .dump());
    sbeasy::AgentClashService clash{clash_config_path};
    std::vector<nlohmann::json> latency_reports;
    const auto tested =
        clash.test_proxies(std::nullopt, [&](const nlohmann::json& report) {
            latency_reports.push_back(report);
        });
    require(tested == 1U && latency_reports.size() == 1U &&
                latency_reports.front().at("Agent Node") == 33,
            "agent Clash tests should skip groups/built-ins and report each delay");
    const auto telemetry = clash.sample_telemetry();
    require(telemetry.has_value() && telemetry->at("up_total") == 4'096 &&
                telemetry->at("down_total") == 8'192 &&
                telemetry->at("conn_count") == 1 && telemetry->at("up") == 0 &&
                telemetry->at("down") == 0,
            "agent Clash telemetry should expose totals and an initial zero rate");

    const auto unchanged = client.poll_config(config.etag);
    require(!unchanged.modified && unchanged.etag == config.etag,
            "agent client should honor 304 responses");

    const auto command = store->enqueue_host_command(created.id, "restart");
    const auto pending = client.pending_commands();
    require(pending.size() == 1U && pending.front().id == command.id,
            "agent client should decode pending commands");
    client.acknowledge_command(command.id, true, "restarted");
    require(store->list_host_commands(created.id).front().status == "done",
            "agent command acknowledgement should reach the store");

    client.report_status("sb-easy-cpp-agent/test", true, config.etag);
    const auto status = store->find_host(created.id);
    require(status.has_value() && status->last_seen.has_value() &&
                status->singbox_state.has_value(),
            "agent client should report status");
    client.report_telemetry({{"up", 1}, {"down", 2}});

    store->database().execute("INSERT INTO proxy_nodes "
                              "(id, tag, node_type, enabled, server, server_port, "
                              "protocol_config, fingerprint) VALUES "
                              "('client-node', 'client-node', 'shadowsocks', TRUE, "
                              "'127.0.0.1', 8388, "
                              "'{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                              "'client-node')");
    require(client.report_proxy_latencies({{"client-node", 8.5}}) == 1U,
            "agent client should report proxy latency");

    sbeasy::AgentClient invalid({
        .server = "http://127.0.0.1:" + std::to_string(port),
        .token = "invalid",
        .timeout = std::chrono::seconds{2},
    });
    bool rejected = false;
    try {
        static_cast<void>(invalid.poll_config());
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "invalid agent credentials should surface as an error");
}

} // namespace

int main() {
    try {
        run_config_transform_contract();
        run_contract();
        std::cout << "[pass] C++ agent client end-to-end contract\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] C++ agent client end-to-end contract: " << error.what()
                  << '\n';
        return 1;
    }
}
