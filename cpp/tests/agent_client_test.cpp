#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

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

#include "sbeasy/agent_client.hpp"
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

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
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
        run_contract();
        std::cout << "[pass] C++ agent client end-to-end contract\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] C++ agent client end-to-end contract: " << error.what()
                  << '\n';
        return 1;
    }
}
