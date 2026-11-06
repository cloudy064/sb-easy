#pragma once

#include <chrono>
#include <condition_variable>
#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/agent_config.hpp"
#include "sbeasy/agent_http.hpp"
#include "sbeasy/platform_clock.hpp"
#include "sbeasy/platform_metadata.hpp"
#include "sbeasy/platform_process.hpp"
#include "sbeasy/platform_storage.hpp"

namespace sbeasy {

/// Process ownership for the managed sing-box instance. Windows will back this
/// with CreateProcess + Job Objects; Linux keeps the existing POSIX supervisor.
class AgentCore {
  public:
    virtual ~AgentCore() = default;

    virtual void apply_config(std::string_view contents) = 0;
    virtual void ensure_alive() = 0;
    virtual void reload() = 0;
    virtual void restart() = 0;
    virtual void stop() = 0;
    [[nodiscard]] virtual bool running() = 0;
    [[nodiscard]] virtual std::optional<std::string> last_error() const = 0;
};

/// Local sing-box observability used by telemetry and UI workflows.
class AgentLocalRuntime {
  public:
    using LatencyReporter = std::function<void(const nlohmann::json& latency)>;

    virtual ~AgentLocalRuntime() = default;

    [[nodiscard]] virtual std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) = 0;
    [[nodiscard]] virtual std::optional<nlohmann::json> sample_telemetry() = 0;
    [[nodiscard]] virtual nlohmann::json test_route(const std::string& url) = 0;

    /// Called only after a new configuration has been validated and activated.
    /// Platforms with durable route aggregation use this boundary to prevent
    /// observations from different policy generations being silently merged.
    virtual void policy_activated(std::string_view) {}
};

struct AgentRuntimeOptions {
    std::filesystem::path config_path{"data/sing-box.gen.json"};
    std::filesystem::path settings_path{"data/agent-ui-settings.json"};
    std::string server;
    std::string service_name{"sb-easy-cpp-agent"};
    std::string version;
    std::string singbox_binary{"sing-box"};
    bool singbox_managed{true};
    bool validate_config{true};
    std::vector<std::string> reload_command;
    std::vector<std::string> restart_command;
    AgentConfigTransformOptions transform_options;
};

struct AgentRuntimeDependencies {
    AgentHttp& http;
    PlatformProcess& process;
    PlatformStorage& storage;
    PlatformClock& clock;
    PlatformMetadata& metadata;
    AgentCore& core;
    AgentLocalRuntime& local_runtime;
};

/// Portable agent orchestration. This class contains no POSIX or Windows API
/// types and is intentionally executable against in-memory test doubles.
class AgentRuntime final {
  public:
    AgentRuntime(AgentRuntimeOptions options, AgentRuntimeDependencies dependencies);

    [[nodiscard]] bool run_cycle();
    void wait_for_work(std::chrono::seconds interval);

    [[nodiscard]] nlohmann::json status() const;
    [[nodiscard]] nlohmann::json settings() const;
    [[nodiscard]] nlohmann::json update_settings(const nlohmann::json& value);
    [[nodiscard]] nlohmann::json config() const;
    [[nodiscard]] nlohmann::json proxies() const;
    [[nodiscard]] nlohmann::json test_route(const std::string& url);
    void queue_action(const std::string& action);

  private:
    struct QueuedActions {
        bool start{false};
        bool stop{false};
        bool reload{false};
        bool restart{false};
    };

    static void record_error(std::vector<std::string>& errors,
                             std::string_view operation, const std::exception& error);
    [[nodiscard]] QueuedActions take_queued_actions();
    void finish_cycle(const std::vector<std::string>& errors);
    [[nodiscard]] std::optional<std::string> etag() const;
    void set_etag(std::string value);
    void set_rule_source(std::string value);
    [[nodiscard]] std::optional<bool> running() const;
    [[nodiscard]] bool desired_running() const;
    void set_running(bool value);
    void update_local_telemetry(const nlohmann::json& telemetry);
    void apply_config(const AgentConfigResponse& config_response);
    void run_local_action(const QueuedActions& actions);
    void run_commands();

    AgentRuntimeOptions options_;
    AgentRuntimeDependencies dependencies_;
    nlohmann::json device_metadata_;
    mutable std::mutex state_mutex_;
    std::condition_variable wakeup_;
    std::optional<std::string> last_etag_;
    std::optional<bool> running_;
    std::optional<std::string> last_cycle_;
    std::optional<std::string> last_error_;
    nlohmann::json last_telemetry_{
        {"available", false}, {"sampled_at", nullptr}, {"up", 0},         {"down", 0},
        {"up_total", 0},      {"down_total", 0},       {"conn_count", 0},
    };
    std::string last_rule_source_{"profile"};
    bool refresh_requested_{false};
    bool start_requested_{false};
    bool stop_requested_{false};
    bool reload_requested_{false};
    bool restart_requested_{false};
    bool desired_running_{true};
};

} // namespace sbeasy
