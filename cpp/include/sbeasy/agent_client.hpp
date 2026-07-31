#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct AgentClientOptions {
    std::string server;
    std::string token;
    std::chrono::milliseconds timeout{15'000};
};

struct AgentConfigResponse {
    bool modified{false};
    std::string etag;
    std::string body;
};

struct AgentCommand {
    std::string id;
    std::string command;
};

class AgentClient final {
  public:
    explicit AgentClient(AgentClientOptions options);
    ~AgentClient();

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;
    AgentClient(AgentClient&&) noexcept;
    AgentClient& operator=(AgentClient&&) noexcept;

    [[nodiscard]] AgentConfigResponse
    poll_config(const std::optional<std::string>& etag = std::nullopt);
    [[nodiscard]] std::vector<AgentCommand> pending_commands();
    void acknowledge_command(const std::string& id, bool success,
                             const std::optional<std::string>& result);
    void report_status(const std::string& version, const std::optional<bool>& running,
                       const std::optional<std::string>& etag);
    void report_telemetry(const nlohmann::json& telemetry);
    [[nodiscard]] std::size_t report_proxy_latencies(const nlohmann::json& results);

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy
