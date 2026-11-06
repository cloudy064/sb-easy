#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/agent_http.hpp"

namespace sbeasy {

struct AgentClientOptions {
    std::string server;
    std::string token;
    std::chrono::milliseconds timeout{15'000};
};

struct DeviceEnrollmentOptions {
    std::string server;
    std::string code;
    nlohmann::json device = nlohmann::json::object();
    std::chrono::milliseconds timeout{15'000};
};

struct DeviceCredential {
    std::string server;
    std::string host_id;
    std::string host_name;
    std::string token;
    std::string profile_id;
    std::string profile_name;
};

/// Redeem the same single-use device enrollment code used by the Android app.
/// The returned bearer token is the device's long-lived internal credential and
/// should be persisted locally instead of exposed in installation commands.
[[nodiscard]] DeviceCredential enroll_device(DeviceEnrollmentOptions options);

class AgentClient final : public AgentHttp {
  public:
    explicit AgentClient(AgentClientOptions options);
    ~AgentClient();

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;
    AgentClient(AgentClient&&) noexcept;
    AgentClient& operator=(AgentClient&&) noexcept;

    [[nodiscard]] AgentConfigResponse
    poll_config(const std::optional<std::string>& etag = std::nullopt) override;
    [[nodiscard]] std::vector<AgentCommand> pending_commands() override;
    void acknowledge_command(const std::string& id, bool success,
                             const std::optional<std::string>& result) override;
    void report_status(const std::string& version, const std::optional<bool>& running,
                       const std::optional<std::string>& etag) override;
    void report_telemetry(const nlohmann::json& telemetry) override;
    [[nodiscard]] std::size_t
    report_proxy_latencies(const nlohmann::json& results) override;
    [[nodiscard]] std::string
    upload_diagnostics(const nlohmann::json& report) override;

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy
