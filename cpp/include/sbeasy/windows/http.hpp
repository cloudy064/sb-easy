#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/http.hpp is only available on Windows"
#endif

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "sbeasy/agent_client.hpp"
#include "sbeasy/agent_http.hpp"

namespace sbeasy::win {

struct WinHttpOptions {
    std::string server;
    std::string token;
    std::chrono::milliseconds timeout{15'000};
    std::size_t maximum_body_bytes{8U * 1024U * 1024U};
};

[[nodiscard]] DeviceCredential
enroll_device_winhttp(DeviceEnrollmentOptions options);

/// Agent transport backed by WinHTTP. It uses the Windows certificate store,
/// never disables certificate validation, and rejects redirects so bearer
/// credentials cannot be forwarded to a different origin.
class WinHttpAgentClient final : public AgentHttp {
  public:
    explicit WinHttpAgentClient(WinHttpOptions options);
    ~WinHttpAgentClient();

    WinHttpAgentClient(const WinHttpAgentClient&) = delete;
    WinHttpAgentClient& operator=(const WinHttpAgentClient&) = delete;
    WinHttpAgentClient(WinHttpAgentClient&&) noexcept;
    WinHttpAgentClient& operator=(WinHttpAgentClient&&) noexcept;

    [[nodiscard]] AgentConfigResponse
    poll_config(const std::optional<std::string>& etag = std::nullopt) override;
    [[nodiscard]] std::vector<AgentCommand> pending_commands() override;
    void acknowledge_command(const std::string& id, bool success,
                             const std::optional<std::string>& result) override;
    void report_status(const std::string& version,
                       const std::optional<bool>& running,
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

} // namespace sbeasy::win
