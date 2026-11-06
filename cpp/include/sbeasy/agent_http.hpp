#pragma once

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct AgentConfigResponse {
    bool modified{false};
    std::string etag;
    std::string body;
    std::string rule_source{"profile"};
};

struct AgentCommand {
    std::string id;
    std::string command;
};

/// Authenticated control-plane contract used by the portable runtime. Drogon,
/// WinHTTP, and test doubles implement this boundary independently.
class AgentHttp {
  public:
    virtual ~AgentHttp() = default;

    [[nodiscard]] virtual AgentConfigResponse
    poll_config(const std::optional<std::string>& etag = std::nullopt) = 0;
    [[nodiscard]] virtual std::vector<AgentCommand> pending_commands() = 0;
    virtual void acknowledge_command(const std::string& id, bool success,
                                     const std::optional<std::string>& result) = 0;
    virtual void report_status(const std::string& version,
                               const std::optional<bool>& running,
                               const std::optional<std::string>& etag) = 0;
    virtual void report_telemetry(const nlohmann::json& telemetry) = 0;
    [[nodiscard]] virtual std::size_t
    report_proxy_latencies(const nlohmann::json& results) = 0;
    [[nodiscard]] virtual std::string
    upload_diagnostics(const nlohmann::json&) {
        throw std::runtime_error("diagnostic upload is unavailable");
    }
};

} // namespace sbeasy
