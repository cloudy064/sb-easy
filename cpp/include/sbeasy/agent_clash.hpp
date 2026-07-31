#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace sbeasy {

/// Agent-side access to the Clash API exposed by the locally running sing-box.
///
/// The controller and secret are read from the installed sing-box config for
/// every operation, so config reloads do not leave the agent with stale
/// credentials.
class AgentClashService final {
  public:
    using LatencyReporter = std::function<void(const nlohmann::json&)>;

    explicit AgentClashService(std::filesystem::path config_path);
    ~AgentClashService();

    AgentClashService(const AgentClashService&) = delete;
    AgentClashService& operator=(const AgentClashService&) = delete;
    AgentClashService(AgentClashService&&) noexcept;
    AgentClashService& operator=(AgentClashService&&) noexcept;

    /// Tests all concrete proxies, or only the requested tags, and invokes the
    /// reporter once per proxy so the control plane can show progressive
    /// results.
    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter);

    /// Returns an agent telemetry payload, or nullopt when the installed config
    /// does not expose a Clash controller.
    [[nodiscard]] std::optional<nlohmann::json> sample_telemetry();

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy
