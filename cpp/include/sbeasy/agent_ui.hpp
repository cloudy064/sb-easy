#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct AgentUiCallbacks {
    std::function<nlohmann::json()> status;
    std::function<nlohmann::json()> settings;
    std::function<nlohmann::json(const nlohmann::json&)> update_settings;
    std::function<nlohmann::json()> config;
    std::function<nlohmann::json()> proxies;
    std::function<void(const std::string&)> request_action;
};

struct AgentLocalUiOptions {
    std::string address{"0.0.0.0"};
    std::uint16_t port{51822};
    std::string username{"admin"};
    std::string password;
};

/// A password-protected management surface embedded in the Agent process.
///
/// Drogon owns a process-global application object, so only one AgentLocalUi
/// may be active in a process.
class AgentLocalUi final {
  public:
    AgentLocalUi(AgentLocalUiOptions options, AgentUiCallbacks callbacks);
    ~AgentLocalUi();

    AgentLocalUi(const AgentLocalUi&) = delete;
    AgentLocalUi& operator=(const AgentLocalUi&) = delete;
    AgentLocalUi(AgentLocalUi&&) = delete;
    AgentLocalUi& operator=(AgentLocalUi&&) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept;

  private:
    class Implementation;
    std::unique_ptr<Implementation> implementation_;
};

} // namespace sbeasy
