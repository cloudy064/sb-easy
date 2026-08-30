#pragma once

#include <cstdint>
#include <filesystem>
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
    std::function<nlohmann::json(const std::string&, const std::string&)>
        select_proxy;
    std::function<nlohmann::json(const std::string&)> test_route;
    std::function<void(const std::string&)> request_action;
};

struct AgentLocalUiOptions {
    std::string address{"0.0.0.0"};
    std::uint16_t port{51822};
    std::string username{"admin"};
    std::string password;
    std::filesystem::path ui_directory;
};

/// Password-protected Agent API with an optional external static UI directory.
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
