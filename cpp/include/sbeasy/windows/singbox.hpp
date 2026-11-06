#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/singbox.hpp is only available on Windows"
#endif

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "sbeasy/agent_runtime.hpp"

namespace sbeasy::win {

struct WindowsSingBoxOptions {
    std::filesystem::path binary;
    std::filesystem::path wintun;
    std::filesystem::path candidate_config;
    std::filesystem::path active_config;
    std::filesystem::path last_good_config;
    std::filesystem::path log_path;
    bool validate_config{true};
    bool restrict_acl{true};
    bool start_enabled{true};
    bool strict_route{false};
    std::chrono::milliseconds health_timeout{10'000};
    std::chrono::milliseconds shutdown_timeout{3'000};
};

/// Owns the private sing-box child process in a kill-on-close Job Object,
/// validates candidates before activation, and rolls back to the last-good
/// config when startup fails.
class WindowsSingBoxSupervisor final : public AgentCore {
  public:
    explicit WindowsSingBoxSupervisor(WindowsSingBoxOptions options);
    ~WindowsSingBoxSupervisor();

    WindowsSingBoxSupervisor(const WindowsSingBoxSupervisor&) = delete;
    WindowsSingBoxSupervisor& operator=(const WindowsSingBoxSupervisor&) = delete;

    void apply_config(std::string_view contents) override;
    void ensure_alive() override;
    void reload() override;
    void restart() override;
    void stop() override;
    [[nodiscard]] bool running() override;
    [[nodiscard]] std::optional<std::string> last_error() const override;

    [[nodiscard]] std::uint16_t clash_port() const noexcept;
    [[nodiscard]] std::string clash_secret() const;
    [[nodiscard]] std::uint16_t route_test_port() const noexcept;
    [[nodiscard]] std::string route_test_password() const;
    void set_strict_route(bool enabled) noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy::win
