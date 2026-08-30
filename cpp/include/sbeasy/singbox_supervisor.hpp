#pragma once

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace sbeasy {

struct SingBoxSupervisorOptions {
    std::string binary{"sing-box"};
    std::filesystem::path config_path{"data/sing-box.gen.json"};
    bool validate_config{true};
    std::chrono::milliseconds restart_backoff{1'000};
    std::chrono::milliseconds shutdown_timeout{2'000};
};

/// Owns a sing-box runtime and its validated atomic config. Normal builds use
/// a supervised child; SB_EASY_EMBED_SINGBOX builds run the engine in-process.
class SingBoxSupervisor final {
  public:
    explicit SingBoxSupervisor(SingBoxSupervisorOptions options);
    ~SingBoxSupervisor();

    SingBoxSupervisor(const SingBoxSupervisor&) = delete;
    SingBoxSupervisor& operator=(const SingBoxSupervisor&) = delete;
    SingBoxSupervisor(SingBoxSupervisor&&) = delete;
    SingBoxSupervisor& operator=(SingBoxSupervisor&&) = delete;

    /// Validate and atomically install a config, then SIGHUP a live child or
    /// start a new child.
    void apply_config(std::string_view contents);

    /// Reap an exited child and respawn it after the configured crash backoff.
    void ensure_alive();
    void reload();
    void restart();
    void stop() noexcept;

    [[nodiscard]] bool running();
    [[nodiscard]] std::optional<pid_t> pid();
    [[nodiscard]] const std::optional<std::string>& last_error() const noexcept;

  private:
    void validate(const std::filesystem::path& path) const;
    void reap();
    void start(bool ignore_backoff);

    SingBoxSupervisorOptions options_;
#if defined(SB_EASY_EMBED_SINGBOX)
    bool running_{false};
#else
    pid_t child_{-1};
#endif
    bool has_started_{false};
    std::chrono::steady_clock::time_point next_start_{};
    std::optional<std::string> last_error_;
};

} // namespace sbeasy
