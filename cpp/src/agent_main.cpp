#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <sys/wait.h>

#include "sbeasy/agent_clash.hpp"
#include "sbeasy/agent_client.hpp"
#include "sbeasy/atomic_file.hpp"

extern char** environ;

namespace {

struct ProcessResult {
    bool success{false};
    std::string detail;
};

[[nodiscard]] std::string environment(const char* name, std::string fallback = {}) {
    const auto* value = std::getenv(name);
    return value == nullptr ? std::move(fallback) : std::string{value};
}

[[nodiscard]] bool environment_flag(const char* name, bool fallback) {
    auto value = environment(name);
    if (value.empty()) {
        return fallback;
    }
    for (auto& character : value) {
        character =
            static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

[[nodiscard]] std::chrono::seconds poll_interval() {
    const auto value = environment("AGENT_INTERVAL", "10");
    std::uint64_t seconds{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), seconds);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::invalid_argument("AGENT_INTERVAL must be an integer");
    }
    return std::chrono::seconds{std::max<std::uint64_t>(seconds, 2U)};
}

[[nodiscard]] std::vector<std::string> split_command_line(std::string_view command) {
    std::vector<std::string> arguments;
    std::string current;
    char quote{};
    bool escaped{false};
    bool started{false};
    for (const char character : command) {
        if (escaped) {
            current.push_back(character);
            escaped = false;
            started = true;
            continue;
        }
        if (character == '\\' && quote != '\'') {
            escaped = true;
            started = true;
            continue;
        }
        if (quote != 0) {
            if (character == quote) {
                quote = 0;
            } else {
                current.push_back(character);
            }
            started = true;
            continue;
        }
        if (character == '\'' || character == '"') {
            quote = character;
            started = true;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(character)) != 0) {
            if (started) {
                arguments.push_back(std::move(current));
                current.clear();
                started = false;
            }
            continue;
        }
        current.push_back(character);
        started = true;
    }
    if (escaped || quote != 0) {
        throw std::invalid_argument("unterminated command escape or quote");
    }
    if (started) {
        arguments.push_back(std::move(current));
    }
    return arguments;
}

[[nodiscard]] ProcessResult run_program(const std::vector<std::string>& arguments) {
    if (arguments.empty() || arguments.front().empty()) {
        return {.success = false, .detail = "command is empty"};
    }
    std::vector<char*> native_arguments;
    native_arguments.reserve(arguments.size() + 1U);
    for (const auto& argument : arguments) {
        native_arguments.push_back(const_cast<char*>(argument.c_str()));
    }
    native_arguments.push_back(nullptr);

    pid_t process{};
    const int spawn_error = ::posix_spawnp(&process, native_arguments.front(), nullptr,
                                           nullptr, native_arguments.data(), environ);
    if (spawn_error != 0) {
        return {.success = false,
                .detail = std::string{"spawn failed: "} + std::strerror(spawn_error)};
    }
    int status{};
    while (::waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            return {.success = false,
                    .detail = std::string{"wait failed: "} + std::strerror(errno)};
        }
    }
    if (WIFEXITED(status)) {
        const auto code = WEXITSTATUS(status);
        return {
            .success = code == 0,
            .detail = "exit code " + std::to_string(code),
        };
    }
    if (WIFSIGNALED(status)) {
        return {.success = false,
                .detail = "terminated by signal " + std::to_string(WTERMSIG(status))};
    }
    return {.success = false, .detail = "process ended without an exit status"};
}

[[nodiscard]] std::optional<std::string>
read_existing(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        if (!std::filesystem::exists(path)) {
            return std::nullopt;
        }
        throw std::runtime_error("cannot read existing config: " + path.string());
    }
    return std::string{std::istreambuf_iterator<char>{input},
                       std::istreambuf_iterator<char>{}};
}

[[nodiscard]] std::optional<std::vector<std::string>>
proxy_test_tags(std::string_view command) {
    constexpr std::string_view prefix{"test-proxies"};
    if (command == prefix) {
        return std::nullopt;
    }
    if (!command.starts_with(prefix) || command.size() <= prefix.size() ||
        std::isspace(static_cast<unsigned char>(command[prefix.size()])) == 0) {
        throw std::invalid_argument("not a test-proxies command");
    }
    auto suffix = command.substr(prefix.size());
    while (!suffix.empty() &&
           std::isspace(static_cast<unsigned char>(suffix.front())) != 0) {
        suffix.remove_prefix(1U);
    }
    auto parsed = nlohmann::json::parse(suffix, nullptr, false);
    if (!parsed.is_array()) {
        return std::nullopt;
    }
    std::vector<std::string> tags;
    tags.reserve(parsed.size());
    for (const auto& value : parsed) {
        if (!value.is_string()) {
            return std::nullopt;
        }
        tags.push_back(value.get<std::string>());
    }
    return tags;
}

class AgentRuntime final {
  public:
    AgentRuntime()
        : server_(environment("SB_EASY_SERVER")), token_(environment("AGENT_TOKEN")),
          config_path_(environment("SINGBOX_CONFIG_PATH", "data/sing-box.gen.json")),
          singbox_bin_(environment("SINGBOX_BIN", "sing-box")),
          reload_command_(split_command_line(
              environment("RELOAD_CMD", "systemctl reload sing-box"))),
          restart_command_(split_command_line(
              environment("RESTART_CMD", "systemctl restart sing-box"))),
          validate_config_(environment_flag("SINGBOX_VALIDATE_CONFIG", true)),
          client_({.server = server_, .token = token_}), clash_(config_path_) {
        if (server_.empty()) {
            throw std::invalid_argument("SB_EASY_SERVER is required");
        }
        if (token_.empty()) {
            throw std::invalid_argument("AGENT_TOKEN is required");
        }
    }

    [[nodiscard]] bool run_cycle() {
        bool healthy = true;
        try {
            const auto config = client_.poll_config(last_etag_);
            if (config.modified) {
                apply_config(config);
            }
        } catch (const std::exception& error) {
            healthy = false;
            running_ = false;
            std::cerr << "config poll/apply failed: " << error.what() << '\n';
        }

        try {
            run_commands();
        } catch (const std::exception& error) {
            healthy = false;
            std::cerr << "command poll failed: " << error.what() << '\n';
        }

        try {
            if (auto telemetry = clash_.sample_telemetry(); telemetry.has_value()) {
                client_.report_telemetry(*telemetry);
            }
        } catch (const std::exception& error) {
            // Telemetry is best effort and must not make an otherwise healthy
            // config/status cycle fail when the local Clash API is disabled.
            std::cerr << "telemetry sample failed: " << error.what() << '\n';
        }

        try {
            client_.report_status("sb-easy-cpp-agent/0.1.0", running_, last_etag_);
        } catch (const std::exception& error) {
            healthy = false;
            std::cerr << "status report failed: " << error.what() << '\n';
        }
        return healthy;
    }

  private:
    void apply_config(const sbeasy::AgentConfigResponse& config) {
        const auto previous = read_existing(config_path_);
        const auto validator = [this](const std::filesystem::path& temporary) {
            if (!validate_config_) {
                return;
            }
            const auto checked =
                run_program({singbox_bin_, "check", "-c", temporary.string()});
            if (!checked.success) {
                throw std::runtime_error("sing-box config validation failed: " +
                                         checked.detail);
            }
        };
        sbeasy::atomic_replace_file(config_path_, config.body, validator);

        const auto reloaded = run_program(reload_command_);
        if (!reloaded.success) {
            if (previous.has_value()) {
                sbeasy::atomic_replace_file(config_path_, *previous);
                static_cast<void>(run_program(reload_command_));
            }
            throw std::runtime_error("sing-box reload failed: " + reloaded.detail);
        }
        running_ = true;
        last_etag_ = config.etag;
        std::cout << "applied config " << config.etag << '\n';
    }

    void run_commands() {
        for (const auto& command : client_.pending_commands()) {
            ProcessResult result;
            bool changes_running_state = false;
            if (command.command == "reload") {
                result = run_program(reload_command_);
                changes_running_state = true;
            } else if (command.command == "restart") {
                result = run_program(restart_command_);
                changes_running_state = true;
            } else if (command.command == "test-proxies" ||
                       command.command.starts_with("test-proxies ")) {
                try {
                    const auto tested = clash_.test_proxies(
                        proxy_test_tags(command.command), [this](const auto& latency) {
                            static_cast<void>(client_.report_proxy_latencies(latency));
                        });
                    result = {
                        .success = true,
                        .detail = "tested " + std::to_string(tested) + " proxies",
                    };
                } catch (const std::exception& error) {
                    result = {
                        .success = false,
                        .detail = "test-proxies: " + std::string{error.what()},
                    };
                }
            } else {
                result.detail = "unknown command: " + command.command;
            }
            if (changes_running_state) {
                running_ = result.success;
            }
            client_.acknowledge_command(command.id, result.success, result.detail);
        }
    }

    std::string server_;
    std::string token_;
    std::filesystem::path config_path_;
    std::string singbox_bin_;
    std::vector<std::string> reload_command_;
    std::vector<std::string> restart_command_;
    bool validate_config_{true};
    sbeasy::AgentClient client_;
    sbeasy::AgentClashService clash_;
    std::optional<std::string> last_etag_;
    std::optional<bool> running_;
};

void usage(const char* executable) {
    std::cerr << "Usage: " << executable << " [--once]\n"
              << "Required environment: SB_EASY_SERVER, AGENT_TOKEN\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        bool once = false;
        if (argc == 2 && std::string_view{argv[1]} == "--once") {
            once = true;
        } else if (argc != 1) {
            usage(argv[0]);
            return 2;
        }

        AgentRuntime runtime;
        if (once) {
            return runtime.run_cycle() ? 0 : 1;
        }
        const auto interval = poll_interval();
        while (true) {
            static_cast<void>(runtime.run_cycle());
            std::this_thread::sleep_for(interval);
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
