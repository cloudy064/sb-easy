#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
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
#include "sbeasy/agent_config.hpp"
#include "sbeasy/agent_ui.hpp"
#include "sbeasy/atomic_file.hpp"
#include "sbeasy/singbox_supervisor.hpp"
#include "sbeasy/version.hpp"

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

[[nodiscard]] std::filesystem::path config_path() {
    auto value = environment("SINGBOX_CONFIG_PATH");
    if (value.empty()) {
        value = environment("SELF_SINGBOX_CONFIG_PATH");
    }
    return value.empty() ? std::filesystem::path{"data/sing-box.gen.json"}
                         : std::filesystem::path{value};
}

[[nodiscard]] std::filesystem::path
settings_path(const std::filesystem::path& singbox_config_path) {
    const auto value = environment("AGENT_UI_SETTINGS_PATH");
    if (!value.empty()) {
        return value;
    }
    auto directory = singbox_config_path.parent_path();
    if (directory.empty()) {
        directory = ".";
    }
    return directory / "agent-ui-settings.json";
}

[[nodiscard]] std::uint16_t parse_port(std::string_view value,
                                       std::string_view variable) {
    std::uint32_t port{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0U ||
        port > 65'535U) {
        throw std::invalid_argument(std::string{variable} +
                                    " must contain a valid TCP port");
    }
    return static_cast<std::uint16_t>(port);
}

[[nodiscard]] sbeasy::AgentLocalUiOptions local_ui_options() {
    const auto bind = environment("AGENT_UI_BIND", "0.0.0.0:51822");
    std::string address;
    std::string_view port;
    if (bind.starts_with('[')) {
        const auto bracket = bind.find(']');
        if (bracket == std::string::npos || bracket + 2U > bind.size() ||
            bind[bracket + 1U] != ':') {
            throw std::invalid_argument(
                "AGENT_UI_BIND IPv6 addresses must use [address]:port");
        }
        address = bind.substr(1U, bracket - 1U);
        port = std::string_view{bind}.substr(bracket + 2U);
    } else {
        const auto colon = bind.rfind(':');
        if (colon == std::string::npos) {
            throw std::invalid_argument("AGENT_UI_BIND must use address:port");
        }
        address = bind.substr(0U, colon);
        port = std::string_view{bind}.substr(colon + 1U);
    }
    if (address.empty()) {
        throw std::invalid_argument("AGENT_UI_BIND address must not be empty");
    }
    return {
        .address = std::move(address),
        .port = parse_port(port, "AGENT_UI_BIND"),
        .username = environment("AGENT_UI_USERNAME", "admin"),
        .password = environment("AGENT_UI_PASSWORD"),
    };
}

[[nodiscard]] std::string current_time_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto value = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    if (::gmtime_r(&value, &utc) == nullptr) {
        return {};
    }
    std::array<char, 32> buffer{};
    if (std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) {
        return {};
    }
    return buffer.data();
}

[[nodiscard]] std::map<std::string, std::string> outbound_server_overrides() {
    const auto value = environment("SINGBOX_OUTBOUND_SERVER_OVERRIDES");
    if (value.empty()) {
        return {};
    }
    const auto parsed = nlohmann::json::parse(value);
    if (!parsed.is_object()) {
        throw std::invalid_argument(
            "SINGBOX_OUTBOUND_SERVER_OVERRIDES must be a JSON object");
    }
    std::map<std::string, std::string> overrides;
    for (const auto& [tag, server] : parsed.items()) {
        if (!server.is_string()) {
            throw std::invalid_argument("outbound server override for " + tag +
                                        " must be a string");
        }
        overrides.emplace(tag, server.get<std::string>());
    }
    return overrides;
}

[[nodiscard]] std::map<std::string, nlohmann::json> outbound_overrides() {
    const auto path = environment("SINGBOX_OUTBOUND_OVERRIDE_FILE");
    if (path.empty()) {
        return {};
    }
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        throw std::runtime_error("cannot read outbound override file: " + path);
    }
    const auto parsed = nlohmann::json::parse(input);
    if (!parsed.is_object()) {
        throw std::invalid_argument(
            "SINGBOX_OUTBOUND_OVERRIDE_FILE must contain a JSON object");
    }
    std::map<std::string, nlohmann::json> overrides;
    for (const auto& [tag, outbound] : parsed.items()) {
        if (!outbound.is_object()) {
            throw std::invalid_argument("outbound override for " + tag +
                                        " must be a JSON object");
        }
        overrides.emplace(tag, outbound);
    }
    return overrides;
}

[[nodiscard]] sbeasy::AgentConfigTransformOptions transform_options() {
    auto default_outbound = environment("SINGBOX_DEFAULT_PROXY_OUTBOUND");
    return {
        .local_proxy_egress = environment_flag("SINGBOX_LOCAL_PROXY_EGRESS", true),
        .outbound_server_overrides = outbound_server_overrides(),
        .outbound_overrides = outbound_overrides(),
        .default_proxy_outbound =
            default_outbound.empty()
                ? std::nullopt
                : std::optional<std::string>{std::move(default_outbound)},
    };
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
          config_path_(config_path()), settings_path_(settings_path(config_path_)),
          singbox_bin_(environment("SINGBOX_BIN", "sing-box")),
          singbox_managed_(environment_flag("SINGBOX_MANAGED", true)),
          reload_command_(split_command_line(
              environment("RELOAD_CMD", "systemctl reload sing-box"))),
          restart_command_(split_command_line(
              environment("RESTART_CMD", "systemctl restart sing-box"))),
          validate_config_(environment_flag("SINGBOX_VALIDATE_CONFIG", true)),
          transform_options_(sbeasy::load_agent_config_transform_options(
              settings_path_, transform_options())),
          supervisor_({
              .binary = singbox_bin_,
              .config_path = config_path_,
              .validate_config = validate_config_,
          }),
          client_({.server = server_, .token = token_}), clash_(config_path_) {
        if (server_.empty()) {
            throw std::invalid_argument("SB_EASY_SERVER is required");
        }
        if (token_.empty()) {
            throw std::invalid_argument("AGENT_TOKEN is required");
        }
    }

    [[nodiscard]] bool run_cycle() {
        std::vector<std::string> errors;
        const auto actions = take_queued_actions();
        try {
            const auto config = client_.poll_config(etag());
            if (config.modified) {
                apply_config(config);
            } else {
                set_rule_source(config.rule_source);
            }
        } catch (const std::exception& error) {
            record_error(errors, "config poll/apply", error);
        }

        try {
            run_local_action(actions);
        } catch (const std::exception& error) {
            record_error(errors, "local action", error);
        }

        if (singbox_managed_) {
            supervisor_.ensure_alive();
            set_running(supervisor_.running());
            if (supervisor_.last_error().has_value()) {
                errors.push_back("managed sing-box: " + *supervisor_.last_error());
                std::cerr << errors.back() << '\n';
            }
        }

        try {
            run_commands();
        } catch (const std::exception& error) {
            record_error(errors, "command poll", error);
        }

        try {
            if (auto telemetry = clash_.sample_telemetry(); telemetry.has_value()) {
                update_local_telemetry(*telemetry);
                client_.report_telemetry(*telemetry);
            }
        } catch (const std::exception& error) {
            // Telemetry is best effort and must not make an otherwise healthy
            // config/status cycle fail when the local Clash API is disabled.
            std::cerr << "telemetry sample failed: " << error.what() << '\n';
        }

        try {
            client_.report_status("sb-easy-cpp-agent/" +
                                      std::string{sbeasy::application_version},
                                  running(), etag());
        } catch (const std::exception& error) {
            record_error(errors, "status report", error);
        }
        finish_cycle(errors);
        return errors.empty();
    }

    void wait_for_work(std::chrono::seconds interval) {
        std::unique_lock lock{state_mutex_};
        static_cast<void>(wakeup_.wait_for(lock, interval, [this] {
            return refresh_requested_ || reload_requested_ || restart_requested_;
        }));
    }

    [[nodiscard]] sbeasy::AgentUiCallbacks ui_callbacks() {
        return {
            .status = [this] { return ui_status(); },
            .settings = [this] { return ui_settings(); },
            .update_settings =
                [this](const nlohmann::json& value) {
                    return ui_update_settings(value);
                },
            .config = [this] { return ui_config(); },
            .proxies = [this] { return ui_proxies(); },
            .request_action =
                [this](const std::string& action) { queue_action(action); },
        };
    }

  private:
    struct QueuedActions {
        bool reload{false};
        bool restart{false};
    };

    static void record_error(std::vector<std::string>& errors,
                             std::string_view operation, const std::exception& error) {
        errors.push_back(std::string{operation} + ": " + error.what());
        std::cerr << errors.back() << '\n';
    }

    [[nodiscard]] QueuedActions take_queued_actions() {
        std::lock_guard lock{state_mutex_};
        if (refresh_requested_) {
            last_etag_.reset();
        }
        const QueuedActions actions{
            .reload = reload_requested_,
            .restart = restart_requested_,
        };
        refresh_requested_ = false;
        reload_requested_ = false;
        restart_requested_ = false;
        return actions;
    }

    void finish_cycle(const std::vector<std::string>& errors) {
        std::string joined;
        for (const auto& error : errors) {
            if (!joined.empty()) {
                joined += "; ";
            }
            joined += error;
        }
        std::lock_guard lock{state_mutex_};
        last_cycle_ = current_time_iso8601();
        last_error_ = joined.empty() ? std::nullopt
                                     : std::optional<std::string>{std::move(joined)};
    }

    [[nodiscard]] std::optional<std::string> etag() const {
        std::lock_guard lock{state_mutex_};
        return last_etag_;
    }

    void set_etag(std::string value) {
        std::lock_guard lock{state_mutex_};
        last_etag_ = std::move(value);
    }

    void set_rule_source(std::string value) {
        std::lock_guard lock{state_mutex_};
        last_rule_source_ = value == "quickjs" ? "quickjs" : "profile";
    }

    [[nodiscard]] std::optional<bool> running() const {
        std::lock_guard lock{state_mutex_};
        return running_;
    }

    void set_running(bool value) {
        std::lock_guard lock{state_mutex_};
        running_ = value;
    }

    void update_local_telemetry(const nlohmann::json& telemetry) {
        const auto integer = [&telemetry](const char* field) {
            const auto found = telemetry.find(field);
            return found != telemetry.end() &&
                           (found->is_number_integer() || found->is_number_unsigned())
                       ? *found
                       : nlohmann::json{0};
        };
        std::lock_guard lock{state_mutex_};
        last_telemetry_ = {
            {"available", true},
            {"sampled_at", current_time_iso8601()},
            {"up", integer("up")},
            {"down", integer("down")},
            {"up_total", integer("up_total")},
            {"down_total", integer("down_total")},
            {"conn_count", integer("conn_count")},
        };
    }

    void apply_config(const sbeasy::AgentConfigResponse& config) {
        sbeasy::AgentConfigTransformOptions options;
        {
            std::lock_guard lock{state_mutex_};
            options = transform_options_;
        }
        const auto prepared = sbeasy::prepare_agent_config(config.body, options);
        if (singbox_managed_) {
            supervisor_.apply_config(prepared);
            set_running(supervisor_.running());
            set_etag(config.etag);
            set_rule_source(config.rule_source);
            std::cout << "applied config " << config.etag << '\n';
            return;
        }

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
        sbeasy::atomic_replace_file(config_path_, prepared, validator);

        const auto reloaded = run_program(reload_command_);
        if (!reloaded.success) {
            if (previous.has_value()) {
                sbeasy::atomic_replace_file(config_path_, *previous);
                static_cast<void>(run_program(reload_command_));
            }
            throw std::runtime_error("sing-box reload failed: " + reloaded.detail);
        }
        set_running(true);
        set_etag(config.etag);
        set_rule_source(config.rule_source);
        std::cout << "applied config " << config.etag << '\n';
    }

    void run_local_action(const QueuedActions& actions) {
        if (!actions.reload && !actions.restart) {
            return;
        }
        const bool restart = actions.restart;
        ProcessResult result;
        if (singbox_managed_) {
            try {
                if (restart) {
                    supervisor_.restart();
                } else {
                    supervisor_.reload();
                }
                result = {
                    .success = supervisor_.running(),
                    .detail = supervisor_.running()
                                  ? (restart ? "restarted" : "reloaded")
                                  : "sing-box did not start",
                };
            } catch (const std::exception& error) {
                result.detail = error.what();
            }
        } else {
            result = run_program(restart ? restart_command_ : reload_command_);
        }
        set_running(singbox_managed_ ? supervisor_.running() : result.success);
        if (!result.success) {
            throw std::runtime_error(result.detail);
        }
        std::cout << "local UI action completed: " << (restart ? "restart" : "reload")
                  << '\n';
    }

    void run_commands() {
        for (const auto& command : client_.pending_commands()) {
            ProcessResult result;
            bool changes_running_state = false;
            if (command.command == "reload") {
                if (singbox_managed_) {
                    try {
                        supervisor_.reload();
                        result = {
                            .success = supervisor_.running(),
                            .detail = supervisor_.running() ? "reloaded"
                                                            : "sing-box did not start",
                        };
                    } catch (const std::exception& error) {
                        result.detail = error.what();
                    }
                } else {
                    result = run_program(reload_command_);
                }
                changes_running_state = true;
            } else if (command.command == "restart") {
                if (singbox_managed_) {
                    try {
                        supervisor_.restart();
                        result = {
                            .success = supervisor_.running(),
                            .detail = supervisor_.running() ? "restarted"
                                                            : "sing-box did not start",
                        };
                    } catch (const std::exception& error) {
                        result.detail = error.what();
                    }
                } else {
                    result = run_program(restart_command_);
                }
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
                set_running(singbox_managed_ ? supervisor_.running() : result.success);
            }
            client_.acknowledge_command(command.id, result.success, result.detail);
        }
    }

    [[nodiscard]] nlohmann::json ui_status() const {
        std::lock_guard lock{state_mutex_};
        return {
            {"service", "sb-easy-cpp-agent"},
            {"version", sbeasy::application_version},
            {"server", server_},
            {"config_path", config_path_.string()},
            {"settings_path", settings_path_.string()},
            {"singbox_managed", singbox_managed_},
            {"running", running_.has_value() ? nlohmann::json(*running_)
                                             : nlohmann::json(nullptr)},
            {"etag", last_etag_.has_value() ? nlohmann::json(*last_etag_)
                                            : nlohmann::json(nullptr)},
            {"last_cycle", last_cycle_.has_value() ? nlohmann::json(*last_cycle_)
                                                   : nlohmann::json(nullptr)},
            {"last_error", last_error_.has_value() ? nlohmann::json(*last_error_)
                                                   : nlohmann::json(nullptr)},
            {"rule_source", last_rule_source_},
            {"pending",
             {
                 {"refresh", refresh_requested_},
                 {"reload", reload_requested_},
                 {"restart", restart_requested_},
             }},
            {"telemetry", last_telemetry_},
        };
    }

    [[nodiscard]] nlohmann::json ui_settings() const {
        std::lock_guard lock{state_mutex_};
        return sbeasy::agent_config_transform_options_to_json(transform_options_);
    }

    [[nodiscard]] nlohmann::json ui_update_settings(const nlohmann::json& value) {
        sbeasy::AgentConfigTransformOptions current;
        {
            std::lock_guard lock{state_mutex_};
            current = transform_options_;
        }
        auto updated = sbeasy::agent_config_transform_options_from_json(value, current);
        sbeasy::save_agent_config_transform_options(settings_path_, updated);
        {
            std::lock_guard lock{state_mutex_};
            transform_options_ = updated;
            refresh_requested_ = true;
        }
        wakeup_.notify_one();
        return sbeasy::agent_config_transform_options_to_json(updated);
    }

    [[nodiscard]] nlohmann::json ui_config() const {
        const auto contents = read_existing(config_path_);
        if (!contents.has_value()) {
            return nlohmann::json::object();
        }
        return nlohmann::json::parse(*contents);
    }

    [[nodiscard]] nlohmann::json ui_proxies() const {
        const auto config = ui_config();
        const auto outbounds = config.find("outbounds");
        if (outbounds == config.end() || !outbounds->is_array()) {
            return nlohmann::json::array();
        }
        std::set<std::string> selected;
        if (const auto route = config.find("route");
            route != config.end() && route->is_object()) {
            if (const auto final = route->find("final");
                final != route->end() && final->is_string()) {
                selected.emplace(final->get<std::string>());
            }
        }
        for (const auto& outbound : *outbounds) {
            if (outbound.is_object()) {
                if (const auto value = outbound.find("default");
                    value != outbound.end() && value->is_string()) {
                    selected.emplace(value->get<std::string>());
                }
            }
        }
        auto proxies = nlohmann::json::array();
        for (const auto& outbound : *outbounds) {
            if (!outbound.is_object()) {
                continue;
            }
            const auto tag = outbound.value("tag", std::string{});
            if (tag.empty()) {
                continue;
            }
            proxies.push_back({
                {"tag", tag},
                {"type", outbound.value("type", std::string{"unknown"})},
                {"default", selected.contains(tag)},
            });
        }
        return proxies;
    }

    void queue_action(const std::string& action) {
        {
            std::lock_guard lock{state_mutex_};
            if (action == "refresh") {
                refresh_requested_ = true;
            } else if (action == "reload") {
                reload_requested_ = true;
            } else if (action == "restart") {
                restart_requested_ = true;
            } else {
                throw std::invalid_argument("unsupported Agent UI action");
            }
        }
        wakeup_.notify_one();
    }

    std::string server_;
    std::string token_;
    std::filesystem::path config_path_;
    std::filesystem::path settings_path_;
    std::string singbox_bin_;
    bool singbox_managed_{true};
    std::vector<std::string> reload_command_;
    std::vector<std::string> restart_command_;
    bool validate_config_{true};
    sbeasy::AgentConfigTransformOptions transform_options_;
    sbeasy::SingBoxSupervisor supervisor_;
    sbeasy::AgentClient client_;
    sbeasy::AgentClashService clash_;
    mutable std::mutex state_mutex_;
    std::condition_variable wakeup_;
    std::optional<std::string> last_etag_;
    std::optional<bool> running_;
    std::optional<std::string> last_cycle_;
    std::optional<std::string> last_error_;
    nlohmann::json last_telemetry_{
        {"available", false}, {"sampled_at", nullptr}, {"up", 0},         {"down", 0},
        {"up_total", 0},      {"down_total", 0},       {"conn_count", 0},
    };
    std::string last_rule_source_{"profile"};
    bool refresh_requested_{false};
    bool reload_requested_{false};
    bool restart_requested_{false};
};

void usage(const char* executable) {
    std::cerr << "Usage: " << executable << " [--once]\n"
              << "Required environment: SB_EASY_SERVER, AGENT_TOKEN\n"
              << "Local UI: set AGENT_UI_PASSWORD; bind defaults to "
                 "0.0.0.0:51822\n";
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
        std::unique_ptr<sbeasy::AgentLocalUi> local_ui;
        if (environment_flag("AGENT_UI_ENABLED", true)) {
            auto options = local_ui_options();
            if (options.password.empty()) {
                std::cerr << "Agent UI disabled: set AGENT_UI_PASSWORD to expose "
                             "the management interface\n";
            } else {
                const auto address = options.address;
                local_ui = std::make_unique<sbeasy::AgentLocalUi>(
                    std::move(options), runtime.ui_callbacks());
                std::cout << "Agent UI listening on " << address << ':'
                          << local_ui->port() << '\n';
            }
        }
        const auto interval = poll_interval();
        while (true) {
            static_cast<void>(runtime.run_cycle());
            runtime.wait_for_work(interval);
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
