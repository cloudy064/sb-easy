#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/agent_clash.hpp"
#include "sbeasy/agent_client.hpp"
#include "sbeasy/agent_config.hpp"
#include "sbeasy/agent_runtime.hpp"
#include "sbeasy/agent_ui.hpp"
#include "sbeasy/platform_adapters.hpp"
#include "sbeasy/singbox_supervisor.hpp"
#include "sbeasy/version.hpp"

namespace {

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

[[nodiscard]] std::filesystem::path
device_credential_path(const std::filesystem::path& singbox_config_path) {
    const auto value = environment("AGENT_CREDENTIAL_PATH");
    if (!value.empty()) {
        return value;
    }
    auto directory = singbox_config_path.parent_path();
    if (directory.empty()) {
        directory = ".";
    }
    return directory / "device-credential.json";
}

struct AgentIdentity {
    std::string server;
    std::string token;
    std::string host_id;
    std::string host_name;
    std::string profile_id;
    std::string profile_name;
};

[[nodiscard]] std::optional<AgentIdentity>
load_device_credential(const sbeasy::PlatformStorage& storage,
                       const std::filesystem::path& path) {
    const auto contents = storage.read(path);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    const auto parsed = nlohmann::json::parse(*contents, nullptr, false);
    if (!parsed.is_object()) {
        throw std::runtime_error("device credential is not valid JSON: " +
                                 path.string());
    }
    AgentIdentity identity{
        .server = parsed.value("server", std::string{}),
        .token = parsed.value("agent_token", std::string{}),
        .host_id = parsed.value("host_id", std::string{}),
        .host_name = parsed.value("host_name", std::string{}),
        .profile_id = parsed.value("profile_id", std::string{}),
        .profile_name = parsed.value("profile_name", std::string{}),
    };
    if (identity.server.empty() || identity.token.empty()) {
        throw std::runtime_error("device credential is incomplete: " + path.string());
    }
    return identity;
}

void save_device_credential(sbeasy::PlatformStorage& storage,
                            const std::filesystem::path& path,
                            const sbeasy::DeviceCredential& credential) {
    const auto serialized =
        nlohmann::json{
            {"server", credential.server},
            {"host_id", credential.host_id},
            {"host_name", credential.host_name},
            {"agent_token", credential.token},
            {"profile_id", credential.profile_id},
            {"profile_name", credential.profile_name},
        }
            .dump(2);
    storage.replace(path, serialized + "\n");
}

[[nodiscard]] AgentIdentity
resolve_agent_identity(sbeasy::PlatformStorage& storage,
                       const sbeasy::PlatformMetadata& metadata,
                       const std::filesystem::path& credential_path) {
    const auto environment_server = environment("SB_EASY_SERVER");
    const auto environment_token = environment("AGENT_TOKEN");
    if (!environment_token.empty()) {
        if (environment_server.empty()) {
            throw std::invalid_argument(
                "SB_EASY_SERVER is required when AGENT_TOKEN is set");
        }
        return {
            .server = environment_server,
            .token = environment_token,
        };
    }

    if (auto persisted = load_device_credential(storage, credential_path);
        persisted.has_value()) {
        return std::move(*persisted);
    }

    const auto enrollment_code = environment("AGENT_ENROLLMENT_CODE");
    if (environment_server.empty() || enrollment_code.empty()) {
        throw std::invalid_argument(
            "set SB_EASY_SERVER with AGENT_ENROLLMENT_CODE for first-time "
            "enrollment, or provide an existing AGENT_TOKEN");
    }
    const auto credential = sbeasy::enroll_device({
        .server = environment_server,
        .code = enrollment_code,
        .device = metadata.device_metadata(),
    });
    save_device_credential(storage, credential_path, credential);
    std::cout << "device enrolled as " << credential.host_name << " ("
              << credential.host_id << ")\n";
    return {
        .server = credential.server,
        .token = credential.token,
        .host_id = credential.host_id,
        .host_name = credential.host_name,
        .profile_id = credential.profile_id,
        .profile_name = credential.profile_name,
    };
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
    sbeasy::PosixStorage storage;
    const auto contents = storage.read(path);
    if (!contents.has_value()) {
        throw std::runtime_error("cannot read outbound override file: " + path);
    }
    const auto parsed = nlohmann::json::parse(*contents);
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

[[nodiscard]] sbeasy::AgentConfigTransformOptions transform_defaults() {
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

[[nodiscard]] sbeasy::AgentConfigTransformOptions
load_transform_options(const sbeasy::PlatformStorage& storage,
                       const std::filesystem::path& path,
                       const sbeasy::AgentConfigTransformOptions& defaults) {
    const auto contents = storage.read(path);
    if (!contents.has_value()) {
        return defaults;
    }
    try {
        return sbeasy::agent_config_transform_options_from_json(
            nlohmann::json::parse(*contents), defaults);
    } catch (const std::exception& error) {
        throw std::invalid_argument("invalid agent settings " + path.string() + ": " +
                                    error.what());
    }
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

class PosixAgentCore final : public sbeasy::AgentCore {
  public:
    explicit PosixAgentCore(sbeasy::SingBoxSupervisorOptions options)
        : supervisor_(std::move(options)) {}

    void apply_config(std::string_view contents) override {
        supervisor_.apply_config(contents);
    }
    void ensure_alive() override {
        supervisor_.ensure_alive();
    }
    void reload() override {
        supervisor_.reload();
    }
    void restart() override {
        supervisor_.restart();
    }
    void stop() override {
        supervisor_.stop();
    }
    [[nodiscard]] bool running() override {
        return supervisor_.running();
    }
    [[nodiscard]] std::optional<std::string> last_error() const override {
        return supervisor_.last_error();
    }

  private:
    sbeasy::SingBoxSupervisor supervisor_;
};

class ClashAgentRuntime final : public sbeasy::AgentLocalRuntime {
  public:
    explicit ClashAgentRuntime(std::filesystem::path config_path)
        : clash_(std::move(config_path)) {}

    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) override {
        return clash_.test_proxies(tags, reporter);
    }
    [[nodiscard]] std::optional<nlohmann::json> sample_telemetry() override {
        return clash_.sample_telemetry();
    }
    [[nodiscard]] nlohmann::json test_route(const std::string& url) override {
        return clash_.test_route(url);
    }

  private:
    sbeasy::AgentClashService clash_;
};

void usage(const char* executable) {
    std::cerr << "Usage: " << executable << " [--once]\n"
              << "First use: SB_EASY_SERVER, AGENT_ENROLLMENT_CODE\n"
              << "Compatibility: SB_EASY_SERVER, AGENT_TOKEN\n"
              << "Enrolled credentials default beside the sing-box config; "
                 "override with AGENT_CREDENTIAL_PATH\n"
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

        const auto singbox_config_path = config_path();
        const auto ui_settings_path = settings_path(singbox_config_path);
        sbeasy::PosixStorage storage;
        sbeasy::PosixPlatformMetadata metadata;
        const auto identity = resolve_agent_identity(
            storage, metadata, device_credential_path(singbox_config_path));
        const auto singbox_binary = environment("SINGBOX_BIN", "sing-box");
        const bool singbox_managed = environment_flag("SINGBOX_MANAGED", true);
        const bool validate_config = environment_flag("SINGBOX_VALIDATE_CONFIG", true);

        sbeasy::AgentClient http({
            .server = identity.server,
            .token = identity.token,
        });
        sbeasy::PosixProcess process;
        sbeasy::SystemClock clock;
        PosixAgentCore core({
            .binary = singbox_binary,
            .config_path = singbox_config_path,
            .validate_config = validate_config,
        });
        ClashAgentRuntime local_runtime{singbox_config_path};
        sbeasy::AgentRuntime runtime(
            {
                .config_path = singbox_config_path,
                .settings_path = ui_settings_path,
                .server = identity.server,
                .service_name = "sb-easy-cpp-agent",
                .version =
                    "sb-easy-cpp-agent/" + std::string{sbeasy::application_version},
                .singbox_binary = singbox_binary,
                .singbox_managed = singbox_managed,
                .validate_config = validate_config,
                .reload_command = split_command_line(
                    environment("RELOAD_CMD", "systemctl reload sing-box")),
                .restart_command = split_command_line(
                    environment("RESTART_CMD", "systemctl restart sing-box")),
                .transform_options = load_transform_options(storage, ui_settings_path,
                                                            transform_defaults()),
            },
            {
                .http = http,
                .process = process,
                .storage = storage,
                .clock = clock,
                .metadata = metadata,
                .core = core,
                .local_runtime = local_runtime,
            });

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
                    std::move(options),
                    sbeasy::AgentUiCallbacks{
                        .status = [&runtime] { return runtime.status(); },
                        .settings = [&runtime] { return runtime.settings(); },
                        .update_settings =
                            [&runtime](const nlohmann::json& value) {
                                return runtime.update_settings(value);
                            },
                        .config = [&runtime] { return runtime.config(); },
                        .proxies = [&runtime] { return runtime.proxies(); },
                        .test_route =
                            [&runtime](const std::string& url) {
                                return runtime.test_route(url);
                            },
                        .request_action =
                            [&runtime](const std::string& action) {
                                runtime.queue_action(action);
                            },
                    });
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
