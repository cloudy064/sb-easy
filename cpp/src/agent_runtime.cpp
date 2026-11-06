#include "sbeasy/agent_runtime.hpp"

#include <cctype>
#include <iostream>
#include <set>
#include <stdexcept>
#include <utility>

namespace sbeasy {
namespace {

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
    const auto parsed = nlohmann::json::parse(suffix, nullptr, false);
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

} // namespace

AgentRuntime::AgentRuntime(AgentRuntimeOptions options,
                           AgentRuntimeDependencies dependencies)
    : options_(std::move(options)), dependencies_(dependencies),
      device_metadata_(dependencies_.metadata.device_metadata()) {
    if (options_.config_path.empty() || options_.settings_path.empty()) {
        throw std::invalid_argument("agent runtime paths must not be empty");
    }
    if (options_.version.empty()) {
        throw std::invalid_argument("agent runtime version must not be empty");
    }
    if (!device_metadata_.is_object()) {
        throw std::invalid_argument("platform metadata must be a JSON object");
    }
}

bool AgentRuntime::run_cycle() {
    std::vector<std::string> errors;
    const auto actions = take_queued_actions();
    try {
        const auto response = dependencies_.http.poll_config(etag());
        if (response.modified) {
            apply_config(response);
        } else {
            set_rule_source(response.rule_source);
        }
    } catch (const std::exception& error) {
        record_error(errors, "config poll/apply", error);
    }

    try {
        run_local_action(actions);
    } catch (const std::exception& error) {
        record_error(errors, "local action", error);
    }

    if (options_.singbox_managed && desired_running()) {
        dependencies_.core.ensure_alive();
        set_running(dependencies_.core.running());
        if (const auto error = dependencies_.core.last_error(); error.has_value()) {
            errors.push_back("managed sing-box: " + *error);
            std::cerr << errors.back() << '\n';
        }
    }

    try {
        run_commands();
    } catch (const std::exception& error) {
        record_error(errors, "command poll", error);
    }

    try {
        if (auto telemetry = dependencies_.local_runtime.sample_telemetry();
            telemetry.has_value()) {
            update_local_telemetry(*telemetry);
            dependencies_.http.report_telemetry(*telemetry);
        }
    } catch (const std::exception& error) {
        // Telemetry is best effort and must not make an otherwise healthy
        // config/status cycle fail when the local Clash API is disabled.
        std::cerr << "telemetry sample failed: " << error.what() << '\n';
    }

    try {
        dependencies_.http.report_status(options_.version, running(), etag());
    } catch (const std::exception& error) {
        record_error(errors, "status report", error);
    }
    finish_cycle(errors);
    return errors.empty();
}

void AgentRuntime::wait_for_work(std::chrono::seconds interval) {
    std::unique_lock lock{state_mutex_};
    static_cast<void>(wakeup_.wait_for(lock, interval, [this] {
        return refresh_requested_ || start_requested_ || stop_requested_ ||
               reload_requested_ || restart_requested_;
    }));
}

void AgentRuntime::record_error(std::vector<std::string>& errors,
                                std::string_view operation,
                                const std::exception& error) {
    errors.push_back(std::string{operation} + ": " + error.what());
    std::cerr << errors.back() << '\n';
}

AgentRuntime::QueuedActions AgentRuntime::take_queued_actions() {
    std::lock_guard lock{state_mutex_};
    if (refresh_requested_) {
        last_etag_.reset();
    }
    const QueuedActions actions{
        .start = start_requested_,
        .stop = stop_requested_,
        .reload = reload_requested_,
        .restart = restart_requested_,
    };
    refresh_requested_ = false;
    start_requested_ = false;
    stop_requested_ = false;
    reload_requested_ = false;
    restart_requested_ = false;
    return actions;
}

void AgentRuntime::finish_cycle(const std::vector<std::string>& errors) {
    std::string joined;
    for (const auto& error : errors) {
        if (!joined.empty()) {
            joined += "; ";
        }
        joined += error;
    }
    std::lock_guard lock{state_mutex_};
    last_cycle_ = dependencies_.clock.now_iso8601();
    last_error_ =
        joined.empty() ? std::nullopt : std::optional<std::string>{std::move(joined)};
}

std::optional<std::string> AgentRuntime::etag() const {
    std::lock_guard lock{state_mutex_};
    return last_etag_;
}

void AgentRuntime::set_etag(std::string value) {
    std::lock_guard lock{state_mutex_};
    last_etag_ = std::move(value);
}

void AgentRuntime::set_rule_source(std::string value) {
    std::lock_guard lock{state_mutex_};
    last_rule_source_ = value == "quickjs" ? "quickjs" : "profile";
}

std::optional<bool> AgentRuntime::running() const {
    std::lock_guard lock{state_mutex_};
    return running_;
}

bool AgentRuntime::desired_running() const {
    std::lock_guard lock{state_mutex_};
    return desired_running_;
}

void AgentRuntime::set_running(bool value) {
    std::lock_guard lock{state_mutex_};
    running_ = value;
}

void AgentRuntime::update_local_telemetry(const nlohmann::json& telemetry) {
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
        {"sampled_at", dependencies_.clock.now_iso8601()},
        {"up", integer("up")},
        {"down", integer("down")},
        {"up_total", integer("up_total")},
        {"down_total", integer("down_total")},
        {"conn_count", integer("conn_count")},
    };
}

void AgentRuntime::apply_config(const AgentConfigResponse& config_response) {
    AgentConfigTransformOptions transform;
    {
        std::lock_guard lock{state_mutex_};
        transform = options_.transform_options;
    }
    const auto prepared = prepare_agent_config(config_response.body, transform);
    if (options_.singbox_managed) {
        dependencies_.core.apply_config(prepared);
        dependencies_.local_runtime.policy_activated(config_response.etag);
        set_running(dependencies_.core.running());
        set_etag(config_response.etag);
        set_rule_source(config_response.rule_source);
        std::cout << "applied config " << config_response.etag << '\n';
        return;
    }

    const auto previous = dependencies_.storage.read(options_.config_path);
    const auto validator = [this](const std::filesystem::path& temporary) {
        if (!options_.validate_config) {
            return;
        }
        const auto checked = dependencies_.process.run(
            {options_.singbox_binary, "check", "-c", temporary.string()});
        if (!checked.success) {
            throw std::runtime_error("sing-box config validation failed: " +
                                     checked.detail);
        }
    };
    dependencies_.storage.replace(options_.config_path, prepared, validator);

    const auto reloaded = dependencies_.process.run(options_.reload_command);
    if (!reloaded.success) {
        if (previous.has_value()) {
            dependencies_.storage.replace(options_.config_path, *previous);
            static_cast<void>(dependencies_.process.run(options_.reload_command));
        }
        throw std::runtime_error("sing-box reload failed: " + reloaded.detail);
    }
    dependencies_.local_runtime.policy_activated(config_response.etag);
    set_running(true);
    set_etag(config_response.etag);
    set_rule_source(config_response.rule_source);
    std::cout << "applied config " << config_response.etag << '\n';
}

void AgentRuntime::run_local_action(const QueuedActions& actions) {
    if (actions.stop) {
        if (!options_.singbox_managed) {
            throw std::runtime_error(
                "stop is unavailable when sing-box is externally managed");
        }
        dependencies_.core.stop();
        set_running(false);
        return;
    }
    if (!actions.start && !actions.reload && !actions.restart) {
        return;
    }
    const bool restart = actions.restart;
    ProcessResult result;
    if (options_.singbox_managed) {
        try {
            if (actions.start) {
                dependencies_.core.ensure_alive();
            } else if (restart) {
                dependencies_.core.restart();
            } else {
                dependencies_.core.reload();
            }
            result = {
                .success = dependencies_.core.running(),
                .detail = dependencies_.core.running()
                              ? (actions.start ? "started"
                                               : (restart ? "restarted" : "reloaded"))
                              : "sing-box did not start",
            };
        } catch (const std::exception& error) {
            result.detail = error.what();
        }
    } else {
        result = dependencies_.process.run(restart ? options_.restart_command
                                                   : options_.reload_command);
    }
    set_running(options_.singbox_managed ? dependencies_.core.running()
                                         : result.success);
    if (!result.success) {
        throw std::runtime_error(result.detail);
    }
    std::cout << "local UI action completed: "
              << (actions.start ? "start" : (restart ? "restart" : "reload"))
              << '\n';
}

void AgentRuntime::run_commands() {
    for (const auto& command : dependencies_.http.pending_commands()) {
        ProcessResult result;
        bool changes_running_state = false;
        if (command.command == "reload") {
            if (options_.singbox_managed) {
                try {
                    dependencies_.core.reload();
                    result = {
                        .success = dependencies_.core.running(),
                        .detail = dependencies_.core.running()
                                      ? "reloaded"
                                      : "sing-box did not start",
                    };
                } catch (const std::exception& error) {
                    result.detail = error.what();
                }
            } else {
                result = dependencies_.process.run(options_.reload_command);
            }
            changes_running_state = true;
        } else if (command.command == "restart") {
            if (options_.singbox_managed) {
                try {
                    dependencies_.core.restart();
                    result = {
                        .success = dependencies_.core.running(),
                        .detail = dependencies_.core.running()
                                      ? "restarted"
                                      : "sing-box did not start",
                    };
                } catch (const std::exception& error) {
                    result.detail = error.what();
                }
            } else {
                result = dependencies_.process.run(options_.restart_command);
            }
            changes_running_state = true;
        } else if (command.command == "test-proxies" ||
                   command.command.starts_with("test-proxies ")) {
            try {
                const auto tested = dependencies_.local_runtime.test_proxies(
                    proxy_test_tags(command.command), [this](const auto& latency) {
                        static_cast<void>(
                            dependencies_.http.report_proxy_latencies(latency));
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
            set_running(options_.singbox_managed ? dependencies_.core.running()
                                                 : result.success);
        }
        dependencies_.http.acknowledge_command(command.id, result.success,
                                               result.detail);
    }
}

nlohmann::json AgentRuntime::status() const {
    std::lock_guard lock{state_mutex_};
    return {
        {"service", options_.service_name},
        {"version", options_.version},
        {"server", options_.server},
        {"config_path", options_.config_path.string()},
        {"settings_path", options_.settings_path.string()},
        {"singbox_managed", options_.singbox_managed},
        {"desired_running", desired_running_},
        {"device", device_metadata_},
        {"running",
         running_.has_value() ? nlohmann::json(*running_) : nlohmann::json(nullptr)},
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
             {"start", start_requested_},
             {"stop", stop_requested_},
             {"reload", reload_requested_},
             {"restart", restart_requested_},
         }},
        {"telemetry", last_telemetry_},
    };
}

nlohmann::json AgentRuntime::settings() const {
    std::lock_guard lock{state_mutex_};
    return agent_config_transform_options_to_json(options_.transform_options);
}

nlohmann::json AgentRuntime::update_settings(const nlohmann::json& value) {
    AgentConfigTransformOptions current;
    {
        std::lock_guard lock{state_mutex_};
        current = options_.transform_options;
    }
    auto updated = agent_config_transform_options_from_json(value, current);
    dependencies_.storage.replace(
        options_.settings_path,
        agent_config_transform_options_to_json(updated).dump(2) + '\n');
    {
        std::lock_guard lock{state_mutex_};
        options_.transform_options = updated;
        refresh_requested_ = true;
    }
    wakeup_.notify_one();
    return agent_config_transform_options_to_json(updated);
}

nlohmann::json AgentRuntime::config() const {
    const auto contents = dependencies_.storage.read(options_.config_path);
    if (!contents.has_value()) {
        return nlohmann::json::object();
    }
    return nlohmann::json::parse(*contents);
}

nlohmann::json AgentRuntime::proxies() const {
    const auto current_config = config();
    const auto outbounds = current_config.find("outbounds");
    if (outbounds == current_config.end() || !outbounds->is_array()) {
        return nlohmann::json::array();
    }
    std::set<std::string> selected;
    if (const auto route = current_config.find("route");
        route != current_config.end() && route->is_object()) {
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
    auto result = nlohmann::json::array();
    for (const auto& outbound : *outbounds) {
        if (!outbound.is_object()) {
            continue;
        }
        const auto tag = outbound.value("tag", std::string{});
        if (tag.empty()) {
            continue;
        }
        result.push_back({
            {"tag", tag},
            {"type", outbound.value("type", std::string{"unknown"})},
            {"default", selected.contains(tag)},
        });
    }
    return result;
}

nlohmann::json AgentRuntime::test_route(const std::string& url) {
    return dependencies_.local_runtime.test_route(url);
}

void AgentRuntime::queue_action(const std::string& action) {
    {
        std::lock_guard lock{state_mutex_};
        if (action == "refresh") {
            refresh_requested_ = true;
        } else if (action == "start") {
            desired_running_ = true;
            start_requested_ = true;
            stop_requested_ = false;
        } else if (action == "stop") {
            desired_running_ = false;
            stop_requested_ = true;
            start_requested_ = false;
            reload_requested_ = false;
            restart_requested_ = false;
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

} // namespace sbeasy
