#include "test_support.hpp"

#include <deque>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/agent_runtime.hpp"

namespace {

class FakeHttp final : public sbeasy::AgentHttp {
  public:
    sbeasy::AgentConfigResponse config_response;
    std::vector<sbeasy::AgentCommand> commands;
    std::vector<nlohmann::json> acknowledgements;
    std::vector<nlohmann::json> latency_reports;
    std::vector<nlohmann::json> telemetry_reports;
    std::optional<std::string> polled_etag;
    std::optional<std::string> reported_etag;
    std::optional<bool> reported_running;
    std::string reported_version;
    bool unavailable{false};

    [[nodiscard]] sbeasy::AgentConfigResponse
    poll_config(const std::optional<std::string>& etag) override {
        if (unavailable) {
            throw std::runtime_error("control plane unavailable");
        }
        polled_etag = etag;
        return config_response;
    }

    [[nodiscard]] std::vector<sbeasy::AgentCommand> pending_commands() override {
        if (unavailable) {
            throw std::runtime_error("control plane unavailable");
        }
        return commands;
    }

    void acknowledge_command(const std::string& id, bool success,
                             const std::optional<std::string>& result) override {
        acknowledgements.push_back({
            {"id", id},
            {"success", success},
            {"result", result},
        });
    }

    void report_status(const std::string& version, const std::optional<bool>& running,
                       const std::optional<std::string>& etag) override {
        if (unavailable) {
            throw std::runtime_error("control plane unavailable");
        }
        reported_version = version;
        reported_running = running;
        reported_etag = etag;
    }

    void report_telemetry(const nlohmann::json& telemetry) override {
        telemetry_reports.push_back(telemetry);
    }

    [[nodiscard]] std::size_t
    report_proxy_latencies(const nlohmann::json& results) override {
        latency_reports.push_back(results);
        return results.size();
    }
};

class FakeProcess final : public sbeasy::PlatformProcess {
  public:
    std::deque<sbeasy::ProcessResult> results;
    std::vector<std::vector<std::string>> calls;

    [[nodiscard]] sbeasy::ProcessResult
    run(const std::vector<std::string>& arguments) override {
        calls.push_back(arguments);
        if (results.empty()) {
            return {.success = true, .detail = "ok"};
        }
        auto result = results.front();
        results.pop_front();
        return result;
    }
};

class FakeStorage final : public sbeasy::PlatformStorage {
  public:
    std::map<std::string, std::string> files;
    std::size_t replacements{0U};

    [[nodiscard]] std::optional<std::string>
    read(const std::filesystem::path& path) const override {
        const auto found = files.find(path.generic_string());
        return found == files.end() ? std::nullopt
                                    : std::optional<std::string>{found->second};
    }

    void replace(const std::filesystem::path& path, std::string_view contents,
                 const sbeasy::StorageValidator& validator) override {
        if (validator) {
            auto candidate = path;
            candidate += ".candidate";
            validator(candidate);
        }
        files[path.generic_string()] = std::string{contents};
        ++replacements;
    }
};

class FakeClock final : public sbeasy::PlatformClock {
  public:
    [[nodiscard]] std::string now_iso8601() const override {
        return "2026-08-04T12:00:00Z";
    }
};

class FakeMetadata final : public sbeasy::PlatformMetadata {
  public:
    [[nodiscard]] nlohmann::json device_metadata() const override {
        return {
            {"platform", "windows"},
            {"architecture", "x86_64"},
            {"interactive_client", true},
            {"supports_proxy_selection", true},
        };
    }
};

class FakeCore final : public sbeasy::AgentCore {
  public:
    bool is_running{true};
    std::optional<std::string> error;
    std::string applied;
    std::size_t ensure_calls{0U};
    std::size_t reload_calls{0U};
    std::size_t restart_calls{0U};
    std::size_t stop_calls{0U};

    void apply_config(std::string_view contents) override {
        applied = contents;
    }
    void ensure_alive() override {
        ++ensure_calls;
        is_running = true;
    }
    void reload() override {
        ++reload_calls;
    }
    void restart() override {
        ++restart_calls;
    }
    void stop() override {
        ++stop_calls;
        is_running = false;
    }
    [[nodiscard]] bool running() override {
        return is_running;
    }
    [[nodiscard]] std::optional<std::string> last_error() const override {
        return error;
    }
};

class FakeLocalRuntime final : public sbeasy::AgentLocalRuntime {
  public:
    std::optional<nlohmann::json> telemetry;
    std::optional<std::vector<std::string>> tested_tags;
    std::optional<std::string> activated_policy;

    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) override {
        tested_tags = tags;
        reporter({{"node-a", 12}});
        return 1U;
    }

    [[nodiscard]] std::optional<nlohmann::json> sample_telemetry() override {
        return telemetry;
    }

    [[nodiscard]] nlohmann::json test_route(const std::string& url) override {
        return {{"url", url}, {"outbound", "node-a"}};
    }

    void policy_activated(std::string_view label) override {
        activated_policy = label;
    }
};

struct Fixture {
    FakeHttp http;
    FakeProcess process;
    FakeStorage storage;
    FakeClock clock;
    FakeMetadata metadata;
    FakeCore core;
    FakeLocalRuntime local_runtime;

    [[nodiscard]] sbeasy::AgentRuntime runtime(bool managed) {
        return sbeasy::AgentRuntime(
            {
                .config_path = "config.json",
                .settings_path = "settings.json",
                .server = "https://panel.example",
                .service_name = "test-agent",
                .version = "test-agent/1",
                .singbox_binary = "sing-box",
                .singbox_managed = managed,
                .validate_config = true,
                .reload_command = {"service", "reload"},
                .restart_command = {"service", "restart"},
                .transform_options = {.local_proxy_egress = false},
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
    }
};

} // namespace

SB_EASY_TEST("portable config transform adds LAN compatibility without local egress") {
    const auto input = nlohmann::json::parse(R"JSON({
      "route": {
        "rules": [{"domain_suffix": "example.com", "outbound": "Proxy"}],
        "final": "Proxy"
      },
      "outbounds": [{"type": "selector", "tag": "Proxy"}]
    })JSON");
    const sbeasy::AgentConfigTransformOptions options{
        .local_proxy_egress = false,
        .lan_compatibility = true,
    };
    const auto transformed = nlohmann::json::parse(
        sbeasy::prepare_agent_config(input.dump(), options));
    sbeasy::test::require(
        transformed.at("route").at("rules").front().at("ip_cidr") ==
                nlohmann::json::array({"224.0.0.0/4", "ff00::/8"}) &&
            transformed.at("route").at("rules").at(1) ==
                input.at("route").at("rules").at(0),
        "LAN compatibility must prepend only the bounded multicast direct rule");
}

SB_EASY_TEST("portable agent runtime runs a complete managed cycle with doubles") {
    Fixture fixture;
    const auto body =
        nlohmann::json{
            {"outbounds",
             nlohmann::json::array({
                 {{"type", "selector"}, {"tag", "Proxy"}, {"default", "node-a"}},
                 {{"type", "shadowsocks"}, {"tag", "node-a"}},
             })},
            {"route", {{"final", "Proxy"}}},
        }
            .dump();
    fixture.http.config_response = {
        .modified = true,
        .etag = "etag-1",
        .body = body,
        .rule_source = "quickjs",
    };
    fixture.http.commands = {{"command-1", "test-proxies [\"node-a\"]"}};
    fixture.local_runtime.telemetry = {
        {"up", 1}, {"down", 2}, {"up_total", 3}, {"down_total", 4}, {"conn_count", 5},
    };

    auto runtime = fixture.runtime(true);
    sbeasy::test::require(runtime.run_cycle(),
                          "managed cycle should succeed with healthy doubles");
    sbeasy::test::require(
        fixture.core.applied == body && fixture.core.ensure_calls == 1U &&
            fixture.local_runtime.activated_policy == "etag-1",
        "managed core should receive the rendered config and health check");
    sbeasy::test::require(fixture.http.reported_etag == "etag-1" &&
                              fixture.http.reported_running == true &&
                              fixture.http.reported_version == "test-agent/1",
                          "cycle should report the activated runtime state");
    sbeasy::test::require(fixture.local_runtime.tested_tags ==
                                  std::optional<std::vector<std::string>>{{"node-a"}} &&
                              fixture.http.acknowledgements.size() == 1U &&
                              fixture.http.acknowledgements.front().at("success") ==
                                  true &&
                              fixture.http.latency_reports.size() == 1U,
                          "bounded proxy-test commands should execute and acknowledge");

    const auto status = runtime.status();
    sbeasy::test::require(
        status.at("last_cycle") == "2026-08-04T12:00:00Z" &&
            status.at("rule_source") == "quickjs" &&
            status.at("device").at("platform") == "windows" &&
            status.at("device").at("interactive_client") == true &&
            status.at("telemetry").at("conn_count") == 5,
        "clock and platform metadata interfaces should feed portable status");

    const auto updated = runtime.update_settings({{"local_proxy_egress", true}});
    sbeasy::test::require(updated.at("local_proxy_egress") == true &&
                              fixture.storage.files.contains("settings.json"),
                          "settings should persist only through the storage boundary");
}

SB_EASY_TEST("portable agent runtime rolls back an unmanaged reload failure") {
    Fixture fixture;
    fixture.storage.files["config.json"] = "{\"old\":true}";
    fixture.http.config_response = {
        .modified = true,
        .etag = "etag-bad",
        .body = "{\"new\":true}",
    };
    fixture.process.results = {
        {.success = true, .detail = "valid"},
        {.success = false, .detail = "reload rejected"},
        {.success = true, .detail = "old config restored"},
    };

    auto runtime = fixture.runtime(false);
    sbeasy::test::require(!runtime.run_cycle(), "failed reload should fail the cycle");
    sbeasy::test::require(
        fixture.storage.files.at("config.json") == "{\"old\":true}" &&
            fixture.process.calls.size() == 3U,
        "failed reload should reinstall and reload the previous config");
    const auto status = runtime.status();
    sbeasy::test::require(
        status.at("etag").is_null() &&
            status.at("last_error").get<std::string>().find("reload rejected") !=
                std::string::npos,
        "an unactivated candidate must not advance the ETag");
}

SB_EASY_TEST("portable agent runtime keeps an explicit stop until start is requested") {
    Fixture fixture;
    auto runtime = fixture.runtime(true);
    runtime.queue_action("stop");
    sbeasy::test::require(runtime.run_cycle(), "stop cycle should succeed");
    sbeasy::test::require(fixture.core.stop_calls == 1U &&
                              fixture.core.ensure_calls == 0U &&
                              runtime.status().at("desired_running") == false &&
                              runtime.status().at("running") == false,
                          "stopped runtime must not immediately respawn the core");

    runtime.queue_action("start");
    sbeasy::test::require(runtime.run_cycle(), "start cycle should succeed");
    sbeasy::test::require(fixture.core.ensure_calls >= 1U &&
                              runtime.status().at("desired_running") == true &&
                              runtime.status().at("running") == true,
                          "explicit start must restore the desired running state");
}

SB_EASY_TEST("managed runtime recovers its core while control plane is unreachable") {
    Fixture fixture;
    fixture.http.unavailable = true;
    fixture.core.is_running = false;
    fixture.storage.files["config.json"] = "{\"active\":true}";

    auto runtime = fixture.runtime(true);
    sbeasy::test::require(
        !runtime.run_cycle(),
        "an unreachable control plane must be visible as a failed sync cycle");
    const auto status = runtime.status();
    sbeasy::test::require(
        fixture.core.ensure_calls == 1U && fixture.core.is_running &&
            status.at("running") == true &&
            fixture.storage.files.at("config.json") == "{\"active\":true}" &&
            status.at("last_error")
                    .get<std::string>()
                    .find("control plane unavailable") != std::string::npos,
        "local core recovery and the last active config must not depend on control-plane reachability");
}
