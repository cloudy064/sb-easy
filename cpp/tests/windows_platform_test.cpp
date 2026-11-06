#include "test_support.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <array>
#include <chrono>
#include <exception>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "sbeasy/windows/enrollment.hpp"
#include "sbeasy/windows/ipc.hpp"
#include "sbeasy/windows/log.hpp"
#include "sbeasy/windows/pipe_client.hpp"
#include "sbeasy/windows/platform.hpp"
#include "sbeasy/windows/route_stats.hpp"

namespace {

class TemporaryDirectory final {
  public:
    TemporaryDirectory() {
        const auto base = std::filesystem::temp_directory_path();
        for (unsigned attempt = 0U; attempt < 100U; ++attempt) {
            path_ = base / (L"sb-easy-windows-test-" +
                            std::to_wstring(::GetCurrentProcessId()) + L"-" +
                            std::to_wstring(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error("cannot create Windows test directory");
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

} // namespace

namespace {

void pipe_write(HANDLE pipe, const nlohmann::json& request) {
    const auto body = request.dump();
    const auto size = static_cast<std::uint32_t>(body.size());
    const std::array<unsigned char, 4> prefix{
        static_cast<unsigned char>(size & 0xffU),
        static_cast<unsigned char>((size >> 8U) & 0xffU),
        static_cast<unsigned char>((size >> 16U) & 0xffU),
        static_cast<unsigned char>((size >> 24U) & 0xffU),
    };
    DWORD written{};
    if (::WriteFile(pipe, prefix.data(), static_cast<DWORD>(prefix.size()), &written,
                    nullptr) == FALSE ||
        written != prefix.size() ||
        ::WriteFile(pipe, body.data(), static_cast<DWORD>(body.size()), &written,
                    nullptr) == FALSE ||
        written != body.size()) {
        throw std::runtime_error("write test pipe request failed");
    }
}

[[nodiscard]] nlohmann::json pipe_read(HANDLE pipe) {
    std::array<unsigned char, 4> prefix{};
    DWORD read{};
    if (::ReadFile(pipe, prefix.data(), static_cast<DWORD>(prefix.size()), &read,
                   nullptr) == FALSE ||
        read != prefix.size()) {
        throw std::runtime_error("read test pipe prefix failed");
    }
    const std::uint32_t size = static_cast<std::uint32_t>(prefix[0]) |
                               (static_cast<std::uint32_t>(prefix[1]) << 8U) |
                               (static_cast<std::uint32_t>(prefix[2]) << 16U) |
                               (static_cast<std::uint32_t>(prefix[3]) << 24U);
    std::string body(size, '\0');
    std::size_t offset{};
    while (offset < body.size()) {
        const auto requested = static_cast<DWORD>(body.size() - offset);
        if (::ReadFile(pipe, body.data() + offset, requested, &read, nullptr) == FALSE ||
            read == 0U) {
            throw std::runtime_error("read test pipe body failed");
        }
        offset += read;
    }
    return nlohmann::json::parse(body);
}

} // namespace

SB_EASY_TEST("Windows storage replaces atomically and preserves validated content") {
    TemporaryDirectory directory;
    const auto path = directory.path() / L"config" / L"active.json";
    sbeasy::win::WindowsStorage storage{false};
    storage.replace(path, "old");
    sbeasy::test::require_throws<std::runtime_error>(
        [&] {
            storage.replace(path, "bad", [](const std::filesystem::path&) {
                throw std::runtime_error("rejected");
            });
        },
        "validator failure must propagate");
    sbeasy::test::require(storage.read(path) == std::optional<std::string>{"old"},
                          "failed validation must preserve the old file");
    storage.replace(path, "new");
    sbeasy::test::require(storage.read(path) == std::optional<std::string>{"new"},
                          "valid replacement must become visible");
}

SB_EASY_TEST("DPAPI credential store round-trips without plaintext on disk") {
    TemporaryDirectory directory;
    const auto path = directory.path() / L"credential.dat";
    sbeasy::win::DpapiCredentialStore credentials{path, false};
    const std::string plaintext =
        R"({"server":"https://panel.example","agent_token":"secret-token"})";
    credentials.replace(plaintext);
    sbeasy::test::require(credentials.read() ==
                              std::optional<std::string>{plaintext},
                          "DPAPI must decrypt under the same machine identity");
    sbeasy::win::WindowsStorage raw{false};
    const auto encrypted = raw.read(path);
    sbeasy::test::require(encrypted.has_value() &&
                              encrypted->find("secret-token") == std::string::npos,
                          "credential file must not contain the Agent token");
    credentials.remove();
    sbeasy::test::require(!credentials.read().has_value(),
                          "credential removal must be idempotent");
}

SB_EASY_TEST("Windows process adapter executes an argument vector without a shell") {
    const auto executable = std::filesystem::path{L"C:\\Windows\\System32\\whoami.exe"};
    sbeasy::win::WindowsProcess process;
    const auto result = process.run({executable.string()});
    sbeasy::test::require(result.success && !result.detail.empty(),
                          "known Windows executable should run successfully");
}

SB_EASY_TEST("Windows metadata advertises interactive device capabilities") {
    const auto metadata = sbeasy::win::WindowsMetadata{}.device_metadata();
    sbeasy::test::require(metadata.at("platform") == "windows" &&
                              metadata.at("interactive_client") == true &&
                              metadata.at("supports_proxy_selection") == true &&
                              !metadata.at("hostname").get<std::string>().empty(),
                          "Windows enrollment metadata must be capability-driven");
}

SB_EASY_TEST("IPC redaction removes credentials and URL query strings") {
    const auto redacted = sbeasy::win::redact_config({
        {"token", "agent-secret"},
        {"outbound", {{"uuid", "uuid-secret"}, {"password", "password-secret"}}},
        {"url", "https://example.test/path?access_token=value"},
    });
    sbeasy::test::require(redacted.at("token") == "***" &&
                              redacted.at("outbound").at("uuid") == "***" &&
                              redacted.at("outbound").at("password") == "***" &&
                              redacted.at("url") ==
                                  "https://example.test/path?<redacted>" &&
                              sbeasy::win::is_sensitive_pipe_method("vpn.start") &&
                              !sbeasy::win::is_sensitive_pipe_method("status.get"),
                          "IPC must enforce its documented secret boundary");
}

SB_EASY_TEST("Windows enrollment links expose only a validated origin and code") {
    const auto code = std::string(64U, 'A');
    const auto parsed = sbeasy::win::parse_enrollment_uri(
        "URL:sbeasy://enroll?server=https%3A%2F%2Fpanel.example.test%3A8443%2F"
        "&code=" +
        code);
    sbeasy::test::require(parsed.server == "https://panel.example.test:8443" &&
                              parsed.code == std::string(64U, 'a'),
                          "protocol activation must normalize its preview");
    sbeasy::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(sbeasy::win::parse_enrollment_uri(
                "sbeasy://enroll?server=https%3A%2F%2Fpanel.example.test%2Fapi"
                "&code=" +
                code));
        },
        "an enrollment preview must reject a server path");
    sbeasy::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(sbeasy::win::parse_enrollment_uri(
                "sbeasy://enroll?server=https%3A%2F%2Fpanel.example.test"
                "&code=short"));
        },
        "an enrollment preview must reject malformed one-time codes");
}

SB_EASY_TEST("named pipe enforces the framed versioned protocol") {
    const auto pipe_name = L"\\\\.\\pipe\\sb-easy-test-" +
                           std::to_wstring(::GetCurrentProcessId()) + L"-protocol";
    std::exception_ptr server_error;
    sbeasy::win::NamedPipeServer server{
        [](const nlohmann::json& request, const sbeasy::win::PipeClient& client) {
            return nlohmann::json{{"method", request.at("method")},
                                  {"pid", client.process_id}};
        },
        pipe_name};
    std::thread worker{[&] {
        try {
            server.run();
        } catch (...) {
            server_error = std::current_exception();
        }
    }};
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0U; attempt < 40U; ++attempt) {
        pipe = ::CreateFileW(pipe_name.c_str(),
                             GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{25});
    }
    try {
        sbeasy::test::require(pipe != INVALID_HANDLE_VALUE,
                              "test client must connect to the local pipe");
        pipe_write(pipe, {{"id", "test-1"},
                          {"version", 1},
                          {"method", "status.get"},
                          {"params", nlohmann::json::object()}});
        const auto response = pipe_read(pipe);
        if (!response.value("ok", false)) {
            throw std::runtime_error(response.at("error").at("message").get<std::string>());
        }
        sbeasy::test::require(response.at("id") == "test-1" &&
                                  response.at("ok") == true &&
                                  response.at("result").at("method") ==
                                      "status.get" &&
                                  response.at("result").at("pid") ==
                                      ::GetCurrentProcessId(),
                              "pipe must preserve IDs and verified client PID");
        pipe_write(pipe, {{"id", "test-2"},
                          {"version", 2},
                          {"method", "status.get"},
                          {"params", nlohmann::json::object()}});
        const auto rejected = pipe_read(pipe);
        sbeasy::test::require(rejected.at("ok") == false,
                              "unknown IPC protocol versions must be rejected");
    } catch (...) {
        if (pipe != INVALID_HANDLE_VALUE) {
            static_cast<void>(::CloseHandle(pipe));
        }
        server.stop();
        worker.join();
        throw;
    }
    static_cast<void>(::CloseHandle(pipe));
    server.stop();
    worker.join();
    if (server_error) {
        std::rethrow_exception(server_error);
    }
}

SB_EASY_TEST("named pipe client validates responses and reconnects per request") {
    const auto pipe_name = L"\\\\.\\pipe\\sb-easy-test-" +
                           std::to_wstring(::GetCurrentProcessId()) + L"-client";
    std::exception_ptr server_error;
    std::atomic_uint requests{};
    sbeasy::win::NamedPipeServer server{
        [&requests](const nlohmann::json& request,
                    const sbeasy::win::PipeClient&) {
            ++requests;
            if (request.at("method") == "status.get") {
                return nlohmann::json{{"phase", "running"}};
            }
            throw std::runtime_error("expected rejection");
        },
        pipe_name};
    std::thread worker{[&] {
        try {
            server.run();
        } catch (...) {
            server_error = std::current_exception();
        }
    }};
    try {
        sbeasy::win::NamedPipeClient client{std::chrono::seconds{2},
                                           1024U * 1024U, pipe_name};
        const auto first = client.request("status.get");
        const auto second = client.request("status.get");
        sbeasy::test::require(first.at("phase") == "running" &&
                                  second.at("phase") == "running" &&
                                  requests.load() == 2U,
                              "UI IPC client must reconnect and preserve results");
        sbeasy::test::require_throws<std::runtime_error>(
            [&] { static_cast<void>(client.request("reject.test")); },
            "service errors must cross the UI IPC boundary");
    } catch (...) {
        server.stop();
        worker.join();
        throw;
    }
    server.stop();
    worker.join();
    if (server_error) {
        std::rethrow_exception(server_error);
    }
}

SB_EASY_TEST("log redaction removes bearer and structured credentials") {
    const auto redacted = sbeasy::win::redact_log_message(
        R"({"agent_token":"secret","url":"https://example.test/?code=value"} Authorization: Bearer token-value password=proxy-pass uuid: client-id)");
    sbeasy::test::require(redacted.find("secret") == std::string::npos &&
                              redacted.find("code=value") == std::string::npos &&
                              redacted.find("token-value") == std::string::npos &&
                              redacted.find("proxy-pass") == std::string::npos &&
                              redacted.find("client-id") == std::string::npos,
                          "service logs must not expose credentials or URL queries");
}

SB_EASY_TEST("Windows rolling log applies bounded retention changes") {
    TemporaryDirectory directory;
    const auto path = directory.path() / L"service.log";
    sbeasy::win::RollingLog log{path, 64U, 3U, false, false};
    log.write("info", "first message forces a bounded rotation soon");
    log.write("info", "second message forces a bounded rotation soon");
    log.write("info", "third message forces a bounded rotation soon");
    sbeasy::test::require(
        std::filesystem::is_regular_file(path.wstring() + L".2"),
        "rolling log should retain older files before the preference changes");
    log.set_retained_files(1U);
    sbeasy::test::require(
        !std::filesystem::exists(path.wstring() + L".2"),
        "lowering log retention should remove excess rotated files");
}

SB_EASY_TEST("Windows route statistics persist aggregate data across restarts") {
    TemporaryDirectory directory;
    const auto database = directory.path() / L"runtime.db";
    const auto snapshot = nlohmann::json::array({
        {{"id", "connection-1"},
         {"upload", 100},
         {"download", 400},
         {"metadata", {{"host", "Example.COM."}}},
         {"chains", nlohmann::json::array({"Proxy", "node-a"})},
         {"rule", "rule_set"},
         {"rulePayload", "geosite-test"}},
    });
    {
        sbeasy::win::RouteStatistics statistics{database};
        statistics.observe(snapshot);
        auto updated = snapshot;
        updated.at(0)["upload"] = 150;
        updated.at(0)["download"] = 700;
        statistics.observe(updated);
        statistics.observe(nlohmann::json::array());
    }
    sbeasy::win::RouteStatistics restored{database};
    const auto rows = restored.query("all");
    sbeasy::test::require(
        rows.size() == 1U && rows.at(0).at("domain") == "example.com" &&
            rows.at(0).at("connection_count") == 1 &&
            rows.at(0).at("uplink_total") == 150 &&
            rows.at(0).at("downlink_total") == 700 &&
            rows.at(0).at("chain").size() == 2U,
        "runtime.db must retain only bounded aggregate route history");
}

SB_EASY_TEST("Windows route statistics isolate activated policy generations") {
    TemporaryDirectory directory;
    sbeasy::win::RouteStatistics statistics{directory.path() / L"runtime.db"};
    auto snapshot = nlohmann::json::array({
        {{"id", "connection-a"},
         {"upload", 10},
         {"download", 20},
         {"metadata", {{"host", "same.example"}}},
         {"chains", nlohmann::json::array({"Proxy", "node-a"})},
         {"rule", "same-rule"}},
    });
    statistics.observe(snapshot);
    statistics.activate_policy("etag-b");
    snapshot.at(0)["id"] = "connection-b";
    statistics.observe(snapshot);

    const auto rows = statistics.query("all");
    std::set<std::int64_t> generations;
    for (const auto& row : rows) {
        generations.insert(row.at("policy_generation").get<std::int64_t>());
    }
    sbeasy::test::require(
        rows.size() == 2U && generations.size() == 2U,
        "identical route identities from separate policy activations must not merge");
}
