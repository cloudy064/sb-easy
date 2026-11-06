#include "test_support.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "sbeasy/windows/platform.hpp"
#include "sbeasy/windows/embedded_runtime.hpp"
#include "sbeasy/windows/singbox.hpp"

namespace {

class TemporaryDirectory final {
  public:
    TemporaryDirectory() {
        const auto base = std::filesystem::temp_directory_path();
        for (unsigned attempt = 0U; attempt < 100U; ++attempt) {
            path_ = base / (L"sb-easy-singbox-test-" +
                            std::to_wstring(::GetCurrentProcessId()) + L"-" +
                            std::to_wstring(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error("cannot create sing-box integration directory");
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

class ResourceModule final {
  public:
    ResourceModule() {
        const auto path = sbeasy::win::executable_directory() /
                          L"sb-easy-service.exe";
        value_ = ::LoadLibraryExW(
            path.c_str(), nullptr,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (value_ == nullptr) {
            throw std::runtime_error("load Service runtime resources failed");
        }
    }
    ~ResourceModule() {
        if (value_ != nullptr) {
            static_cast<void>(::FreeLibrary(value_));
        }
    }
    ResourceModule(const ResourceModule&) = delete;
    ResourceModule& operator=(const ResourceModule&) = delete;
    [[nodiscard]] HMODULE get() const noexcept {
        return value_;
    }

  private:
    HMODULE value_{};
};

} // namespace

namespace {

class TestSocket final {
  public:
    explicit TestSocket(SOCKET value) : value_(value) {}
    ~TestSocket() {
        if (value_ != INVALID_SOCKET) {
            static_cast<void>(::closesocket(value_));
        }
    }
    TestSocket(const TestSocket&) = delete;
    TestSocket& operator=(const TestSocket&) = delete;

    [[nodiscard]] SOCKET get() const noexcept {
        return value_;
    }

  private:
    SOCKET value_{INVALID_SOCKET};
};

} // namespace

SB_EASY_TEST("Windows supervisor starts sing-box and protects local API") {
    TemporaryDirectory directory;
    ResourceModule resources;
    const auto runtime = sbeasy::win::materialize_embedded_runtime(
        directory.path(), resources.get(), false);
    sbeasy::test::require(std::filesystem::is_regular_file(runtime.sing_box) &&
                              std::filesystem::is_regular_file(runtime.wintun),
                          "Service must materialize both embedded runtime files");
    const auto active = directory.path() / L"config" / L"active.json";
    sbeasy::win::WindowsSingBoxSupervisor supervisor({
        .binary = runtime.sing_box,
        .wintun = runtime.wintun,
        .candidate_config = directory.path() / L"config" / L"candidate.json",
        .active_config = active,
        .last_good_config = directory.path() / L"config" / L"last-good.json",
        .log_path = directory.path() / L"logs" / L"sing-box.log",
        .validate_config = true,
        .restrict_acl = false,
        .health_timeout = std::chrono::seconds{10},
    });
    const auto config = nlohmann::json{
        {"log", {{"disabled", true}}},
        {"inbounds", nlohmann::json::array()},
        {"outbounds", nlohmann::json::array({{{"type", "direct"},
                                               {"tag", "direct"}}})},
        {"route", {{"final", "direct"}}},
    }.dump();
    supervisor.apply_config(config);
    sbeasy::test::require(supervisor.running(),
                          "supervisor must keep sing-box running");

    sbeasy::win::WindowsStorage storage{false};
    const auto installed = nlohmann::json::parse(storage.read(active).value());
    const auto& clash = installed.at("experimental").at("clash_api");
    sbeasy::test::require(
        clash.at("external_controller").get<std::string>().starts_with(
            "127.0.0.1:") &&
            clash.at("secret").get<std::string>().size() == 64U &&
            clash.at("secret") == supervisor.clash_secret(),
        "service must replace remote Clash fields with a private loopback API");
    const auto route_test = std::find_if(
        installed.at("inbounds").begin(), installed.at("inbounds").end(),
        [](const nlohmann::json& inbound) {
            return inbound.is_object() &&
                   inbound.value("tag", std::string{}) ==
                       "sb-easy-internal-route-test";
        });
    sbeasy::test::require(
        route_test != installed.at("inbounds").end() &&
            route_test->at("listen") == "127.0.0.1" &&
            route_test->at("listen_port") == supervisor.route_test_port() &&
            route_test->at("users").size() == 1U &&
            route_test->at("users").at(0).at("password") ==
                supervisor.route_test_password(),
        "route tests must use a random authenticated loopback-only proxy");

    const auto before = storage.read(active);
    sbeasy::test::require_throws<std::runtime_error>(
        [&] { supervisor.apply_config(R"({"inbounds":"invalid"})"); },
        "invalid candidate must fail sing-box check");
    sbeasy::test::require(storage.read(active) == before && supervisor.running(),
                          "invalid candidate must not replace the active config");
    supervisor.stop();
    sbeasy::test::require(!supervisor.running(),
                          "explicit stop must close sing-box");
}

SB_EASY_TEST("Windows supervisor rotates a persisted local port when occupied") {
    TemporaryDirectory directory;
    ResourceModule resources;
    const auto runtime = sbeasy::win::materialize_embedded_runtime(
        directory.path(), resources.get(), false);
    const auto active = directory.path() / L"config" / L"active.json";
    const sbeasy::win::WindowsSingBoxOptions options{
        .binary = runtime.sing_box,
        .wintun = runtime.wintun,
        .candidate_config = directory.path() / L"config" / L"candidate.json",
        .active_config = active,
        .last_good_config = directory.path() / L"config" / L"last-good.json",
        .log_path = directory.path() / L"logs" / L"sing-box.log",
        .validate_config = true,
        .restrict_acl = false,
        .health_timeout = std::chrono::seconds{10},
    };
    const auto config = nlohmann::json{
        {"log", {{"disabled", true}}},
        {"inbounds", nlohmann::json::array()},
        {"outbounds", nlohmann::json::array(
                          {{{"type", "direct"}, {"tag", "direct"}}})},
        {"route", {{"final", "direct"}}},
    }.dump();

    std::uint16_t occupied_port{};
    {
        sbeasy::win::WindowsSingBoxSupervisor initial{options};
        initial.apply_config(config);
        occupied_port = initial.clash_port();
        initial.stop();
    }

    sbeasy::win::WindowsSingBoxSupervisor recovered{options};
    TestSocket blocker{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    sbeasy::test::require(blocker.get() != INVALID_SOCKET,
                          "test must create a loopback blocker socket");
    const BOOL exclusive = TRUE;
    sbeasy::test::require(
        ::setsockopt(blocker.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) != SOCKET_ERROR,
        "test must protect its occupied port");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(occupied_port);
    sbeasy::test::require(
        ::bind(blocker.get(), reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != SOCKET_ERROR &&
            ::listen(blocker.get(), 1) != SOCKET_ERROR,
        "test must occupy the persisted local API port");

    recovered.restart();
    sbeasy::test::require(recovered.running() &&
                              recovered.clash_port() != occupied_port,
                          "supervisor must start after rotating the occupied port");
    sbeasy::win::WindowsStorage storage{false};
    const auto installed = nlohmann::json::parse(storage.read(active).value());
    sbeasy::test::require(
        installed.at("experimental")
                .at("clash_api")
                .at("external_controller") ==
            "127.0.0.1:" + std::to_string(recovered.clash_port()),
        "rotated endpoint must be persisted atomically before startup");
    recovered.stop();
}
