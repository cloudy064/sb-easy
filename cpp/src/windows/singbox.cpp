#include "sbeasy/windows/singbox.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/windows/platform.hpp"

namespace sbeasy::win {
namespace {

class OwnedHandle final {
  public:
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE value) noexcept : value_(value) {}
    ~OwnedHandle() {
        reset();
    }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    OwnedHandle(OwnedHandle&& other) noexcept : value_(other.release()) {}
    OwnedHandle& operator=(OwnedHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(value_, nullptr);
    }
    void reset(HANDLE value = nullptr) noexcept {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            static_cast<void>(::CloseHandle(value_));
        }
        value_ = value;
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
  private:
    HANDLE value_{};
};

[[nodiscard]] std::wstring quote_argument(std::wstring_view value) {
    if (value.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring{value};
    }
    std::wstring result{L"\""};
    std::size_t backslashes{};
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
        } else if (character == L'\"') {
            result.append(backslashes * 2U + 1U, L'\\');
            result.push_back(character);
            backslashes = 0U;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0U;
            result.push_back(character);
        }
    }
    result.append(backslashes * 2U, L'\\');
    result.push_back(L'\"');
    return result;
}

[[nodiscard]] std::wstring make_command_line(
    const std::filesystem::path& binary,
    const std::vector<std::wstring>& arguments) {
    std::wstring result = quote_argument(binary.wstring());
    for (const auto& argument : arguments) {
        result.push_back(L' ');
        result += quote_argument(argument);
    }
    return result;
}

[[nodiscard]] OwnedHandle create_kill_on_close_job() {
    OwnedHandle job{::CreateJobObjectW(nullptr, nullptr)};
    if (!job) {
        throw std::runtime_error("create sing-box Job Object failed");
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (::SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                  &limits, sizeof(limits)) == FALSE) {
        throw std::runtime_error("configure sing-box Job Object failed");
    }
    return job;
}

[[nodiscard]] OwnedHandle launch_process(
    const std::filesystem::path& binary,
    const std::vector<std::wstring>& arguments,
    const std::filesystem::path& log_path, HANDLE job) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    OwnedHandle log{::CreateFileW(
        log_path.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &security,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!log) {
        throw std::runtime_error("open sing-box log failed");
    }

    SIZE_T attribute_size{};
    static_cast<void>(::InitializeProcThreadAttributeList(
        nullptr, 1U, 0U, &attribute_size));
    std::vector<std::byte> attributes(attribute_size);
    auto* attribute_list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(
        attributes.data());
    if (::InitializeProcThreadAttributeList(attribute_list, 1U, 0U,
                                            &attribute_size) == FALSE) {
        throw std::runtime_error("initialize sing-box process attributes failed");
    }
    struct AttributeGuard final {
        PPROC_THREAD_ATTRIBUTE_LIST value;
        ~AttributeGuard() {
            ::DeleteProcThreadAttributeList(value);
        }
    } attribute_guard{attribute_list};
    HANDLE inherited = log.get();
    if (::UpdateProcThreadAttribute(
            attribute_list, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited,
            sizeof(inherited), nullptr, nullptr) == FALSE) {
        throw std::runtime_error("restrict sing-box inherited handles failed");
    }

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nullptr;
    startup.StartupInfo.hStdOutput = log.get();
    startup.StartupInfo.hStdError = log.get();
    startup.lpAttributeList = attribute_list;
    PROCESS_INFORMATION process{};
    auto command = make_command_line(binary, arguments);
    const auto working_directory = binary.parent_path().wstring();
    const DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                        EXTENDED_STARTUPINFO_PRESENT;
    if (::CreateProcessW(binary.c_str(), command.data(), nullptr, nullptr, TRUE,
                         flags, nullptr, working_directory.c_str(),
                         &startup.StartupInfo, &process) == FALSE) {
        throw std::runtime_error("start sing-box failed with error " +
                                 std::to_string(::GetLastError()));
    }
    OwnedHandle process_handle{process.hProcess};
    OwnedHandle thread_handle{process.hThread};
    if (::AssignProcessToJobObject(job, process_handle.get()) == FALSE) {
        static_cast<void>(::TerminateProcess(process_handle.get(), 1U));
        throw std::runtime_error("assign sing-box to Job Object failed");
    }
    if (::ResumeThread(thread_handle.get()) == static_cast<DWORD>(-1)) {
        static_cast<void>(::TerminateProcess(process_handle.get(), 1U));
        throw std::runtime_error("resume sing-box process failed");
    }
    return process_handle;
}

[[nodiscard]] DWORD wait_for_process(HANDLE process,
                                     std::chrono::milliseconds timeout,
                                     HANDLE job) {
    const auto bounded = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(timeout.count()),
        static_cast<std::uint64_t>(INFINITE - 1U));
    if (::WaitForSingleObject(process, static_cast<DWORD>(bounded)) !=
        WAIT_OBJECT_0) {
        static_cast<void>(::TerminateJobObject(job, ERROR_TIMEOUT));
        static_cast<void>(::WaitForSingleObject(process, 2'000U));
        throw std::runtime_error("sing-box command timed out");
    }
    DWORD exit_code{};
    if (::GetExitCodeProcess(process, &exit_code) == FALSE) {
        throw std::runtime_error("read sing-box exit code failed");
    }
    return exit_code;
}

class Socket final {
  public:
    Socket() = default;
    explicit Socket(SOCKET value) : value_(value) {}
    ~Socket() {
        reset();
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value_(other.release()) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    [[nodiscard]] SOCKET get() const noexcept {
        return value_;
    }
    [[nodiscard]] SOCKET release() noexcept {
        return std::exchange(value_, INVALID_SOCKET);
    }
    void reset(SOCKET value = INVALID_SOCKET) noexcept {
        if (value_ != INVALID_SOCKET) {
            static_cast<void>(::closesocket(value_));
        }
        value_ = value;
    }
    explicit operator bool() const noexcept {
        return value_ != INVALID_SOCKET;
    }

  private:
    SOCKET value_{INVALID_SOCKET};
};

[[nodiscard]] std::string random_secret() {
    std::array<unsigned char, 32> bytes{};
    if (::BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("generate Clash API secret failed");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2U);
    for (const auto value : bytes) {
        result.push_back(digits[value >> 4U]);
        result.push_back(digits[value & 0x0fU]);
    }
    return result;
}

[[nodiscard]] std::uint16_t available_loopback_port() {
    Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (!socket) {
        throw std::runtime_error("create loopback socket failed");
    }
    const BOOL exclusive = TRUE;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) == SOCKET_ERROR) {
        throw std::runtime_error("protect loopback port reservation failed");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(socket.get(), reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) == SOCKET_ERROR) {
        throw std::runtime_error("reserve loopback port failed");
    }
    int length = sizeof(address);
    if (::getsockname(socket.get(), reinterpret_cast<sockaddr*>(&address), &length) ==
        SOCKET_ERROR) {
        throw std::runtime_error("read loopback port failed");
    }
    return ntohs(address.sin_port);
}

[[nodiscard]] bool loopback_port_available(std::uint16_t port) noexcept {
    Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (!socket) {
        return false;
    }
    const BOOL exclusive = TRUE;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) == SOCKET_ERROR) {
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return ::bind(socket.get(), reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) != SOCKET_ERROR;
}

[[nodiscard]] bool loopback_api_healthy(std::uint16_t port,
                                        const std::string& secret) {
    Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (!socket) {
        return false;
    }
    DWORD timeout = 500U;
    static_cast<void>(::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                                   reinterpret_cast<const char*>(&timeout),
                                   sizeof(timeout)));
    static_cast<void>(::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO,
                                   reinterpret_cast<const char*>(&timeout),
                                   sizeof(timeout)));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::connect(socket.get(), reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) == SOCKET_ERROR) {
        return false;
    }
    const std::string request =
        "GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " +
        secret + "\r\nConnection: close\r\n\r\n";
    std::size_t sent{};
    while (sent < request.size()) {
        const auto remaining = request.size() - sent;
        const int chunk = static_cast<int>(std::min<std::size_t>(
            remaining, static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int result = ::send(socket.get(), request.data() + sent, chunk, 0);
        if (result <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    std::array<char, 256> response{};
    const int received =
        ::recv(socket.get(), response.data(), static_cast<int>(response.size()), 0);
    if (received <= 0) {
        return false;
    }
    const std::string_view status{response.data(),
                                  static_cast<std::size_t>(received)};
    return status.find(" 200 ") != std::string_view::npos;
}

[[nodiscard]] std::optional<std::pair<std::uint16_t, std::string>>
read_local_api(const WindowsStorage& storage,
               const std::filesystem::path& active_config) {
    const auto contents = storage.read(active_config);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    const auto parsed = nlohmann::json::parse(*contents, nullptr, false);
    if (!parsed.is_object()) {
        return std::nullopt;
    }
    const auto experimental = parsed.find("experimental");
    if (experimental == parsed.end() || !experimental->is_object()) {
        return std::nullopt;
    }
    const auto clash = experimental->find("clash_api");
    if (clash == experimental->end() || !clash->is_object()) {
        return std::nullopt;
    }
    const auto controller = clash->value("external_controller", std::string{});
    const auto secret = clash->value("secret", std::string{});
    constexpr std::string_view prefix{"127.0.0.1:"};
    if (!controller.starts_with(prefix) || secret.empty()) {
        return std::nullopt;
    }
    try {
        const auto port_value = std::stoul(controller.substr(prefix.size()));
        if (port_value == 0U || port_value > 65'535U) {
            return std::nullopt;
        }
        return std::pair{static_cast<std::uint16_t>(port_value), secret};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::pair<std::uint16_t, std::string>>
read_route_test_api(const WindowsStorage& storage,
                    const std::filesystem::path& active_config) {
    const auto contents = storage.read(active_config);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    const auto parsed = nlohmann::json::parse(*contents, nullptr, false);
    const auto inbounds = parsed.is_object() ? parsed.find("inbounds") : parsed.end();
    if (inbounds == parsed.end() || !inbounds->is_array()) {
        return std::nullopt;
    }
    for (const auto& inbound : *inbounds) {
        if (!inbound.is_object() ||
            inbound.value("tag", std::string{}) !=
                "sb-easy-internal-route-test" ||
            inbound.value("listen", std::string{}) != "127.0.0.1") {
            continue;
        }
        const auto port = inbound.value("listen_port", 0U);
        const auto users = inbound.find("users");
        if (port == 0U || port > 65'535U || users == inbound.end() ||
            !users->is_array() || users->size() != 1U ||
            !users->at(0).is_object() ||
            users->at(0).value("username", std::string{}) != "sb-easy") {
            return std::nullopt;
        }
        const auto password = users->at(0).value("password", std::string{});
        if (password.empty()) {
            return std::nullopt;
        }
        return std::pair{static_cast<std::uint16_t>(port), password};
    }
    return std::nullopt;
}

void install_private_endpoints(nlohmann::json& config, std::uint16_t clash_port,
                               const std::string& clash_secret,
                               std::uint16_t route_test_port,
                               const std::string& route_test_password,
                               bool strict_route) {
    auto& experimental = config["experimental"];
    if (!experimental.is_object()) {
        experimental = nlohmann::json::object();
    }
    auto& clash = experimental["clash_api"];
    if (!clash.is_object()) {
        clash = nlohmann::json::object();
    }
    clash["external_controller"] =
        "127.0.0.1:" + std::to_string(clash_port);
    clash["secret"] = clash_secret;

    auto& inbounds = config["inbounds"];
    if (inbounds.is_null()) {
        inbounds = nlohmann::json::array();
    }
    if (!inbounds.is_array()) {
        throw std::runtime_error("sing-box inbounds must be an array");
    }
    for (auto inbound = inbounds.begin(); inbound != inbounds.end();) {
        if (inbound->is_object() &&
            inbound->value("tag", std::string{}) ==
                "sb-easy-internal-route-test") {
            inbound = inbounds.erase(inbound);
        } else {
            ++inbound;
        }
    }
    for (auto& inbound : inbounds) {
        if (inbound.is_object() &&
            inbound.value("type", std::string{}) == "tun") {
            inbound["strict_route"] = strict_route;
        }
    }
    inbounds.push_back({
        {"type", "mixed"},
        {"tag", "sb-easy-internal-route-test"},
        {"listen", "127.0.0.1"},
        {"listen_port", route_test_port},
        {"users",
         nlohmann::json::array(
             {nlohmann::json{{"username", "sb-easy"},
                             {"password", route_test_password}}})},
    });
}

void rotate_singbox_log(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size <= 10U * 1024U * 1024U) {
        return;
    }
    const auto rotated = [&path](unsigned index) {
        return std::filesystem::path{path.wstring() + L"." +
                                     std::to_wstring(index)};
    };
    static_cast<void>(::DeleteFileW(rotated(3U).c_str()));
    for (unsigned index = 3U; index > 1U; --index) {
        const auto source = rotated(index - 1U);
        if (::MoveFileExW(source.c_str(), rotated(index).c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ==
                FALSE &&
            ::GetLastError() != ERROR_FILE_NOT_FOUND) {
            throw std::runtime_error("rotate sing-box log failed");
        }
    }
    if (::MoveFileExW(path.c_str(), rotated(1U).c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        throw std::runtime_error("rotate active sing-box log failed");
    }
}

} // namespace

class WindowsSingBoxSupervisor::Impl final {
  public:
    explicit Impl(WindowsSingBoxOptions options)
        : options_(std::move(options)), storage_(options_.restrict_acl),
          job_(create_kill_on_close_job()) {
        if (options_.binary.empty() || options_.wintun.empty() ||
            options_.candidate_config.empty() || options_.active_config.empty() ||
            options_.last_good_config.empty() || options_.log_path.empty()) {
            throw std::invalid_argument("Windows sing-box paths must not be empty");
        }
        if (options_.health_timeout <= std::chrono::milliseconds::zero() ||
            options_.shutdown_timeout < std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("Windows sing-box timeouts are invalid");
        }
        WSADATA sockets{};
        if (::WSAStartup(MAKEWORD(2, 2), &sockets) != 0) {
            throw std::runtime_error("initialize Winsock failed");
        }
        winsock_started_ = true;
        if (const auto persisted = read_local_api(storage_, options_.active_config);
            persisted.has_value()) {
            clash_port_ = persisted->first;
            clash_secret_ = persisted->second;
        } else {
            clash_port_ = available_loopback_port();
            clash_secret_ = random_secret();
        }
        if (const auto persisted =
                read_route_test_api(storage_, options_.active_config);
            persisted.has_value()) {
            route_test_port_ = persisted->first;
            route_test_password_ = persisted->second;
        } else {
            do {
                route_test_port_ = available_loopback_port();
            } while (route_test_port_ == clash_port_);
            route_test_password_ = random_secret();
        }
        desired_running_ = options_.start_enabled;
        strict_route_ = options_.strict_route;
    }

    ~Impl() {
        stop();
        if (winsock_started_) {
            static_cast<void>(::WSACleanup());
        }
    }

    void apply_config(std::string_view contents) {
        auto parsed = nlohmann::json::parse(contents, nullptr, false);
        if (!parsed.is_object()) {
            throw std::invalid_argument("sing-box config must be a JSON object");
        }
        {
            std::lock_guard lock{mutex_};
            install_private_endpoints(parsed, clash_port_, clash_secret_,
                                      route_test_port_, route_test_password_,
                                      strict_route_);
        }
        const auto protected_config = parsed.dump();
        storage_.replace(
            options_.candidate_config, protected_config,
            [this](const std::filesystem::path& candidate) {
                if (!options_.validate_config) {
                    return;
                }
                validate_candidate(candidate, "sing-box candidate validation failed: ");
            });

        const auto previous = storage_.read(options_.active_config);
        if (previous.has_value()) {
            storage_.replace(options_.last_good_config, *previous);
        }
        storage_.replace(options_.active_config, protected_config);

        bool should_start{};
        {
            std::lock_guard lock{mutex_};
            should_start = desired_running_;
        }
        if (should_start) {
            try {
                restart();
            } catch (...) {
                if (previous.has_value()) {
                    storage_.replace(options_.active_config, *previous);
                    try {
                        restart();
                    } catch (const std::exception& rollback_error) {
                        std::lock_guard lock{mutex_};
                        desired_running_ = false;
                        degraded_ = true;
                        last_error_ = "rollback failed: " +
                                      std::string{rollback_error.what()};
                    }
                } else {
                    stop();
                }
                throw;
            }
        }
        storage_.remove(options_.candidate_config);
    }

    void ensure_alive() {
        std::lock_guard lock{mutex_};
        if (!desired_running_ || degraded_ || running_locked()) {
            return;
        }
        if (std::chrono::steady_clock::now() < next_start_) {
            return;
        }
        try {
            start_locked();
        } catch (const std::exception& error) {
            last_error_ = error.what();
            record_failure_locked();
        }
    }

    void reload() {
        restart();
    }

    void restart() {
        std::unique_lock lock{mutex_};
        desired_running_ = true;
        degraded_ = false;
        stop_locked();
        try {
            start_locked();
        } catch (...) {
            record_failure_locked();
            throw;
        }
        const auto deadline = std::chrono::steady_clock::now() +
                              options_.health_timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!running_locked()) {
                throw std::runtime_error(
                    last_error_.value_or("sing-box stopped during startup"));
            }
            const auto port = clash_port_;
            const auto secret = clash_secret_;
            lock.unlock();
            const bool healthy = loopback_api_healthy(port, secret);
            lock.lock();
            if (healthy) {
                last_error_.reset();
                failure_times_.clear();
                return;
            }
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            lock.lock();
        }
        stop_locked();
        record_failure_locked();
        throw std::runtime_error("sing-box local API health deadline expired");
    }

    void stop() noexcept {
        std::lock_guard lock{mutex_};
        desired_running_ = false;
        stop_locked();
    }

    [[nodiscard]] bool running() {
        std::lock_guard lock{mutex_};
        return running_locked();
    }

    [[nodiscard]] std::optional<std::string> last_error() const {
        std::lock_guard lock{mutex_};
        return last_error_;
    }

    [[nodiscard]] std::uint16_t clash_port() const noexcept {
        std::lock_guard lock{mutex_};
        return clash_port_;
    }

    [[nodiscard]] std::string clash_secret() const {
        std::lock_guard lock{mutex_};
        return clash_secret_;
    }

    [[nodiscard]] std::uint16_t route_test_port() const noexcept {
        std::lock_guard lock{mutex_};
        return route_test_port_;
    }

    [[nodiscard]] std::string route_test_password() const {
        std::lock_guard lock{mutex_};
        return route_test_password_;
    }

    void set_strict_route(bool enabled) noexcept {
        std::lock_guard lock{mutex_};
        strict_route_ = enabled;
    }

  private:
    void validate_candidate(const std::filesystem::path& candidate,
                            std::string_view prefix) const {
        if (!std::filesystem::is_regular_file(options_.binary)) {
            throw std::runtime_error(std::string{prefix} +
                                     "bundled sing-box.exe is missing");
        }
        std::error_code directory_error;
        std::filesystem::create_directories(options_.log_path.parent_path(),
                                            directory_error);
        if (directory_error) {
            throw std::runtime_error(std::string{prefix} +
                                     "create log directory failed");
        }
        auto validation_job = create_kill_on_close_job();
        auto validation = launch_process(
            options_.binary, {L"check", L"-c", candidate.wstring()},
            options_.log_path, validation_job.get());
        const DWORD exit_code = wait_for_process(
            validation.get(), options_.health_timeout, validation_job.get());
        if (exit_code != 0U) {
            throw std::runtime_error(std::string{prefix} + "exit code " +
                                     std::to_string(exit_code));
        }
    }

    void rotate_occupied_local_ports_locked() {
        if (loopback_port_available(clash_port_) &&
            loopback_port_available(route_test_port_)) {
            return;
        }
        const auto contents = storage_.read(options_.active_config);
        if (!contents.has_value()) {
            return;
        }
        auto parsed = nlohmann::json::parse(*contents, nullptr, false);
        if (!parsed.is_object()) {
            throw std::runtime_error(
                "active sing-box config is invalid while rotating local ports");
        }
        const auto new_clash_port = available_loopback_port();
        std::uint16_t new_route_test_port{};
        do {
            new_route_test_port = available_loopback_port();
        } while (new_route_test_port == new_clash_port);
        install_private_endpoints(parsed, new_clash_port, clash_secret_,
                                  new_route_test_port, route_test_password_,
                                  strict_route_);
        const auto protected_config = parsed.dump();
        storage_.replace(
            options_.active_config, protected_config,
            [this](const std::filesystem::path& candidate) {
                if (!options_.validate_config) {
                    return;
                }
                validate_candidate(
                    candidate,
                    "sing-box local-port recovery validation failed: ");
            });
        clash_port_ = new_clash_port;
        route_test_port_ = new_route_test_port;
    }

    void start_locked() {
        if (running_locked()) {
            return;
        }
        if (!std::filesystem::is_regular_file(options_.binary)) {
            throw std::runtime_error("bundled sing-box.exe is missing");
        }
        if (!std::filesystem::is_regular_file(options_.wintun)) {
            throw std::runtime_error("bundled wintun.dll is missing");
        }
        if (!std::filesystem::is_regular_file(options_.active_config)) {
            return;
        }
        rotate_occupied_local_ports_locked();
        std::error_code directory_error;
        std::filesystem::create_directories(options_.log_path.parent_path(),
                                            directory_error);
        if (directory_error) {
            throw std::runtime_error("create sing-box log directory failed: " +
                                     directory_error.message());
        }
        rotate_singbox_log(options_.log_path);
        process_ = launch_process(
            options_.binary,
            {L"run", L"-c", options_.active_config.wstring()},
            options_.log_path, job_.get());
        desired_running_ = true;
        last_error_.reset();
    }

    void stop_locked() noexcept {
        if (!process_) {
            return;
        }
        static_cast<void>(::TerminateJobObject(job_.get(), 0U));
        const auto bounded = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(options_.shutdown_timeout.count()),
            static_cast<std::uint64_t>(INFINITE - 1U));
        if (::WaitForSingleObject(process_.get(), static_cast<DWORD>(bounded)) !=
            WAIT_OBJECT_0) {
            static_cast<void>(::TerminateProcess(process_.get(), 1U));
            static_cast<void>(::WaitForSingleObject(process_.get(), 1'000U));
        }
        process_.reset();
    }

    [[nodiscard]] bool running_locked() {
        if (!process_) {
            return false;
        }
        DWORD exit_code{};
        if (::GetExitCodeProcess(process_.get(), &exit_code) == FALSE) {
            last_error_ = "read sing-box process state failed";
            process_.reset();
            return false;
        }
        if (exit_code == STILL_ACTIVE) {
            return true;
        }
        last_error_ = "sing-box exited with code " + std::to_string(exit_code);
        process_.reset();
        return false;
    }

    void record_failure_locked() {
        const auto now = std::chrono::steady_clock::now();
        while (!failure_times_.empty() &&
               now - failure_times_.front() > std::chrono::seconds{60}) {
            failure_times_.pop_front();
        }
        failure_times_.push_back(now);
        if (failure_times_.size() >= 3U) {
            degraded_ = true;
            desired_running_ = false;
            stop_locked();
            last_error_ =
                "sing-box entered DEGRADED after three failures in 60 seconds";
            return;
        }
        const auto exponent = std::min<std::size_t>(failure_times_.size() - 1U, 4U);
        next_start_ = now + std::chrono::seconds{1LL << exponent};
    }

    WindowsSingBoxOptions options_;
    WindowsStorage storage_;
    OwnedHandle job_;
    OwnedHandle process_;
    mutable std::mutex mutex_;
    std::deque<std::chrono::steady_clock::time_point> failure_times_;
    std::chrono::steady_clock::time_point next_start_{};
    std::optional<std::string> last_error_;
    std::uint16_t clash_port_{};
    std::string clash_secret_;
    std::uint16_t route_test_port_{};
    std::string route_test_password_;
    bool desired_running_{true};
    bool strict_route_{false};
    bool degraded_{false};
    bool winsock_started_{false};
};

WindowsSingBoxSupervisor::WindowsSingBoxSupervisor(WindowsSingBoxOptions options)
    : implementation_(std::make_unique<Impl>(std::move(options))) {}
WindowsSingBoxSupervisor::~WindowsSingBoxSupervisor() = default;

void WindowsSingBoxSupervisor::apply_config(std::string_view contents) {
    implementation_->apply_config(contents);
}
void WindowsSingBoxSupervisor::ensure_alive() {
    implementation_->ensure_alive();
}
void WindowsSingBoxSupervisor::reload() {
    implementation_->reload();
}
void WindowsSingBoxSupervisor::restart() {
    implementation_->restart();
}
void WindowsSingBoxSupervisor::stop() {
    implementation_->stop();
}
bool WindowsSingBoxSupervisor::running() {
    return implementation_->running();
}
std::optional<std::string> WindowsSingBoxSupervisor::last_error() const {
    return implementation_->last_error();
}
std::uint16_t WindowsSingBoxSupervisor::clash_port() const noexcept {
    return implementation_->clash_port();
}
std::string WindowsSingBoxSupervisor::clash_secret() const {
    return implementation_->clash_secret();
}
std::uint16_t WindowsSingBoxSupervisor::route_test_port() const noexcept {
    return implementation_->route_test_port();
}
std::string WindowsSingBoxSupervisor::route_test_password() const {
    return implementation_->route_test_password();
}
void WindowsSingBoxSupervisor::set_strict_route(bool enabled) noexcept {
    implementation_->set_strict_route(enabled);
}

} // namespace sbeasy::win
