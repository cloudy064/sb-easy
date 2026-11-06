#include "sbeasy/windows/ipc.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <sddl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace sbeasy::win {
namespace {

constexpr std::uint32_t maximum_message_size = 1024U * 1024U;

class Handle final {
  public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() {
        reset();
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
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
    HANDLE value_{nullptr};
};

[[nodiscard]] std::runtime_error pipe_error(std::string_view operation,
                                            DWORD error = ::GetLastError()) {
    return std::runtime_error(std::string{operation} + " failed with Windows error " +
                              std::to_string(error));
}

void read_exact(HANDLE pipe, void* destination, std::size_t size) {
    auto* output = static_cast<unsigned char*>(destination);
    std::size_t offset{};
    while (offset < size) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            size - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD received{};
        if (::ReadFile(pipe, output + offset, requested, &received, nullptr) == FALSE) {
            throw pipe_error("read named pipe");
        }
        if (received == 0U) {
            throw std::runtime_error("named pipe closed during message");
        }
        offset += received;
    }
}

void write_exact(HANDLE pipe, const void* source, std::size_t size) {
    const auto* input = static_cast<const unsigned char*>(source);
    std::size_t offset{};
    while (offset < size) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            size - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD written{};
        if (::WriteFile(pipe, input + offset, requested, &written, nullptr) == FALSE) {
            throw pipe_error("write named pipe");
        }
        if (written == 0U) {
            throw std::runtime_error("named pipe closed during response");
        }
        offset += written;
    }
}

[[nodiscard]] PipeClient client_context(HANDLE pipe) {
    ULONG process_id{};
    if (::GetNamedPipeClientProcessId(pipe, &process_id) == FALSE ||
        process_id == 0U) {
        throw pipe_error("identify named-pipe client");
    }
    Handle process{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 process_id)};
    if (!process) {
        throw pipe_error("open named-pipe client process");
    }
    HANDLE token_raw{};
    if (::OpenProcessToken(process.get(), TOKEN_QUERY | TOKEN_DUPLICATE, &token_raw) ==
        FALSE) {
        throw pipe_error("open named-pipe client token");
    }
    Handle token{token_raw};
    HANDLE membership_token_raw{};
    if (::DuplicateToken(token.get(), SecurityIdentification,
                         &membership_token_raw) == FALSE) {
        throw pipe_error("duplicate named-pipe client token");
    }
    Handle membership_token{membership_token_raw};
    DWORD session{};
    DWORD returned{};
    if (::GetTokenInformation(token.get(), TokenSessionId, &session, sizeof(session),
                              &returned) == FALSE) {
        throw pipe_error("read named-pipe client session");
    }
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> sid_buffer{};
    DWORD sid_size = static_cast<DWORD>(sid_buffer.size());
    if (::CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                             sid_buffer.data(), &sid_size) == FALSE) {
        throw pipe_error("create administrators SID");
    }
    BOOL administrator{};
    if (::CheckTokenMembership(membership_token.get(), sid_buffer.data(),
                               &administrator) == FALSE) {
        throw pipe_error("check named-pipe client membership");
    }
    const DWORD active_session = ::WTSGetActiveConsoleSessionId();
    return {
        .process_id = process_id,
        .session_id = session,
        .administrator = administrator != FALSE,
        .active_console_session =
            active_session != 0xffffffffU && session == active_session,
    };
}

[[nodiscard]] nlohmann::json failure_response(const nlohmann::json& id,
                                              std::string message) {
    if (message.size() > 512U) {
        message.resize(512U);
    }
    return {
        {"id", id},
        {"ok", false},
        {"error", {{"code", "request_failed"}, {"message", std::move(message)}}},
    };
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return value;
}

[[nodiscard]] bool sensitive_key(std::string_view key) {
    const auto normalized = lowercase(std::string{key});
    static constexpr std::array<std::string_view, 7> fragments{
        "token", "password", "secret", "uuid", "private_key", "credential",
        "authorization"};
    return std::any_of(fragments.begin(), fragments.end(),
                       [&normalized](std::string_view fragment) {
        return normalized.find(fragment) != std::string::npos;
    });
}

void redact_in_place(nlohmann::json& value, std::string_view parent_key = {}) {
    if (sensitive_key(parent_key) && !value.is_null()) {
        value = "***";
        return;
    }
    if (value.is_object()) {
        for (auto& [key, child] : value.items()) {
            redact_in_place(child, key);
        }
        return;
    }
    if (value.is_array()) {
        for (auto& child : value) {
            redact_in_place(child);
        }
        return;
    }
    if (value.is_string()) {
        auto text = value.get<std::string>();
        const auto scheme = text.find("://");
        const auto query = scheme == std::string::npos
                               ? std::string::npos
                               : text.find('?', scheme + 3U);
        if (query != std::string::npos) {
            text.erase(query);
            text += "?<redacted>";
            value = std::move(text);
        }
    }
}

} // namespace

bool is_sensitive_pipe_method(std::string_view method) noexcept {
    static const std::set<std::string_view> sensitive{
        "enrollment.apply", "enrollment.forget", "vpn.start", "vpn.stop",
        "vpn.restart",      "config.refresh",    "proxy.select",
        "proxies.test",     "route.test",        "logs.clear",
        "logs.export",
        "logs.upload",      "settings.update"};
    return sensitive.contains(method);
}

nlohmann::json redact_config(nlohmann::json value) {
    redact_in_place(value);
    return value;
}

class NamedPipeServer::Impl final {
  public:
    explicit Impl(PipeRequestHandler handler, std::wstring pipe_name)
        : handler_(std::move(handler)), pipe_name_(std::move(pipe_name)) {
        if (!handler_) {
            throw std::invalid_argument("named-pipe request handler is required");
        }
    }

    void run() {
        PSECURITY_DESCRIPTOR descriptor_raw{};
        // Network is denied first. LocalSystem/admins receive full access;
        // interactive users receive only read/write, not ACL/owner rights.
        constexpr wchar_t sddl[] =
            L"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
        if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &descriptor_raw, nullptr) == FALSE) {
            throw pipe_error("create named-pipe security descriptor");
        }
        const std::unique_ptr<void, decltype(&::LocalFree)> descriptor{
            descriptor_raw, &::LocalFree};
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.get(), FALSE};

        while (!stopping_.load()) {
            Handle pipe{::CreateNamedPipeW(
                pipe_name_.c_str(), PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                    PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, 64U * 1024U, 64U * 1024U, 0,
                &attributes)};
            if (!pipe) {
                throw pipe_error("create named pipe");
            }
            current_pipe_.store(pipe.get());
            const BOOL connected = ::ConnectNamedPipe(pipe.get(), nullptr);
            if (connected == FALSE && ::GetLastError() != ERROR_PIPE_CONNECTED) {
                if (stopping_.load()) {
                    current_pipe_.store(nullptr);
                    return;
                }
                current_pipe_.store(nullptr);
                continue;
            }
            if (stopping_.load()) {
                current_pipe_.store(nullptr);
                return;
            }
            try {
                serve(pipe.get());
            } catch (const std::exception&) {
                // A malformed or disconnected client must not terminate the service.
            }
            static_cast<void>(::FlushFileBuffers(pipe.get()));
            static_cast<void>(::DisconnectNamedPipe(pipe.get()));
            current_pipe_.store(nullptr);
        }
    }

    void stop() noexcept {
        stopping_.store(true);
        if (const auto current = current_pipe_.load(); current != nullptr) {
            static_cast<void>(::DisconnectNamedPipe(current));
            static_cast<void>(::CancelIoEx(current, nullptr));
        }
        Handle wake{::CreateFileW(pipe_name_.c_str(), GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr)};
    }

  private:
    void serve(HANDLE pipe) {
        std::optional<PipeClient> client;
        std::optional<std::string> client_error;
        try {
            client = client_context(pipe);
        } catch (const std::exception& error) {
            client_error = error.what();
        }
        while (!stopping_.load()) {
            std::array<unsigned char, 4> prefix{};
            read_exact(pipe, prefix.data(), prefix.size());
            const std::uint32_t length =
                static_cast<std::uint32_t>(prefix[0]) |
                (static_cast<std::uint32_t>(prefix[1]) << 8U) |
                (static_cast<std::uint32_t>(prefix[2]) << 16U) |
                (static_cast<std::uint32_t>(prefix[3]) << 24U);
            if (length == 0U || length > maximum_message_size) {
                throw std::runtime_error("named-pipe message length is invalid");
            }
            std::string serialized(length, '\0');
            read_exact(pipe, serialized.data(), serialized.size());
            auto request = nlohmann::json::parse(serialized, nullptr, false);
            const auto id = request.is_object() && request.contains("id")
                                ? request.at("id")
                                : nlohmann::json{nullptr};
            nlohmann::json response;
            try {
                if (!request.is_object() || !request.contains("id") ||
                    !request.at("id").is_string() ||
                    request.at("id").get_ref<const std::string&>().size() > 128U ||
                    request.value("version", 0) != 1 ||
                    !request.contains("method") ||
                    !request.at("method").is_string()) {
                    throw std::invalid_argument("invalid IPC request envelope");
                }
                if (client_error.has_value() || !client.has_value()) {
                    throw std::runtime_error(
                        client_error.value_or("named-pipe client is not authorized"));
                }
                const auto method = request.at("method").get<std::string>();
                auto verified_client = *client;
                if (is_sensitive_pipe_method(method)) {
                    // Re-open the PID and token for every mutation. A UI that
                    // remained connected across a console-session switch must
                    // not retain stale mutation authority.
                    verified_client = client_context(pipe);
                }
                if (is_sensitive_pipe_method(method) &&
                    !verified_client.administrator &&
                    !verified_client.active_console_session) {
                    throw std::runtime_error(
                        "mutation requires the active console session or an "
                        "administrator");
                }
                response = {
                    {"id", id},
                    {"ok", true},
                    {"result", handler_(request, verified_client)},
                };
            } catch (const std::exception& error) {
                response = failure_response(id, error.what());
            }
            const auto body = response.dump();
            if (body.size() > maximum_message_size) {
                response = failure_response(id, "IPC response exceeds 1 MiB");
            }
            const auto final_body = response.dump();
            const auto response_size = static_cast<std::uint32_t>(final_body.size());
            const std::array<unsigned char, 4> response_prefix{
                static_cast<unsigned char>(response_size & 0xffU),
                static_cast<unsigned char>((response_size >> 8U) & 0xffU),
                static_cast<unsigned char>((response_size >> 16U) & 0xffU),
                static_cast<unsigned char>((response_size >> 24U) & 0xffU),
            };
            write_exact(pipe, response_prefix.data(), response_prefix.size());
            write_exact(pipe, final_body.data(), final_body.size());
        }
    }

    PipeRequestHandler handler_;
    std::wstring pipe_name_;
    std::atomic_bool stopping_{false};
    std::atomic<HANDLE> current_pipe_{nullptr};
};

NamedPipeServer::NamedPipeServer(PipeRequestHandler handler, std::wstring pipe_name)
    : implementation_(std::make_unique<Impl>(std::move(handler),
                                           std::move(pipe_name))) {}
NamedPipeServer::~NamedPipeServer() = default;
void NamedPipeServer::run() {
    implementation_->run();
}
void NamedPipeServer::stop() noexcept {
    implementation_->stop();
}

} // namespace sbeasy::win
