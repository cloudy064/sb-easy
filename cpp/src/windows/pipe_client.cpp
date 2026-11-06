#include "sbeasy/windows/pipe_client.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace sbeasy::win {
namespace {

std::atomic_uint64_t next_request_id{1U};

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
    return std::runtime_error(std::string{operation} +
                              " failed with Windows error " +
                              std::to_string(error));
}

[[nodiscard]] DWORD remaining_timeout(
    std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return 0U;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
    return static_cast<DWORD>(std::clamp<long long>(remaining.count(), 1LL,
                                                    MAXDWORD - 1LL));
}

enum class Operation { read, write };

void transfer_exact(HANDLE pipe, void* buffer, std::size_t size,
                    Operation operation,
                    std::chrono::steady_clock::time_point deadline) {
    auto* bytes = static_cast<unsigned char*>(buffer);
    std::size_t offset{};
    while (offset < size) {
        Handle event{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        if (!event) {
            throw pipe_error("create named-pipe I/O event");
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            size - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD transferred{};
        const BOOL completed = operation == Operation::read
                                   ? ::ReadFile(pipe, bytes + offset, requested,
                                                &transferred, &overlapped)
                                   : ::WriteFile(pipe, bytes + offset, requested,
                                                 &transferred, &overlapped);
        if (completed == FALSE) {
            const DWORD error = ::GetLastError();
            if (error != ERROR_IO_PENDING) {
                throw pipe_error(operation == Operation::read
                                     ? "read service control pipe"
                                     : "write service control pipe",
                                 error);
            }
            const DWORD wait = remaining_timeout(deadline);
            if (wait == 0U || ::WaitForSingleObject(event.get(), wait) !=
                                  WAIT_OBJECT_0) {
                static_cast<void>(::CancelIoEx(pipe, &overlapped));
                static_cast<void>(::WaitForSingleObject(event.get(), INFINITE));
                throw std::runtime_error("service control pipe request timed out");
            }
            if (::GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) ==
                FALSE) {
                throw pipe_error(operation == Operation::read
                                     ? "complete service control pipe read"
                                     : "complete service control pipe write");
            }
        }
        if (transferred == 0U) {
            throw std::runtime_error("service control pipe closed during message");
        }
        offset += transferred;
    }
}

[[nodiscard]] Handle connect(std::chrono::milliseconds timeout,
                             const std::wstring& pipe_name) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    Handle pipe;
    for (;;) {
        pipe.reset(::CreateFileW(
            pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        if (pipe) {
            break;
        }
        const DWORD error = ::GetLastError();
        const DWORD wait = remaining_timeout(deadline);
        if (wait == 0U) {
            throw pipe_error("connect service control pipe", error);
        }
        if (error == ERROR_PIPE_BUSY) {
            if (::WaitNamedPipeW(pipe_name.c_str(), wait) == FALSE) {
                const DWORD wait_error = ::GetLastError();
                if (wait_error != ERROR_SEM_TIMEOUT &&
                    wait_error != ERROR_FILE_NOT_FOUND) {
                    throw pipe_error("wait for service control pipe", wait_error);
                }
            }
            continue;
        }
        if (error == ERROR_FILE_NOT_FOUND) {
            ::Sleep(std::min<DWORD>(wait, 20U));
            continue;
        }
        throw pipe_error("connect service control pipe", error);
    }
    DWORD mode = PIPE_READMODE_BYTE;
    if (::SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr) == FALSE) {
        throw pipe_error("configure service control pipe");
    }
    return pipe;
}

[[nodiscard]] std::string error_message(const nlohmann::json& response) {
    const auto error = response.value("error", nlohmann::json::object());
    if (error.is_object()) {
        const auto message = error.value("message", std::string{});
        if (!message.empty()) {
            return message;
        }
    }
    return "service rejected the IPC request";
}

} // namespace

NamedPipeClient::NamedPipeClient(std::chrono::milliseconds timeout,
                                 std::size_t maximum_message_size,
                                 std::wstring pipe_name)
    : timeout_(timeout), maximum_message_size_(maximum_message_size),
      pipe_name_(std::move(pipe_name)) {
    if (timeout_ <= std::chrono::milliseconds::zero() ||
        maximum_message_size_ == 0U ||
        maximum_message_size_ > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("named-pipe client limits are invalid");
    }
}

nlohmann::json NamedPipeClient::request(std::string_view method,
                                        const nlohmann::json& params) const {
    if (method.empty() || method.size() > 128U || !params.is_object()) {
        throw std::invalid_argument("invalid named-pipe request");
    }
    const auto id = std::to_string(::GetCurrentProcessId()) + "-" +
                    std::to_string(next_request_id.fetch_add(1U));
    const auto body = nlohmann::json{{"id", id},
                                     {"version", 1},
                                     {"method", method},
                                     {"params", params}}
                          .dump();
    if (body.empty() || body.size() > maximum_message_size_) {
        throw std::invalid_argument("named-pipe request exceeds size limit");
    }
    const auto body_size = static_cast<std::uint32_t>(body.size());
    std::array<unsigned char, 4> prefix{
        static_cast<unsigned char>(body_size & 0xffU),
        static_cast<unsigned char>((body_size >> 8U) & 0xffU),
        static_cast<unsigned char>((body_size >> 16U) & 0xffU),
        static_cast<unsigned char>((body_size >> 24U) & 0xffU),
    };
    auto pipe = connect(timeout_, pipe_name_);
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    transfer_exact(pipe.get(), prefix.data(), prefix.size(), Operation::write,
                   deadline);
    transfer_exact(pipe.get(), const_cast<char*>(body.data()), body.size(),
                   Operation::write, deadline);

    std::array<unsigned char, 4> response_prefix{};
    transfer_exact(pipe.get(), response_prefix.data(), response_prefix.size(),
                   Operation::read, deadline);
    const std::uint32_t response_size =
        static_cast<std::uint32_t>(response_prefix[0]) |
        (static_cast<std::uint32_t>(response_prefix[1]) << 8U) |
        (static_cast<std::uint32_t>(response_prefix[2]) << 16U) |
        (static_cast<std::uint32_t>(response_prefix[3]) << 24U);
    if (response_size == 0U || response_size > maximum_message_size_) {
        throw std::runtime_error("service control pipe response length is invalid");
    }
    std::string response_body(response_size, '\0');
    transfer_exact(pipe.get(), response_body.data(), response_body.size(),
                   Operation::read, deadline);
    const auto response =
        nlohmann::json::parse(response_body, nullptr, false, false);
    if (!response.is_object() || response.value("id", std::string{}) != id ||
        !response.contains("ok") || !response.at("ok").is_boolean()) {
        throw std::runtime_error("service returned an invalid IPC response");
    }
    if (!response.at("ok").get<bool>()) {
        throw std::runtime_error(error_message(response));
    }
    if (!response.contains("result")) {
        throw std::runtime_error("service IPC response is missing a result");
    }
    return response.at("result");
}

} // namespace sbeasy::win
