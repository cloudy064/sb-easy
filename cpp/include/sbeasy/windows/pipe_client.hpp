#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/pipe_client.hpp is only available on Windows"
#endif

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sbeasy::win {

/// A short-lived, framed RPC client for the service control pipe. Each request
/// uses a new connection so the service re-evaluates the caller process and
/// console-session security context instead of relying on UI-side state.
class NamedPipeClient final {
  public:
    explicit NamedPipeClient(
        std::chrono::milliseconds timeout = std::chrono::seconds{60},
        std::size_t maximum_message_size = 1024U * 1024U,
        std::wstring pipe_name = L"\\\\.\\pipe\\sb-easy-control-v1");

    [[nodiscard]] nlohmann::json
    request(std::string_view method,
            const nlohmann::json& params = nlohmann::json::object()) const;

  private:
    std::chrono::milliseconds timeout_;
    std::size_t maximum_message_size_;
    std::wstring pipe_name_;
};

} // namespace sbeasy::win
