#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/ipc.hpp is only available on Windows"
#endif

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sbeasy::win {

struct PipeClient {
    unsigned long process_id{};
    unsigned long session_id{};
    bool administrator{false};
    bool active_console_session{false};
};

using PipeRequestHandler =
    std::function<nlohmann::json(const nlohmann::json&, const PipeClient&)>;

/// Blocking named-pipe server intended to run on the service's worker thread.
/// The DACL admits System, administrators, and interactive users, explicitly
/// denies Network, and each mutation receives verified client process context.
class NamedPipeServer final {
  public:
    explicit NamedPipeServer(
        PipeRequestHandler handler,
        std::wstring pipe_name = L"\\\\.\\pipe\\sb-easy-control-v1");
    ~NamedPipeServer();

    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;

    void run();
    void stop() noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

[[nodiscard]] bool is_sensitive_pipe_method(std::string_view method) noexcept;
[[nodiscard]] nlohmann::json redact_config(nlohmann::json value);

} // namespace sbeasy::win
