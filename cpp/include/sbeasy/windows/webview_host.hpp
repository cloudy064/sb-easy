#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/webview_host.hpp is only available on Windows"
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <memory>

#include "sbeasy/windows/enrollment.hpp"

namespace sbeasy::win {

class WebViewHost final {
  public:
    WebViewHost(HWND window, std::filesystem::path asset_directory,
                std::filesystem::path user_data_directory);
    ~WebViewHost();

    WebViewHost(const WebViewHost&) = delete;
    WebViewHost& operator=(const WebViewHost&) = delete;

    void initialize();
    void resize() const noexcept;
    void deliver_activation(EnrollmentPreview preview);
    void deliver_rpc_responses();

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy::win
