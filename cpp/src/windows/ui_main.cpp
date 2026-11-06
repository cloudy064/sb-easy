#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "sbeasy/windows/enrollment.hpp"
#include "sbeasy/windows/ui_messages.hpp"
#include "sbeasy/windows/ui_preferences.hpp"
#include "sbeasy/windows/webview_host.hpp"

namespace sbeasy::win {
namespace {

constexpr wchar_t window_class[] = L"SbEasyDesktopWindowV1";
constexpr wchar_t window_title[] = L"sb-easy";
constexpr wchar_t mutex_name[] = L"Local\\sb-easy-ui-v1";

[[nodiscard]] std::string utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = ::WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::invalid_argument("activation is not valid Unicode");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(), size,
                              nullptr, nullptr) != size) {
        throw std::invalid_argument("activation is not valid Unicode");
    }
    return result;
}

[[nodiscard]] std::wstring wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (size <= 0) {
        throw std::invalid_argument("activation is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(),
                              size) != size) {
        throw std::invalid_argument("activation is not valid UTF-8");
    }
    return result;
}

[[nodiscard]] std::filesystem::path executable_directory() {
    std::wstring value(32'768U, L'\0');
    const DWORD length =
        ::GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length == 0U || length >= value.size()) {
        throw std::runtime_error("resolve executable directory failed");
    }
    value.resize(length);
    return std::filesystem::path{value}.parent_path();
}

[[nodiscard]] std::filesystem::path webview_data_directory() {
    PWSTR raw{};
    if (FAILED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE,
                                      nullptr, &raw)) ||
        raw == nullptr) {
        throw std::runtime_error("resolve LocalAppData failed");
    }
    const std::unique_ptr<wchar_t, decltype(&::CoTaskMemFree)> value{
        raw, &::CoTaskMemFree};
    return std::filesystem::path{value.get()} / L"sb-easy" / L"WebView2";
}

[[nodiscard]] std::optional<std::wstring> command_line_activation() {
    int count{};
    LPWSTR* raw = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    const std::unique_ptr<LPWSTR, decltype(&::LocalFree)> arguments{
        raw, &::LocalFree};
    if (raw == nullptr) {
        return std::nullopt;
    }
    for (int index = 1; index < count; ++index) {
        const std::wstring_view value{raw[index]};
        if (value.size() >= 9U &&
            ::_wcsnicmp(value.data(), L"sbeasy://", 9U) == 0) {
            return std::wstring{value};
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool command_line_flag(std::wstring_view flag) {
    int count{};
    LPWSTR* raw = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    const std::unique_ptr<LPWSTR, decltype(&::LocalFree)> arguments{
        raw, &::LocalFree};
    if (raw == nullptr) {
        return false;
    }
    for (int index = 1; index < count; ++index) {
        if (std::wstring_view{raw[index]} == flag) {
            return true;
        }
    }
    return false;
}

class DesktopWindow final {
  public:
    DesktopWindow(HINSTANCE instance, std::optional<EnrollmentPreview> activation,
                  bool start_hidden)
        : instance_(instance), activation_(std::move(activation)),
          start_hidden_(start_hidden) {}

    void create() {
        WNDCLASSEXW window_class_info{sizeof(window_class_info)};
        window_class_info.style = CS_HREDRAW | CS_VREDRAW;
        window_class_info.lpfnWndProc = &window_proc;
        window_class_info.hInstance = instance_;
        window_class_info.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        window_class_info.hIconSm = window_class_info.hIcon;
        window_class_info.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        window_class_info.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        window_class_info.lpszClassName = window_class;
        if (::RegisterClassExW(&window_class_info) == 0U &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            throw std::runtime_error("register desktop window failed");
        }
        window_ = ::CreateWindowExW(
            0, window_class, window_title, WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 1'180, 780, nullptr, nullptr, instance_,
            this);
        if (window_ == nullptr) {
            throw std::runtime_error("create desktop window failed");
        }
        webview_ = std::make_unique<WebViewHost>(
            window_, executable_directory() / L"ui", webview_data_directory());
        add_tray_icon();
        webview_->initialize();
        if (activation_.has_value()) {
            webview_->deliver_activation(std::move(*activation_));
            activation_.reset();
        }
        if (!start_hidden_) {
            show();
        }
    }

    [[nodiscard]] HWND window() const noexcept {
        return window_;
    }

  private:
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam,
                                        LPARAM lparam) {
        DesktopWindow* self = reinterpret_cast<DesktopWindow*>(
            ::GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
            self = static_cast<DesktopWindow*>(create->lpCreateParams);
            self->window_ = window;
            ::SetWindowLongPtrW(window, GWLP_USERDATA,
                                reinterpret_cast<LONG_PTR>(self));
        }
        return self == nullptr ? ::DefWindowProcW(window, message, wparam, lparam)
                               : self->handle(message, wparam, lparam);
    }

    LRESULT handle(UINT message, WPARAM wparam, LPARAM lparam) {
        switch (message) {
        case WM_SIZE:
            if (wparam == SIZE_MINIMIZED &&
                load_ui_preferences().minimize_to_tray) {
                ::ShowWindow(window_, SW_HIDE);
                return 0;
            }
            if (webview_) {
                webview_->resize();
            }
            return 0;
        case WM_DPICHANGED: {
            const auto* suggested = reinterpret_cast<RECT*>(lparam);
            static_cast<void>(::SetWindowPos(
                window_, nullptr, suggested->left, suggested->top,
                suggested->right - suggested->left,
                suggested->bottom - suggested->top,
                SWP_NOACTIVATE | SWP_NOZORDER));
            return 0;
        }
        case WM_GETMINMAXINFO: {
            auto* bounds = reinterpret_cast<MINMAXINFO*>(lparam);
            const UINT dpi = ::GetDpiForWindow(window_);
            bounds->ptMinTrackSize.x = ::MulDiv(900, static_cast<int>(dpi), 96);
            bounds->ptMinTrackSize.y = ::MulDiv(620, static_cast<int>(dpi), 96);
            return 0;
        }
        case WM_CLOSE:
            if (load_ui_preferences().close_to_tray) {
                ::ShowWindow(window_, SW_HIDE);
            } else {
                ::DestroyWindow(window_);
            }
            return 0;
        case WM_COMMAND:
            if (LOWORD(wparam) == tray_open_command) {
                show();
            } else if (LOWORD(wparam) == tray_exit_command) {
                ::DestroyWindow(window_);
            }
            return 0;
        case tray_message:
            if (LOWORD(lparam) == WM_LBUTTONUP) {
                show();
            } else if (LOWORD(lparam) == WM_RBUTTONUP ||
                       LOWORD(lparam) == WM_CONTEXTMENU) {
                show_tray_menu();
            }
            return 0;
        case rpc_response_message:
            if (webview_) {
                webview_->deliver_rpc_responses();
            }
            return 0;
        case show_window_message:
            show();
            return 0;
        case exit_ui_message:
            ::DestroyWindow(window_);
            return 0;
        case WM_COPYDATA:
            receive_activation(reinterpret_cast<const COPYDATASTRUCT*>(lparam));
            return TRUE;
        case WM_DESTROY:
            remove_tray_icon();
            webview_.reset();
            ::PostQuitMessage(0);
            return 0;
        default:
            return ::DefWindowProcW(window_, message, wparam, lparam);
        }
    }

    void show() const noexcept {
        ::ShowWindow(window_, SW_SHOW);
        static_cast<void>(::SetForegroundWindow(window_));
    }

    void add_tray_icon() {
        tray_.cbSize = sizeof(tray_);
        tray_.hWnd = window_;
        tray_.uID = 1U;
        tray_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        tray_.uCallbackMessage = tray_message;
        tray_.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        static_cast<void>(::wcscpy_s(tray_.szTip, L"sb-easy"));
        if (::Shell_NotifyIconW(NIM_ADD, &tray_) != FALSE) {
            tray_added_ = true;
            tray_.uVersion = NOTIFYICON_VERSION_4;
            static_cast<void>(::Shell_NotifyIconW(NIM_SETVERSION, &tray_));
        }
    }

    void remove_tray_icon() noexcept {
        if (tray_added_) {
            static_cast<void>(::Shell_NotifyIconW(NIM_DELETE, &tray_));
            tray_added_ = false;
        }
    }

    void show_tray_menu() {
        HMENU raw = ::CreatePopupMenu();
        if (raw == nullptr) {
            return;
        }
        const std::unique_ptr<std::remove_pointer_t<HMENU>,
                              decltype(&::DestroyMenu)>
            menu{raw, &::DestroyMenu};
        static_cast<void>(::AppendMenuW(menu.get(), MF_STRING, tray_open_command,
                                        L"打开 sb-easy"));
        static_cast<void>(::AppendMenuW(menu.get(), MF_SEPARATOR, 0U, nullptr));
        static_cast<void>(::AppendMenuW(menu.get(), MF_STRING, tray_exit_command,
                                        L"退出界面"));
        POINT point{};
        static_cast<void>(::GetCursorPos(&point));
        static_cast<void>(::SetForegroundWindow(window_));
        static_cast<void>(::TrackPopupMenu(
            menu.get(), TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
            point.x, point.y, 0, window_, nullptr));
    }

    void receive_activation(const COPYDATASTRUCT* data) {
        if (data == nullptr || data->dwData != enrollment_copy_data ||
            data->lpData == nullptr || data->cbData < sizeof(wchar_t) ||
            data->cbData > 8'192U || data->cbData % sizeof(wchar_t) != 0U) {
            return;
        }
        const auto count = data->cbData / sizeof(wchar_t);
        const auto* value = static_cast<const wchar_t*>(data->lpData);
        if (value[count - 1U] != L'\0') {
            return;
        }
        try {
            auto preview = parse_enrollment_uri(
                utf8(std::wstring_view{value, count - 1U}));
            if (webview_) {
                webview_->deliver_activation(std::move(preview));
            }
            show();
        } catch (const std::exception&) {
            static_cast<void>(::MessageBoxW(
                window_, L"收到的注册链接无效，未进行注册。", L"sb-easy",
                MB_OK | MB_ICONWARNING));
        }
    }

    HINSTANCE instance_{};
    HWND window_{};
    std::unique_ptr<WebViewHost> webview_;
    std::optional<EnrollmentPreview> activation_;
    NOTIFYICONDATAW tray_{};
    bool tray_added_{false};
    bool start_hidden_{false};
};

[[nodiscard]] bool forward_to_existing(const std::optional<std::wstring>& raw) {
    for (unsigned attempt{}; attempt < 60U; ++attempt) {
        if (const HWND window = ::FindWindowW(window_class, nullptr);
            window != nullptr) {
            if (raw.has_value()) {
                COPYDATASTRUCT data{};
                data.dwData = enrollment_copy_data;
                data.cbData = static_cast<DWORD>((raw->size() + 1U) *
                                                 sizeof(wchar_t));
                data.lpData = const_cast<wchar_t*>(raw->c_str());
                DWORD_PTR ignored{};
                return ::SendMessageTimeoutW(
                           window, WM_COPYDATA, 0,
                           reinterpret_cast<LPARAM>(&data),
                           SMTO_ABORTIFHUNG | SMTO_BLOCK, 3'000U, &ignored) != 0;
            }
            return ::PostMessageW(window, show_window_message, 0, 0) != FALSE;
        }
        ::Sleep(50U);
    }
    return false;
}

} // namespace
} // namespace sbeasy::win

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    using namespace sbeasy::win;
    static_cast<void>(::SetProcessDpiAwarenessContext(
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
    const HRESULT com = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) {
        return 1;
    }
    const auto uninitialize = std::unique_ptr<void, void (*)(void*)>{
        reinterpret_cast<void*>(1), [](void*) { ::CoUninitialize(); }};
    HANDLE mutex_raw = ::CreateMutexW(nullptr, FALSE, L"Local\\sb-easy-ui-v1");
    const bool already_running = ::GetLastError() == ERROR_ALREADY_EXISTS;
    const std::unique_ptr<void, decltype(&::CloseHandle)> mutex{mutex_raw,
                                                               &::CloseHandle};
    if (mutex_raw == nullptr) {
        return 1;
    }
    const auto raw_activation = command_line_activation();
    const bool background = command_line_flag(L"--background");
    if (already_running) {
        if (raw_activation.has_value() || !background) {
            static_cast<void>(forward_to_existing(raw_activation));
        }
        return 0;
    }
    try {
        std::optional<EnrollmentPreview> activation;
        if (raw_activation.has_value()) {
            activation = parse_enrollment_uri(utf8(*raw_activation));
        }
        DesktopWindow desktop{instance, std::move(activation), background};
        desktop.create();
        MSG message{};
        while (::GetMessageW(&message, nullptr, 0, 0) > 0) {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    } catch (const std::exception& error) {
        std::wstring message;
        try {
            message = wide(error.what());
        } catch (const std::exception&) {
            message = L"Windows 客户端启动失败。";
        }
        static_cast<void>(::MessageBoxW(nullptr, message.c_str(), L"sb-easy",
                                        MB_OK | MB_ICONERROR));
        return 1;
    }
}
