#include "sbeasy/windows/webview_host.hpp"

#include "sbeasy/windows/pipe_client.hpp"
#include "sbeasy/windows/ui_messages.hpp"
#include "sbeasy/windows/ui_preferences.hpp"

#include <objbase.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <wrl.h>
#include <WebView2.h>

#include <algorithm>
#include <condition_variable>
#include <cwchar>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

namespace sbeasy::win {
namespace {

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

constexpr wchar_t app_uri[] = L"https://app.sbeasy.local/index.html";
constexpr std::wstring_view app_prefix{L"https://app.sbeasy.local/"};

class CoTaskString final {
  public:
    ~CoTaskString() {
        ::CoTaskMemFree(value_);
    }
    [[nodiscard]] LPWSTR* output() noexcept {
        return &value_;
    }
    [[nodiscard]] std::wstring_view view() const noexcept {
        return value_ == nullptr ? std::wstring_view{} : std::wstring_view{value_};
    }

  private:
    LPWSTR value_{};
};

[[nodiscard]] std::wstring wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int length = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (length <= 0) {
        throw std::runtime_error("bridge response is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(),
                              length) != length) {
        throw std::runtime_error("bridge response is not valid UTF-8");
    }
    return result;
}

[[nodiscard]] std::string utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int length = ::WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        throw std::runtime_error("native path is not valid Unicode");
    }
    std::string result(static_cast<std::size_t>(length), '\0');
    if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(), length,
                              nullptr, nullptr) != length) {
        throw std::runtime_error("native path is not valid Unicode");
    }
    return result;
}

[[nodiscard]] bool starts_with_case_insensitive(std::wstring_view value,
                                                std::wstring_view prefix) {
    return value.size() >= prefix.size() &&
           ::_wcsnicmp(value.data(), prefix.data(), prefix.size()) == 0;
}

[[nodiscard]] bool is_app_resource(std::wstring_view uri) {
    return starts_with_case_insensitive(uri, app_prefix);
}

[[nodiscard]] bool is_external_http(std::wstring_view uri) {
    return starts_with_case_insensitive(uri, L"https://") ||
           starts_with_case_insensitive(uri, L"http://");
}

[[nodiscard]] bool is_safe_subresource(std::wstring_view uri) {
    return is_app_resource(uri) || starts_with_case_insensitive(uri, L"data:") ||
           starts_with_case_insensitive(uri, L"blob:");
}

[[nodiscard]] bool open_external(std::wstring_view uri) {
    if (!is_external_http(uri) || uri.size() > 2'048U ||
        uri.find_first_of(L"\r\n\0") != std::wstring_view::npos) {
        return false;
    }
    const std::wstring value{uri};
    return reinterpret_cast<INT_PTR>(::ShellExecuteW(
               nullptr, L"open", value.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) >
           32;
}

[[nodiscard]] nlohmann::json bridge_error(std::string id,
                                          std::string message) {
    if (message.size() > 512U) {
        message.resize(512U);
    }
    return {{"type", "rpc-result"},
            {"id", std::move(id)},
            {"ok", false},
            {"error", std::move(message)}};
}

[[nodiscard]] nlohmann::json ui_preferences_json() {
    const auto preferences = load_ui_preferences();
    return {{"launch_at_logon", preferences.launch_at_logon},
            {"close_to_tray", preferences.close_to_tray},
            {"minimize_to_tray", preferences.minimize_to_tray},
            {"update_notifications", preferences.update_notifications}};
}

[[nodiscard]] UiPreferences
parse_ui_preferences(const nlohmann::json& value) {
    if (!value.is_object()) {
        throw std::invalid_argument("UI preferences must be an object");
    }
    const auto boolean = [&value](const char* name) {
        const auto found = value.find(name);
        if (found == value.end() || !found->is_boolean()) {
            throw std::invalid_argument(std::string{name} +
                                        " must be a boolean");
        }
        return found->get<bool>();
    };
    return {.launch_at_logon = boolean("launch_at_logon"),
            .close_to_tray = boolean("close_to_tray"),
            .minimize_to_tray = boolean("minimize_to_tray"),
            .update_notifications = boolean("update_notifications")};
}

} // namespace

class WebViewHost::Impl final {
  public:
    Impl(HWND window, std::filesystem::path asset_directory,
         std::filesystem::path user_data_directory)
        : window_(window), asset_directory_(std::move(asset_directory)),
          user_data_directory_(std::move(user_data_directory)),
          worker_([this](std::stop_token stop) { rpc_worker(stop); }) {}

    ~Impl() {
        worker_.request_stop();
        request_ready_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
        }
        if (controller_) {
            static_cast<void>(controller_->Close());
        }
    }

    void initialize() {
        if (!std::filesystem::is_regular_file(asset_directory_ / L"index.html")) {
            show_failure(L"打包的 UI 资源不完整，缺少 ui\\index.html。");
            return;
        }
        std::error_code error;
        std::filesystem::create_directories(user_data_directory_, error);
        const HRESULT started = ::CreateCoreWebView2EnvironmentWithOptions(
            nullptr, user_data_directory_.c_str(), nullptr,
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [this](HRESULT result,
                       ICoreWebView2Environment* environment) -> HRESULT {
                    if (FAILED(result) || environment == nullptr) {
                        show_failure(
                            L"无法启动 Microsoft Edge WebView2 Runtime。请先安装 "
                            L"WebView2 Evergreen Runtime。");
                        return S_OK;
                    }
                    environment_ = environment;
                    const HRESULT creating =
                        environment_->CreateCoreWebView2Controller(
                            window_,
                            Callback<
                                ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                                [this](HRESULT controller_result,
                                       ICoreWebView2Controller* controller)
                                    -> HRESULT {
                                    if (FAILED(controller_result) ||
                                        controller == nullptr) {
                                        show_failure(L"无法创建 WebView2 控制器。");
                                        return S_OK;
                                    }
                                    controller_ = controller;
                                    if (FAILED(controller_->get_CoreWebView2(
                                            &webview_))) {
                                        show_failure(L"无法初始化 WebView2 页面。");
                                        return S_OK;
                                    }
                                    configure();
                                    resize();
                                    return S_OK;
                                })
                                .Get());
                    if (FAILED(creating)) {
                        show_failure(L"无法创建 WebView2 控制器。");
                    }
                    return S_OK;
                })
                .Get());
        if (FAILED(started)) {
            show_failure(L"当前系统未安装可用的 WebView2 Runtime。");
        }
    }

    void resize() const noexcept {
        if (!controller_) {
            return;
        }
        RECT bounds{};
        if (::GetClientRect(window_, &bounds) != FALSE) {
            static_cast<void>(controller_->put_Bounds(bounds));
        }
    }

    void deliver_activation(EnrollmentPreview preview) {
        pending_activation_ = std::move(preview);
        send_pending_activation();
    }

    void deliver_rpc_responses() {
        std::deque<nlohmann::json> ready;
        {
            std::lock_guard lock{response_mutex_};
            ready.swap(responses_);
        }
        for (const auto& response : ready) {
            post_json(response);
        }
    }

  private:
    struct RpcRequest {
        std::string id;
        std::string method;
        nlohmann::json params;
    };

    [[nodiscard]] std::optional<std::filesystem::path> choose_log_export() const {
        ComPtr<IFileSaveDialog> dialog;
        if (FAILED(::CoCreateInstance(CLSID_FileSaveDialog, nullptr,
                                      CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))) ||
            !dialog) {
            throw std::runtime_error("create Windows save dialog failed");
        }
        constexpr COMDLG_FILTERSPEC filters[]{{L"日志文件", L"*.log"},
                                               {L"所有文件", L"*.*"}};
        static_cast<void>(dialog->SetFileTypes(2U, filters));
        static_cast<void>(dialog->SetDefaultExtension(L"log"));
        static_cast<void>(dialog->SetFileName(L"sb-easy-diagnostics.log"));
        const HRESULT shown = dialog->Show(window_);
        if (shown == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
            return std::nullopt;
        }
        if (FAILED(shown)) {
            throw std::runtime_error("show Windows save dialog failed");
        }
        ComPtr<IShellItem> result;
        if (FAILED(dialog->GetResult(&result)) || !result) {
            throw std::runtime_error("read Windows save selection failed");
        }
        CoTaskString path;
        if (FAILED(result->GetDisplayName(SIGDN_FILESYSPATH, path.output())) ||
            path.view().empty()) {
            throw std::runtime_error("selected log path is invalid");
        }
        return std::filesystem::path{path.view()};
    }

    [[nodiscard]] nlohmann::json
    export_logs(const std::filesystem::path& path) const {
        const auto service =
            pipe_.request("logs.tail", {{"source", "service"}, {"lines", 2'000}});
        const auto core = pipe_.request(
            "logs.tail", {{"source", "sing-box"}, {"lines", 2'000}});
        std::string contents;
        const auto append = [&contents](std::string_view source,
                                        const nlohmann::json& response) {
            const auto lines = response.find("lines");
            if (lines == response.end() || !lines->is_array()) {
                return;
            }
            for (const auto& line : *lines) {
                if (line.is_string()) {
                    contents += "[" + std::string{source} + "] " +
                                line.get<std::string>() + "\r\n";
                }
            }
        };
        append("service", service);
        append("sing-box", core);
        if (contents.size() > 8U * 1024U * 1024U) {
            throw std::runtime_error("exported logs exceed the local size limit");
        }
        HANDLE raw = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                   nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (raw == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("create exported log file failed");
        }
        const std::unique_ptr<void, decltype(&::CloseHandle)> file{raw,
                                                                  &::CloseHandle};
        std::size_t offset{};
        while (offset < contents.size()) {
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                contents.size() - offset, 1024U * 1024U));
            DWORD written{};
            if (::WriteFile(file.get(), contents.data() + offset, requested,
                            &written, nullptr) == FALSE ||
                written == 0U) {
                throw std::runtime_error("write exported log file failed");
            }
            offset += written;
        }
        return {{"exported", true}, {"file", utf8(path.filename().wstring())}};
    }

    void show_failure(const wchar_t* message) const {
        static_cast<void>(::MessageBoxW(window_, message, L"sb-easy",
                                        MB_OK | MB_ICONERROR));
    }

    void configure() {
        ComPtr<ICoreWebView2Settings> settings;
        if (SUCCEEDED(webview_->get_Settings(&settings)) && settings) {
            static_cast<void>(settings->put_IsScriptEnabled(TRUE));
            static_cast<void>(settings->put_IsWebMessageEnabled(TRUE));
            static_cast<void>(settings->put_AreDefaultScriptDialogsEnabled(FALSE));
            static_cast<void>(settings->put_AreDevToolsEnabled(FALSE));
            static_cast<void>(settings->put_AreDefaultContextMenusEnabled(FALSE));
            static_cast<void>(settings->put_IsStatusBarEnabled(FALSE));
            static_cast<void>(settings->put_IsZoomControlEnabled(FALSE));
            ComPtr<ICoreWebView2Settings4> settings4;
            if (SUCCEEDED(settings.As(&settings4)) && settings4) {
                static_cast<void>(
                    settings4->put_IsPasswordAutosaveEnabled(FALSE));
                static_cast<void>(settings4->put_IsGeneralAutofillEnabled(FALSE));
            }
        }
        ComPtr<ICoreWebView2_3> webview3;
        if (FAILED(webview_.As(&webview3)) || !webview3 ||
            FAILED(webview3->SetVirtualHostNameToFolderMapping(
                L"app.sbeasy.local", asset_directory_.c_str(),
                COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY))) {
            show_failure(L"无法映射本地 UI 资源。");
            return;
        }
        EventRegistrationToken token{};
        static_cast<void>(webview_->add_NavigationStarting(
            Callback<ICoreWebView2NavigationStartingEventHandler>(
                [](ICoreWebView2*,
                   ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                    CoTaskString uri;
                    if (FAILED(args->get_Uri(uri.output())) ||
                        !is_app_resource(uri.view())) {
                        BOOL initiated{};
                        static_cast<void>(args->get_IsUserInitiated(&initiated));
                        if (initiated != FALSE) {
                            static_cast<void>(open_external(uri.view()));
                        }
                        static_cast<void>(args->put_Cancel(TRUE));
                    }
                    return S_OK;
                })
                .Get(),
            &token));
        static_cast<void>(webview_->add_NewWindowRequested(
            Callback<ICoreWebView2NewWindowRequestedEventHandler>(
                [](ICoreWebView2*,
                   ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                    CoTaskString uri;
                    static_cast<void>(args->get_Uri(uri.output()));
                    static_cast<void>(open_external(uri.view()));
                    static_cast<void>(args->put_Handled(TRUE));
                    return S_OK;
                })
                .Get(),
            &token));
        static_cast<void>(webview_->add_PermissionRequested(
            Callback<ICoreWebView2PermissionRequestedEventHandler>(
                [](ICoreWebView2*,
                   ICoreWebView2PermissionRequestedEventArgs* args) -> HRESULT {
                    COREWEBVIEW2_PERMISSION_KIND kind{};
                    BOOL initiated{};
                    CoTaskString uri;
                    static_cast<void>(args->get_PermissionKind(&kind));
                    static_cast<void>(args->get_IsUserInitiated(&initiated));
                    static_cast<void>(args->get_Uri(uri.output()));
                    const bool allowed =
                        kind == COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ &&
                        initiated != FALSE && is_app_resource(uri.view());
                    static_cast<void>(args->put_State(
                        allowed ? COREWEBVIEW2_PERMISSION_STATE_ALLOW
                                : COREWEBVIEW2_PERMISSION_STATE_DENY));
                    return S_OK;
                })
                .Get(),
            &token));
        static_cast<void>(webview_->add_WebMessageReceived(
            Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                [this](ICoreWebView2*,
                       ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                    handle_web_message(args);
                    return S_OK;
                })
                .Get(),
            &token));
        static_cast<void>(webview_->AddWebResourceRequestedFilter(
            L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL));
        static_cast<void>(webview_->add_WebResourceRequested(
            Callback<ICoreWebView2WebResourceRequestedEventHandler>(
                [this](ICoreWebView2*,
                       ICoreWebView2WebResourceRequestedEventArgs* args)
                    -> HRESULT {
                    ComPtr<ICoreWebView2WebResourceRequest> request;
                    CoTaskString uri;
                    if (SUCCEEDED(args->get_Request(&request)) && request &&
                        SUCCEEDED(request->get_Uri(uri.output())) &&
                        !is_safe_subresource(uri.view())) {
                        ComPtr<ICoreWebView2WebResourceResponse> blocked;
                        if (SUCCEEDED(environment_->CreateWebResourceResponse(
                                nullptr, 403, L"Blocked",
                                L"Content-Type: text/plain", &blocked))) {
                            static_cast<void>(args->put_Response(blocked.Get()));
                        }
                    }
                    return S_OK;
                })
                .Get(),
            &token));
        static_cast<void>(webview_->Navigate(app_uri));
    }

    void handle_web_message(ICoreWebView2WebMessageReceivedEventArgs* args) {
        CoTaskString source;
        CoTaskString raw;
        if (FAILED(args->get_Source(source.output())) ||
            !is_app_resource(source.view()) ||
            FAILED(args->get_WebMessageAsJson(raw.output())) ||
            raw.view().size() > 1024U * 1024U) {
            return;
        }
        nlohmann::json request;
        try {
            const auto serialized = raw.view();
            const int size = ::WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, serialized.data(),
                static_cast<int>(serialized.size()), nullptr, 0, nullptr, nullptr);
            if (size <= 0) {
                return;
            }
            std::string encoded(static_cast<std::size_t>(size), '\0');
            if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                      serialized.data(),
                                      static_cast<int>(serialized.size()),
                                      encoded.data(), size, nullptr, nullptr) != size) {
                return;
            }
            request = nlohmann::json::parse(encoded);
        } catch (const std::exception&) {
            return;
        }
        const std::string id = request.is_object()
                                   ? request.value("id", std::string{})
                                   : std::string{};
        try {
            if (!request.is_object() || id.empty() || id.size() > 128U ||
                !request.contains("method") ||
                !request.at("method").is_string()) {
                throw std::invalid_argument("invalid native bridge request");
            }
            const auto method = request.at("method").get<std::string>();
            const auto params =
                request.value("params", nlohmann::json::object());
            if (!params.is_object()) {
                throw std::invalid_argument("native bridge params must be an object");
            }
            if (method == "host.ready") {
                web_content_ready_ = true;
                post_json({{"type", "rpc-result"},
                           {"id", id},
                           {"ok", true},
                           {"result", {{"bridge_version", 1}}}});
                send_pending_activation();
                return;
            }
            if (method == "host.openExternal") {
                const auto uri = wide(params.at("url").get<std::string>());
                if (!open_external(uri)) {
                    throw std::invalid_argument("external URL is not allowed");
                }
                post_json({{"type", "rpc-result"},
                           {"id", id},
                           {"ok", true},
                           {"result", {{"opened", true}}}});
                return;
            }
            if (method == "host.exit") {
                static_cast<void>(::PostMessageW(window_, exit_ui_message, 0, 0));
                post_json({{"type", "rpc-result"},
                           {"id", id},
                           {"ok", true},
                           {"result", {{"exiting", true}}}});
                return;
            }
            if (method == "host.preferences") {
                post_json({{"type", "rpc-result"},
                           {"id", id},
                           {"ok", true},
                           {"result", ui_preferences_json()}});
                return;
            }
            if (method == "host.preferences.update") {
                const auto preferences =
                    parse_ui_preferences(params.at("preferences"));
                save_ui_preferences(preferences);
                post_json({{"type", "rpc-result"},
                           {"id", id},
                           {"ok", true},
                           {"result", ui_preferences_json()}});
                return;
            }
            if (method == "host.exportLogs") {
                const auto path = choose_log_export();
                if (!path.has_value()) {
                    post_json({{"type", "rpc-result"},
                               {"id", id},
                               {"ok", true},
                               {"result", {{"cancelled", true}}}});
                    return;
                }
                {
                    std::lock_guard lock{request_mutex_};
                    requests_.push_back(
                        {id, method, {{"path", utf8(path->wstring())}}});
                }
                request_ready_.notify_one();
                return;
            }
            static const std::set<std::string> allowed{
                "enrollment.status", "enrollment.apply", "enrollment.forget",
                "status.get",        "vpn.start",       "vpn.stop",
                "vpn.restart",       "config.refresh",  "config.summary",
                "config.redacted",   "proxies.list",    "proxy.select",
                "proxies.test",      "route.test",      "routes.stats",
                "logs.tail",         "logs.clear",      "logs.upload",
                "settings.get",      "settings.update"};
            if (!allowed.contains(method)) {
                throw std::invalid_argument("native bridge method is not allowed");
            }
            {
                std::lock_guard lock{request_mutex_};
                requests_.push_back({id, method, params});
            }
            request_ready_.notify_one();
        } catch (const std::exception& error) {
            post_json(bridge_error(id, error.what()));
        }
    }

    void rpc_worker(std::stop_token stop) {
        while (!stop.stop_requested()) {
            std::optional<RpcRequest> request;
            {
                std::unique_lock lock{request_mutex_};
                request_ready_.wait(lock, [&] {
                    return stop.stop_requested() || !requests_.empty();
                });
                if (stop.stop_requested()) {
                    return;
                }
                request = std::move(requests_.front());
                requests_.pop_front();
            }
            nlohmann::json response;
            try {
                const auto result = request->method == "host.exportLogs"
                                        ? export_logs(std::filesystem::path{
                                              wide(request->params.at("path")
                                                       .get<std::string>())})
                                        : pipe_.request(request->method,
                                                        request->params);
                response = {{"type", "rpc-result"},
                            {"id", request->id},
                            {"ok", true},
                            {"result", result}};
            } catch (const std::exception& error) {
                response = bridge_error(request->id, error.what());
            }
            {
                std::lock_guard lock{response_mutex_};
                responses_.push_back(std::move(response));
            }
            static_cast<void>(
                ::PostMessageW(window_, rpc_response_message, 0, 0));
        }
    }

    void post_json(const nlohmann::json& value) const {
        if (!webview_) {
            return;
        }
        try {
            const auto serialized = wide(value.dump());
            static_cast<void>(webview_->PostWebMessageAsJson(serialized.c_str()));
        } catch (const std::exception&) {
        }
    }

    void send_pending_activation() {
        if (!web_content_ready_ || !pending_activation_.has_value()) {
            return;
        }
        post_json({{"type", "enrollment-activation"},
                   {"server", pending_activation_->server},
                   {"code", pending_activation_->code}});
        pending_activation_.reset();
    }

    HWND window_{};
    std::filesystem::path asset_directory_;
    std::filesystem::path user_data_directory_;
    ComPtr<ICoreWebView2Environment> environment_;
    ComPtr<ICoreWebView2Controller> controller_;
    ComPtr<ICoreWebView2> webview_;
    NamedPipeClient pipe_;
    bool web_content_ready_{false};
    std::optional<EnrollmentPreview> pending_activation_;
    std::mutex request_mutex_;
    std::condition_variable request_ready_;
    std::deque<RpcRequest> requests_;
    std::mutex response_mutex_;
    std::deque<nlohmann::json> responses_;
    std::jthread worker_;
};

WebViewHost::WebViewHost(HWND window, std::filesystem::path asset_directory,
                         std::filesystem::path user_data_directory)
    : implementation_(std::make_unique<Impl>(window, std::move(asset_directory),
                                             std::move(user_data_directory))) {}
WebViewHost::~WebViewHost() = default;
void WebViewHost::initialize() {
    implementation_->initialize();
}
void WebViewHost::resize() const noexcept {
    implementation_->resize();
}
void WebViewHost::deliver_activation(EnrollmentPreview preview) {
    implementation_->deliver_activation(std::move(preview));
}
void WebViewHost::deliver_rpc_responses() {
    implementation_->deliver_rpc_responses();
}

} // namespace sbeasy::win
