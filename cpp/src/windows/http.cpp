#include "sbeasy/windows/http.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "sbeasy/version.hpp"

namespace sbeasy::win {
namespace {

class InternetHandle final {
  public:
    InternetHandle() = default;
    explicit InternetHandle(HINTERNET value) : value_(value) {}
    ~InternetHandle() {
        reset();
    }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    InternetHandle(InternetHandle&& other) noexcept : value_(other.release()) {}
    InternetHandle& operator=(InternetHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    [[nodiscard]] HINTERNET get() const noexcept {
        return value_;
    }
    [[nodiscard]] HINTERNET release() noexcept {
        return std::exchange(value_, nullptr);
    }
    void reset(HINTERNET value = nullptr) noexcept {
        if (value_ != nullptr) {
            static_cast<void>(::WinHttpCloseHandle(value_));
        }
        value_ = value;
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr;
    }

  private:
    HINTERNET value_{nullptr};
};

[[nodiscard]] std::wstring wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("HTTP value is too long");
    }
    const int size = static_cast<int>(value.size());
    const int required =
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size,
                              nullptr, 0);
    if (required <= 0) {
        throw std::invalid_argument("HTTP value is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size,
                              result.data(), required) != required) {
        throw std::invalid_argument("HTTP value is not valid UTF-8");
    }
    return result;
}

[[nodiscard]] std::string utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("HTTP header is too long");
    }
    const int size = static_cast<int>(value.size());
    const int required = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                                value.data(), size, nullptr, 0,
                                                nullptr, nullptr);
    if (required <= 0) {
        throw std::runtime_error("HTTP header is not valid UTF-16");
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), size,
                              result.data(), required, nullptr, nullptr) != required) {
        throw std::runtime_error("HTTP header is not valid UTF-16");
    }
    return result;
}

[[nodiscard]] std::runtime_error http_error(std::string_view operation) {
    return std::runtime_error(std::string{operation} + " failed with WinHTTP error " +
                              std::to_string(::GetLastError()));
}

struct ServerAddress {
    std::wstring host;
    INTERNET_PORT port{};
    std::wstring path_prefix;
    bool secure{false};
};

[[nodiscard]] ServerAddress parse_server(const std::string& server) {
    if (server.find_first_of("?#") != std::string::npos) {
        throw std::invalid_argument(
            "agent server must not contain a query or fragment");
    }
    auto value = wide(server);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwUserNameLength = static_cast<DWORD>(-1);
    components.dwPasswordLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (::WinHttpCrackUrl(value.c_str(), static_cast<DWORD>(value.size()), 0,
                          &components) == FALSE) {
        throw std::invalid_argument("agent server URL is invalid");
    }
    if (components.nScheme != INTERNET_SCHEME_HTTP &&
        components.nScheme != INTERNET_SCHEME_HTTPS) {
        throw std::invalid_argument("agent server must use http:// or https://");
    }
    if (components.dwHostNameLength == 0U || components.dwUserNameLength != 0U ||
        components.dwPasswordLength != 0U || components.dwExtraInfoLength != 0U) {
        throw std::invalid_argument(
            "agent server must contain a host and no credentials, query, or fragment");
    }
    ServerAddress result{
        .host = std::wstring{components.lpszHostName,
                             components.dwHostNameLength},
        .port = components.nPort,
        .path_prefix = std::wstring{components.lpszUrlPath,
                                    components.dwUrlPathLength},
        .secure = components.nScheme == INTERNET_SCHEME_HTTPS,
    };
    while (result.path_prefix.size() > 1U &&
           result.path_prefix.back() == L'/') {
        result.path_prefix.pop_back();
    }
    if (result.path_prefix == L"/") {
        result.path_prefix.clear();
    }
    return result;
}

[[nodiscard]] std::wstring header(HINTERNET request, const wchar_t* name) {
    DWORD bytes{};
    if (::WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, nullptr, &bytes,
                              WINHTTP_NO_HEADER_INDEX) == FALSE &&
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return {};
    }
    if (bytes < sizeof(wchar_t)) {
        return {};
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    if (::WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, value.data(),
                              &bytes, WINHTTP_NO_HEADER_INDEX) == FALSE) {
        return {};
    }
    if (!value.empty() && value.back() == L'\0') {
        value.pop_back();
    }
    return value;
}

[[nodiscard]] std::string encode_path_segment(std::string_view value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        if (std::isalnum(character) != 0 || character == '-' || character == '_' ||
            character == '.' || character == '~') {
            result.push_back(static_cast<char>(character));
        } else {
            result.push_back('%');
            result.push_back(hex[character >> 4U]);
            result.push_back(hex[character & 0x0fU]);
        }
    }
    return result;
}

struct Response {
    DWORD status{};
    std::string body;
    std::string etag;
    std::string rule_source;
};

class Transport final {
  public:
    Transport(std::string server, std::string token,
              std::chrono::milliseconds timeout, std::size_t maximum_body_bytes)
        : address_(parse_server(server)), token_(std::move(token)),
          maximum_body_bytes_(maximum_body_bytes) {
        if (timeout <= std::chrono::milliseconds::zero() ||
            maximum_body_bytes_ == 0U) {
            throw std::invalid_argument("WinHTTP limits must be positive");
        }
        const auto agent = wide("sb-easy-windows/" +
                                std::string{application_version});
        session_.reset(::WinHttpOpen(agent.c_str(),
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session_) {
            throw http_error("open WinHTTP session");
        }
        const auto milliseconds = static_cast<unsigned long long>(timeout.count());
        const int timeout_value = static_cast<int>(std::min<unsigned long long>(
            milliseconds,
            static_cast<unsigned long long>(std::numeric_limits<int>::max())));
        if (::WinHttpSetTimeouts(session_.get(), timeout_value, timeout_value,
                                 timeout_value, timeout_value) == FALSE) {
            throw http_error("set WinHTTP timeouts");
        }
        connection_.reset(
            ::WinHttpConnect(session_.get(), address_.host.c_str(), address_.port, 0));
        if (!connection_) {
            throw http_error("connect WinHTTP session");
        }
    }

    [[nodiscard]] Response send(const wchar_t* verb, const std::string& path,
                                const std::optional<nlohmann::json>& body =
                                    std::nullopt,
                                const std::optional<std::string>& etag =
                                    std::nullopt) {
        auto request_path = address_.path_prefix + wide(path);
        const DWORD flags = address_.secure ? WINHTTP_FLAG_SECURE : 0U;
        InternetHandle request{::WinHttpOpenRequest(
            connection_.get(), verb, request_path.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)};
        if (!request) {
            throw http_error("open WinHTTP request");
        }
        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (::WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
                               &redirect_policy, sizeof(redirect_policy)) == FALSE) {
            throw http_error("disable WinHTTP redirects");
        }
        DWORD autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        static_cast<void>(::WinHttpSetOption(request.get(),
                                             WINHTTP_OPTION_AUTOLOGON_POLICY,
                                             &autologon, sizeof(autologon)));

        std::wstring headers{L"Accept: application/json\r\n"};
        if (!token_.empty()) {
            if (token_.find_first_of("\r\n") != std::string::npos) {
                throw std::invalid_argument("agent token contains a line break");
            }
            headers += L"Authorization: Bearer " + wide(token_) + L"\r\n";
        }
        if (etag.has_value()) {
            if (etag->find_first_of("\r\n") != std::string::npos) {
                throw std::invalid_argument("ETag contains a line break");
            }
            headers += L"If-None-Match: " + wide(*etag) + L"\r\n";
        }
        std::string serialized;
        if (body.has_value()) {
            serialized = body->dump();
            headers += L"Content-Type: application/json; charset=utf-8\r\n";
        }
        if (serialized.size() > std::numeric_limits<DWORD>::max()) {
            throw std::invalid_argument("WinHTTP request body is too large");
        }
        const DWORD body_size = static_cast<DWORD>(serialized.size());
        LPVOID body_pointer = serialized.empty()
                                 ? WINHTTP_NO_REQUEST_DATA
                                 : static_cast<void*>(serialized.data());
        if (::WinHttpSendRequest(request.get(), headers.c_str(),
                                 static_cast<DWORD>(headers.size()), body_pointer,
                                 body_size, body_size, 0) == FALSE) {
            throw http_error("send WinHTTP request");
        }
        if (::WinHttpReceiveResponse(request.get(), nullptr) == FALSE) {
            throw http_error("receive WinHTTP response");
        }
        DWORD status{};
        DWORD status_size = sizeof(status);
        if (::WinHttpQueryHeaders(request.get(),
                                  WINHTTP_QUERY_STATUS_CODE |
                                      WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                                  WINHTTP_NO_HEADER_INDEX) == FALSE) {
            throw http_error("read WinHTTP status");
        }
        std::string response_body;
        for (;;) {
            DWORD available{};
            if (::WinHttpQueryDataAvailable(request.get(), &available) == FALSE) {
                throw http_error("query WinHTTP response body");
            }
            if (available == 0U) {
                break;
            }
            if (response_body.size() + available > maximum_body_bytes_) {
                throw std::runtime_error("WinHTTP response exceeds configured limit");
            }
            const auto offset = response_body.size();
            response_body.resize(offset + available);
            DWORD received{};
            if (::WinHttpReadData(request.get(), response_body.data() + offset,
                                  available, &received) == FALSE) {
                throw http_error("read WinHTTP response body");
            }
            response_body.resize(offset + received);
            if (received == 0U) {
                break;
            }
        }
        return {
            .status = status,
            .body = std::move(response_body),
            .etag = utf8(header(request.get(), L"ETag")),
            .rule_source = utf8(header(request.get(),
                                      L"X-SB-Easy-Rule-Source")),
        };
    }

  private:
    ServerAddress address_;
    std::string token_;
    std::size_t maximum_body_bytes_;
    InternetHandle session_;
    InternetHandle connection_;
};

[[nodiscard]] nlohmann::json parse_json(const Response& response) {
    auto parsed = nlohmann::json::parse(response.body, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("agent endpoint returned invalid JSON");
    }
    return parsed;
}

[[nodiscard]] nlohmann::json require_success(const Response& response) {
    if (response.status < 200U || response.status >= 300U) {
        throw std::runtime_error("agent endpoint returned HTTP " +
                                 std::to_string(response.status));
    }
    return parse_json(response);
}

} // namespace

DeviceCredential enroll_device_winhttp(DeviceEnrollmentOptions options) {
    if (options.code.size() < 32U) {
        throw std::invalid_argument("device enrollment code is required");
    }
    if (!options.device.is_object()) {
        throw std::invalid_argument("device enrollment metadata must be an object");
    }
    Transport transport{options.server, {}, options.timeout, 1024U * 1024U};
    const auto response = transport.send(
        L"POST", "/api/devices/enroll",
        nlohmann::json{{"code", options.code}, {"device", options.device}});
    const auto body = require_success(response);
    const auto profile = body.value("profile", nlohmann::json::object());
    DeviceCredential credential{
        .server = body.value("server", options.server),
        .host_id = body.value("host_id", std::string{}),
        .host_name = body.value("host_name", std::string{}),
        .token = body.value("agent_token", std::string{}),
        .profile_id = profile.value("id", std::string{}),
        .profile_name = profile.value("name", std::string{}),
    };
    if (credential.server.empty() || credential.host_id.empty() ||
        credential.token.empty()) {
        throw std::runtime_error("device enrollment response is incomplete");
    }
    return credential;
}

class WinHttpAgentClient::Impl final {
  public:
    explicit Impl(WinHttpOptions options)
        : transport_(options.server, require_token(options.token), options.timeout,
                     options.maximum_body_bytes) {}

    Transport transport_;

  private:
    [[nodiscard]] static std::string require_token(std::string token) {
        if (token.empty()) {
            throw std::invalid_argument("agent token is required");
        }
        return token;
    }
};

WinHttpAgentClient::WinHttpAgentClient(WinHttpOptions options)
    : implementation_(std::make_unique<Impl>(std::move(options))) {}
WinHttpAgentClient::~WinHttpAgentClient() = default;
WinHttpAgentClient::WinHttpAgentClient(WinHttpAgentClient&&) noexcept = default;
WinHttpAgentClient&
WinHttpAgentClient::operator=(WinHttpAgentClient&&) noexcept = default;

AgentConfigResponse
WinHttpAgentClient::poll_config(const std::optional<std::string>& etag) {
    const auto response = implementation_->transport_.send(
        L"GET", "/api/agent/config", std::nullopt, etag);
    if (response.status == HTTP_STATUS_NOT_MODIFIED) {
        return {
            .modified = false,
            .etag = response.etag.empty() ? etag.value_or("") : response.etag,
            .body = {},
            .rule_source =
                response.rule_source.empty() ? "profile" : response.rule_source,
        };
    }
    if (response.status != HTTP_STATUS_OK) {
        throw std::runtime_error("agent config endpoint returned HTTP " +
                                 std::to_string(response.status));
    }
    if (response.etag.empty()) {
        throw std::runtime_error("agent config response is missing ETag");
    }
    if (!parse_json(response).is_object()) {
        throw std::runtime_error("agent config response must be a JSON object");
    }
    return {
        .modified = true,
        .etag = response.etag,
        .body = response.body,
        .rule_source =
            response.rule_source.empty() ? "profile" : response.rule_source,
    };
}

std::vector<AgentCommand> WinHttpAgentClient::pending_commands() {
    const auto response = require_success(
        implementation_->transport_.send(L"GET", "/api/agent/commands"));
    if (!response.is_array()) {
        throw std::runtime_error("agent commands response must be an array");
    }
    std::vector<AgentCommand> result;
    result.reserve(response.size());
    for (const auto& command : response) {
        if (!command.is_object() || !command.contains("id") ||
            !command.at("id").is_string() || !command.contains("command") ||
            !command.at("command").is_string()) {
            throw std::runtime_error("agent command has an invalid shape");
        }
        result.push_back({command.at("id").get<std::string>(),
                          command.at("command").get<std::string>()});
    }
    return result;
}

void WinHttpAgentClient::acknowledge_command(
    const std::string& id, bool success,
    const std::optional<std::string>& result) {
    static_cast<void>(require_success(implementation_->transport_.send(
        L"POST", "/api/agent/commands/" + encode_path_segment(id) + "/ack",
        nlohmann::json{{"status", success ? "done" : "failed"},
                       {"result", result}})));
}

void WinHttpAgentClient::report_status(const std::string& version,
                                       const std::optional<bool>& running,
                                       const std::optional<std::string>& etag) {
    static_cast<void>(require_success(implementation_->transport_.send(
        L"POST", "/api/agent/status",
        nlohmann::json{{"singbox_version", version},
                       {"singbox_running", running},
                       {"config_etag", etag}})));
}

void WinHttpAgentClient::report_telemetry(const nlohmann::json& telemetry) {
    if (!telemetry.is_object()) {
        throw std::invalid_argument("agent telemetry must be a JSON object");
    }
    static_cast<void>(require_success(implementation_->transport_.send(
        L"POST", "/api/agent/telemetry", telemetry)));
}

std::size_t
WinHttpAgentClient::report_proxy_latencies(const nlohmann::json& results) {
    if (!results.is_object()) {
        throw std::invalid_argument(
            "agent proxy latency results must be a JSON object");
    }
    const auto response = require_success(implementation_->transport_.send(
        L"POST", "/api/agent/proxy-latency",
        nlohmann::json{{"results", results}}));
    return response.at("updated").get<std::size_t>();
}

std::string
WinHttpAgentClient::upload_diagnostics(const nlohmann::json& report) {
    if (!report.is_object()) {
        throw std::invalid_argument("agent diagnostic report must be an object");
    }
    const auto response = require_success(implementation_->transport_.send(
        L"POST", "/api/agent/diagnostics", report));
    return response.at("report_id").get<std::string>();
}

} // namespace sbeasy::win
