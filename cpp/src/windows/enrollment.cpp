#include "sbeasy/windows/enrollment.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

namespace sbeasy::win {
namespace {

[[nodiscard]] std::string trim(std::string value) {
    value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
    const auto first = std::find_if_not(value.begin(), value.end(), [](char item) {
        return std::isspace(static_cast<unsigned char>(item)) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](char item) {
                          return std::isspace(static_cast<unsigned char>(item)) != 0;
                      }).base();
    if (first >= last) {
        return {};
    }
    return std::string{first, last};
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char item) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(item)));
    });
    return value;
}

[[nodiscard]] unsigned hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned>(value - '0');
    }
    const char normalized =
        static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
    if (normalized >= 'a' && normalized <= 'f') {
        return static_cast<unsigned>(normalized - 'a' + 10);
    }
    throw std::invalid_argument("enrollment link contains invalid escaping");
}

[[nodiscard]] std::string decode_component(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t index{}; index < value.size(); ++index) {
        const char current = value[index];
        if (current == '+') {
            result.push_back(' ');
        } else if (current == '%') {
            if (index + 2U >= value.size()) {
                throw std::invalid_argument(
                    "enrollment link contains invalid escaping");
            }
            const auto decoded =
                (hex_value(value[index + 1U]) << 4U) |
                hex_value(value[index + 2U]);
            if (decoded == 0U) {
                throw std::invalid_argument(
                    "enrollment link contains an embedded NUL");
            }
            result.push_back(static_cast<char>(decoded));
            index += 2U;
        } else {
            result.push_back(current);
        }
    }
    return result;
}

[[nodiscard]] std::wstring wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int length = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (length <= 0) {
        throw std::invalid_argument("server address is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(),
                              length) != length) {
        throw std::invalid_argument("server address is not valid UTF-8");
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
        throw std::invalid_argument("server address contains invalid characters");
    }
    std::string result(static_cast<std::size_t>(length), '\0');
    if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                              static_cast<int>(value.size()), result.data(), length,
                              nullptr, nullptr) != length) {
        throw std::invalid_argument("server address contains invalid characters");
    }
    return result;
}

[[nodiscard]] std::string normalize_origin(std::string raw) {
    raw = trim(std::move(raw));
    if (raw.empty() || raw.size() > 2'048U) {
        throw std::invalid_argument("enrollment server origin is invalid");
    }
    const auto value = wide(raw);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUserNameLength = static_cast<DWORD>(-1);
    components.dwPasswordLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (::WinHttpCrackUrl(value.c_str(), static_cast<DWORD>(value.size()), 0,
                          &components) == FALSE ||
        components.lpszHostName == nullptr || components.dwHostNameLength == 0U ||
        components.dwUserNameLength != 0U || components.dwPasswordLength != 0U ||
        components.dwExtraInfoLength != 0U) {
        throw std::invalid_argument("enrollment server must be an HTTP(S) origin");
    }
    const bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    if (!secure && components.nScheme != INTERNET_SCHEME_HTTP) {
        throw std::invalid_argument("enrollment server must use HTTP or HTTPS");
    }
    const std::wstring_view path{components.lpszUrlPath,
                                 components.dwUrlPathLength};
    if (!path.empty() && path != L"/") {
        throw std::invalid_argument("enrollment server must not contain a path");
    }
    std::wstring host{components.lpszHostName, components.dwHostNameLength};
    if (host.find(L':') != std::wstring::npos &&
        !(host.starts_with(L"[") && host.ends_with(L"]"))) {
        host = L"[" + host + L"]";
    }
    const INTERNET_PORT default_port = secure ? INTERNET_DEFAULT_HTTPS_PORT
                                               : INTERNET_DEFAULT_HTTP_PORT;
    std::string result = secure ? "https://" : "http://";
    result += utf8(host);
    if (components.nPort != default_port) {
        result += ":" + std::to_string(components.nPort);
    }
    return result;
}

[[nodiscard]] bool valid_code(std::string_view code) {
    return code.size() == 64U &&
           std::all_of(code.begin(), code.end(), [](char item) {
               return std::isxdigit(static_cast<unsigned char>(item)) != 0;
           });
}

} // namespace

EnrollmentPreview parse_enrollment_uri(std::string_view input) {
    auto value = trim(std::string{input});
    if (value.size() >= 2U &&
        ((value.front() == '"' && value.back() == '"') ||
         (value.front() == '\'' && value.back() == '\''))) {
        value = trim(value.substr(1U, value.size() - 2U));
    }
    if (value.size() > 4U && lowercase(value.substr(0U, 4U)) == "url:") {
        value = trim(value.substr(4U));
    }
    constexpr std::string_view prefix{"sbeasy://enroll?"};
    if (value.size() <= prefix.size() ||
        lowercase(value.substr(0U, prefix.size())) != prefix ||
        value.find('#') != std::string::npos || value.size() > 4'096U) {
        throw std::invalid_argument("not a valid sb-easy enrollment link");
    }
    std::map<std::string, std::string> parameters;
    const std::string_view query{value.data() + prefix.size(),
                                 value.size() - prefix.size()};
    std::size_t start{};
    while (start <= query.size()) {
        const auto end = query.find('&', start);
        const auto part = query.substr(
            start, end == std::string_view::npos ? std::string_view::npos
                                                  : end - start);
        if (!part.empty()) {
            const auto separator = part.find('=');
            const auto key = lowercase(decode_component(part.substr(0U, separator)));
            const auto decoded =
                separator == std::string_view::npos
                    ? std::string{}
                    : decode_component(part.substr(separator + 1U));
            if (key.empty() || !parameters.emplace(key, decoded).second) {
                throw std::invalid_argument(
                    "enrollment link contains duplicate parameters");
            }
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1U;
    }
    const auto server = parameters.find("server");
    const auto code = parameters.find("code");
    if (server == parameters.end() || code == parameters.end() ||
        !valid_code(code->second)) {
        throw std::invalid_argument("enrollment link is missing a valid code");
    }
    return {
        .server = normalize_origin(server->second),
        .code = lowercase(code->second),
    };
}

} // namespace sbeasy::win
