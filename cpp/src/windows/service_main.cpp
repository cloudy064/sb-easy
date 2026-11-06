#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/agent_config.hpp"
#include "sbeasy/agent_runtime.hpp"
#include "sbeasy/version.hpp"
#include "sbeasy/windows/embedded_runtime.hpp"
#include "sbeasy/windows/http.hpp"
#include "sbeasy/windows/ipc.hpp"
#include "sbeasy/windows/log.hpp"
#include "sbeasy/windows/platform.hpp"
#include "sbeasy/windows/route_stats.hpp"
#include "sbeasy/windows/singbox.hpp"

namespace sbeasy::win {
namespace {

constexpr wchar_t service_name[] = L"sb-easy";

[[nodiscard]] std::filesystem::path prepared_data_directory() {
    const auto path = program_data_directory();
    prepare_service_directory(path);
    return path;
}

class Handle final {
  public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            static_cast<void>(::CloseHandle(value_));
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
                static_cast<void>(::CloseHandle(value_));
            }
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE value_{nullptr};
};

class ServiceHandle final {
  public:
    ServiceHandle() = default;
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {}
    ~ServiceHandle() {
        if (value_ != nullptr) {
            static_cast<void>(::CloseServiceHandle(value_));
        }
    }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    [[nodiscard]] SC_HANDLE get() const noexcept {
        return value_;
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr;
    }

  private:
    SC_HANDLE value_{nullptr};
};

class Socket final {
  public:
    explicit Socket(SOCKET value) : value_(value) {}
    ~Socket() {
        if (value_ != INVALID_SOCKET) {
            static_cast<void>(::closesocket(value_));
        }
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept
        : value_(std::exchange(other.value_, INVALID_SOCKET)) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            if (value_ != INVALID_SOCKET) {
                static_cast<void>(::closesocket(value_));
            }
            value_ = std::exchange(other.value_, INVALID_SOCKET);
        }
        return *this;
    }
    [[nodiscard]] SOCKET get() const noexcept {
        return value_;
    }
    explicit operator bool() const noexcept {
        return value_ != INVALID_SOCKET;
    }

  private:
    SOCKET value_{INVALID_SOCKET};
};

struct RouteTarget {
    std::string url;
    std::string host;
    std::uint16_t port{};
};

[[nodiscard]] std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](char item) {
        return std::isspace(static_cast<unsigned char>(item)) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](char item) {
                          return std::isspace(static_cast<unsigned char>(item)) != 0;
                      }).base();
    return first >= last ? std::string{} : std::string{first, last};
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char item) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(item)));
    });
    return value;
}

[[nodiscard]] std::uint16_t parse_route_port(std::string_view value) {
    unsigned port{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0U ||
        port > 65'535U) {
        throw std::invalid_argument("route test URL port is invalid");
    }
    return static_cast<std::uint16_t>(port);
}

[[nodiscard]] RouteTarget parse_route_target(std::string value) {
    value = trim(std::move(value));
    if (value.empty() || value.size() > 4'096U) {
        throw std::invalid_argument("route test URL is required");
    }
    const auto scheme_end = value.find("://");
    if (scheme_end == std::string::npos) {
        throw std::invalid_argument("route test URL must use HTTP or HTTPS");
    }
    const auto scheme = lowercase(value.substr(0U, scheme_end));
    if (scheme != "http" && scheme != "https") {
        throw std::invalid_argument("route test URL must use HTTP or HTTPS");
    }
    const auto authority_begin = scheme_end + 3U;
    const auto authority_end = value.find_first_of("/?#", authority_begin);
    auto authority = value.substr(authority_begin, authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos ||
        std::any_of(authority.begin(), authority.end(), [](char item) {
            return std::iscntrl(static_cast<unsigned char>(item)) != 0 ||
                   std::isspace(static_cast<unsigned char>(item)) != 0;
        })) {
        throw std::invalid_argument("route test URL host is invalid");
    }
    std::string host;
    std::uint16_t port = scheme == "https" ? 443U : 80U;
    if (authority.starts_with('[')) {
        const auto bracket = authority.find(']');
        if (bracket == std::string::npos) {
            throw std::invalid_argument("route test IPv6 host is invalid");
        }
        host = authority.substr(1U, bracket - 1U);
        if (bracket + 1U < authority.size()) {
            if (authority[bracket + 1U] != ':') {
                throw std::invalid_argument("route test URL host is invalid");
            }
            port = parse_route_port(
                std::string_view{authority}.substr(bracket + 2U));
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            host = authority.substr(0U, colon);
            port = parse_route_port(std::string_view{authority}.substr(colon + 1U));
        } else {
            host = std::move(authority);
        }
    }
    if (host.empty()) {
        throw std::invalid_argument("route test URL host is invalid");
    }
    return {.url = std::move(value), .host = std::move(host), .port = port};
}

[[nodiscard]] std::string base64(std::string_view value) {
    constexpr std::string_view alphabet{
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
    std::string result;
    result.reserve((value.size() + 2U) / 3U * 4U);
    for (std::size_t offset{}; offset < value.size(); offset += 3U) {
        const auto first = static_cast<unsigned char>(value[offset]);
        const auto second = offset + 1U < value.size()
                                ? static_cast<unsigned char>(value[offset + 1U])
                                : 0U;
        const auto third = offset + 2U < value.size()
                               ? static_cast<unsigned char>(value[offset + 2U])
                               : 0U;
        const unsigned bits = (static_cast<unsigned>(first) << 16U) |
                              (static_cast<unsigned>(second) << 8U) |
                              static_cast<unsigned>(third);
        result.push_back(alphabet[(bits >> 18U) & 0x3fU]);
        result.push_back(alphabet[(bits >> 12U) & 0x3fU]);
        result.push_back(offset + 1U < value.size()
                             ? alphabet[(bits >> 6U) & 0x3fU]
                             : '=');
        result.push_back(offset + 2U < value.size() ? alphabet[bits & 0x3fU]
                                                    : '=');
    }
    return result;
}

[[nodiscard]] Socket connect_route_test_proxy(std::uint16_t port) {
    Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (!socket) {
        throw std::runtime_error("create route test socket failed");
    }
    DWORD timeout = 5'000U;
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
        throw std::runtime_error("connect protected route test proxy failed");
    }
    return socket;
}

void send_all(SOCKET socket, std::string_view value) {
    std::size_t sent{};
    while (sent < value.size()) {
        const int count = static_cast<int>(std::min<std::size_t>(
            value.size() - sent,
            static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int result = ::send(socket, value.data() + sent, count, 0);
        if (result <= 0) {
            throw std::runtime_error("send route test request failed");
        }
        sent += static_cast<std::size_t>(result);
    }
}

[[nodiscard]] std::uint16_t source_port(SOCKET socket) {
    sockaddr_in address{};
    int length = sizeof(address);
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) ==
        SOCKET_ERROR) {
        throw std::runtime_error("read route test source port failed");
    }
    return ntohs(address.sin_port);
}

[[nodiscard]] bool metadata_matches_port(const nlohmann::json& metadata,
                                         std::uint16_t port) {
    const auto value = metadata.find("sourcePort");
    if (value == metadata.end()) {
        return false;
    }
    if (value->is_number_unsigned() || value->is_number_integer()) {
        return value->get<unsigned>() == port;
    }
    if (value->is_string()) {
        try {
            return parse_route_port(value->get<std::string>()) == port;
        } catch (const std::invalid_argument&) {
            return false;
        }
    }
    return false;
}

[[nodiscard]] std::optional<nlohmann::json>
find_route_connection(const nlohmann::json& response, std::uint16_t port) {
    const auto connections = response.find("connections");
    if (connections == response.end() || !connections->is_array()) {
        return std::nullopt;
    }
    for (const auto& connection : *connections) {
        const auto metadata = connection.is_object()
                                  ? connection.find("metadata")
                                  : connection.end();
        if (connection.is_object() && metadata != connection.end() &&
            metadata->is_object() && metadata_matches_port(*metadata, port)) {
            return connection;
        }
    }
    return std::nullopt;
}

[[nodiscard]] nlohmann::json
route_result(const RouteTarget& target, const nlohmann::json& connection) {
    auto chains = connection.value("chains", nlohmann::json::array());
    if (!chains.is_array()) {
        chains = nlohmann::json::array();
    }
    std::string outbound;
    if (!chains.empty() && chains.front().is_string()) {
        outbound = chains.front().get<std::string>();
    }
    const auto normalized = lowercase(outbound);
    const auto kind = normalized == "direct"
                          ? "direct"
                          : ((normalized == "block" || normalized == "reject")
                                 ? "block"
                                 : (normalized.empty() ? "unknown" : "proxy"));
    return {{"success", true},
            {"available", true},
            {"url", target.url},
            {"host", target.host},
            {"port", target.port},
            {"kind", kind},
            {"outbound", outbound},
            {"chains", std::move(chains)},
            {"rule", connection.value("rule", "")},
            {"rule_payload", connection.value("rulePayload", "")}};
}

[[nodiscard]] std::vector<std::string>
bound_log_lines(std::vector<std::string> lines, std::size_t maximum_lines,
                std::size_t maximum_bytes) {
    std::vector<std::string> newest;
    newest.reserve(std::min(lines.size(), maximum_lines));
    std::size_t bytes{};
    for (auto line = lines.rbegin();
         line != lines.rend() && newest.size() < maximum_lines; ++line) {
        auto redacted = redact_log_message(std::move(*line));
        redacted.resize(std::min<std::size_t>(redacted.size(), 4'000U));
        if (bytes + redacted.size() + 2U > maximum_bytes) {
            break;
        }
        bytes += redacted.size() + 2U;
        newest.push_back(std::move(redacted));
    }
    std::reverse(newest.begin(), newest.end());
    return newest;
}

[[nodiscard]] std::string percent_encode(std::string_view value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
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

[[nodiscard]] std::string decode_chunked_body(std::string_view body) {
    std::string decoded;
    std::size_t position{};
    while (position < body.size()) {
        const auto line_end = body.find("\r\n", position);
        if (line_end == std::string_view::npos) {
            throw std::runtime_error("local Clash API chunk header is invalid");
        }
        auto size_text = body.substr(position, line_end - position);
        if (const auto extension = size_text.find(';');
            extension != std::string_view::npos) {
            size_text = size_text.substr(0U, extension);
        }
        std::size_t chunk_size{};
        const auto [end, error] = std::from_chars(
            size_text.data(), size_text.data() + size_text.size(), chunk_size, 16);
        if (error != std::errc{} || end != size_text.data() + size_text.size()) {
            throw std::runtime_error("local Clash API chunk size is invalid");
        }
        position = line_end + 2U;
        if (chunk_size == 0U) {
            return decoded;
        }
        if (chunk_size > body.size() - position ||
            decoded.size() + chunk_size > 8U * 1024U * 1024U) {
            throw std::runtime_error("local Clash API chunk exceeds size limit");
        }
        decoded.append(body.substr(position, chunk_size));
        position += chunk_size;
        if (position + 2U > body.size() || body.substr(position, 2U) != "\r\n") {
            throw std::runtime_error("local Clash API chunk terminator is invalid");
        }
        position += 2U;
    }
    throw std::runtime_error("local Clash API chunked body is incomplete");
}

[[nodiscard]] nlohmann::json local_request(std::uint16_t port,
                                           const std::string& secret,
                                           std::string_view method,
                                           const std::string& path,
                                           const std::optional<nlohmann::json>& body =
                                               std::nullopt) {
    Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (!socket) {
        throw std::runtime_error("create local Clash API socket failed");
    }
    DWORD timeout = 5'000U;
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
        throw std::runtime_error("connect local Clash API failed");
    }
    const std::string serialized = body.has_value() ? body->dump() : std::string{};
    std::string request = std::string{method} + " " + path +
                          " HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " +
                          secret + "\r\nAccept: application/json\r\nConnection: close\r\n";
    if (body.has_value()) {
        request += "Content-Type: application/json\r\nContent-Length: " +
                   std::to_string(serialized.size()) + "\r\n";
    }
    request += "\r\n" + serialized;
    std::size_t offset{};
    while (offset < request.size()) {
        const int length = static_cast<int>(std::min<std::size_t>(
            request.size() - offset,
            static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int sent = ::send(socket.get(), request.data() + offset, length, 0);
        if (sent <= 0) {
            throw std::runtime_error("send local Clash API request failed");
        }
        offset += static_cast<std::size_t>(sent);
    }
    std::string response;
    std::array<char, 8U * 1024U> buffer{};
    for (;;) {
        const int received =
            ::recv(socket.get(), buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received == 0) {
            break;
        }
        if (received < 0) {
            throw std::runtime_error("read local Clash API response failed");
        }
        if (response.size() + static_cast<std::size_t>(received) >
            8U * 1024U * 1024U) {
            throw std::runtime_error("local Clash API response exceeds 8 MiB");
        }
        response.append(buffer.data(), static_cast<std::size_t>(received));
    }
    const auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        throw std::runtime_error("local Clash API returned an invalid response");
    }
    const auto first_line = response.substr(0, response.find("\r\n"));
    if (first_line.find(" 200 ") == std::string::npos &&
        first_line.find(" 204 ") == std::string::npos) {
        throw std::runtime_error("local Clash API request failed: " + first_line);
    }
    const auto headers = lowercase(response.substr(0U, header_end));
    auto payload = response.substr(header_end + 4U);
    if (headers.find("transfer-encoding: chunked") != std::string::npos) {
        payload = decode_chunked_body(payload);
    }
    if (payload.empty()) {
        return nlohmann::json::object();
    }
    auto parsed = nlohmann::json::parse(payload, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("local Clash API returned invalid JSON");
    }
    return parsed;
}

class WindowsLocalRuntime final : public AgentLocalRuntime {
  public:
    WindowsLocalRuntime(WindowsSingBoxSupervisor& supervisor,
                        std::filesystem::path route_database)
        : supervisor_(supervisor), route_statistics_(std::move(route_database)) {}

    [[nodiscard]] nlohmann::json proxies() {
        const auto response = request("GET", "/proxies");
        const auto found = response.find("proxies");
        if (found == response.end() || !found->is_object()) {
            return nlohmann::json::array();
        }
        nlohmann::json groups = nlohmann::json::array();
        for (const auto& [name, proxy] : found->items()) {
            if (!proxy.is_object() || !proxy.contains("all") ||
                !proxy.at("all").is_array()) {
                continue;
            }
            nlohmann::json delays = nlohmann::json::object();
            for (const auto& member : proxy.at("all")) {
                if (!member.is_string()) {
                    continue;
                }
                const auto member_name = member.get<std::string>();
                const auto detail = found->find(member_name);
                if (detail == found->end() || !detail->is_object()) {
                    delays[member_name] = nullptr;
                    continue;
                }
                const auto history = detail->find("history");
                if (history != detail->end() && history->is_array() &&
                    !history->empty() && history->back().is_object()) {
                    const auto delay = history->back().find("delay");
                    delays[member_name] =
                        delay != history->back().end() && delay->is_number()
                            ? *delay
                            : nlohmann::json{};
                } else {
                    delays[member_name] = nullptr;
                }
            }
            groups.push_back({{"tag", name},
                              {"name", name},
                              {"type", proxy.value("type", "Selector")},
                              {"now", proxy.value("now", "")},
                              {"all", proxy.at("all")},
                              {"delays", std::move(delays)}});
        }
        std::sort(groups.begin(), groups.end(), [](const auto& left,
                                                    const auto& right) {
            return left.value("tag", "") < right.value("tag", "");
        });
        return groups;
    }

    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) override {
        const auto proxies = request("GET", "/proxies");
        const auto found = proxies.find("proxies");
        if (found == proxies.end() || !found->is_object()) {
            return 0U;
        }
        static const std::set<std::string> skipped{
            "Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject",
            "Compatible", "Pass", "Dns", "Block", "Loopback"};
        const std::set<std::string> wanted =
            tags.has_value() ? std::set<std::string>{tags->begin(), tags->end()}
                             : std::set<std::string>{};
        std::size_t tested{};
        for (const auto& [name, proxy] : found->items()) {
            const auto type = proxy.is_object() ? proxy.value("type", "") : "";
            if (skipped.contains(type) ||
                (tags.has_value() && !wanted.contains(name))) {
                continue;
            }
            try {
                const auto result = request(
                    "GET", "/proxies/" + percent_encode(name) +
                               "/delay?timeout=5000&url=" +
                               percent_encode("https://www.gstatic.com/generate_204"));
                reporter(nlohmann::json{{name, result.value("delay", 0)}});
            } catch (const std::exception&) {
                reporter(nlohmann::json{{name, nullptr}});
            }
            ++tested;
        }
        return tested;
    }

    [[nodiscard]] std::optional<nlohmann::json> sample_telemetry() override {
        if (!supervisor_.running()) {
            return std::nullopt;
        }
        const auto response = request("GET", "/connections");
        const auto upload_total = response.value("uploadTotal", std::int64_t{});
        const auto download_total = response.value("downloadTotal", std::int64_t{});
        const auto now = std::chrono::steady_clock::now();
        std::int64_t upload_rate{};
        std::int64_t download_rate{};
        if (last_sample_.has_value()) {
            const auto elapsed = std::max(
                std::chrono::duration<double>{now - last_sample_->at}.count(), 0.001);
            upload_rate = static_cast<std::int64_t>(
                static_cast<double>(std::max(upload_total - last_sample_->upload, 0LL)) /
                elapsed);
            download_rate = static_cast<std::int64_t>(
                static_cast<double>(
                    std::max(download_total - last_sample_->download, 0LL)) /
                elapsed);
        }
        last_sample_ = Sample{now, upload_total, download_total};
        auto connections = response.value("connections", nlohmann::json::array());
        if (!connections.is_array()) {
            connections = nlohmann::json::array();
        }
        const auto count = connections.size();
        route_statistics_.observe(connections);
        return nlohmann::json{
            {"up", upload_rate},
            {"down", download_rate},
            {"up_total", upload_total},
            {"down_total", download_total},
            {"conn_count", count},
            {"connections", std::move(connections)},
            {"domain_stats", route_statistics_.query("all")},
            {"logs", nlohmann::json::array()},
        };
    }

    [[nodiscard]] nlohmann::json test_route(const std::string& url) override {
        if (!supervisor_.running()) {
            throw std::runtime_error("sing-box must be running for a route test");
        }
        const auto target = parse_route_target(url);
        auto socket = connect_route_test_proxy(supervisor_.route_test_port());
        const auto local_port = source_port(socket.get());
        const auto authority =
            (target.host.find(':') == std::string::npos
                 ? target.host
                 : "[" + target.host + "]") +
            ":" + std::to_string(target.port);
        const auto authorization =
            base64("sb-easy:" + supervisor_.route_test_password());
        send_all(socket.get(),
                 "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                     "\r\nUser-Agent: sb-easy-route-test/1.0\r\n"
                     "Proxy-Authorization: Basic " +
                     authorization + "\r\nProxy-Connection: keep-alive\r\n\r\n");
        for (unsigned attempt{}; attempt < 50U; ++attempt) {
            const auto connections = request("GET", "/connections");
            if (const auto connection =
                    find_route_connection(connections, local_port);
                connection.has_value()) {
                return route_result(target, *connection);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        throw std::runtime_error(
            "route test connection was not observed by the protected Clash API");
    }

    void policy_activated(std::string_view label) override {
        route_statistics_.activate_policy(label);
    }

    [[nodiscard]] nlohmann::json route_stats(std::string_view period) const {
        return route_statistics_.query(period);
    }

    void select_proxy(const std::string& group, const std::string& proxy) {
        static_cast<void>(request("PUT", "/proxies/" + percent_encode(group),
                                  nlohmann::json{{"name", proxy}}));
        const auto confirmed =
            request("GET", "/proxies/" + percent_encode(group));
        if (confirmed.value("now", std::string{}) != proxy) {
            throw std::runtime_error(
                "running core did not confirm the requested proxy selection");
        }
    }

  private:
    struct Sample {
        std::chrono::steady_clock::time_point at;
        std::int64_t upload{};
        std::int64_t download{};
    };

    [[nodiscard]] nlohmann::json
    request(std::string_view method, const std::string& path,
            const std::optional<nlohmann::json>& body = std::nullopt) const {
        return local_request(supervisor_.clash_port(), supervisor_.clash_secret(),
                             method, path, body);
    }

    WindowsSingBoxSupervisor& supervisor_;
    RouteStatistics route_statistics_;
    std::optional<Sample> last_sample_;
};

struct Credential {
    std::string server;
    std::string host_id;
    std::string host_name;
    std::string token;
    std::string profile_id;
    std::string profile_name;
};

[[nodiscard]] Credential parse_credential(std::string_view serialized) {
    const auto body = nlohmann::json::parse(serialized, nullptr, false);
    if (!body.is_object()) {
        throw std::runtime_error("DPAPI credential contains invalid JSON");
    }
    Credential result{
        .server = body.value("server", std::string{}),
        .host_id = body.value("host_id", std::string{}),
        .host_name = body.value("host_name", std::string{}),
        .token = body.value("agent_token", std::string{}),
        .profile_id = body.value("profile_id", std::string{}),
        .profile_name = body.value("profile_name", std::string{}),
    };
    if (result.server.empty() || result.host_id.empty() || result.token.empty()) {
        throw std::runtime_error("DPAPI credential is incomplete");
    }
    return result;
}

[[nodiscard]] std::string serialize_credential(const DeviceCredential& credential) {
    return nlohmann::json{
        {"server", credential.server},
        {"host_id", credential.host_id},
        {"host_name", credential.host_name},
        {"agent_token", credential.token},
        {"profile_id", credential.profile_id},
        {"profile_name", credential.profile_name},
    }.dump();
}

[[nodiscard]] AgentConfigTransformOptions
load_transform_options(const WindowsStorage& storage,
                       const std::filesystem::path& path) {
    AgentConfigTransformOptions defaults;
    defaults.local_proxy_egress = true;
    defaults.lan_compatibility = true;
    const auto serialized = storage.read(path);
    if (!serialized.has_value()) {
        return defaults;
    }
    const auto parsed = nlohmann::json::parse(*serialized, nullptr, false);
    if (!parsed.is_object()) {
        return defaults;
    }
    return agent_config_transform_options_from_json(parsed, defaults);
}

[[nodiscard]] nlohmann::json
load_settings_object(const WindowsStorage& storage,
                     const std::filesystem::path& path) {
    const auto serialized = storage.read(path);
    if (!serialized.has_value()) {
        return nlohmann::json::object();
    }
    auto parsed = nlohmann::json::parse(*serialized, nullptr, false);
    return parsed.is_object() ? std::move(parsed) : nlohmann::json::object();
}

[[nodiscard]] bool load_boolean_setting(const WindowsStorage& storage,
                                        const std::filesystem::path& path,
                                        const char* field,
                                        bool default_value) {
    const auto settings = load_settings_object(storage, path);
    const auto value = settings.find(field);
    return value != settings.end() && value->is_boolean()
               ? value->get<bool>()
               : default_value;
}

class RuntimeBundle final {
  public:
    RuntimeBundle(Credential credential,
                  const std::filesystem::path& data_directory,
                  const EmbeddedRuntimePaths& embedded_runtime)
        : credential_(std::move(credential)),
          http_({.server = credential_.server, .token = credential_.token}),
          core_({
              .binary = embedded_runtime.sing_box,
              .wintun = embedded_runtime.wintun,
              .candidate_config = data_directory / L"config" / L"candidate.json",
              .active_config = data_directory / L"config" / L"active.json",
              .last_good_config = data_directory / L"config" / L"last-good.json",
              .log_path = data_directory / L"logs" / L"sing-box.log",
              .start_enabled = load_boolean_setting(
                  storage_, data_directory / L"settings.json",
                  "connect_at_boot", true),
              .strict_route = load_boolean_setting(
                  storage_, data_directory / L"settings.json", "strict_dns",
                  false),
          }),
          local_runtime_(core_, data_directory / L"runtime.db"),
          runtime_(
              {
                  .config_path = data_directory / L"config" / L"active.json",
                  .settings_path = data_directory / L"settings.json",
                  .server = credential_.server,
                  .service_name = "sb-easy-service",
                  .version = "sb-easy-windows/" +
                             std::string{application_version},
                  .singbox_binary = embedded_runtime.sing_box.string(),
                  .singbox_managed = true,
                  .validate_config = true,
                  .transform_options = load_transform_options(
                      storage_, data_directory / L"settings.json"),
              },
              {
                  .http = http_,
                  .process = process_,
                  .storage = storage_,
                  .clock = clock_,
                  .metadata = metadata_,
                  .core = core_,
                  .local_runtime = local_runtime_,
              }) {
        if (!load_boolean_setting(storage_, data_directory / L"settings.json",
                                  "connect_at_boot", true)) {
            runtime_.queue_action("stop");
        }
    }

    Credential credential_;
    WindowsProcess process_;
    WindowsStorage storage_;
    WindowsClock clock_;
    WindowsMetadata metadata_;
    WinHttpAgentClient http_;
    WindowsSingBoxSupervisor core_;
    WindowsLocalRuntime local_runtime_;
    AgentRuntime runtime_;
};

class ServiceHost final {
  public:
    explicit ServiceHost(bool mirror_console = false)
        : data_directory_(prepared_data_directory()),
          embedded_runtime_(materialize_embedded_runtime(data_directory_)),
          credential_store_(data_directory_ / L"credential.dat"),
          log_(data_directory_ / L"logs" / L"service.log", 5U * 1024U * 1024U,
               3U, mirror_console),
          wake_event_(::CreateEventW(nullptr, FALSE, FALSE, nullptr)) {
        if (!wake_event_) {
            throw std::runtime_error("create service wake event failed");
        }
        const auto settings = load_settings_object(
            WindowsStorage{}, data_directory_ / L"settings.json");
        const auto retained = settings.value("log_retention_files", 3U);
        log_.set_retained_files(
            std::clamp<std::size_t>(retained, 1U, 10U));
        if (const auto stored = credential_store_.read(); stored.has_value()) {
            bundle_ = std::make_shared<RuntimeBundle>(parse_credential(*stored),
                                                       data_directory_,
                                                       embedded_runtime_);
        }
        log_.write("info", "service host initialized");
    }

    void run(HANDLE stop_event) {
        HANDLE network_notification{};
        const DWORD notification_result = ::NotifyIpInterfaceChange(
            AF_UNSPEC, &ServiceHost::network_change_callback, this, FALSE,
            &network_notification);
        if (notification_result != NO_ERROR) {
            throw std::runtime_error("subscribe to IP interface changes failed with error " +
                                     std::to_string(notification_result));
        }
        const std::unique_ptr<void, decltype(&::CancelMibChangeNotify2)>
            network_notification_guard{network_notification,
                                       &::CancelMibChangeNotify2};
        NamedPipeServer pipe{[this](const nlohmann::json& request,
                                    const PipeClient& client) {
            return handle_request(request, client);
        }};
        std::exception_ptr pipe_error;
        std::thread pipe_thread{[this, &pipe, &pipe_error, stop_event] {
            try {
                pipe.run();
            } catch (...) {
                pipe_error = std::current_exception();
                try {
                    std::rethrow_exception(pipe_error);
                } catch (const std::exception& error) {
                    log_.write("error", std::string{"named-pipe server: "} +
                                            error.what());
                }
                static_cast<void>(::SetEvent(stop_event));
            }
        }};
        log_.write("info", "service entered RUNNING state");
        const std::array<HANDLE, 2> events{stop_event, wake_event_.get()};
        while (::WaitForMultipleObjects(static_cast<DWORD>(events.size()),
                                        events.data(), FALSE, 10'000U) !=
               WAIT_OBJECT_0) {
            std::shared_ptr<RuntimeBundle> current;
            {
                std::lock_guard lock{mutex_};
                current = bundle_;
            }
            if (current) {
                if (environment_change_pending_.exchange(false)) {
                    // Coalesce the burst of address/route notifications emitted by
                    // a single Wi-Fi or Ethernet transition.
                    if (::WaitForSingleObject(stop_event, 1'500U) == WAIT_OBJECT_0) {
                        break;
                    }
                    current->runtime_.queue_action("restart");
                    log_.write("info",
                               "network or power resume change queued a core restart");
                }
                const bool healthy = current->runtime_.run_cycle();
                const auto status = current->runtime_.status();
                const auto error = status.at("last_error");
                const auto current_error =
                    error.is_string()
                        ? std::optional<std::string>{error.get<std::string>()}
                        : std::nullopt;
                if (!healthy && current_error != last_runtime_error_) {
                    log_.write("error", current_error.value_or("runtime cycle failed"));
                } else if (healthy && last_runtime_error_.has_value()) {
                    log_.write("info", "runtime recovered after an error");
                }
                last_runtime_error_ = current_error;
            }
        }
        pipe.stop();
        pipe_thread.join();
        std::shared_ptr<RuntimeBundle> current;
        {
            std::lock_guard lock{mutex_};
            current = std::move(bundle_);
        }
        if (current) {
            current->core_.stop();
        }
        log_.write("info", "service stopped sing-box and left RUNNING state");
        if (pipe_error) {
            std::rethrow_exception(pipe_error);
        }
    }

    void enroll(const std::string& server, const std::string& code) {
        {
            std::lock_guard lock{mutex_};
            if (bundle_) {
                throw std::runtime_error("device is already enrolled");
            }
        }
        WindowsMetadata metadata;
        const auto credential = enroll_device_winhttp({
            .server = server,
            .code = code,
            .device = metadata.device_metadata(),
        });
        auto created = std::make_shared<RuntimeBundle>(
            Credential{
                .server = credential.server,
                .host_id = credential.host_id,
                .host_name = credential.host_name,
                .token = credential.token,
                .profile_id = credential.profile_id,
                .profile_name = credential.profile_name,
            },
            data_directory_, embedded_runtime_);
        credential_store_.replace(serialize_credential(credential));
        {
            std::lock_guard lock{mutex_};
            if (bundle_) {
                throw std::runtime_error("device enrollment raced another client");
            }
            bundle_ = std::move(created);
        }
        log_.write("info", "device enrolled as " + credential.host_id +
                               " against " + credential.server);
        static_cast<void>(::SetEvent(wake_event_.get()));
    }

    [[nodiscard]] nlohmann::json enrollment_status() const {
        std::lock_guard lock{mutex_};
        if (!bundle_) {
            return {{"enrolled", false}};
        }
        return {
            {"enrolled", true},
            {"server", bundle_->credential_.server},
            {"host_id", bundle_->credential_.host_id},
            {"host_name", bundle_->credential_.host_name},
            {"profile",
             {{"id", bundle_->credential_.profile_id},
              {"name", bundle_->credential_.profile_name}}},
        };
    }

    void notify_environment_change() noexcept {
        environment_change_pending_.store(true);
        static_cast<void>(::SetEvent(wake_event_.get()));
    }

  private:
    static void CALLBACK network_change_callback(PVOID context,
                                                 PMIB_IPINTERFACE_ROW,
                                                 MIB_NOTIFICATION_TYPE) {
        if (context != nullptr) {
            static_cast<ServiceHost*>(context)->notify_environment_change();
        }
    }

    [[nodiscard]] std::shared_ptr<RuntimeBundle> require_bundle() const {
        std::lock_guard lock{mutex_};
        if (!bundle_) {
            throw std::runtime_error("device is not enrolled");
        }
        return bundle_;
    }

    void wake() const {
        static_cast<void>(::SetEvent(wake_event_.get()));
    }

    void forget() {
        std::shared_ptr<RuntimeBundle> current;
        {
            std::lock_guard lock{mutex_};
            current = std::move(bundle_);
        }
        if (current) {
            current->core_.stop();
        }
        credential_store_.remove();
        WindowsStorage storage;
        storage.remove(data_directory_ / L"config" / L"candidate.json");
        storage.remove(data_directory_ / L"config" / L"active.json");
        storage.remove(data_directory_ / L"config" / L"last-good.json");
        log_.write("info", "device credential and generated configs removed");
    }

    [[nodiscard]] std::vector<std::string>
    tail_file(const std::filesystem::path& path, std::size_t maximum_lines) const {
        WindowsStorage storage;
        const auto contents = storage.read(path).value_or(std::string{});
        std::vector<std::string> lines;
        std::size_t start{};
        while (start < contents.size()) {
            const auto end = contents.find('\n', start);
            auto line = contents.substr(start, end == std::string::npos
                                                   ? std::string::npos
                                                   : end - start);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            lines.push_back(redact_log_message(std::move(line)));
            if (end == std::string::npos) {
                break;
            }
            start = end + 1U;
        }
        if (lines.size() > maximum_lines) {
            lines.erase(lines.begin(), lines.end() -
                                           static_cast<std::ptrdiff_t>(maximum_lines));
        }
        return lines;
    }

    void clear_core_log() const {
        const auto path = data_directory_ / L"logs" / L"sing-box.log";
        Handle file{::CreateFileW(path.c_str(), GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE |
                                      FILE_SHARE_DELETE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                  nullptr)};
        if (!file) {
            throw std::runtime_error("open sing-box log for clearing failed");
        }
        LARGE_INTEGER beginning{};
        if (::SetFilePointerEx(file.get(), beginning, nullptr, FILE_BEGIN) == FALSE ||
            ::SetEndOfFile(file.get()) == FALSE) {
            throw std::runtime_error("clear sing-box log failed");
        }
    }

    [[nodiscard]] nlohmann::json
    client_settings(const std::shared_ptr<RuntimeBundle>& current) const {
        auto result = current->runtime_.settings();
        const auto stored = load_settings_object(
            current->storage_, data_directory_ / L"settings.json");
        result["connect_at_boot"] =
            stored.value("connect_at_boot", true);
        result["strict_dns"] = stored.value("strict_dns", false);
        result["log_retention_files"] =
            stored.value("log_retention_files", 3U);
        return result;
    }

    [[nodiscard]] nlohmann::json
    update_client_settings(const std::shared_ptr<RuntimeBundle>& current,
                           const nlohmann::json& requested) {
        if (!requested.is_object()) {
            throw std::invalid_argument("settings must be an object");
        }
        const auto require_boolean = [&requested](const char* field,
                                                   bool default_value) {
            const auto value = requested.find(field);
            if (value == requested.end()) {
                return default_value;
            }
            if (!value->is_boolean()) {
                throw std::invalid_argument(std::string{field} +
                                            " must be a boolean");
            }
            return value->get<bool>();
        };
        const auto stored = load_settings_object(
            current->storage_, data_directory_ / L"settings.json");
        const bool connect_at_boot = require_boolean(
            "connect_at_boot", stored.value("connect_at_boot", true));
        const bool strict_dns =
            require_boolean("strict_dns", stored.value("strict_dns", false));
        const auto requested_retention = requested.find("log_retention_files");
        auto log_retention_files =
            stored.value("log_retention_files", std::size_t{3U});
        if (requested_retention != requested.end()) {
            if (!requested_retention->is_number_unsigned() &&
                !requested_retention->is_number_integer()) {
                throw std::invalid_argument(
                    "log_retention_files must be an integer");
            }
            const auto retention = requested_retention->get<std::int64_t>();
            if (retention < 1 || retention > 10) {
                throw std::invalid_argument(
                    "log_retention_files must be between 1 and 10");
            }
            log_retention_files = static_cast<std::size_t>(retention);
        }
        auto result = current->runtime_.update_settings(requested);
        result["connect_at_boot"] = connect_at_boot;
        result["strict_dns"] = strict_dns;
        result["log_retention_files"] = log_retention_files;
        current->storage_.replace(data_directory_ / L"settings.json",
                                  result.dump(2) + '\n');
        current->core_.set_strict_route(strict_dns);
        log_.set_retained_files(log_retention_files);
        return result;
    }

    [[nodiscard]] nlohmann::json
    handle_request(const nlohmann::json& request, const PipeClient&) {
        const auto method = request.at("method").get<std::string>();
        const auto params = request.value("params", nlohmann::json::object());
        if (!params.is_object()) {
            throw std::invalid_argument("IPC params must be an object");
        }
        if (method == "enrollment.status") {
            return enrollment_status();
        }
        if (method == "enrollment.apply") {
            enroll(params.at("server").get<std::string>(),
                   params.at("code").get<std::string>());
            return enrollment_status();
        }
        if (method == "enrollment.forget") {
            forget();
            return {{"enrolled", false}};
        }
        if (method == "logs.tail") {
            const auto source = params.value("source", std::string{"service"});
            const auto requested = params.value("lines", std::size_t{200U});
            const auto lines = std::clamp<std::size_t>(requested, 1U, 2'000U);
            if (source == "service") {
                return {{"source", source},
                        {"lines", bound_log_lines(log_.tail(lines), lines,
                                                  900U * 1024U)}};
            }
            if (source == "sing-box") {
                return {{"source", source},
                        {"lines",
                         bound_log_lines(tail_file(data_directory_ / L"logs" /
                                                       L"sing-box.log",
                                                   lines),
                                         lines, 900U * 1024U)}};
            }
            throw std::invalid_argument("unknown log source");
        }
        if (method == "logs.clear") {
            const auto source = params.value("source", std::string{"service"});
            if (source == "service") {
                log_.clear();
                log_.write("info", "service log cleared by an authorized IPC client");
            } else if (source == "sing-box") {
                clear_core_log();
                log_.write("info", "sing-box log cleared by an authorized IPC client");
            } else {
                throw std::invalid_argument("unknown log source");
            }
            return {{"cleared", true}, {"source", source}};
        }
        auto current = require_bundle();
        if (method == "logs.upload") {
            nlohmann::json lines = nlohmann::json::array();
            for (auto& line : bound_log_lines(log_.tail(750U), 750U,
                                               3U * 1024U * 1024U)) {
                lines.push_back("service: " + redact_log_message(std::move(line)));
            }
            for (auto& line : bound_log_lines(
                     tail_file(data_directory_ / L"logs" / L"sing-box.log",
                               750U),
                     750U, 3U * 1024U * 1024U)) {
                lines.push_back("sing-box: " +
                                redact_log_message(std::move(line)));
            }
            const auto runtime_status = current->runtime_.status();
            const bool runtime_running =
                runtime_status.contains("running") &&
                runtime_status.at("running").is_boolean() &&
                runtime_status.at("running").get<bool>();
            const auto report_id = current->http_.upload_diagnostics({
                {"reason", "manual"},
                {"app_version", std::string{application_version}},
                {"core_version", "1.13.12"},
                {"device", current->metadata_.device_metadata()},
                {"vpn",
                 {{"running", runtime_running},
                  {"desired_running",
                   runtime_status.value("desired_running", false)},
                  {"last_error",
                   runtime_status.value("last_error", nlohmann::json{})}}},
                {"network", nlohmann::json::object()},
                {"config",
                 {{"profile_id", current->credential_.profile_id},
                  {"profile_name", current->credential_.profile_name},
                  {"etag", runtime_status.value("etag", nlohmann::json{})},
                  {"rule_source", runtime_status.value("rule_source", "profile")}}},
                {"runtime_log_count", lines.size()},
                {"connection_count",
                 runtime_status.value("telemetry", nlohmann::json::object())
                     .value("conn_count", 0)},
                {"logs", std::move(lines)},
            });
            log_.write("info", "redacted diagnostics uploaded as " + report_id);
            return {{"report_id", report_id}};
        }
        if (method == "status.get") {
            return current->runtime_.status();
        }
        if (method == "vpn.start" || method == "vpn.stop" ||
            method == "vpn.restart") {
            const auto action = method.substr(4U);
            current->runtime_.queue_action(action);
            wake();
            return {{"phase", action == "stop" ? "stopping" : "starting"}};
        }
        if (method == "config.refresh") {
            current->runtime_.queue_action("refresh");
            wake();
            return {{"queued", true}};
        }
        if (method == "config.summary") {
            const auto config = current->runtime_.config();
            return {
                {"available", !config.empty()},
                {"outbounds",
                 config.contains("outbounds") && config.at("outbounds").is_array()
                     ? config.at("outbounds").size()
                     : 0U},
                {"rules", config.contains("route") &&
                                  config.at("route").is_object() &&
                                  config.at("route").contains("rules") &&
                                  config.at("route").at("rules").is_array()
                              ? config.at("route").at("rules").size()
                              : 0U},
            };
        }
        if (method == "config.redacted") {
            return redact_config(current->runtime_.config());
        }
        if (method == "proxies.list") {
            if (current->core_.running()) {
                try {
                    return current->local_runtime_.proxies();
                } catch (const std::exception&) {
                    // Preserve an offline, config-derived view while the local
                    // API is between lifecycle states.
                }
            }
            return current->runtime_.proxies();
        }
        if (method == "proxy.select") {
            current->local_runtime_.select_proxy(
                params.at("group").get<std::string>(),
                params.at("proxy").get<std::string>());
            return {{"selected", params.at("proxy")}};
        }
        if (method == "proxies.test") {
            nlohmann::json delays = nlohmann::json::object();
            std::optional<std::vector<std::string>> tags;
            if (params.contains("tags")) {
                tags = params.at("tags").get<std::vector<std::string>>();
            }
            const auto tested = current->local_runtime_.test_proxies(
                tags, [&delays](const nlohmann::json& update) {
                    delays.update(update);
                });
            return {{"tested", tested}, {"results", std::move(delays)}};
        }
        if (method == "route.test") {
            return current->runtime_.test_route(
                params.at("url").get<std::string>());
        }
        if (method == "routes.stats") {
            const auto period = params.value("period", std::string{"today"});
            return {{"available", true},
                    {"period", period},
                    {"rows", current->local_runtime_.route_stats(period)}};
        }
        if (method == "settings.get") {
            return client_settings(current);
        }
        if (method == "settings.update") {
            const auto result =
                update_client_settings(current, params.at("settings"));
            wake();
            return result;
        }
        throw std::invalid_argument("unsupported IPC method: " + method);
    }

    std::filesystem::path data_directory_;
    EmbeddedRuntimePaths embedded_runtime_;
    DpapiCredentialStore credential_store_;
    RollingLog log_;
    mutable std::mutex mutex_;
    std::shared_ptr<RuntimeBundle> bundle_;
    Handle wake_event_;
    std::optional<std::string> last_runtime_error_;
    std::atomic_bool environment_change_pending_{false};
};

SERVICE_STATUS_HANDLE status_handle{};
SERVICE_STATUS service_status{};
Handle service_stop_event;
std::mutex active_service_host_mutex;
std::shared_ptr<ServiceHost> active_service_host;

void report_service_status(DWORD state, DWORD error = NO_ERROR,
                           DWORD wait_hint = 0U) {
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = state;
    service_status.dwWin32ExitCode = error;
    service_status.dwWaitHint = wait_hint;
    service_status.dwControlsAccepted =
        state == SERVICE_RUNNING
            ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
                  SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_POWEREVENT
            : 0U;
    if (status_handle != nullptr) {
        static_cast<void>(::SetServiceStatus(status_handle, &service_status));
    }
}

DWORD WINAPI service_control(DWORD control, DWORD event_type, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN ||
        control == SERVICE_CONTROL_PRESHUTDOWN) {
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 10'000U);
        if (service_stop_event) {
            static_cast<void>(::SetEvent(service_stop_event.get()));
        }
    }
    if (control == SERVICE_CONTROL_POWEREVENT &&
        (event_type == PBT_APMRESUMEAUTOMATIC ||
         event_type == PBT_APMRESUMESUSPEND)) {
        std::shared_ptr<ServiceHost> host;
        {
            std::lock_guard lock{active_service_host_mutex};
            host = active_service_host;
        }
        if (host) {
            host->notify_environment_change();
        }
    }
    return NO_ERROR;
}

void WINAPI service_entry(DWORD, LPWSTR*) {
    status_handle =
        ::RegisterServiceCtrlHandlerExW(service_name, &service_control, nullptr);
    if (status_handle == nullptr) {
        return;
    }
    report_service_status(SERVICE_START_PENDING, NO_ERROR, 10'000U);
    service_stop_event = Handle{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!service_stop_event) {
        report_service_status(SERVICE_STOPPED, ::GetLastError());
        return;
    }
    try {
        auto host = std::make_shared<ServiceHost>();
        {
            std::lock_guard lock{active_service_host_mutex};
            active_service_host = host;
        }
        report_service_status(SERVICE_RUNNING);
        try {
            host->run(service_stop_event.get());
        } catch (...) {
            std::lock_guard lock{active_service_host_mutex};
            active_service_host.reset();
            throw;
        }
        {
            std::lock_guard lock{active_service_host_mutex};
            active_service_host.reset();
        }
        report_service_status(SERVICE_STOPPED);
    } catch (const std::exception&) {
        report_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
}

BOOL WINAPI console_control(DWORD control) {
    if ((control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT ||
         control == CTRL_CLOSE_EVENT) &&
        service_stop_event) {
        static_cast<void>(::SetEvent(service_stop_event.get()));
        return TRUE;
    }
    return FALSE;
}

void change_service_config_or_throw(SC_HANDLE service, DWORD level, void* value,
                                    std::string_view description) {
    if (::ChangeServiceConfig2W(service, level, value) == FALSE) {
        throw std::runtime_error(std::string{description} + " failed with error " +
                                 std::to_string(::GetLastError()));
    }
}

void apply_service_configuration(SC_HANDLE service) {
    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    change_service_config_or_throw(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                   &delayed, "configure delayed service start");
    SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
    change_service_config_or_throw(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid,
                                   "configure service SID");
    std::array<SC_ACTION, 3> actions{
        SC_ACTION{SC_ACTION_RESTART, 5'000U},
        SC_ACTION{SC_ACTION_RESTART, 15'000U},
        SC_ACTION{SC_ACTION_RESTART, 60'000U},
    };
    SERVICE_FAILURE_ACTIONSW failure{
        86'400U, nullptr, nullptr, static_cast<DWORD>(actions.size()), actions.data()};
    change_service_config_or_throw(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure,
                                   "configure service failure actions");
    SERVICE_FAILURE_ACTIONS_FLAG failure_flag{TRUE};
    change_service_config_or_throw(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                                   &failure_flag,
                                   "configure service non-crash failure actions");
    SERVICE_DESCRIPTIONW description{
        const_cast<LPWSTR>(L"Owns sb-easy enrollment, configuration, and TUN runtime.")};
    change_service_config_or_throw(service, SERVICE_CONFIG_DESCRIPTION, &description,
                                   "configure service description");
}

void configure_service() {
    ServiceHandle manager{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager) {
        throw std::runtime_error("open Service Control Manager failed with error " +
                                 std::to_string(::GetLastError()));
    }
    // SC_ACTION_RESTART also requires SERVICE_START on the configuration handle.
    ServiceHandle service{::OpenServiceW(
        manager.get(), service_name, SERVICE_CHANGE_CONFIG | SERVICE_START)};
    if (!service) {
        throw std::runtime_error("open sb-easy Windows Service failed with error " +
                                 std::to_string(::GetLastError()));
    }
    apply_service_configuration(service.get());
}

void install_service() {
    ServiceHandle manager{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!manager) {
        throw std::runtime_error("open Service Control Manager failed");
    }
    const auto executable = executable_directory() / L"sb-easy-service.exe";
    const auto command = L"\"" + executable.wstring() + L"\"";
    ServiceHandle service{::CreateServiceW(
        manager.get(), service_name, L"sb-easy VPN Service", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr)};
    if (!service) {
        throw std::runtime_error("create sb-easy Windows Service failed with error " +
                                 std::to_string(::GetLastError()));
    }
    apply_service_configuration(service.get());
}

} // namespace
} // namespace sbeasy::win

int wmain(int argc, wchar_t** argv) {
    using namespace sbeasy::win;
    try {
        if (argc >= 2 && std::wstring_view{argv[1]} == L"--console") {
            service_stop_event = Handle{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
            if (!service_stop_event) {
                throw std::runtime_error("create console stop event failed");
            }
            static_cast<void>(::SetConsoleCtrlHandler(&console_control, TRUE));
            ServiceHost host{true};
            if (argc == 5 && std::wstring_view{argv[2]} == L"--enroll") {
                const auto convert = [](std::wstring_view value) {
                    if (value.size() >
                        static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                        throw std::invalid_argument("command line argument is too long");
                    }
                    const int length = static_cast<int>(value.size());
                    const int required = ::WideCharToMultiByte(
                        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), length, nullptr, 0,
                        nullptr, nullptr);
                    if (required <= 0) {
                        throw std::invalid_argument("command line is not valid UTF-16");
                    }
                    std::string result(static_cast<std::size_t>(required), '\0');
                    static_cast<void>(::WideCharToMultiByte(
                        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), length,
                        result.data(), required, nullptr, nullptr));
                    return result;
                };
                host.enroll(convert(argv[3]), convert(argv[4]));
            } else if (argc != 2) {
                throw std::invalid_argument(
                    "usage: sb-easy-service.exe --console [--enroll <server> <code>]");
            }
            std::cout << "sb-easy service running in console mode; press Ctrl+C to stop\n";
            host.run(service_stop_event.get());
            return 0;
        }
        if (argc == 2 && std::wstring_view{argv[1]} == L"--install") {
            install_service();
            std::wcout << L"sb-easy service installed\n";
            return 0;
        }
        if (argc == 2 && std::wstring_view{argv[1]} == L"--configure") {
            configure_service();
            return 0;
        }
        if (argc != 1) {
            throw std::invalid_argument(
                "usage: sb-easy-service.exe [--console [--enroll <server> <code>] | "
                "--install | --configure]");
        }
        SERVICE_TABLE_ENTRYW table[] = {
            {const_cast<LPWSTR>(service_name), &service_entry},
            {nullptr, nullptr},
        };
        if (::StartServiceCtrlDispatcherW(table) == FALSE) {
            throw std::runtime_error("start Service Control Dispatcher failed with error " +
                                     std::to_string(::GetLastError()));
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
