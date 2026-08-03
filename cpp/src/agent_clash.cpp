#include "sbeasy/agent_clash.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <netdb.h>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <unistd.h>

#include "sbeasy/clash_client.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;

struct TrafficSample {
    std::int64_t upload_total{};
    std::int64_t download_total{};
    std::chrono::steady_clock::time_point at;
};

struct DomainRouteAccumulator {
    json identity;
    std::int64_t connection_count{};
    std::int64_t uplink_total{};
    std::int64_t downlink_total{};
    std::int64_t first_seen{};
    std::int64_t last_seen{};
};

struct ObservedConnection {
    std::string route_key;
    std::int64_t uplink_total{};
    std::int64_t downlink_total{};
};

struct UrlTarget {
    std::string url;
    std::string host;
    std::uint16_t port{};
};

struct LocalProxy {
    std::string host;
    std::uint16_t port{};
};

class Socket final {
  public:
    explicit Socket(int descriptor) : descriptor_(descriptor) {}
    ~Socket() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}
    Socket& operator=(Socket&&) = delete;

    [[nodiscard]] int get() const noexcept {
        return descriptor_;
    }

  private:
    int descriptor_;
};

[[nodiscard]] std::string trim(std::string value) {
    const auto whitespace = [](unsigned char character) {
        return std::isspace(character) != 0;
    };
    const auto first = std::ranges::find_if_not(value, whitespace);
    const auto last = std::find_if_not(value.rbegin(), value.rend(), whitespace).base();
    if (first >= last) {
        return {};
    }
    return {first, last};
}

[[nodiscard]] std::string lowercase(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

[[nodiscard]] std::uint16_t parse_port(std::string_view value) {
    unsigned int port{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0U ||
        port > 65'535U) {
        throw std::invalid_argument("URL 端口无效");
    }
    return static_cast<std::uint16_t>(port);
}

[[nodiscard]] UrlTarget parse_url(std::string value) {
    value = trim(std::move(value));
    if (value.empty()) {
        throw std::invalid_argument("请输入要测试的 URL");
    }
    if (value.find("://") == std::string::npos) {
        value = "https://" + value;
    }
    const auto scheme_end = value.find("://");
    const auto scheme = lowercase(value.substr(0, scheme_end));
    if (scheme != "http" && scheme != "https") {
        throw std::invalid_argument("只支持 http:// 或 https:// URL");
    }
    const auto authority_begin = scheme_end + 3U;
    const auto authority_end = value.find_first_of("/?#", authority_begin);
    auto authority = value.substr(authority_begin, authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos ||
        std::ranges::any_of(authority, [](unsigned char character) {
            return std::iscntrl(character) != 0 || std::isspace(character) != 0;
        })) {
        throw std::invalid_argument("URL 主机名无效");
    }

    std::string host;
    std::uint16_t port = scheme == "https" ? 443U : 80U;
    if (authority.starts_with('[')) {
        const auto bracket = authority.find(']');
        if (bracket == std::string::npos) {
            throw std::invalid_argument("URL IPv6 主机名无效");
        }
        host = authority.substr(1U, bracket - 1U);
        if (bracket + 1U < authority.size()) {
            if (authority[bracket + 1U] != ':') {
                throw std::invalid_argument("URL 主机名无效");
            }
            port = parse_port(std::string_view{authority}.substr(bracket + 2U));
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            host = authority.substr(0U, colon);
            port = parse_port(std::string_view{authority}.substr(colon + 1U));
        } else {
            host = std::move(authority);
        }
    }
    if (host.empty()) {
        throw std::invalid_argument("URL 主机名无效");
    }
    return {
        .url = std::move(value),
        .host = std::move(host),
        .port = port,
    };
}

[[nodiscard]] LocalProxy read_local_proxy(const json& config) {
    const auto inbounds = config.find("inbounds");
    if (inbounds == config.end() || !inbounds->is_array()) {
        throw std::runtime_error("当前配置没有可用于测试的 HTTP/mixed 入站");
    }
    for (const auto& inbound : *inbounds) {
        if (!inbound.is_object()) {
            continue;
        }
        const auto type = inbound.value("type", "");
        if (type != "mixed" && type != "http") {
            continue;
        }
        const auto port = inbound.find("listen_port");
        if (port == inbound.end() ||
            !(port->is_number_integer() || port->is_number_unsigned())) {
            continue;
        }
        const auto number = port->get<unsigned int>();
        if (number == 0U || number > 65'535U) {
            continue;
        }
        auto host = inbound.value("listen", "127.0.0.1");
        if (host.empty() || host == "0.0.0.0") {
            host = "127.0.0.1";
        } else if (host == "::" || host == "[::]") {
            host = "::1";
        }
        return {
            .host = std::move(host),
            .port = static_cast<std::uint16_t>(number),
        };
    }
    throw std::runtime_error("当前配置需要 mixed 或 http 入站才能执行真实路由测试");
}

[[nodiscard]] Socket connect_local_proxy(const LocalProxy& proxy) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses{};
    const auto service = std::to_string(proxy.port);
    const auto result =
        ::getaddrinfo(proxy.host.c_str(), service.c_str(), &hints, &addresses);
    if (result != 0) {
        throw std::runtime_error("无法解析本地代理入口");
    }
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> values{addresses,
                                                                ::freeaddrinfo};
    for (auto* address = values.get(); address != nullptr; address = address->ai_next) {
        const auto descriptor =
            ::socket(address->ai_family, address->ai_socktype | SOCK_CLOEXEC,
                     address->ai_protocol);
        if (descriptor < 0) {
            continue;
        }
        Socket socket{descriptor};
        timeval timeout{.tv_sec = 5, .tv_usec = 0};
        static_cast<void>(::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
                                       sizeof(timeout)));
        static_cast<void>(::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout,
                                       sizeof(timeout)));
        if (::connect(socket.get(), address->ai_addr, address->ai_addrlen) == 0) {
            return socket;
        }
    }
    throw std::runtime_error("无法连接当前配置的本地代理入口");
}

[[nodiscard]] std::uint16_t source_port(int descriptor) {
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &length) !=
        0) {
        throw std::runtime_error("无法读取测试连接源端口");
    }
    if (address.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
    }
    if (address.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    }
    throw std::runtime_error("测试连接使用了不支持的地址类型");
}

void send_all(int descriptor, std::string_view value) {
    std::size_t sent{};
    while (sent < value.size()) {
        const auto count =
            ::send(descriptor, value.data() + sent, value.size() - sent, MSG_NOSIGNAL);
        if (count <= 0) {
            throw std::runtime_error("无法向本地代理发送测试请求");
        }
        sent += static_cast<std::size_t>(count);
    }
}

[[nodiscard]] bool metadata_matches_port(const json& metadata, std::uint16_t port) {
    const auto found = metadata.find("sourcePort");
    if (found == metadata.end()) {
        return false;
    }
    if (found->is_number_unsigned()) {
        return found->get<unsigned int>() == port;
    }
    if (found->is_string()) {
        try {
            return parse_port(found->get<std::string>()) == port;
        } catch (const std::invalid_argument&) {
            return false;
        }
    }
    return false;
}

[[nodiscard]] std::optional<json> find_connection(const json& response,
                                                  std::uint16_t port) {
    const auto connections = response.find("connections");
    if (connections == response.end() || !connections->is_array()) {
        return std::nullopt;
    }
    for (const auto& connection : *connections) {
        const auto metadata = connection.find("metadata");
        if (connection.is_object() && metadata != connection.end() &&
            metadata->is_object() && metadata_matches_port(*metadata, port)) {
            return connection;
        }
    }
    return std::nullopt;
}

[[nodiscard]] json route_result(const UrlTarget& target, const json& connection) {
    auto chains = connection.value("chains", json::array());
    if (!chains.is_array()) {
        chains = json::array();
    }
    std::string outbound;
    if (!chains.empty() && chains.front().is_string()) {
        outbound = chains.front().get<std::string>();
    }
    const auto normalized = lowercase(outbound);
    auto kind = std::string{"proxy"};
    if (normalized == "direct") {
        kind = "direct";
    } else if (normalized == "block" || normalized == "reject") {
        kind = "block";
    } else if (outbound.empty()) {
        kind = "unknown";
    }
    return {
        {"success", true},
        {"url", target.url},
        {"host", target.host},
        {"port", target.port},
        {"kind", std::move(kind)},
        {"outbound", std::move(outbound)},
        {"chains", std::move(chains)},
        {"rule", connection.value("rule", "")},
        {"rule_payload", connection.value("rulePayload", "")},
    };
}

[[nodiscard]] std::string encode_component(std::string_view value) {
    static constexpr std::string_view hexadecimal{"0123456789ABCDEF"};
    std::string encoded;
    encoded.reserve(value.size());
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (std::isalnum(byte) != 0 || character == '-' || character == '_' ||
            character == '.' || character == '~') {
            encoded.push_back(character);
        } else {
            encoded.push_back('%');
            encoded.push_back(hexadecimal[byte >> 4U]);
            encoded.push_back(hexadecimal[byte & 0x0fU]);
        }
    }
    return encoded;
}

void replace_all(std::string& value, std::string_view from, std::string_view to) {
    std::size_t position{};
    while ((position = value.find(from, position)) != std::string::npos) {
        value.replace(position, from.size(), to);
        position += to.size();
    }
}

[[nodiscard]] json read_config(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        throw std::runtime_error("cannot read sing-box config: " + path.string());
    }
    const std::string source{std::istreambuf_iterator<char>{input},
                             std::istreambuf_iterator<char>{}};
    auto config = json::parse(source, nullptr, false);
    if (!config.is_object()) {
        throw std::runtime_error("sing-box config is not a JSON object: " +
                                 path.string());
    }
    return config;
}

[[nodiscard]] std::optional<ClashTarget> read_target(const std::filesystem::path& path,
                                                     bool use_default_controller) {
    const auto config = read_config(path);
    static const json::json_pointer controller_pointer{
        "/experimental/clash_api/external_controller"};
    static const json::json_pointer secret_pointer{"/experimental/clash_api/secret"};
    const auto* controller =
        config.contains(controller_pointer) ? &config.at(controller_pointer) : nullptr;
    std::string address;
    if (controller != nullptr && controller->is_string()) {
        address = controller->get<std::string>();
    } else if (use_default_controller) {
        address = "127.0.0.1:9090";
    } else {
        return std::nullopt;
    }
    if (address.empty()) {
        if (!use_default_controller) {
            return std::nullopt;
        }
        address = "127.0.0.1:9090";
    }
    replace_all(address, "0.0.0.0", "127.0.0.1");
    replace_all(address, "[::]", "127.0.0.1");
    if (!address.starts_with("http://") && !address.starts_with("https://")) {
        address = "http://" + address;
    }
    while (address.ends_with('/')) {
        address.pop_back();
    }

    std::string secret;
    if (config.contains(secret_pointer) && config.at(secret_pointer).is_string()) {
        secret = config.at(secret_pointer).get<std::string>();
    }
    return ClashTarget{
        .base_url = std::move(address),
        .secret = std::move(secret),
    };
}

[[nodiscard]] bool successful(const ClashResponse& response) {
    return response.status >= 200 && response.status < 300;
}

[[nodiscard]] std::int64_t integer_or_zero(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() ||
        !(found->is_number_integer() || found->is_number_unsigned())) {
        return 0;
    }
    return found->get<std::int64_t>();
}

} // namespace

class AgentClashService::Impl final {
  public:
    explicit Impl(std::filesystem::path config_path)
        : config_path_(std::move(config_path)),
          client_({.timeout = std::chrono::seconds{8},
                   .maximum_body_bytes = 8U * 1024U * 1024U}) {}

    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) {
        const auto target = *read_target(config_path_, true);
        const auto response = client_.get(target, "/proxies");
        if (!successful(response)) {
            throw std::runtime_error("Clash proxy list returned HTTP " +
                                     std::to_string(response.status));
        }

        const auto found = response.body.find("proxies");
        if (found == response.body.end() || !found->is_object()) {
            return 0U;
        }
        static const std::unordered_set<std::string> skipped_types{
            "Selector",   "URLTest", "Fallback", "LoadBalance", "Direct",   "Reject",
            "Compatible", "Pass",    "Dns",      "Block",       "Loopback",
        };
        const std::unordered_set<std::string> wanted =
            tags.has_value()
                ? std::unordered_set<std::string>{tags->begin(), tags->end()}
                : std::unordered_set<std::string>{};

        std::vector<std::string> names;
        for (const auto& [name, proxy] : found->items()) {
            const auto type = proxy.is_object() ? proxy.value("type", "") : "";
            const bool is_group = proxy.is_object() && proxy.contains("all");
            if (!is_group && !skipped_types.contains(type) &&
                (!tags.has_value() || wanted.contains(name))) {
                names.push_back(name);
            }
        }
        std::ranges::sort(names);

        std::size_t tested{};
        for (const auto& name : names) {
            json latency = nullptr;
            try {
                const auto path =
                    "/proxies/" + encode_component(name) + "/delay?url=" +
                    encode_component("https://www.gstatic.com/generate_204") +
                    "&timeout=5000";
                const auto delay = client_.get(target, path);
                if (successful(delay)) {
                    const auto value = delay.body.find("delay");
                    if (value != delay.body.end() && value->is_number()) {
                        latency = *value;
                    }
                }
            } catch (const ClashRequestError&) {
                // An unreachable proxy is a valid null measurement; continue
                // reporting the remaining nodes.
            }
            json result = json::object();
            result[name] = std::move(latency);
            reporter(result);
            ++tested;
        }
        return tested;
    }

    [[nodiscard]] std::optional<json> sample_telemetry() {
        const auto target = read_target(config_path_, false);
        if (!target.has_value()) {
            return std::nullopt;
        }
        const auto response = client_.get(*target, "/connections");
        if (!successful(response)) {
            throw std::runtime_error("Clash connections returned HTTP " +
                                     std::to_string(response.status));
        }

        const auto upload_total = integer_or_zero(response.body, "uploadTotal");
        const auto download_total = integer_or_zero(response.body, "downloadTotal");
        const auto now = std::chrono::steady_clock::now();
        std::int64_t upload_rate{};
        std::int64_t download_rate{};
        if (last_sample_.has_value()) {
            const auto elapsed = std::max(
                std::chrono::duration<double>{now - last_sample_->at}.count(), 0.001);
            const auto upload_delta =
                std::max<std::int64_t>(upload_total - last_sample_->upload_total, 0);
            const auto download_delta = std::max<std::int64_t>(
                download_total - last_sample_->download_total, 0);
            upload_rate =
                static_cast<std::int64_t>(static_cast<double>(upload_delta) / elapsed);
            download_rate = static_cast<std::int64_t>(
                static_cast<double>(download_delta) / elapsed);
        }
        last_sample_ = TrafficSample{
            .upload_total = upload_total,
            .download_total = download_total,
            .at = now,
        };

        auto connections = json::array();
        if (const auto found = response.body.find("connections");
            found != response.body.end()) {
            connections = *found;
        }
        const auto connection_count = connections.is_array() ? connections.size() : 0U;
        auto domain_stats = update_domain_route_stats(connections);
        return json{
            {"up", upload_rate},
            {"down", download_rate},
            {"up_total", upload_total},
            {"down_total", download_total},
            {"conn_count", connection_count},
            {"connections", std::move(connections)},
            {"domain_stats", std::move(domain_stats)},
            {"logs", json::array()},
        };
    }

    [[nodiscard]] json test_route(const std::string& url) {
        const auto destination = parse_url(url);
        const auto config = read_config(config_path_);
        const auto proxy = read_local_proxy(config);
        const auto clash_target = *read_target(config_path_, true);
        ClashClient client({.timeout = std::chrono::seconds{2},
                            .maximum_body_bytes = 8U * 1024U * 1024U});
        auto socket = connect_local_proxy(proxy);
        const auto port = source_port(socket.get());
        const auto authority = (destination.host.find(':') == std::string::npos
                                    ? destination.host
                                    : "[" + destination.host + "]") +
                               ":" + std::to_string(destination.port);
        send_all(socket.get(), "CONNECT " + authority +
                                   " HTTP/1.1\r\nHost: " + authority +
                                   "\r\nUser-Agent: sb-easy-route-test/1.0\r\n"
                                   "Proxy-Connection: keep-alive\r\n\r\n");

        for (int attempt = 0; attempt < 50; ++attempt) {
            const auto response = client.get(clash_target, "/connections");
            if (!successful(response)) {
                throw std::runtime_error("Clash connections returned HTTP " +
                                         std::to_string(response.status));
            }
            if (const auto connection = find_connection(response.body, port);
                connection.has_value()) {
                return route_result(destination, *connection);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        throw std::runtime_error(
            "未能在 Clash API 中找到测试连接；目标可能不可达或被规则拒绝");
    }

  private:
    [[nodiscard]] json update_domain_route_stats(const json& connections) {
        if (!connections.is_array()) {
            observed_connections_.clear();
            return json::array();
        }
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        std::unordered_set<std::string> seen;
        for (const auto& connection : connections) {
            if (!connection.is_object()) {
                continue;
            }
            const auto id_value = connection.find("id");
            if (id_value == connection.end() || !id_value->is_string() ||
                id_value->get_ref<const std::string&>().empty()) {
                continue;
            }
            const auto id = id_value->get<std::string>();
            seen.insert(id);
            const auto identity = domain_route_identity(connection);
            const auto route_key = identity.dump();
            const auto uplink = nonnegative_connection_integer(connection, "upload");
            const auto downlink = nonnegative_connection_integer(connection, "download");
            const auto observed = observed_connections_.find(id);
            if (observed == observed_connections_.end()) {
                add_domain_route(identity, route_key, 1, uplink, downlink, now);
                observed_connections_[id] = {route_key, uplink, downlink};
                continue;
            }
            if (observed->second.route_key != route_key) {
                subtract_domain_route(observed->second);
                add_domain_route(identity, route_key, 1, uplink, downlink, now);
                observed->second = {route_key, uplink, downlink};
                continue;
            }
            add_domain_route(
                identity, route_key, 0,
                std::max<std::int64_t>(uplink - observed->second.uplink_total, 0),
                std::max<std::int64_t>(downlink - observed->second.downlink_total, 0),
                now);
            observed->second.uplink_total =
                std::max(observed->second.uplink_total, uplink);
            observed->second.downlink_total =
                std::max(observed->second.downlink_total, downlink);
        }
        std::erase_if(observed_connections_,
                      [&seen](const auto& item) { return !seen.contains(item.first); });

        std::vector<const DomainRouteAccumulator*> ordered;
        ordered.reserve(domain_route_stats_.size());
        for (const auto& [_, stat] : domain_route_stats_) {
            ordered.push_back(&stat);
        }
        std::ranges::sort(ordered, [](const auto* left, const auto* right) {
            if (left->connection_count != right->connection_count) {
                return left->connection_count > right->connection_count;
            }
            return left->uplink_total + left->downlink_total >
                   right->uplink_total + right->downlink_total;
        });
        json result = json::array();
        for (const auto* stat : ordered) {
            auto value = stat->identity;
            value["connection_count"] = stat->connection_count;
            value["uplink_total"] = stat->uplink_total;
            value["downlink_total"] = stat->downlink_total;
            value["first_seen"] = stat->first_seen;
            value["last_seen"] = stat->last_seen;
            result.push_back(std::move(value));
        }
        return result;
    }

    [[nodiscard]] static json domain_route_identity(const json& connection) {
        const auto metadata_value = connection.find("metadata");
        const auto* metadata = metadata_value != connection.end() &&
                                       metadata_value->is_object()
                                   ? &*metadata_value
                                   : nullptr;
        auto string_value = [](const json* value, const char* field) {
            if (value == nullptr) {
                return std::string{};
            }
            const auto found = value->find(field);
            return found != value->end() && found->is_string()
                       ? found->get<std::string>()
                       : std::string{};
        };
        auto domain = string_value(metadata, "host");
        if (domain.empty()) {
            domain = string_value(metadata, "destinationIP");
        }
        if (domain.empty()) {
            domain = "unknown";
        }
        while (domain.ends_with('.')) {
            domain.pop_back();
        }
        std::ranges::transform(domain, domain.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        domain.resize(std::min<std::size_t>(domain.size(), 512U));

        json chain = json::array();
        if (const auto chains = connection.find("chains");
            chains != connection.end() && chains->is_array()) {
            for (const auto& tag : *chains) {
                if (tag.is_string() && chain.size() < 16U) {
                    auto value = tag.get<std::string>();
                    value.resize(std::min<std::size_t>(value.size(), 256U));
                    chain.push_back(std::move(value));
                }
            }
        }
        const auto outbound =
            chain.empty() ? std::string{} : chain.back().get<std::string>();
        auto route_text = outbound;
        std::ranges::transform(route_text, route_text.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        const auto outbound_type = route_text.find("direct") != std::string::npos
                                       ? "direct"
                                       : (route_text.empty() ? "" : "proxy");
        auto rule = string_value(&connection, "rule");
        const auto payload = string_value(&connection, "rulePayload");
        if (!payload.empty()) {
            rule += (rule.empty() ? "" : ": ") + payload;
        }
        rule.resize(std::min<std::size_t>(rule.size(), 512U));
        return {
            {"domain", std::move(domain)},
            {"outbound", outbound},
            {"outbound_type", outbound_type},
            {"rule", std::move(rule)},
            {"chain", std::move(chain)},
        };
    }

    [[nodiscard]] static std::int64_t
    nonnegative_connection_integer(const json& connection, const char* field) {
        const auto value = connection.find(field);
        if (value == connection.end() ||
            !(value->is_number_integer() || value->is_number_unsigned())) {
            return 0;
        }
        return std::max<std::int64_t>(value->get<std::int64_t>(), 0);
    }

    void add_domain_route(const json& identity, const std::string& route_key,
                          std::int64_t connections, std::int64_t uplink,
                          std::int64_t downlink, std::int64_t now) {
        if (!domain_route_stats_.contains(route_key) &&
            domain_route_stats_.size() >= 1'000U) {
            const auto oldest = std::ranges::min_element(
                domain_route_stats_, {},
                [](const auto& item) { return item.second.last_seen; });
            if (oldest != domain_route_stats_.end()) {
                domain_route_stats_.erase(oldest);
            }
        }
        auto found = domain_route_stats_
                         .try_emplace(route_key,
                                      DomainRouteAccumulator{identity, 0, 0, 0, now, now})
                         .first;
        found->second.connection_count += std::max<std::int64_t>(connections, 0);
        found->second.uplink_total += std::max<std::int64_t>(uplink, 0);
        found->second.downlink_total += std::max<std::int64_t>(downlink, 0);
        found->second.last_seen = std::max(found->second.last_seen, now);
    }

    void subtract_domain_route(const ObservedConnection& observed) {
        const auto found = domain_route_stats_.find(observed.route_key);
        if (found == domain_route_stats_.end()) {
            return;
        }
        found->second.connection_count =
            std::max<std::int64_t>(found->second.connection_count - 1, 0);
        found->second.uplink_total =
            std::max<std::int64_t>(found->second.uplink_total - observed.uplink_total, 0);
        found->second.downlink_total = std::max<std::int64_t>(
            found->second.downlink_total - observed.downlink_total, 0);
        if (found->second.connection_count == 0 &&
            found->second.uplink_total == 0 && found->second.downlink_total == 0) {
            domain_route_stats_.erase(found);
        }
    }

    std::filesystem::path config_path_;
    ClashClient client_;
    std::optional<TrafficSample> last_sample_;
    std::unordered_map<std::string, ObservedConnection> observed_connections_;
    std::unordered_map<std::string, DomainRouteAccumulator> domain_route_stats_;
};

AgentClashService::AgentClashService(std::filesystem::path config_path)
    : implementation_(std::make_unique<Impl>(std::move(config_path))) {}

AgentClashService::~AgentClashService() = default;
AgentClashService::AgentClashService(AgentClashService&&) noexcept = default;
AgentClashService& AgentClashService::operator=(AgentClashService&&) noexcept = default;

std::size_t
AgentClashService::test_proxies(const std::optional<std::vector<std::string>>& tags,
                                const LatencyReporter& reporter) {
    if (!reporter) {
        throw std::invalid_argument("proxy latency reporter is required");
    }
    return implementation_->test_proxies(tags, reporter);
}

std::optional<nlohmann::json> AgentClashService::sample_telemetry() {
    return implementation_->sample_telemetry();
}

nlohmann::json AgentClashService::test_route(const std::string& url) {
    return implementation_->test_route(url);
}

} // namespace sbeasy
