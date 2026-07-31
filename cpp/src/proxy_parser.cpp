#include "sbeasy/proxy_parser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <yaml-cpp/yaml.h>

namespace sbeasy {
namespace {

using nlohmann::json;

[[nodiscard]] std::string trim(std::string_view value) {
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return std::string{value};
}

[[nodiscard]] int hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

[[nodiscard]] std::string percent_decode(std::string_view value,
                                         bool plus_as_space = false) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '%' && index + 2U < value.size()) {
            const auto high = hex_value(value[index + 1U]);
            const auto low = hex_value(value[index + 2U]);
            if (high >= 0 && low >= 0) {
                decoded.push_back(static_cast<char>((high << 4) | low));
                index += 2U;
                continue;
            }
        }
        if (plus_as_space && value[index] == '+') {
            decoded.push_back(' ');
        } else {
            decoded.push_back(value[index]);
        }
    }
    return decoded;
}

[[nodiscard]] std::optional<std::string> decode_base64(std::string_view encoded) {
    std::string normalized;
    normalized.reserve(encoded.size() + 3U);
    for (const auto character : encoded) {
        if (std::isspace(static_cast<unsigned char>(character)) != 0) {
            continue;
        }
        if (character == '-') {
            normalized.push_back('+');
        } else if (character == '_') {
            normalized.push_back('/');
        } else {
            normalized.push_back(character);
        }
    }
    if (normalized.empty() || normalized.size() % 4U == 1U ||
        normalized.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    while (normalized.size() % 4U != 0U) {
        normalized.push_back('=');
    }
    if (!std::ranges::all_of(normalized, [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '+' ||
                   character == '/' || character == '=';
        })) {
        return std::nullopt;
    }

    std::vector<unsigned char> output((normalized.size() / 4U) * 3U);
    const auto decoded = EVP_DecodeBlock(
        output.data(), reinterpret_cast<const unsigned char*>(normalized.data()),
        static_cast<int>(normalized.size()));
    if (decoded < 0) {
        return std::nullopt;
    }
    auto size = static_cast<std::size_t>(decoded);
    if (normalized.ends_with("==")) {
        size -= 2U;
    } else if (normalized.ends_with('=')) {
        size -= 1U;
    }
    return std::string{reinterpret_cast<const char*>(output.data()), size};
}

[[nodiscard]] std::optional<std::uint16_t> parse_port(std::string_view value) {
    unsigned int port{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0U ||
        port > 65'535U) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
}

[[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>>
parse_host_port(std::string_view value, std::uint16_t default_port) {
    if (value.empty()) {
        return std::nullopt;
    }
    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string_view::npos || close == 1U) {
            return std::nullopt;
        }
        const auto host = value.substr(1, close - 1U);
        if (close + 1U == value.size()) {
            return std::pair{std::string{host}, default_port};
        }
        if (value[close + 1U] != ':') {
            return std::nullopt;
        }
        auto port = parse_port(value.substr(close + 2U));
        if (!port.has_value()) {
            return std::nullopt;
        }
        return std::pair{std::string{host}, *port};
    }

    const auto colon = value.rfind(':');
    if (colon == std::string_view::npos) {
        return std::pair{std::string{value}, default_port};
    }
    auto port = parse_port(value.substr(colon + 1U));
    if (!port.has_value()) {
        return std::nullopt;
    }
    const auto host = value.substr(0, colon);
    if (host.empty()) {
        return std::nullopt;
    }
    return std::pair{std::string{host}, *port};
}

struct StructuredUri {
    std::string user_info;
    std::string host;
    std::uint16_t port{};
    std::string fragment;
    std::map<std::string, std::string> query;
};

[[nodiscard]] std::optional<StructuredUri>
parse_structured_uri(std::string_view uri, std::string_view scheme,
                     std::uint16_t default_port) {
    const std::string prefix = std::string{scheme} + "://";
    if (!uri.starts_with(prefix)) {
        return std::nullopt;
    }
    uri.remove_prefix(prefix.size());

    StructuredUri parsed;
    if (const auto hash = uri.find('#'); hash != std::string_view::npos) {
        parsed.fragment = percent_decode(uri.substr(hash + 1U));
        uri = uri.substr(0, hash);
    }
    std::string_view query;
    if (const auto question = uri.find('?'); question != std::string_view::npos) {
        query = uri.substr(question + 1U);
        uri = uri.substr(0, question);
    }
    if (const auto slash = uri.find('/'); slash != std::string_view::npos) {
        uri = uri.substr(0, slash);
    }
    const auto at = uri.rfind('@');
    if (at == std::string_view::npos) {
        return std::nullopt;
    }
    parsed.user_info = percent_decode(uri.substr(0, at));
    const auto host_port = parse_host_port(uri.substr(at + 1U), default_port);
    if (!host_port.has_value()) {
        return std::nullopt;
    }
    parsed.host = host_port->first;
    parsed.port = host_port->second;

    while (!query.empty()) {
        const auto ampersand = query.find('&');
        const auto pair = query.substr(0, ampersand);
        const auto equals = pair.find('=');
        const auto key = percent_decode(pair.substr(0, equals), true);
        const auto value = equals == std::string_view::npos
                               ? std::string{}
                               : percent_decode(pair.substr(equals + 1U), true);
        parsed.query.insert_or_assign(key, value);
        if (ampersand == std::string_view::npos) {
            break;
        }
        query.remove_prefix(ampersand + 1U);
    }
    return parsed;
}

[[nodiscard]] std::string query_value(const StructuredUri& uri, std::string_view key) {
    const auto found = uri.query.find(std::string{key});
    return found == uri.query.end() ? std::string{} : found->second;
}

[[nodiscard]] bool query_true(const StructuredUri& uri, std::string_view key) {
    auto value = query_value(uri, key);
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value == "1" || value == "true";
}

[[nodiscard]] json tls_from_uri(const StructuredUri& uri, bool enabled) {
    if (!enabled) {
        return nullptr;
    }
    json tls{{"enabled", true}};
    auto sni = query_value(uri, "sni");
    if (sni.empty()) {
        sni = query_value(uri, "servername");
    }
    if (!sni.empty()) {
        tls["server_name"] = sni;
    }
    const auto alpn = query_value(uri, "alpn");
    if (!alpn.empty()) {
        tls["alpn"] = json::array();
        std::string_view remaining{alpn};
        while (!remaining.empty()) {
            const auto comma = remaining.find(',');
            tls["alpn"].push_back(trim(remaining.substr(0, comma)));
            if (comma == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(comma + 1U);
        }
    }
    auto fingerprint = query_value(uri, "fp");
    if (fingerprint.empty()) {
        fingerprint = query_value(uri, "fingerprint");
    }
    if (!fingerprint.empty()) {
        tls["utls"] = {{"enabled", true}, {"fingerprint", fingerprint}};
    }
    if (query_true(uri, "allowInsecure") || query_true(uri, "skip-cert-verify") ||
        query_true(uri, "insecure")) {
        tls["insecure"] = true;
    }
    return tls;
}

[[nodiscard]] bool has_nonempty_string(const json& value, const char* field) {
    const auto found = value.find(field);
    return found != value.end() && found->is_string() &&
           !found->get_ref<const std::string&>().empty();
}

[[nodiscard]] bool has_required_secret(const ParsedProxyNode& node) {
    if (node.node_type == "shadowsocks") {
        return has_nonempty_string(node.protocol_config, "method") &&
               has_nonempty_string(node.protocol_config, "password");
    }
    if (node.node_type == "vmess" || node.node_type == "vless") {
        return has_nonempty_string(node.protocol_config, "uuid");
    }
    if (node.node_type == "trojan" || node.node_type == "hysteria2") {
        return has_nonempty_string(node.protocol_config, "password");
    }
    if (node.node_type == "tuic") {
        return has_nonempty_string(node.protocol_config, "uuid") &&
               has_nonempty_string(node.protocol_config, "password");
    }
    return false;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_shadowsocks(std::string_view uri) {
    uri.remove_prefix(std::string_view{"ss://"}.size());
    std::string tag;
    if (const auto hash = uri.find('#'); hash != std::string_view::npos) {
        tag = percent_decode(uri.substr(hash + 1U));
        uri = uri.substr(0, hash);
    }
    if (const auto question = uri.find('?'); question != std::string_view::npos) {
        uri = uri.substr(0, question);
    }

    std::string credentials;
    std::string_view host_port;
    if (const auto at = uri.rfind('@'); at != std::string_view::npos) {
        const auto decoded = decode_base64(uri.substr(0, at));
        if (!decoded.has_value()) {
            return std::nullopt;
        }
        credentials = *decoded;
        host_port = uri.substr(at + 1U);
    } else {
        const auto decoded = decode_base64(uri);
        if (!decoded.has_value()) {
            return std::nullopt;
        }
        const auto decoded_at = decoded->rfind('@');
        if (decoded_at == std::string::npos) {
            return std::nullopt;
        }
        credentials = decoded->substr(0, decoded_at);
        host_port = std::string_view{*decoded}.substr(decoded_at + 1U);
    }
    const auto colon = credentials.find(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    const auto endpoint = parse_host_port(host_port, 8'388);
    if (!endpoint.has_value()) {
        return std::nullopt;
    }
    ParsedProxyNode node{
        .node_type = "shadowsocks",
        .tag = tag.empty() ? endpoint->first + ":" + std::to_string(endpoint->second)
                           : std::move(tag),
        .server = endpoint->first,
        .server_port = endpoint->second,
        .protocol_config =
            {
                {"method", credentials.substr(0, colon)},
                {"password", credentials.substr(colon + 1U)},
            },
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_vmess(std::string_view uri) {
    uri.remove_prefix(std::string_view{"vmess://"}.size());
    const auto decoded = decode_base64(uri);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    const auto value = json::parse(*decoded, nullptr, false);
    if (!value.is_object()) {
        return std::nullopt;
    }
    const auto server_value = value.contains("add") && value["add"].is_string()
                                  ? value["add"]
                                  : value.value("host", json{});
    if (!server_value.is_string() ||
        server_value.get_ref<const std::string&>().empty()) {
        return std::nullopt;
    }
    std::optional<std::uint16_t> port;
    if (const auto found = value.find("port"); found != value.end()) {
        if (found->is_number_unsigned()) {
            const auto raw = found->get<std::uint64_t>();
            if (raw > 0U && raw <= 65'535U) {
                port = static_cast<std::uint16_t>(raw);
            }
        } else if (found->is_number_integer()) {
            const auto raw = found->get<std::int64_t>();
            if (raw > 0 && raw <= 65'535) {
                port = static_cast<std::uint16_t>(raw);
            }
        } else if (found->is_string()) {
            port = parse_port(found->get_ref<const std::string&>());
        }
    }
    if (!port.has_value()) {
        return std::nullopt;
    }
    const auto server = server_value.get<std::string>();
    auto tag = value.value("ps", value.value("name", std::string{"vmess"}));
    json config{
        {"uuid", value.value("id", "")},
        {"alter_id", value.value("aid", 0)},
        {"security", value.value("scy", "auto")},
    };
    const auto network = value.value("net", "tcp");
    if (network != "tcp") {
        config["transport"] = {{"type", network}};
        if (value.contains("path") && value["path"].is_string()) {
            config["transport"]["path"] = value["path"];
        }
        if (value.contains("host") && value["host"].is_string()) {
            config["transport"]["headers"] = {{"Host", value["host"]}};
        }
    }
    if (value.value("tls", "") == "tls") {
        config["tls"] = {{"enabled", true}};
        if (value.contains("sni") && value["sni"].is_string()) {
            config["tls"]["server_name"] = value["sni"];
        }
    }
    ParsedProxyNode node{
        .node_type = "vmess",
        .tag = std::move(tag),
        .server = server,
        .server_port = *port,
        .protocol_config = std::move(config),
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_trojan(std::string_view uri) {
    const auto parsed = parse_structured_uri(uri, "trojan", 443);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    ParsedProxyNode node{
        .node_type = "trojan",
        .tag = parsed->fragment.empty() ? "trojan" : parsed->fragment,
        .server = parsed->host,
        .server_port = parsed->port,
        .protocol_config =
            {
                {"password", parsed->user_info},
                {"tls", tls_from_uri(*parsed, true)},
            },
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_vless(std::string_view uri) {
    const auto parsed = parse_structured_uri(uri, "vless", 443);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    json config{
        {"uuid", parsed->user_info},
        {"flow", query_value(*parsed, "flow")},
        {"packet_encoding", "xudp"},
    };
    auto network = query_value(*parsed, "type");
    if (network.empty()) {
        network = query_value(*parsed, "network");
    }
    if (!network.empty() && network != "tcp") {
        config["transport"] = {{"type", network}};
        const auto path = query_value(*parsed, "path");
        if (!path.empty()) {
            config["transport"]["path"] = path;
        }
        const auto host = query_value(*parsed, "host");
        if (!host.empty()) {
            config["transport"]["headers"] = {{"Host", host}};
        }
    }
    const auto security = query_value(*parsed, "security");
    if (security == "tls" || security == "reality") {
        config["tls"] = tls_from_uri(*parsed, true);
    }
    ParsedProxyNode node{
        .node_type = "vless",
        .tag = parsed->fragment.empty() ? "vless" : parsed->fragment,
        .server = parsed->host,
        .server_port = parsed->port,
        .protocol_config = std::move(config),
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_hysteria2(std::string_view uri) {
    std::string normalized{uri};
    if (normalized.starts_with("hy2://")) {
        normalized.replace(0, 6, "hysteria2://");
    }
    const auto parsed = parse_structured_uri(normalized, "hysteria2", 443);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    json config{{"password", parsed->user_info}};
    const auto tls = tls_from_uri(*parsed, true);
    if (tls.size() > 1U) {
        config["tls"] = tls;
    }
    const auto obfs = query_value(*parsed, "obfs");
    if (!obfs.empty()) {
        config["obfs"] = {{"type", obfs}};
        const auto password = query_value(*parsed, "obfs-password");
        if (!password.empty()) {
            config["obfs"]["password"] = password;
        }
    }
    ParsedProxyNode node{
        .node_type = "hysteria2",
        .tag = parsed->fragment.empty() ? "hysteria2" : parsed->fragment,
        .server = parsed->host,
        .server_port = parsed->port,
        .protocol_config = std::move(config),
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_tuic(std::string_view uri) {
    const auto parsed = parse_structured_uri(uri, "tuic", 443);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    const auto colon = parsed->user_info.find(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    json config{
        {"uuid", parsed->user_info.substr(0, colon)},
        {"password", parsed->user_info.substr(colon + 1U)},
        {"congestion_control", "bbr"},
        {"udp_relay_mode", "native"},
        {"heartbeat", "10s"},
    };
    auto congestion = query_value(*parsed, "congestion_control");
    if (congestion.empty()) {
        congestion = query_value(*parsed, "congestion");
    }
    if (!congestion.empty()) {
        config["congestion_control"] = congestion;
    }
    const auto tls = tls_from_uri(*parsed, true);
    if (tls.size() > 1U) {
        config["tls"] = tls;
    }
    ParsedProxyNode node{
        .node_type = "tuic",
        .tag = parsed->fragment.empty() ? "tuic" : parsed->fragment,
        .server = parsed->host,
        .server_port = parsed->port,
        .protocol_config = std::move(config),
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] json yaml_to_json(const YAML::Node& node) {
    if (!node || node.IsNull()) {
        return nullptr;
    }
    if (node.IsScalar()) {
        return node.Scalar();
    }
    if (node.IsSequence()) {
        auto value = json::array();
        for (const auto& child : node) {
            value.push_back(yaml_to_json(child));
        }
        return value;
    }
    if (node.IsMap()) {
        auto value = json::object();
        for (const auto& entry : node) {
            if (entry.first.IsScalar()) {
                value[entry.first.Scalar()] = yaml_to_json(entry.second);
            }
        }
        return value;
    }
    return nullptr;
}

[[nodiscard]] std::optional<std::string> string_value(const json& value,
                                                      const char* field) {
    const auto found = value.find(field);
    if (found == value.end() || found->is_null()) {
        return std::nullopt;
    }
    if (found->is_string()) {
        return found->get<std::string>();
    }
    if (found->is_boolean()) {
        return found->get<bool>() ? "true" : "false";
    }
    if (found->is_number()) {
        return found->dump();
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::int64_t> integer_value(const json& value,
                                                        const char* field) {
    const auto found = value.find(field);
    if (found == value.end()) {
        return std::nullopt;
    }
    if (found->is_number_integer()) {
        return found->get<std::int64_t>();
    }
    if (found->is_string()) {
        std::int64_t parsed{};
        const auto& text = found->get_ref<const std::string&>();
        const auto [end, error] =
            std::from_chars(text.data(), text.data() + text.size(), parsed);
        if (error == std::errc{} && end == text.data() + text.size()) {
            return parsed;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool boolean_value(const json& value, const char* field) {
    const auto found = value.find(field);
    if (found == value.end()) {
        return false;
    }
    if (found->is_boolean()) {
        return found->get<bool>();
    }
    if (found->is_string()) {
        auto text = found->get<std::string>();
        std::ranges::transform(text, text.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return text == "true" || text == "1";
    }
    return false;
}

[[nodiscard]] std::optional<json> clash_transport(const json& proxy) {
    const auto network = string_value(proxy, "network").value_or("");
    if (network == "ws") {
        json transport{{"type", "ws"}};
        if (const auto options = proxy.find("ws-opts");
            options != proxy.end() && options->is_object()) {
            if (options->contains("path")) {
                transport["path"] = (*options)["path"];
            }
            if (options->contains("headers")) {
                transport["headers"] = (*options)["headers"];
            }
        } else if (const auto path = string_value(proxy, "ws-path"); path.has_value()) {
            transport["path"] = *path;
        }
        return transport;
    }
    if (network == "grpc") {
        json transport{{"type", "grpc"}};
        if (const auto options = proxy.find("grpc-opts");
            options != proxy.end() && options->is_object()) {
            if (const auto name = string_value(*options, "grpc-service-name");
                name.has_value()) {
                transport["service_name"] = *name;
            }
        }
        return transport;
    }
    if (network == "h2" || network == "http") {
        json transport{{"type", "http"}};
        const auto options = proxy.find(network == "h2" ? "h2-opts" : "http-opts");
        if (options != proxy.end() && options->is_object()) {
            if (options->contains("host")) {
                transport["host"] = (*options)["host"];
            }
            if (const auto path = options->find("path"); path != options->end()) {
                if (path->is_array() && !path->empty()) {
                    transport["path"] = path->front();
                } else if (path->is_string()) {
                    transport["path"] = *path;
                }
            }
        }
        return transport;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<json> clash_tls(const json& proxy, bool enabled) {
    if (!enabled) {
        return std::nullopt;
    }
    json tls{{"enabled", true}};
    auto sni = string_value(proxy, "sni");
    if (!sni.has_value() || sni->empty()) {
        sni = string_value(proxy, "servername");
    }
    if (sni.has_value() && !sni->empty()) {
        tls["server_name"] = *sni;
    }
    if (boolean_value(proxy, "skip-cert-verify")) {
        tls["insecure"] = true;
    }
    if (const auto alpn = proxy.find("alpn"); alpn != proxy.end()) {
        if (alpn->is_array()) {
            tls["alpn"] = *alpn;
        } else if (alpn->is_string()) {
            tls["alpn"] = json::array();
            std::string_view remaining{alpn->get_ref<const std::string&>()};
            while (!remaining.empty()) {
                const auto comma = remaining.find(',');
                tls["alpn"].push_back(trim(remaining.substr(0, comma)));
                if (comma == std::string_view::npos) {
                    break;
                }
                remaining.remove_prefix(comma + 1U);
            }
        }
    }
    if (const auto fingerprint = string_value(proxy, "client-fingerprint");
        fingerprint.has_value() && !fingerprint->empty()) {
        tls["utls"] = {{"enabled", true}, {"fingerprint", *fingerprint}};
    }
    if (const auto reality = proxy.find("reality-opts");
        reality != proxy.end() && reality->is_object()) {
        tls["reality"] = {{"enabled", true}};
        if (const auto key = string_value(*reality, "public-key"); key.has_value()) {
            tls["reality"]["public_key"] = *key;
        }
        if (const auto id = string_value(*reality, "short-id"); id.has_value()) {
            tls["reality"]["short_id"] = *id;
        }
        if (!tls.contains("utls")) {
            tls["utls"] = {{"enabled", true}, {"fingerprint", "chrome"}};
        }
    }
    return tls;
}

[[nodiscard]] std::string clash_type(std::string value) {
    if (value == "ss" || value == "shadowsocks") {
        return "shadowsocks";
    }
    if (value == "hy2") {
        return "hysteria2";
    }
    return value;
}

[[nodiscard]] std::optional<ParsedProxyNode> clash_proxy(const json& proxy) {
    if (!proxy.is_object()) {
        return std::nullopt;
    }
    auto type = clash_type(string_value(proxy, "type").value_or(""));
    const auto server = string_value(proxy, "server").value_or("");
    const auto raw_port = integer_value(proxy, "port").value_or(0);
    if (server.empty() || raw_port <= 0 || raw_port > 65'535) {
        return std::nullopt;
    }
    const auto port = static_cast<std::uint16_t>(raw_port);
    auto tag = string_value(proxy, "name").value_or("");
    if (tag.empty()) {
        tag = server + ":" + std::to_string(port);
    }

    json config;
    if (type == "shadowsocks") {
        config = {
            {"method", string_value(proxy, "cipher").value_or("")},
            {"password", string_value(proxy, "password").value_or("")},
        };
    } else if (type == "vmess") {
        config = {
            {"uuid", string_value(proxy, "uuid").value_or("")},
            {"alter_id", integer_value(proxy, "alterId")
                             .value_or(integer_value(proxy, "alterid").value_or(0))},
            {"security", string_value(proxy, "cipher").value_or("auto")},
        };
        if (const auto transport = clash_transport(proxy); transport.has_value()) {
            config["transport"] = *transport;
        }
        if (const auto tls = clash_tls(proxy, boolean_value(proxy, "tls"));
            tls.has_value()) {
            config["tls"] = *tls;
        }
    } else if (type == "vless") {
        config = {
            {"uuid", string_value(proxy, "uuid").value_or("")},
            {"flow", string_value(proxy, "flow").value_or("")},
            {"packet_encoding", "xudp"},
        };
        if (const auto transport = clash_transport(proxy); transport.has_value()) {
            config["transport"] = *transport;
        }
        const auto reality = proxy.contains("reality-opts");
        if (const auto tls = clash_tls(proxy, boolean_value(proxy, "tls") || reality);
            tls.has_value()) {
            config["tls"] = *tls;
        }
    } else if (type == "trojan") {
        config = {{"password", string_value(proxy, "password").value_or("")}};
        if (const auto transport = clash_transport(proxy); transport.has_value()) {
            config["transport"] = *transport;
        }
        config["tls"] = *clash_tls(proxy, true);
    } else if (type == "hysteria2") {
        auto password = string_value(proxy, "password").value_or("");
        if (password.empty()) {
            password = string_value(proxy, "auth").value_or("");
        }
        if (password.empty()) {
            password = string_value(proxy, "auth-str").value_or("");
        }
        config = {{"password", password}, {"tls", *clash_tls(proxy, true)}};
        if (const auto obfs = string_value(proxy, "obfs");
            obfs.has_value() && !obfs->empty()) {
            config["obfs"] = {{"type", *obfs}};
            if (const auto password_value = string_value(proxy, "obfs-password");
                password_value.has_value()) {
                config["obfs"]["password"] = *password_value;
            }
        }
    } else if (type == "tuic") {
        config = {
            {"uuid", string_value(proxy, "uuid").value_or("")},
            {"password", string_value(proxy, "password").value_or("")},
            {"congestion_control",
             string_value(proxy, "congestion-controller").value_or("bbr")},
            {"udp_relay_mode",
             string_value(proxy, "udp-relay-mode").value_or("native")},
            {"tls", *clash_tls(proxy, true)},
        };
    } else {
        return std::nullopt;
    }

    ParsedProxyNode node{
        .node_type = std::move(type),
        .tag = std::move(tag),
        .server = server,
        .server_port = port,
        .protocol_config = std::move(config),
    };
    return has_required_secret(node) ? std::optional{std::move(node)} : std::nullopt;
}

[[nodiscard]] bool likely_base64(std::string_view body) {
    const auto value = trim(body);
    return value.size() > 20U && value.find(' ') == std::string::npos &&
           value.find('\n') == std::string::npos &&
           std::ranges::all_of(value, [](unsigned char character) {
               return std::isalnum(character) != 0 || character == '+' ||
                      character == '/' || character == '-' || character == '_' ||
                      character == '=';
           });
}

[[nodiscard]] std::optional<std::uint16_t> outbound_port(const json& outbound) {
    const auto found = outbound.find("server_port");
    if (found == outbound.end()) {
        return std::nullopt;
    }
    if (found->is_number_unsigned()) {
        const auto value = found->get<std::uint64_t>();
        if (value > 0U && value <= 65'535U) {
            return static_cast<std::uint16_t>(value);
        }
    } else if (found->is_number_integer()) {
        const auto value = found->get<std::int64_t>();
        if (value > 0 && value <= 65'535) {
            return static_cast<std::uint16_t>(value);
        }
    } else if (found->is_string()) {
        return parse_port(found->get_ref<const std::string&>());
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<ParsedProxyNode> parse_outbound(const json& outbound) {
    if (!outbound.is_object() || !outbound.contains("type") ||
        !outbound["type"].is_string() || !outbound.contains("server") ||
        !outbound["server"].is_string()) {
        return std::nullopt;
    }
    const auto type = outbound["type"].get<std::string>();
    const auto server = outbound["server"].get<std::string>();
    const auto port = outbound_port(outbound);
    if (!port.has_value() || server.empty()) {
        return std::nullopt;
    }
    auto tag = outbound.value("tag", server);
    json config = json::object();
    if (type == "shadowsocks") {
        config["method"] = outbound.value("method", json{nullptr});
        config["password"] = outbound.value("password", json{nullptr});
    } else if (type == "vmess") {
        config["uuid"] = outbound.value("uuid", json{nullptr});
        config["alter_id"] = outbound.value("alter_id", json{0});
        config["security"] = outbound.value("security", json{"auto"});
    } else if (type == "vless") {
        config["uuid"] = outbound.value("uuid", json{nullptr});
        config["flow"] = outbound.value("flow", json{""});
        config["packet_encoding"] = outbound.value("packet_encoding", json{"xudp"});
    } else if (type == "trojan") {
        config["password"] = outbound.value("password", json{nullptr});
    } else if (type == "hysteria2") {
        config["password"] = outbound.value("password", json{nullptr});
        if (outbound.contains("obfs")) {
            config["obfs"] = outbound["obfs"];
        }
    } else if (type == "tuic") {
        config["uuid"] = outbound.value("uuid", json{nullptr});
        config["password"] = outbound.value("password", json{nullptr});
        if (outbound.contains("congestion_control")) {
            config["congestion_control"] = outbound["congestion_control"];
        }
        if (outbound.contains("udp_relay_mode")) {
            config["udp_relay_mode"] = outbound["udp_relay_mode"];
        }
    } else {
        return std::nullopt;
    }
    if (type != "shadowsocks") {
        if (outbound.contains("tls")) {
            config["tls"] = outbound["tls"];
        }
        if (outbound.contains("transport")) {
            config["transport"] = outbound["transport"];
        }
    }
    return ParsedProxyNode{
        .node_type = type,
        .tag = std::move(tag),
        .server = server,
        .server_port = *port,
        .protocol_config = std::move(config),
    };
}

} // namespace

std::string ParsedProxyNode::fingerprint() const {
    std::string key_material;
    if (node_type == "shadowsocks" || node_type == "trojan" ||
        node_type == "hysteria2") {
        key_material = protocol_config.value("password", "");
    } else if (node_type == "vmess" || node_type == "vless") {
        key_material = protocol_config.value("uuid", "");
    } else if (node_type == "tuic") {
        key_material = protocol_config.value("uuid", "") + ":" +
                       protocol_config.value("password", "");
    }
    const auto raw = server + ":" + std::to_string(server_port) + ":" + node_type +
                     ":" + key_material;

    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), raw.data(), raw.size()) != 1) {
        throw std::runtime_error("proxy fingerprint SHA-256 initialization failed");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size{};
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1) {
        throw std::runtime_error("proxy fingerprint SHA-256 failed");
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
}

std::optional<ParsedProxyNode> parse_proxy_uri(std::string_view uri) {
    const auto value = trim(uri);
    if (value.starts_with("ss://")) {
        return parse_shadowsocks(value);
    }
    if (value.starts_with("vmess://")) {
        return parse_vmess(value);
    }
    if (value.starts_with("trojan://")) {
        return parse_trojan(value);
    }
    if (value.starts_with("vless://")) {
        return parse_vless(value);
    }
    if (value.starts_with("hysteria2://") || value.starts_with("hy2://")) {
        return parse_hysteria2(value);
    }
    if (value.starts_with("tuic://")) {
        return parse_tuic(value);
    }
    return std::nullopt;
}

std::vector<ParsedProxyNode> parse_subscription_body(std::string_view body) {
    auto decoded = std::string{body};
    if (likely_base64(body)) {
        if (const auto value = decode_base64(trim(body)); value.has_value()) {
            decoded = *value;
        }
    }

    try {
        const auto yaml = YAML::Load(decoded);
        if (yaml.IsMap() && yaml["proxies"] && yaml["proxies"].IsSequence() &&
            yaml["proxies"].size() > 0U) {
            std::vector<ParsedProxyNode> nodes;
            nodes.reserve(yaml["proxies"].size());
            for (const auto& proxy : yaml["proxies"]) {
                if (auto node = clash_proxy(yaml_to_json(proxy)); node.has_value()) {
                    nodes.push_back(std::move(*node));
                }
            }
            return nodes;
        }
    } catch (const YAML::Exception&) {
    }

    std::vector<ParsedProxyNode> nodes;
    std::istringstream input{decoded};
    std::string line;
    while (std::getline(input, line)) {
        const auto value = trim(line);
        if (value.empty() || value.starts_with('#') || value.starts_with("//")) {
            continue;
        }
        if (auto node = parse_proxy_uri(value); node.has_value()) {
            nodes.push_back(std::move(*node));
        }
    }
    return nodes;
}

ProxyImport parse_outbound_config(const nlohmann::json& config) {
    const json* outbounds = nullptr;
    if (config.is_object() && config.contains("outbounds") &&
        config["outbounds"].is_array()) {
        outbounds = &config["outbounds"];
    } else if (config.is_array()) {
        outbounds = &config;
    }
    if (outbounds == nullptr) {
        return {};
    }

    static const std::array<std::string_view, 6> supported{
        "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic"};
    ProxyImport result;
    for (const auto& outbound : *outbounds) {
        const auto type = outbound.is_object() ? outbound.value("type", "") : "";
        if (std::ranges::find(supported, type) == supported.end()) {
            continue;
        }
        if (auto node = parse_outbound(outbound); node.has_value()) {
            result.nodes.push_back(std::move(*node));
        } else {
            result.skipped.push_back(outbound.value("tag", "?") + " (" + type + ")");
        }
    }
    return result;
}

} // namespace sbeasy
