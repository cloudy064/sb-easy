#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct ParsedProxyNode {
    std::string node_type;
    std::string tag;
    std::string server;
    std::uint16_t server_port{};
    nlohmann::json protocol_config = nlohmann::json::object();

    [[nodiscard]] std::string fingerprint() const;
};

struct ProxyImport {
    std::vector<ParsedProxyNode> nodes;
    std::vector<std::string> skipped;
};

/// Parse one supported proxy URI:
/// ss, vmess, trojan, vless, hysteria2/hy2, or tuic.
[[nodiscard]] std::optional<ParsedProxyNode> parse_proxy_uri(std::string_view uri);

/// Parse a subscription response as Clash YAML, a base64-encoded URI list, or
/// a plain newline-separated URI list.
[[nodiscard]] std::vector<ParsedProxyNode>
parse_subscription_body(std::string_view body);

/// Parse proxy outbounds from a complete sing-box config or a bare outbounds
/// array. Selector/urltest and built-in outbounds are ignored.
[[nodiscard]] ProxyImport parse_outbound_config(const nlohmann::json& config);

} // namespace sbeasy
