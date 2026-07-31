#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sbeasy {

struct AgentConfigTransformOptions {
    bool local_proxy_egress{true};
    std::map<std::string, std::string> outbound_server_overrides;
    std::map<std::string, nlohmann::json> outbound_overrides;
    std::optional<std::string> default_proxy_outbound;
};

/// Apply node-local adjustments to a panel-rendered sing-box configuration.
///
/// The transformation mirrors the legacy Rust agent mode: proxy transports use
/// the node's own egress instead of the management WireGuard detour, optional
/// node-specific outbound replacements are applied, and proxy DNS is injected
/// for OpenAI domains.
[[nodiscard]] std::string
prepare_agent_config(std::string_view body, const AgentConfigTransformOptions& options);

} // namespace sbeasy
