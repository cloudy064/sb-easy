#pragma once

#include <filesystem>
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

/// Serializes the node-local transform settings used by the Agent UI.
[[nodiscard]] nlohmann::json
agent_config_transform_options_to_json(const AgentConfigTransformOptions& options);

/// Applies a JSON settings object over the supplied defaults and validates every
/// supported value.
[[nodiscard]] AgentConfigTransformOptions agent_config_transform_options_from_json(
    const nlohmann::json& value, const AgentConfigTransformOptions& defaults = {});

/// Loads persisted settings, returning the supplied defaults when the file does
/// not exist.
[[nodiscard]] AgentConfigTransformOptions
load_agent_config_transform_options(const std::filesystem::path& path,
                                    const AgentConfigTransformOptions& defaults = {});

/// Persists a complete settings object using an atomic replacement.
void save_agent_config_transform_options(const std::filesystem::path& path,
                                         const AgentConfigTransformOptions& options);

} // namespace sbeasy
