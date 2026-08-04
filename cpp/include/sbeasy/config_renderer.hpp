#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/script_engine.hpp"

namespace sbeasy {

struct ProxyNode {
    std::string id;
    std::string tag;
    std::string type;
    bool enabled{true};
    std::string server;
    std::uint16_t server_port{};
    nlohmann::json protocol_config = nlohmann::json::object();
};

void from_json(const nlohmann::json& value, ProxyNode& node);
void to_json(nlohmann::json& value, const ProxyNode& node);

enum class ProfileMode {
    managed,
    full,
};

struct RenderRequest {
    ProfileMode mode{ProfileMode::managed};
    nlohmann::json profile = nlohmann::json::object();
    std::vector<ProxyNode> nodes;
    nlohmann::json host_context = nlohmann::json::object();
    std::vector<std::string> external_route_tags;
    // Server-owned routes that must survive user profile and QuickJS rule
    // replacement, such as the managed sb-easy private network endpoint.
    nlohmann::json priority_route_rules = nlohmann::json::array();
    // Public control-plane URL used by managed clients. It is routed directly
    // so configuration sync and diagnostics do not depend on a working proxy.
    std::string control_plane_server;
    std::optional<std::string> rule_script;
    std::string clash_controller;
    std::string clash_secret;
};

class ConfigRenderer final {
  public:
    explicit ConfigRenderer(ScriptLimits limits = {});

    [[nodiscard]] nlohmann::json render(const RenderRequest& request) const;
    [[nodiscard]] static nlohmann::json generate_outbound(const ProxyNode& node);
    [[nodiscard]] static nlohmann::json
    generate_outbounds(const std::vector<ProxyNode>& nodes);

  private:
    RuleScriptEngine scripts_;
};

} // namespace sbeasy
