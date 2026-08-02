#include "sbeasy/config_renderer.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace sbeasy {
namespace {

using nlohmann::json;

[[nodiscard]] json value_or_null(const json& value, const char* key) {
    const auto found = value.find(key);
    return found == value.end() ? json(nullptr) : *found;
}

void copy_if_present(json& destination, const json& source, const char* key) {
    const auto found = source.find(key);
    if (found != source.end()) {
        destination[key] = *found;
    }
}

[[nodiscard]] std::string string_or(const json& value, const char* key,
                                    std::string fallback) {
    const auto found = value.find(key);
    if (found == value.end() || !found->is_string()) {
        return fallback;
    }
    return found->get<std::string>();
}

void validate_rule_tags(const json& rules, const std::set<std::string>& allowed) {
    for (const auto& rule : rules) {
        const auto outbound = rule.find("outbound");
        if (outbound != rule.end() && outbound->is_string()) {
            const auto tag = outbound->get<std::string>();
            if (!allowed.contains(tag)) {
                throw ScriptError("generated rule references unknown outbound tag: " +
                                  tag);
            }
        }
        const auto nested = rule.find("rules");
        if (nested != rule.end() && nested->is_array()) {
            validate_rule_tags(*nested, allowed);
        }
    }
}

void inject_clash_api(json& config, const std::string& controller,
                      const std::string& secret) {
    if (controller.empty() || !config.is_object()) {
        return;
    }
    if (config.contains("experimental") && config["experimental"].is_object() &&
        config["experimental"].contains("clash_api")) {
        return;
    }

    auto& experimental = config["experimental"];
    if (experimental.is_null()) {
        experimental = json::object();
    }
    if (!experimental.is_object()) {
        return;
    }

    json clash_api{{"external_controller", controller}};
    if (!secret.empty()) {
        clash_api["secret"] = secret;
    }
    experimental["clash_api"] = std::move(clash_api);
}

void disable_clash_dashboard(json& config) {
    if (!config.contains("experimental") || !config["experimental"].is_object() ||
        !config["experimental"].contains("clash_api") ||
        !config["experimental"]["clash_api"].is_object()) {
        return;
    }
    auto& api = config["experimental"]["clash_api"];
    api.erase("external_ui");
    api.erase("external_ui_download_url");
    api.erase("external_ui_download_detour");
}

} // namespace

void from_json(const nlohmann::json& value, ProxyNode& node) {
    value.at("tag").get_to(node.tag);
    node.id = value.value("id", node.tag);
    node.type = value.value("type", value.value("node_type", ""));
    node.enabled = value.value("enabled", true);
    node.server = value.value("server", "");

    const auto raw_port = value.value("server_port", 0);
    if (raw_port < 0 || raw_port > 65535) {
        throw std::invalid_argument("proxy server_port is out of range");
    }
    node.server_port = static_cast<std::uint16_t>(raw_port);
    node.protocol_config = value.value("protocol_config", nlohmann::json::object());
    if (node.protocol_config.is_string()) {
        node.protocol_config =
            nlohmann::json::parse(node.protocol_config.get<std::string>());
    }
    if (!node.protocol_config.is_object()) {
        node.protocol_config = nlohmann::json::object();
    }
}

void to_json(nlohmann::json& value, const ProxyNode& node) {
    value = nlohmann::json{
        {"id", node.id},
        {"tag", node.tag},
        {"type", node.type},
        {"enabled", node.enabled},
        {"server", node.server},
        {"server_port", node.server_port},
        {"protocol_config", node.protocol_config},
    };
}

ConfigRenderer::ConfigRenderer(ScriptLimits limits) : scripts_(limits) {}

nlohmann::json ConfigRenderer::generate_outbound(const ProxyNode& node) {
    const auto& config = node.protocol_config;
    json outbound;

    if (node.type == "shadowsocks") {
        outbound = {
            {"type", "shadowsocks"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"method", value_or_null(config, "method")},
            {"password", value_or_null(config, "password")},
        };
    } else if (node.type == "vmess") {
        outbound = {
            {"type", "vmess"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"uuid", value_or_null(config, "uuid")},
            {"alter_id", config.value("alter_id", 0)},
            {"security", string_or(config, "security", "auto")},
        };
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (node.type == "trojan") {
        outbound = {
            {"type", "trojan"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"password", value_or_null(config, "password")},
        };
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (node.type == "vless") {
        outbound = {
            {"type", "vless"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"uuid", value_or_null(config, "uuid")},
            {"flow", string_or(config, "flow", "")},
            {"packet_encoding", string_or(config, "packet_encoding", "xudp")},
        };
        copy_if_present(outbound, config, "transport");
        copy_if_present(outbound, config, "tls");
    } else if (node.type == "hysteria2") {
        outbound = {
            {"type", "hysteria2"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"password", value_or_null(config, "password")},
        };
        copy_if_present(outbound, config, "tls");
        copy_if_present(outbound, config, "obfs");
    } else if (node.type == "tuic") {
        outbound = {
            {"type", "tuic"},
            {"tag", node.tag},
            {"server", node.server},
            {"server_port", node.server_port},
            {"uuid", value_or_null(config, "uuid")},
            {"password", value_or_null(config, "password")},
            {"congestion_control", string_or(config, "congestion_control", "bbr")},
            {"udp_relay_mode", string_or(config, "udp_relay_mode", "native")},
        };
        copy_if_present(outbound, config, "tls");
    } else {
        outbound = {{"type", "direct"}, {"tag", node.tag}};
    }

    return outbound;
}

nlohmann::json ConfigRenderer::generate_outbounds(const std::vector<ProxyNode>& nodes) {
    std::map<std::string, unsigned int> seen;
    json outbounds = json::array();
    json auto_tags = json::array();

    for (const auto& node : nodes) {
        if (!node.enabled) {
            continue;
        }
        auto outbound = generate_outbound(node);
        auto& occurrence = seen[node.tag];
        ++occurrence;
        const auto tag =
            occurrence == 1 ? node.tag : node.tag + " #" + std::to_string(occurrence);
        outbound["tag"] = tag;
        auto_tags.push_back(tag);
        outbounds.push_back(std::move(outbound));
    }

    if (!auto_tags.empty()) {
        outbounds.push_back({
            {"type", "urltest"},
            {"tag", "auto"},
            {"outbounds", std::move(auto_tags)},
            {"url", "https://www.gstatic.com/generate_204"},
            {"interval", "24h"},
        });
    }
    return outbounds;
}

nlohmann::json ConfigRenderer::render(const RenderRequest& request) const {
    if (!request.profile.is_object()) {
        throw std::invalid_argument("profile template must be a JSON object");
    }

    json config = request.profile;
    if (request.mode == ProfileMode::managed) {
        auto outbounds = generate_outbounds(request.nodes);
        const bool has_auto = std::ranges::any_of(outbounds, [](const auto& outbound) {
            return outbound.value("tag", "") == "auto";
        });
        const auto capabilities =
            request.host_context.value("capabilities", json::object());
        const bool is_android = capabilities.is_object() &&
                                capabilities.value("platform", "") == "android";
        std::optional<std::string> android_selector;
        if (has_auto && is_android) {
            auto selector_tag = std::string{"Proxy"};
            while (std::ranges::any_of(outbounds, [&selector_tag](const auto& outbound) {
                return outbound.value("tag", "") == selector_tag;
            })) {
                selector_tag += " group";
            }
            json selector_outbounds = json::array({"auto"});
            for (const auto& outbound : outbounds) {
                const auto tag = outbound.value("tag", "");
                if (!tag.empty() && tag != "auto") {
                    selector_outbounds.push_back(tag);
                }
            }
            outbounds.push_back({
                {"type", "selector"},
                {"tag", selector_tag},
                {"outbounds", std::move(selector_outbounds)},
                {"default", "auto"},
            });
            android_selector = std::move(selector_tag);
        }
        if (!has_auto) {
            outbounds.push_back({{"type", "direct"}, {"tag", "direct"}});
        }
        config["outbounds"] = std::move(outbounds);

        if (config.contains("route") && config["route"].is_object()) {
            auto& route = config["route"];
            if (route.contains("final") && route["final"].is_string()) {
                const auto current = route["final"].get<std::string>();
                if (!has_auto) {
                    route["final"] = "direct";
                } else if (android_selector.has_value() &&
                           (current == "Proxy" || current == "Auto" ||
                            current == "auto")) {
                    route["final"] = *android_selector;
                } else if (current == "Proxy" || current == "Auto") {
                    route["final"] = "auto";
                }
            }
        }
    }

    if (request.rule_script.has_value() && !request.rule_script->empty()) {
        if (!config.contains("route") || !config["route"].is_object()) {
            config["route"] = json::object();
        }

        std::set<std::string> allowed{
            "direct",
            "block",
            "dns",
            "reject",
        };
        if (config.contains("outbounds") && config["outbounds"].is_array()) {
            for (const auto& outbound : config["outbounds"]) {
                if (outbound.contains("tag") && outbound["tag"].is_string()) {
                    allowed.insert(outbound["tag"].get<std::string>());
                }
            }
        }
        allowed.insert(request.external_route_tags.begin(),
                       request.external_route_tags.end());

        json context{
            {"host", request.host_context},
            {"outboundTags", json::array()},
            {"currentRules", config["route"].value("rules", json::array())},
        };
        for (const auto& tag : allowed) {
            context["outboundTags"].push_back(tag);
        }

        auto rules = scripts_.build_rules(*request.rule_script, context);
        validate_rule_tags(rules, allowed);
        config["route"]["rules"] = std::move(rules);
    }

    // These fields remain under server control even when scripting is enabled.
    inject_clash_api(config, request.clash_controller, request.clash_secret);
    disable_clash_dashboard(config);
    return config;
}

} // namespace sbeasy
