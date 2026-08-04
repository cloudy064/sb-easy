#include "sbeasy/config_renderer.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
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

[[nodiscard]] std::string url_host(std::string value) {
    const auto scheme = value.find("://");
    if (scheme != std::string::npos) {
        value.erase(0, scheme + 3U);
    }
    if (const auto path = value.find_first_of("/?#"); path != std::string::npos) {
        value.erase(path);
    }
    if (value.starts_with('[')) {
        const auto closing = value.find(']');
        return closing == std::string::npos ? std::string{} :
                                             value.substr(1, closing - 1U);
    }
    if (const auto colon = value.rfind(':');
        colon != std::string::npos && value.find(':') == colon) {
        value.erase(colon);
    }
    return value;
}

[[nodiscard]] json control_plane_route(const std::string& server) {
    const auto host = url_host(server);
    if (host.empty()) {
        return nullptr;
    }
    in_addr ipv4{};
    if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        return {{"ip_cidr", json::array({host + "/32"})},
                {"outbound", "direct"}};
    }
    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        return {{"ip_cidr", json::array({host + "/128"})},
                {"outbound", "direct"}};
    }
    return {{"domain", json::array({host})}, {"outbound", "direct"}};
}

void normalize_managed_dns_detours(
    json& config, bool has_auto,
    const std::optional<std::string>& android_selector) {
    if (!config.contains("dns") || !config["dns"].is_object()) {
        return;
    }
    auto& servers = config["dns"]["servers"];
    if (!servers.is_array()) {
        return;
    }
    const auto target = !has_auto ? std::string{"direct"} :
                                    android_selector.value_or("auto");
    for (auto& server : servers) {
        if (!server.is_object() || !server.contains("detour") ||
            !server["detour"].is_string()) {
            continue;
        }
        const auto detour = server["detour"].get<std::string>();
        if (detour == "Proxy" || detour == "Auto") {
            server["detour"] = target;
        }
    }
}

constexpr std::string_view meta_rules_base{
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/"};

[[nodiscard]] bool rule_set_tag_matches(const json& value,
                                        std::string_view tag) {
    if (value.is_string()) {
        return value.get_ref<const std::string&>() == tag;
    }
    if (!value.is_array()) {
        return false;
    }
    return std::ranges::any_of(value, [tag](const json& item) {
        return item.is_string() && item.get_ref<const std::string&>() == tag;
    });
}

[[nodiscard]] bool has_rule_for_set(const json& rules, std::string_view tag) {
    if (!rules.is_array()) {
        return false;
    }
    return std::ranges::any_of(rules, [tag](const json& rule) {
        const auto found = rule.is_object() ? rule.find("rule_set") : rule.end();
        return found != rule.end() && rule_set_tag_matches(*found, tag);
    });
}

[[nodiscard]] bool has_private_ip_rule(const json& rules) {
    if (!rules.is_array()) {
        return false;
    }
    return std::ranges::any_of(rules, [](const json& rule) {
        return rule.is_object() && rule.value("ip_is_private", false);
    });
}

void add_remote_rule_set(json& rule_sets, std::string tag,
                         std::string relative_url) {
    const bool exists = std::ranges::any_of(rule_sets, [&tag](const json& item) {
        return item.is_object() && item.value("tag", "") == tag;
    });
    if (exists) {
        return;
    }
    rule_sets.push_back({
        {"type", "remote"},
        {"tag", std::move(tag)},
        {"format", "binary"},
        {"url", std::string{meta_rules_base} + std::move(relative_url)},
        {"download_detour", "direct"},
        {"update_interval", "7d"},
    });
}

void inject_managed_geo_policy(json& config) {
    auto& route = config["route"];
    if (route.is_null()) {
        route = json::object();
    }
    if (!route.is_object()) {
        throw std::invalid_argument("managed route must be a JSON object");
    }
    auto& rules = route["rules"];
    if (rules.is_null()) {
        rules = json::array();
    }
    if (!rules.is_array()) {
        throw std::invalid_argument("managed route rules must be an array");
    }
    auto& rule_sets = route["rule_set"];
    if (rule_sets.is_null()) {
        rule_sets = json::array();
    }
    if (!rule_sets.is_array()) {
        throw std::invalid_argument("managed route rule_set must be an array");
    }

    add_remote_rule_set(rule_sets, "geosite-private", "geosite/private.srs");
    add_remote_rule_set(rule_sets, "geosite-cn", "geosite/cn.srs");
    add_remote_rule_set(rule_sets, "geoip-cn", "geoip/cn.srs");

    // Explicit Profile / QuickJS rules are already at the front of the list.
    // Append the managed defaults so users can still override any destination.
    if (!has_rule_for_set(rules, "geosite-private")) {
        rules.push_back({{"rule_set", json::array({"geosite-private"})},
                         {"outbound", "direct"}});
    }
    if (!has_private_ip_rule(rules)) {
        rules.push_back({{"ip_is_private", true}, {"outbound", "direct"}});
    }
    if (!has_rule_for_set(rules, "geosite-cn")) {
        rules.push_back({{"rule_set", json::array({"geosite-cn"})},
                         {"outbound", "direct"}});
    }
    if (!has_rule_for_set(rules, "geoip-cn")) {
        rules.push_back({{"rule_set", json::array({"geoip-cn"})},
                         {"outbound", "direct"}});
    }

    auto& experimental = config["experimental"];
    if (experimental.is_null()) {
        experimental = json::object();
    }
    if (experimental.is_object()) {
        auto& cache = experimental["cache_file"];
        if (cache.is_null()) {
            cache = json::object();
        }
        if (cache.is_object()) {
            cache["enabled"] = true;
        }
    }
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
            // libbox requires the test interval to be no greater than the idle
            // timeout. Keep both long so mobile clients still effectively test
            // once at startup without waking up for frequent background tests.
            {"idle_timeout", "24h"},
        });
    }
    return outbounds;
}

nlohmann::json ConfigRenderer::render(const RenderRequest& request) const {
    if (!request.profile.is_object()) {
        throw std::invalid_argument("profile template must be a JSON object");
    }

    json config = request.profile;
    bool managed_has_proxy = false;
    if (request.mode == ProfileMode::managed) {
        auto outbounds = generate_outbounds(request.nodes);
        const bool has_auto = std::ranges::any_of(outbounds, [](const auto& outbound) {
            return outbound.value("tag", "") == "auto";
        });
        managed_has_proxy = has_auto;
        const auto capabilities =
            request.host_context.value("capabilities", json::object());
        const bool is_android = capabilities.is_object() &&
                                capabilities.value("platform", "") == "android";
        const bool has_direct =
            std::ranges::any_of(outbounds, [](const auto& outbound) {
                return outbound.value("tag", "") == "direct";
            });
        if (!has_direct) {
            outbounds.push_back({{"type", "direct"}, {"tag", "direct"}});
        }
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
        config["outbounds"] = std::move(outbounds);
        normalize_managed_dns_detours(config, has_auto, android_selector);

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

    if (managed_has_proxy) {
        inject_managed_geo_policy(config);
    }

    auto protected_rules = json::array();
    const auto control_rule = control_plane_route(request.control_plane_server);
    if (!control_rule.is_null()) {
        protected_rules.push_back(control_rule);
    }
    if (request.priority_route_rules.is_array()) {
        protected_rules.insert(protected_rules.end(),
                               request.priority_route_rules.begin(),
                               request.priority_route_rules.end());
    }
    if (!protected_rules.empty()) {
        if (!config.contains("route") || !config["route"].is_object()) {
            config["route"] = json::object();
        }
        auto& rules = config["route"]["rules"];
        if (!rules.is_array()) {
            rules = json::array();
        }
        rules.insert(rules.begin(), protected_rules.begin(),
                     protected_rules.end());
    }

    // These fields remain under server control even when scripting is enabled.
    inject_clash_api(config, request.clash_controller, request.clash_secret);
    disable_clash_dashboard(config);
    return config;
}

} // namespace sbeasy
