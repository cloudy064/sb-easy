#include "sbeasy/agent_config.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>

namespace sbeasy {
namespace {

using json = nlohmann::json;

void rewrite_tag_references(json& value,
                            const std::map<std::string, std::string>& renames) {
    if (value.is_string()) {
        const auto found = renames.find(value.get_ref<const std::string&>());
        if (found != renames.end()) {
            value = found->second;
        }
        return;
    }
    if (value.is_array()) {
        for (auto& child : value) {
            rewrite_tag_references(child, renames);
        }
        return;
    }
    if (value.is_object()) {
        for (auto& [key, child] : value.items()) {
            static_cast<void>(key);
            rewrite_tag_references(child, renames);
        }
    }
}

[[nodiscard]] bool is_builtin_route(std::string_view tag) {
    return tag == "direct" || tag == "block" || tag == "wg-internal";
}

} // namespace

std::string prepare_agent_config(std::string_view body,
                                 const AgentConfigTransformOptions& options) {
    if (!options.local_proxy_egress) {
        return std::string{body};
    }

    auto config = json::parse(body);
    std::optional<std::string> original_route_final;
    if (const auto* route = config.contains("route") ? &config.at("route") : nullptr;
        route != nullptr && route->is_object()) {
        const auto found = route->find("final");
        if (found != route->end() && found->is_string()) {
            original_route_final = found->get<std::string>();
        }
    }

    std::size_t changes = 0U;
    std::map<std::string, std::string> renamed_outbounds;
    const auto outbounds = config.find("outbounds");
    if (outbounds != config.end() && outbounds->is_array()) {
        for (auto& outbound : *outbounds) {
            if (!outbound.is_object()) {
                continue;
            }
            const auto tag_value = outbound.find("tag");
            if (tag_value == outbound.end() || !tag_value->is_string()) {
                continue;
            }
            const auto original_tag = tag_value->get<std::string>();
            if (const auto replacement = options.outbound_overrides.find(original_tag);
                replacement != options.outbound_overrides.end()) {
                if (!replacement->second.is_object()) {
                    throw std::invalid_argument("outbound override for " +
                                                original_tag +
                                                " must be a JSON object");
                }
                outbound = replacement->second;
                ++changes;
            }

            auto effective_tag = original_tag;
            if (const auto replacement_tag = outbound.find("tag");
                replacement_tag != outbound.end() && replacement_tag->is_string()) {
                effective_tag = replacement_tag->get<std::string>();
            }
            if (effective_tag != original_tag) {
                renamed_outbounds.emplace(original_tag, effective_tag);
            }
            outbound["tag"] = effective_tag;

            if (const auto detour = outbound.find("detour"); detour != outbound.end() &&
                                                             detour->is_string() &&
                                                             *detour == "wg-internal") {
                outbound.erase(detour);
                ++changes;
            }
            if (const auto server =
                    options.outbound_server_overrides.find(original_tag);
                server != options.outbound_server_overrides.end()) {
                if (!outbound.contains("server") ||
                    outbound.at("server") != server->second) {
                    outbound["server"] = server->second;
                    ++changes;
                }
            }

            if (options.default_proxy_outbound.has_value() &&
                original_route_final == original_tag &&
                outbound.value("type", std::string{}) == "selector") {
                const auto choices = outbound.find("outbounds");
                bool allowed = false;
                if (choices != outbound.end() && choices->is_array()) {
                    for (const auto& choice : *choices) {
                        if (choice.is_string() &&
                            choice == *options.default_proxy_outbound) {
                            allowed = true;
                            break;
                        }
                    }
                }
                if (!allowed) {
                    throw std::invalid_argument("default proxy outbound " +
                                                *options.default_proxy_outbound +
                                                " is not in selector " + original_tag);
                }
                if (!outbound.contains("default") ||
                    outbound.at("default") != *options.default_proxy_outbound) {
                    outbound["default"] = *options.default_proxy_outbound;
                    ++changes;
                }
            }
        }
    }

    if (!renamed_outbounds.empty()) {
        rewrite_tag_references(config, renamed_outbounds);
        ++changes;
    }

    auto dns = config.find("dns");
    if (dns != config.end() && dns->is_object()) {
        auto servers = dns->find("servers");
        if (servers != dns->end() && servers->is_array()) {
            for (auto& server : *servers) {
                if (!server.is_object()) {
                    continue;
                }
                const auto detour = server.find("detour");
                if (detour != server.end() && detour->is_string() &&
                    *detour == "wg-internal") {
                    server.erase(detour);
                    ++changes;
                }
            }
        }
    }

    std::optional<std::string> proxy_detour;
    const auto route = config.find("route");
    if (route != config.end() && route->is_object()) {
        const auto final = route->find("final");
        if (final != route->end() && final->is_string() &&
            !is_builtin_route(final->get_ref<const std::string&>())) {
            proxy_detour = final->get<std::string>();
        }
    }
    if (proxy_detour.has_value() && dns != config.end() && dns->is_object()) {
        auto servers = dns->find("servers");
        if (servers != dns->end() && servers->is_array()) {
            bool present = false;
            for (const auto& server : *servers) {
                if (server.is_object() &&
                    server.value("tag", std::string{}) == "proxy-dns") {
                    present = true;
                    break;
                }
            }
            if (!present) {
                servers->push_back({
                    {"type", "https"},
                    {"tag", "proxy-dns"},
                    {"server", "1.1.1.1"},
                    {"server_port", 443},
                    {"path", "/dns-query"},
                    {"tls", {{"enabled", true}, {"server_name", "cloudflare-dns.com"}}},
                    {"detour", *proxy_detour},
                });
                ++changes;
            }
        }

        auto rules = dns->find("rules");
        if (rules != dns->end() && rules->is_array()) {
            bool present = false;
            for (const auto& rule : *rules) {
                if (rule.is_object() &&
                    rule.value("server", std::string{}) == "proxy-dns") {
                    present = true;
                    break;
                }
            }
            if (!present) {
                const json rule{
                    {"domain_suffix",
                     json::array({"chatgpt.com", "openai.com", "oaistatic.com",
                                  "oaiusercontent.com"})},
                    {"server", "proxy-dns"},
                };
                rules->insert(rules->begin(), rule);
                ++changes;
            }
        }
    }

    return changes == 0U ? std::string{body} : config.dump(2);
}

} // namespace sbeasy
