#include "sbeasy/agent_config.hpp"

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include "sbeasy/atomic_file.hpp"

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

[[nodiscard]] std::map<std::string, std::string>
server_overrides_from_json(const json& value) {
    if (!value.is_object()) {
        throw std::invalid_argument("outbound_server_overrides must be a JSON object");
    }
    std::map<std::string, std::string> overrides;
    for (const auto& [tag, server] : value.items()) {
        if (tag.empty() || !server.is_string() ||
            server.get_ref<const std::string&>().empty()) {
            throw std::invalid_argument(
                "outbound_server_overrides values must be non-empty strings");
        }
        overrides.emplace(tag, server.get<std::string>());
    }
    return overrides;
}

[[nodiscard]] std::map<std::string, json>
outbound_overrides_from_json(const json& value) {
    if (!value.is_object()) {
        throw std::invalid_argument("outbound_overrides must be a JSON object");
    }
    std::map<std::string, json> overrides;
    for (const auto& [tag, outbound] : value.items()) {
        if (tag.empty() || !outbound.is_object()) {
            throw std::invalid_argument(
                "outbound_overrides values must be JSON objects");
        }
        overrides.emplace(tag, outbound);
    }
    return overrides;
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

nlohmann::json
agent_config_transform_options_to_json(const AgentConfigTransformOptions& options) {
    json server_overrides = json::object();
    for (const auto& [tag, server] : options.outbound_server_overrides) {
        server_overrides[tag] = server;
    }
    json outbound_overrides = json::object();
    for (const auto& [tag, outbound] : options.outbound_overrides) {
        outbound_overrides[tag] = outbound;
    }
    return {
        {"local_proxy_egress", options.local_proxy_egress},
        {"default_proxy_outbound", options.default_proxy_outbound.has_value()
                                       ? json(*options.default_proxy_outbound)
                                       : json(nullptr)},
        {"outbound_server_overrides", std::move(server_overrides)},
        {"outbound_overrides", std::move(outbound_overrides)},
    };
}

AgentConfigTransformOptions
agent_config_transform_options_from_json(const nlohmann::json& value,
                                         const AgentConfigTransformOptions& defaults) {
    if (!value.is_object()) {
        throw std::invalid_argument("agent settings must be a JSON object");
    }
    auto options = defaults;
    if (const auto found = value.find("local_proxy_egress"); found != value.end()) {
        if (!found->is_boolean()) {
            throw std::invalid_argument("local_proxy_egress must be a boolean");
        }
        options.local_proxy_egress = found->get<bool>();
    }
    if (const auto found = value.find("default_proxy_outbound"); found != value.end()) {
        if (found->is_null()) {
            options.default_proxy_outbound.reset();
        } else if (found->is_string()) {
            auto selected = found->get<std::string>();
            if (selected.empty()) {
                options.default_proxy_outbound.reset();
            } else {
                options.default_proxy_outbound = std::move(selected);
            }
        } else {
            throw std::invalid_argument(
                "default_proxy_outbound must be a string or null");
        }
    }
    if (const auto found = value.find("outbound_server_overrides");
        found != value.end()) {
        options.outbound_server_overrides = server_overrides_from_json(*found);
    }
    if (const auto found = value.find("outbound_overrides"); found != value.end()) {
        options.outbound_overrides = outbound_overrides_from_json(*found);
    }
    return options;
}

AgentConfigTransformOptions
load_agent_config_transform_options(const std::filesystem::path& path,
                                    const AgentConfigTransformOptions& defaults) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        if (!std::filesystem::exists(path)) {
            return defaults;
        }
        throw std::runtime_error("cannot read agent settings: " + path.string());
    }
    try {
        return agent_config_transform_options_from_json(json::parse(input), defaults);
    } catch (const std::exception& error) {
        throw std::invalid_argument("invalid agent settings " + path.string() + ": " +
                                    error.what());
    }
}

void save_agent_config_transform_options(const std::filesystem::path& path,
                                         const AgentConfigTransformOptions& options) {
    atomic_replace_file(path,
                        agent_config_transform_options_to_json(options).dump(2) + '\n');
}

} // namespace sbeasy
