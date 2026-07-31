#include "sbeasy/store.hpp"

#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sqlite3.h>

#include "sqlite_utils.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;

[[nodiscard]] ProfileMode parse_profile_mode(const std::string& value) {
    return value == "full" ? ProfileMode::full : ProfileMode::managed;
}

[[nodiscard]] const char* profile_mode_name(ProfileMode value) {
    return value == ProfileMode::full ? "full" : "managed";
}

[[nodiscard]] json parse_object(const std::string& value, const char* description) {
    auto parsed = json::parse(value, nullptr, false);
    if (!parsed.is_object()) {
        throw std::runtime_error(std::string{description} +
                                 " must contain a JSON object");
    }
    return parsed;
}

[[nodiscard]] ConfigProfile read_profile(sqlite::Statement& statement) {
    return ConfigProfile{
        .id = statement.text(0),
        .name = statement.text(1),
        .profile = parse_object(statement.text(2), "profile template"),
        .mode = parse_profile_mode(statement.text(3)),
        .rule_script = statement.text(4),
        .rule_script_enabled = statement.integer(5) != 0,
        .created_at = statement.text(6),
        .updated_at = statement.text(7),
    };
}

[[nodiscard]] std::string uuid_v4() {
    std::array<unsigned char, 16> bytes{};
    std::random_device random;
    for (auto& byte : bytes) {
        byte = static_cast<unsigned char>(random());
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);

    std::ostringstream value;
    value << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) {
            value << '-';
        }
        value << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    return value.str();
}

[[nodiscard]] std::string controller_address(std::optional<std::string> address) {
    if (!address.has_value() || address->empty()) {
        return "0.0.0.0:9090";
    }
    auto value = *address;
    if (value.starts_with("https://")) {
        value.erase(0, 8);
    } else if (value.starts_with("http://")) {
        value.erase(0, 7);
    }
    while (value.ends_with('/')) {
        value.pop_back();
    }
    return value;
}

[[nodiscard]] std::vector<ProxyNode>
read_nodes(sqlite3* database, const std::string& sql,
           const std::optional<std::string>& host_id) {
    sqlite::Statement statement{database, sql};
    if (host_id.has_value()) {
        statement.bind(1, *host_id);
    }

    std::vector<ProxyNode> nodes;
    while (statement.step_row()) {
        const auto server_port = statement.integer(5);
        if (server_port < 0 || server_port > 65'535) {
            throw std::runtime_error("proxy server_port is out of range for node " +
                                     statement.text(0));
        }
        nodes.push_back(ProxyNode{
            .id = statement.text(0),
            .tag = statement.text(1),
            .type = statement.text(2),
            .enabled = statement.integer(3) != 0,
            .server = statement.text(4),
            .server_port = static_cast<std::uint16_t>(server_port),
            .protocol_config = parse_object(statement.text(6), "proxy protocol_config"),
        });
    }
    return nodes;
}

} // namespace

void to_json(nlohmann::json& value, const ConfigProfile& profile) {
    value = nlohmann::json{
        {"id", profile.id},
        {"name", profile.name},
        {"template", profile.profile},
        {"mode", profile_mode_name(profile.mode)},
        {"rule_script", profile.rule_script},
        {"rule_script_enabled", profile.rule_script_enabled},
        {"created_at", profile.created_at},
        {"updated_at", profile.updated_at},
    };
}

Store::Store(const std::filesystem::path& database_path,
             const std::filesystem::path& migration_directory)
    : database_(database_path) {
    database_.migrate(migration_directory);
}

std::vector<ConfigProfile> Store::list_profiles() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT id, name, template, mode, rule_script, "
                                "rule_script_enabled, created_at, updated_at "
                                "FROM config_profiles ORDER BY name"};

    std::vector<ConfigProfile> profiles;
    while (statement.step_row()) {
        profiles.push_back(read_profile(statement));
    }
    return profiles;
}

std::optional<ConfigProfile> Store::find_profile(const std::string& id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT id, name, template, mode, rule_script, "
                                "rule_script_enabled, created_at, updated_at "
                                "FROM config_profiles WHERE id = ?1"};
    statement.bind(1, id);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_profile(statement);
}

ConfigProfile Store::create_profile(ConfigProfile profile) {
    if (profile.name.empty() || !profile.profile.is_object()) {
        throw std::invalid_argument("profile name and object template are required");
    }
    if (profile.id.empty()) {
        profile.id = uuid_v4();
    }

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{database_.handle_,
                                    "INSERT INTO config_profiles "
                                    "(id, name, template, mode, rule_script, "
                                    "rule_script_enabled, created_at, updated_at) "
                                    "VALUES (?1, ?2, ?3, ?4, ?5, ?6, "
                                    "datetime('now'), datetime('now'))"};
        statement.bind(1, profile.id);
        statement.bind(2, profile.name);
        statement.bind(3, profile.profile.dump());
        statement.bind(4, profile_mode_name(profile.mode));
        statement.bind(5, profile.rule_script);
        statement.bind(6, profile.rule_script_enabled);
        statement.step_done();
    }

    return *find_profile(profile.id);
}

ConfigProfile Store::update_profile(ConfigProfile profile) {
    if (profile.id.empty() || profile.name.empty() || !profile.profile.is_object()) {
        throw std::invalid_argument(
            "profile id, name, and object template are required");
    }

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{
            database_.handle_, "UPDATE config_profiles SET name = ?1, template = ?2, "
                               "mode = ?3, rule_script = ?4, rule_script_enabled = ?5, "
                               "updated_at = datetime('now') WHERE id = ?6"};
        statement.bind(1, profile.name);
        statement.bind(2, profile.profile.dump());
        statement.bind(3, profile_mode_name(profile.mode));
        statement.bind(4, profile.rule_script);
        statement.bind(5, profile.rule_script_enabled);
        statement.bind(6, profile.id);
        statement.step_done();
        if (sqlite3_changes(database_.handle_) == 0) {
            throw std::runtime_error("profile not found: " + profile.id);
        }
    }

    return *find_profile(profile.id);
}

RenderRequest Store::render_request_for_host(const std::string& host_id) const {
    const std::scoped_lock lock{database_.mutex_};

    sqlite::Statement host{database_.handle_,
                           "SELECT id, name, capabilities, profile_id, clash_api, "
                           "clash_secret FROM hosts WHERE id = ?1 AND enabled = 1"};
    host.bind(1, host_id);
    if (!host.step_row()) {
        throw std::runtime_error("host not found: " + host_id);
    }

    const auto profile_id = host.optional_text(3).value_or("default");
    sqlite::Statement profile_statement{database_.handle_,
                                        "SELECT id, name, template, mode, rule_script, "
                                        "rule_script_enabled, created_at, updated_at "
                                        "FROM config_profiles WHERE id = ?1"};
    profile_statement.bind(1, profile_id);
    if (!profile_statement.step_row()) {
        throw std::runtime_error("host profile not found: " + profile_id);
    }
    const auto profile = read_profile(profile_statement);

    std::vector<ProxyNode> nodes;
    if (profile.mode == ProfileMode::managed) {
        nodes = read_nodes(database_.handle_,
                           "SELECT p.id, p.tag, p.node_type, p.enabled, p.server, "
                           "p.server_port, p.protocol_config FROM proxy_nodes p "
                           "JOIN host_outbounds h ON h.node_id = p.id "
                           "WHERE h.host_id = ?1 AND p.enabled = 1 "
                           "ORDER BY p.node_type, p.tag",
                           host_id);
        if (nodes.empty()) {
            nodes =
                read_nodes(database_.handle_,
                           "SELECT id, tag, node_type, enabled, server, server_port, "
                           "protocol_config FROM proxy_nodes WHERE enabled = 1 "
                           "ORDER BY node_type, tag",
                           std::nullopt);
        }
    }

    RenderRequest request{
        .mode = profile.mode,
        .profile = profile.profile,
        .nodes = std::move(nodes),
        .host_context =
            {
                {"id", host.text(0)},
                {"name", host.text(1)},
                {"capabilities", parse_object(host.text(2), "host capabilities")},
            },
        .external_route_tags = {},
        .rule_script = std::nullopt,
        .clash_controller = controller_address(host.optional_text(4)),
        .clash_secret = host.text(5),
    };
    if (profile.rule_script_enabled && !profile.rule_script.empty()) {
        request.rule_script = profile.rule_script;
    }

    if (request.profile.contains("endpoints") &&
        request.profile["endpoints"].is_array()) {
        for (const auto& endpoint : request.profile["endpoints"]) {
            if (endpoint.contains("tag") && endpoint["tag"].is_string()) {
                request.external_route_tags.push_back(
                    endpoint["tag"].get<std::string>());
            }
        }
    }
    return request;
}

} // namespace sbeasy
