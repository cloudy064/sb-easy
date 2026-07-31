#include "sbeasy/store.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/rand.h>
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

[[nodiscard]] json parse_object_or_empty(const std::string& value) {
    auto parsed = json::parse(value, nullptr, false);
    return parsed.is_object() ? std::move(parsed) : json::object();
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

[[nodiscard]] Host read_host(sqlite::Statement& statement) {
    return Host{
        .id = statement.text(0),
        .name = statement.text(1),
        .agent_token = statement.text(2),
        .capabilities = parse_object_or_empty(statement.text(3)),
        .profile_id = statement.optional_text(4),
        .wg_address = statement.optional_text(5),
        .wg_public_key = statement.optional_text(6),
        .wg_endpoint = statement.optional_text(7),
        .clash_api = statement.optional_text(8),
        .clash_secret = statement.text(9),
        .last_seen = statement.optional_text(10),
        .singbox_state = statement.optional_text(11),
        .enabled = statement.integer(12) != 0,
        .created_at = statement.text(13),
        .updated_at = statement.text(14),
        .assigned_outbounds = static_cast<std::size_t>(statement.integer(15)),
    };
}

[[nodiscard]] HostCommand read_host_command(sqlite::Statement& statement) {
    return HostCommand{
        .id = statement.text(0),
        .host_id = statement.text(1),
        .command = statement.text(2),
        .status = statement.text(3),
        .result = statement.optional_text(4),
        .created_at = statement.text(5),
        .acked_at = statement.optional_text(6),
    };
}

[[nodiscard]] std::string uuid_v4() {
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("secure random generation failed");
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

[[nodiscard]] std::string new_agent_token() {
    auto first = uuid_v4();
    auto second = uuid_v4();
    std::erase(first, '-');
    std::erase(second, '-');
    return first + second;
}

constexpr auto host_select = R"SQL(
SELECT h.id, h.name, h.agent_token, h.capabilities, h.profile_id,
       h.wg_address, h.wg_public_key, h.wg_endpoint, h.clash_api,
       h.clash_secret, h.last_seen, h.singbox_state, h.enabled,
       h.created_at, h.updated_at,
       (SELECT COUNT(*) FROM host_outbounds o WHERE o.host_id = h.id)
FROM hosts h
)SQL";

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
        {"template", profile.profile.dump()},
        {"mode", profile_mode_name(profile.mode)},
        {"rule_script", profile.rule_script},
        {"rule_script_enabled", profile.rule_script_enabled},
        {"created_at", profile.created_at},
        {"updated_at", profile.updated_at},
    };
}

void to_json(nlohmann::json& value, const Host& host) {
    value = nlohmann::json{
        {"id", host.id},
        {"name", host.name},
        {"capabilities", host.capabilities},
        {"profile_id", host.profile_id},
        {"wg_address", host.wg_address},
        {"wg_public_key", host.wg_public_key},
        {"wg_endpoint", host.wg_endpoint},
        {"clash_api", host.clash_api},
        {"last_seen", host.last_seen},
        {"singbox_state", host.singbox_state},
        {"enabled", host.enabled},
        {"created_at", host.created_at},
        {"updated_at", host.updated_at},
        {"assigned_outbounds", host.assigned_outbounds},
        {"has_token", !host.agent_token.empty()},
    };
}

void to_json(nlohmann::json& value, const HostCommand& command) {
    value = nlohmann::json{
        {"id", command.id},
        {"host_id", command.host_id},
        {"command", command.command},
        {"status", command.status},
        {"result", command.result},
        {"created_at", command.created_at},
        {"acked_at", command.acked_at},
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
        throw ValidationError("Profile name and object template are required");
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
        throw ValidationError("Profile id, name, and object template are required");
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
            throw NotFoundError("Profile not found");
        }
    }

    return *find_profile(profile.id);
}

void Store::delete_profile(const std::string& id) {
    if (id == "default") {
        throw ValidationError("Cannot delete the default profile");
    }

    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement reset_hosts{
        database_.handle_,
        "UPDATE hosts SET profile_id = 'default', updated_at = datetime('now') "
        "WHERE profile_id = ?1"};
    reset_hosts.bind(1, id);
    reset_hosts.step_done();

    sqlite::Statement remove{database_.handle_,
                             "DELETE FROM config_profiles WHERE id = ?1"};
    remove.bind(1, id);
    remove.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Profile not found");
    }
    transaction.commit();
}

std::vector<Host> Store::list_hosts() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                std::string{host_select} + " ORDER BY h.created_at"};
    std::vector<Host> hosts;
    while (statement.step_row()) {
        hosts.push_back(read_host(statement));
    }
    return hosts;
}

std::optional<Host> Store::find_host(const std::string& id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                std::string{host_select} + " WHERE h.id = ?1"};
    statement.bind(1, id);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_host(statement);
}

Host Store::create_host(Host host) {
    if (host.name.empty() || !host.capabilities.is_object()) {
        throw ValidationError("Host name and object capabilities are required");
    }
    if (host.id.empty()) {
        host.id = uuid_v4();
    }
    if (host.agent_token.empty()) {
        host.agent_token = new_agent_token();
    }
    if (!host.profile_id.has_value()) {
        host.profile_id = "default";
    }

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{
            database_.handle_,
            "INSERT INTO hosts "
            "(id, name, agent_token, capabilities, profile_id, wg_address, "
            "wg_public_key, wg_endpoint, clash_api, clash_secret, last_seen, "
            "singbox_state, enabled, created_at, updated_at) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
            "?13, datetime('now'), datetime('now'))"};
        statement.bind(1, host.id);
        statement.bind(2, host.name);
        statement.bind(3, host.agent_token);
        statement.bind(4, host.capabilities.dump());
        statement.bind(5, host.profile_id);
        statement.bind(6, host.wg_address);
        statement.bind(7, host.wg_public_key);
        statement.bind(8, host.wg_endpoint);
        statement.bind(9, host.clash_api);
        statement.bind(10, host.clash_secret);
        statement.bind(11, host.last_seen);
        statement.bind(12, host.singbox_state);
        statement.bind(13, host.enabled);
        statement.step_done();
    }
    return *find_host(host.id);
}

Host Store::update_host(Host host) {
    if (host.id.empty() || host.name.empty() || !host.capabilities.is_object()) {
        throw ValidationError("Host id, name, and object capabilities are required");
    }

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{
            database_.handle_,
            "UPDATE hosts SET name = ?1, capabilities = ?2, profile_id = ?3, "
            "wg_address = ?4, wg_public_key = ?5, wg_endpoint = ?6, "
            "clash_api = ?7, clash_secret = ?8, enabled = ?9, "
            "updated_at = datetime('now') WHERE id = ?10"};
        statement.bind(1, host.name);
        statement.bind(2, host.capabilities.dump());
        statement.bind(3, host.profile_id);
        statement.bind(4, host.wg_address);
        statement.bind(5, host.wg_public_key);
        statement.bind(6, host.wg_endpoint);
        statement.bind(7, host.clash_api);
        statement.bind(8, host.clash_secret);
        statement.bind(9, host.enabled);
        statement.bind(10, host.id);
        statement.step_done();
        if (sqlite3_changes(database_.handle_) == 0) {
            throw NotFoundError("Host not found");
        }
    }
    return *find_host(host.id);
}

void Store::delete_host(const std::string& id) {
    if (id == "self") {
        throw ValidationError("Cannot delete the built-in self host");
    }

    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement remove_outbounds{database_.handle_,
                                       "DELETE FROM host_outbounds WHERE host_id = ?1"};
    remove_outbounds.bind(1, id);
    remove_outbounds.step_done();

    sqlite::Statement remove_host{database_.handle_, "DELETE FROM hosts WHERE id = ?1"};
    remove_host.bind(1, id);
    remove_host.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Host not found");
    }
    transaction.commit();
}

std::vector<std::string> Store::host_outbounds(const std::string& host_id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement host{database_.handle_, "SELECT 1 FROM hosts WHERE id = ?1"};
    host.bind(1, host_id);
    if (!host.step_row()) {
        throw NotFoundError("Host not found");
    }

    sqlite::Statement statement{database_.handle_,
                                "SELECT node_id FROM host_outbounds WHERE host_id = ?1 "
                                "ORDER BY node_id"};
    statement.bind(1, host_id);
    std::vector<std::string> ids;
    while (statement.step_row()) {
        ids.push_back(statement.text(0));
    }
    return ids;
}

void Store::set_host_outbounds(const std::string& host_id,
                               const std::vector<std::string>& node_ids) {
    const std::scoped_lock lock{database_.mutex_};
    {
        sqlite::Statement host{database_.handle_, "SELECT 1 FROM hosts WHERE id = ?1"};
        host.bind(1, host_id);
        if (!host.step_row()) {
            throw NotFoundError("Host not found");
        }
    }

    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement remove{database_.handle_,
                             "DELETE FROM host_outbounds WHERE host_id = ?1"};
    remove.bind(1, host_id);
    remove.step_done();
    for (const auto& node_id : node_ids) {
        sqlite::Statement insert{
            database_.handle_,
            "INSERT OR IGNORE INTO host_outbounds (host_id, node_id) "
            "VALUES (?1, ?2)"};
        insert.bind(1, host_id);
        insert.bind(2, node_id);
        insert.step_done();
    }
    transaction.commit();
}

std::string Store::rotate_agent_token(const std::string& host_id) {
    const auto token = new_agent_token();
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement update{
        database_.handle_,
        "UPDATE hosts SET agent_token = ?1, updated_at = datetime('now') "
        "WHERE id = ?2"};
    update.bind(1, token);
    update.bind(2, host_id);
    update.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Host not found");
    }
    return token;
}

std::optional<Host> Store::find_enabled_host_by_token(const std::string& token) const {
    if (token.empty()) {
        return std::nullopt;
    }
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                std::string{host_select} +
                                    " WHERE h.agent_token = ?1 "
                                    "AND h.agent_token != '' AND h.enabled = 1"};
    statement.bind(1, token);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_host(statement);
}

void Store::touch_host(const std::string& host_id) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        "UPDATE hosts SET last_seen = datetime('now') WHERE id = ?1"};
    statement.bind(1, host_id);
    statement.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Host not found");
    }
}

void Store::update_agent_status(const std::string& host_id,
                                const nlohmann::json& state) {
    if (!state.is_object()) {
        throw ValidationError("Agent state must be a JSON object");
    }
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        "UPDATE hosts SET last_seen = datetime('now'), singbox_state = ?1 "
        "WHERE id = ?2"};
    statement.bind(1, state.dump());
    statement.bind(2, host_id);
    statement.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Host not found");
    }
}

HostCommand Store::enqueue_host_command(const std::string& host_id,
                                        const std::string& command) {
    if (command.empty()) {
        throw ValidationError("Command is required");
    }

    const auto id = uuid_v4();
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement host{database_.handle_, "SELECT 1 FROM hosts WHERE id = ?1"};
    host.bind(1, host_id);
    if (!host.step_row()) {
        throw NotFoundError("Host not found");
    }

    sqlite::Statement insert{database_.handle_,
                             "INSERT INTO host_commands "
                             "(id, host_id, command, status, created_at) "
                             "VALUES (?1, ?2, ?3, 'pending', datetime('now'))"};
    insert.bind(1, id);
    insert.bind(2, host_id);
    insert.bind(3, command);
    insert.step_done();

    sqlite::Statement select{
        database_.handle_,
        "SELECT id, host_id, command, status, result, created_at, acked_at "
        "FROM host_commands WHERE id = ?1"};
    select.bind(1, id);
    if (!select.step_row()) {
        throw std::runtime_error("created host command could not be reloaded");
    }
    return read_host_command(select);
}

std::vector<HostCommand> Store::list_host_commands(const std::string& host_id,
                                                   bool pending_only) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement host{database_.handle_, "SELECT 1 FROM hosts WHERE id = ?1"};
    host.bind(1, host_id);
    if (!host.step_row()) {
        throw NotFoundError("Host not found");
    }

    const std::string sql =
        pending_only
            ? "SELECT id, host_id, command, status, result, created_at, acked_at "
              "FROM host_commands WHERE host_id = ?1 AND status = 'pending' "
              "ORDER BY created_at"
            : "SELECT id, host_id, command, status, result, created_at, acked_at "
              "FROM host_commands WHERE host_id = ?1 "
              "ORDER BY created_at DESC LIMIT 20";
    sqlite::Statement statement{database_.handle_, sql};
    statement.bind(1, host_id);
    std::vector<HostCommand> commands;
    while (statement.step_row()) {
        commands.push_back(read_host_command(statement));
    }
    return commands;
}

bool Store::acknowledge_host_command(const std::string& host_id,
                                     const std::string& command_id,
                                     const std::string& status,
                                     const std::optional<std::string>& result) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, "UPDATE host_commands SET status = ?1, result = ?2, "
                           "acked_at = datetime('now') WHERE id = ?3 AND host_id = ?4"};
    statement.bind(1, status);
    statement.bind(2, result);
    statement.bind(3, command_id);
    statement.bind(4, host_id);
    statement.step_done();
    return sqlite3_changes(database_.handle_) != 0;
}

std::size_t Store::update_proxy_latencies(const nlohmann::json& results) {
    if (!results.is_object()) {
        throw ValidationError("results must be a JSON object");
    }

    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    std::size_t updated{};
    for (const auto& [tag, value] : results.items()) {
        std::optional<double> latency;
        if (!value.is_null()) {
            if (!value.is_number()) {
                throw ValidationError("proxy latency values must be numbers or null");
            }
            latency = value.get<double>();
        }
        sqlite::Statement statement{
            database_.handle_, "UPDATE proxy_nodes SET latency = ?1, "
                               "last_latency_test = datetime('now') WHERE tag = ?2"};
        statement.bind(1, latency);
        statement.bind(2, tag);
        statement.step_done();
        updated += static_cast<std::size_t>(sqlite3_changes(database_.handle_));
    }
    transaction.commit();
    return updated;
}

RenderRequest Store::render_request_for_host(const std::string& host_id) const {
    const std::scoped_lock lock{database_.mutex_};

    sqlite::Statement host{database_.handle_,
                           "SELECT id, name, capabilities, profile_id, clash_api, "
                           "clash_secret FROM hosts WHERE id = ?1"};
    host.bind(1, host_id);
    if (!host.step_row()) {
        throw NotFoundError("Host not found");
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
