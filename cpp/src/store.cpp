#include "sbeasy/store.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <optional>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sqlite3.h>

#include "sbeasy/auth.hpp"
#include "sqlite_utils.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;

[[nodiscard]] UserAccount read_user(sqlite::Statement& statement) {
    return UserAccount{
        .id = statement.text(0),
        .username = statement.text(1),
        .password_hash = statement.text(2),
        .role = statement.text(3),
        .created_at = statement.text(4),
    };
}

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

[[nodiscard]] WireGuardPeer read_wireguard_peer(sqlite::Statement& statement) {
    return WireGuardPeer{
        .id = statement.text(0),
        .name = statement.text(1),
        .private_key = statement.text(2),
        .public_key = statement.text(3),
        .preshared_key = statement.optional_text(4),
        .address = statement.text(5),
        .dns = statement.text(6),
        .enabled = statement.integer(7) != 0,
        .persistent_keepalive =
            static_cast<std::int32_t>(statement.integer(8)),
        .allowed_ips = statement.text(9),
        .expire_at = statement.optional_text(10),
        .quota_bytes = statement.integer(11),
        .created_at = statement.text(12),
        .updated_at = statement.text(13),
        .notes = statement.optional_text(14),
        .host_id = statement.optional_text(15),
    };
}

[[nodiscard]] ProxyRecord read_proxy_record(sqlite::Statement& statement) {
    const auto raw_port = statement.integer(5);
    if (raw_port <= 0 || raw_port > 65'535) {
        throw std::runtime_error("proxy server_port is out of range for node " +
                                 statement.text(0));
    }
    return ProxyRecord{
        .id = statement.text(0),
        .tag = statement.text(1),
        .node_type = statement.text(2),
        .enabled = statement.integer(3) != 0,
        .server = statement.text(4),
        .server_port = static_cast<std::uint16_t>(raw_port),
        .protocol_config = parse_object(statement.text(6), "proxy protocol_config"),
        .subscription_id = statement.optional_text(7),
        .fingerprint = statement.text(8),
        .latency = statement.optional_real(9),
        .last_latency_test = statement.optional_text(10),
        .created_at = statement.text(11),
        .updated_at = statement.text(12),
    };
}

[[nodiscard]] Subscription read_subscription(sqlite::Statement& statement) {
    return Subscription{
        .id = statement.text(0),
        .name = statement.text(1),
        .url = statement.text(2),
        .enabled = statement.integer(3) != 0,
        .refresh_interval = statement.integer(4),
        .last_fetched_at = statement.optional_text(5),
        .last_fetch_result = statement.optional_text(6),
        .created_at = statement.text(7),
        .updated_at = statement.text(8),
    };
}

[[nodiscard]] bool supported_proxy_type(const std::string& type) {
    static constexpr std::array<std::string_view, 6> supported{
        "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic"};
    return std::ranges::find(supported, type) != supported.end();
}

void validate_proxy(const ProxyRecord& node) {
    if (node.tag.empty() || node.server.empty() || node.server_port == 0U ||
        !node.protocol_config.is_object()) {
        throw ValidationError(
            "Proxy tag, server, port, and object protocol_config are required");
    }
    if (!supported_proxy_type(node.node_type)) {
        throw ValidationError("Unsupported proxy type: " + node.node_type);
    }
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

[[nodiscard]] std::string sha256_hex(std::string_view value) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), value.data(), value.size()) != 1) {
        throw std::runtime_error("SHA-256 initialization failed");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size{};
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1 ||
        size != 32U) {
        throw std::runtime_error("SHA-256 finalization failed");
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
}

constexpr auto host_select = R"SQL(
SELECT h.id, h.name, h.agent_token, h.capabilities, h.profile_id,
       h.wg_address, h.wg_public_key, h.wg_endpoint, h.clash_api,
       h.clash_secret, h.last_seen, h.singbox_state, h.enabled,
       h.created_at, h.updated_at,
       (SELECT COUNT(*) FROM host_outbounds o WHERE o.host_id = h.id)
FROM hosts h
)SQL";

constexpr auto wireguard_peer_select = R"SQL(
SELECT id, name, private_key, public_key, preshared_key, address, dns,
       enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes,
       created_at, updated_at, notes, host_id
FROM wireguard_peers
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

void to_json(nlohmann::json& value, const UserAccount& user) {
    value = {
        {"id", user.id},
        {"username", user.username},
        {"role", user.role},
        {"created_at", user.created_at},
    };
}

void to_json(nlohmann::json& value, const AuditEntry& entry) {
    value = {
        {"id", entry.id},         {"ts", entry.timestamp},  {"actor", entry.actor},
        {"action", entry.action}, {"target", entry.target},
    };
}

void to_json(nlohmann::json& value, const WireGuardPeer& peer) {
    value = {
        {"id", peer.id},
        {"name", peer.name},
        {"private_key", peer.private_key},
        {"public_key", peer.public_key},
        {"preshared_key", peer.preshared_key},
        {"address", peer.address},
        {"dns", peer.dns},
        {"enabled", peer.enabled},
        {"persistent_keepalive", peer.persistent_keepalive},
        {"allowed_ips", peer.allowed_ips},
        {"expire_at", peer.expire_at},
        {"quota_bytes", peer.quota_bytes},
        {"created_at", peer.created_at},
        {"updated_at", peer.updated_at},
        {"notes", peer.notes},
        {"host_id", peer.host_id},
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

void to_json(nlohmann::json& value, const ProxyRecord& node) {
    value = nlohmann::json{
        {"id", node.id},
        {"tag", node.tag},
        {"node_type", node.node_type},
        {"enabled", node.enabled},
        {"server", node.server},
        {"server_port", node.server_port},
        {"protocol_config", node.protocol_config.dump()},
        {"subscription_id", node.subscription_id},
        {"fingerprint", node.fingerprint},
        {"latency", node.latency},
        {"last_latency_test", node.last_latency_test},
        {"created_at", node.created_at},
        {"updated_at", node.updated_at},
    };
}

void to_json(nlohmann::json& value, const Subscription& subscription) {
    value = nlohmann::json{
        {"id", subscription.id},
        {"name", subscription.name},
        {"url", subscription.url},
        {"enabled", subscription.enabled},
        {"refresh_interval", subscription.refresh_interval},
        {"last_fetched_at", subscription.last_fetched_at},
        {"last_fetch_result", subscription.last_fetch_result},
        {"created_at", subscription.created_at},
        {"updated_at", subscription.updated_at},
    };
}

void to_json(nlohmann::json& value, const SubscriptionFetchResult& result) {
    value = nlohmann::json{
        {"added", result.added},     {"updated", result.updated},
        {"skipped", result.skipped}, {"found", result.found},
        {"errors", result.errors},
    };
}

Store::Store(const std::filesystem::path& database_path,
             const std::filesystem::path& migration_directory)
    : database_(database_path) {
    database_.migrate(migration_directory);
}

void Store::ensure_default_admin(const std::string& password) {
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement count{database_.handle_, "SELECT COUNT(*) FROM users"};
        if (count.step_row() && count.integer(0) != 0) {
            return;
        }
    }
    static_cast<void>(create_user("admin", hash_password(password), "admin"));
}

std::vector<UserAccount> Store::list_users() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT id, username, password_hash, role, created_at "
                                "FROM users ORDER BY created_at"};
    std::vector<UserAccount> users;
    while (statement.step_row()) {
        users.push_back(read_user(statement));
    }
    return users;
}

std::optional<UserAccount>
Store::find_user_by_username(const std::string& username) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT id, username, password_hash, role, created_at "
                                "FROM users WHERE username = ?1 LIMIT 1"};
    statement.bind(1, username);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_user(statement);
}

UserAccount Store::create_user(const std::string& username,
                               const std::string& password_hash,
                               const std::string& role) {
    if (username.empty() || password_hash.empty() ||
        (role != "admin" && role != "viewer")) {
        throw ValidationError("Invalid user");
    }
    const auto id = uuid_v4();
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement duplicate{database_.handle_,
                                    "SELECT 1 FROM users WHERE username = ?1"};
        duplicate.bind(1, username);
        if (duplicate.step_row()) {
            throw ConflictError("Username already exists");
        }
        sqlite::Statement insert{
            database_.handle_, "INSERT INTO users (id, username, password_hash, role) "
                               "VALUES (?1, ?2, ?3, ?4)"};
        insert.bind(1, id);
        insert.bind(2, username);
        insert.bind(3, password_hash);
        insert.bind(4, role);
        insert.step_done();
    }
    auto created = find_user_by_username(username);
    if (!created.has_value()) {
        throw std::runtime_error("created user could not be reloaded");
    }
    return std::move(*created);
}

void Store::delete_user(const std::string& actor_id, const std::string& user_id) {
    if (actor_id == user_id) {
        throw ValidationError("You cannot delete your own account");
    }
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement target{database_.handle_, "SELECT role FROM users WHERE id = ?1"};
    target.bind(1, user_id);
    if (!target.step_row()) {
        return;
    }
    if (target.text(0) == "admin") {
        sqlite::Statement count{database_.handle_,
                                "SELECT COUNT(*) FROM users WHERE role = 'admin'"};
        if (count.step_row() && count.integer(0) <= 1) {
            throw ValidationError("Cannot delete the last admin");
        }
    }
    sqlite::Statement remove{database_.handle_, "DELETE FROM users WHERE id = ?1"};
    remove.bind(1, user_id);
    remove.step_done();
}

void Store::reset_user_password(const std::string& user_id,
                                const std::string& password_hash) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement update{database_.handle_,
                             "UPDATE users SET password_hash = ?1 WHERE id = ?2"};
    update.bind(1, password_hash);
    update.bind(2, user_id);
    update.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("User not found");
    }
}

void Store::record_audit(const std::string& actor, const std::string& action,
                         const std::optional<std::string>& target) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement insert{
        database_.handle_,
        "INSERT INTO audit_log (actor, action, target) VALUES (?1, ?2, ?3)"};
    insert.bind(1, actor);
    insert.bind(2, action);
    insert.bind(3, target);
    insert.step_done();
}

std::vector<AuditEntry> Store::list_audit(std::size_t limit) const {
    const auto bounded =
        std::min<std::size_t>(std::max<std::size_t>(limit, 1U), 1'000U);
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT id, ts, actor, action, target FROM audit_log "
                                "ORDER BY id DESC LIMIT ?1"};
    statement.bind(1, static_cast<std::int64_t>(bounded));
    std::vector<AuditEntry> entries;
    while (statement.step_row()) {
        entries.push_back(AuditEntry{
            .id = statement.integer(0),
            .timestamp = statement.text(1),
            .actor = statement.text(2),
            .action = statement.text(3),
            .target = statement.optional_text(4),
        });
    }
    return entries;
}

nlohmann::json Store::app_settings() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "SELECT key, value FROM app_settings"};
    json settings = json::object();
    while (statement.step_row()) {
        auto value = json::parse(statement.text(1), nullptr, false);
        if (!value.is_discarded()) {
            settings[statement.text(0)] = std::move(value);
        }
    }
    return settings;
}

void Store::update_app_settings(const nlohmann::json& sections) {
    if (!sections.is_object()) {
        throw ValidationError("settings must be a JSON object");
    }
    static constexpr std::array<std::string_view, 3> allowed{
        "wireguard_interface", "singbox_connection", "general"};
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    for (const auto key : allowed) {
        const auto found = sections.find(std::string{key});
        if (found == sections.end()) {
            continue;
        }
        sqlite::Statement upsert{
            database_.handle_, "INSERT INTO app_settings (key, value, updated_at) "
                               "VALUES (?1, ?2, datetime('now')) "
                               "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                               "updated_at = datetime('now')"};
        upsert.bind(1, std::string{key});
        upsert.bind(2, found->dump());
        upsert.step_done();
    }
    transaction.commit();
}

std::optional<nlohmann::json>
Store::app_setting(const std::string& key) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, "SELECT value FROM app_settings WHERE key = ?1"};
    statement.bind(1, key);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    auto value = json::parse(statement.text(0), nullptr, false);
    return value.is_discarded() ? std::nullopt :
                                  std::optional<json>{std::move(value)};
}

void Store::set_app_setting(const std::string& key,
                            const nlohmann::json& value) {
    if (key.empty()) {
        throw ValidationError("setting key is required");
    }
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement upsert{
        database_.handle_,
        "INSERT INTO app_settings (key, value, updated_at) "
        "VALUES (?1, ?2, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
        "updated_at = datetime('now')"};
    upsert.bind(1, key);
    upsert.bind(2, value.dump());
    upsert.step_done();
}

std::vector<WireGuardPeer> Store::list_wireguard_peers() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, std::string{wireguard_peer_select} + " ORDER BY address"};
    std::vector<WireGuardPeer> peers;
    while (statement.step_row()) {
        peers.push_back(read_wireguard_peer(statement));
    }
    return peers;
}

std::optional<WireGuardPeer>
Store::find_wireguard_peer(const std::string& id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        std::string{wireguard_peer_select} + " WHERE id = ?1"};
    statement.bind(1, id);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_wireguard_peer(statement);
}

WireGuardPeer Store::create_wireguard_peer(WireGuardPeer peer) {
    if (peer.name.empty() || peer.private_key.empty() ||
        peer.public_key.empty() || peer.address.empty()) {
        throw ValidationError(
            "WireGuard name, keys, and address are required");
    }
    if (peer.persistent_keepalive < 0 || peer.persistent_keepalive > 65'535 ||
        peer.quota_bytes < 0) {
        throw ValidationError("Invalid WireGuard keepalive or quota");
    }
    if (peer.id.empty()) {
        peer.id = uuid_v4();
    }
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement duplicate{
            database_.handle_,
            "SELECT 1 FROM wireguard_peers WHERE address = ?1"};
        duplicate.bind(1, peer.address);
        if (duplicate.step_row()) {
            throw ConflictError("WireGuard address already exists");
        }
        sqlite::Statement insert{
            database_.handle_,
            "INSERT INTO wireguard_peers "
            "(id, name, private_key, public_key, preshared_key, address, dns, "
            "enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes, "
            "created_at, updated_at, notes, host_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
            "datetime('now'), datetime('now'), ?13, ?14)"};
        insert.bind(1, peer.id);
        insert.bind(2, peer.name);
        insert.bind(3, peer.private_key);
        insert.bind(4, peer.public_key);
        insert.bind(5, peer.preshared_key);
        insert.bind(6, peer.address);
        insert.bind(7, peer.dns);
        insert.bind(8, peer.enabled);
        insert.bind(9, static_cast<std::int64_t>(peer.persistent_keepalive));
        insert.bind(10, peer.allowed_ips);
        insert.bind(11, peer.expire_at);
        insert.bind(12, peer.quota_bytes);
        insert.bind(13, peer.notes);
        insert.bind(14, peer.host_id);
        insert.step_done();
    }
    return *find_wireguard_peer(peer.id);
}

WireGuardPeer Store::update_wireguard_peer(WireGuardPeer peer) {
    if (peer.id.empty() || peer.name.empty() || peer.persistent_keepalive < 0 ||
        peer.persistent_keepalive > 65'535 || peer.quota_bytes < 0) {
        throw ValidationError("Invalid WireGuard peer");
    }
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement update{
            database_.handle_,
            "UPDATE wireguard_peers SET name = ?1, enabled = ?2, dns = ?3, "
            "persistent_keepalive = ?4, allowed_ips = ?5, expire_at = ?6, "
            "quota_bytes = ?7, updated_at = datetime('now'), notes = ?8 "
            "WHERE id = ?9"};
        update.bind(1, peer.name);
        update.bind(2, peer.enabled);
        update.bind(3, peer.dns);
        update.bind(4, static_cast<std::int64_t>(peer.persistent_keepalive));
        update.bind(5, peer.allowed_ips);
        update.bind(6, peer.expire_at);
        update.bind(7, peer.quota_bytes);
        update.bind(8, peer.notes);
        update.bind(9, peer.id);
        update.step_done();
        if (sqlite3_changes(database_.handle_) == 0) {
            throw NotFoundError("Peer not found");
        }
    }
    return *find_wireguard_peer(peer.id);
}

void Store::delete_wireguard_peer(const std::string& id) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement remove{
        database_.handle_, "DELETE FROM wireguard_peers WHERE id = ?1"};
    remove.bind(1, id);
    remove.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Peer not found");
    }
}

void Store::set_wireguard_peer_enabled(const std::string& id, bool enabled) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement update{
        database_.handle_,
        "UPDATE wireguard_peers SET enabled = ?1, updated_at = datetime('now') "
        "WHERE id = ?2"};
    update.bind(1, enabled);
    update.bind(2, id);
    update.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Peer not found");
    }
}

std::string
Store::next_wireguard_address(const std::string& server_address) const {
    const auto slash = server_address.find('/');
    const auto host = server_address.substr(0, slash);
    const auto dot = host.rfind('.');
    const auto base =
        dot == std::string::npos ? std::string{"10.59.32"} :
                                   host.substr(0, dot);
    std::array<bool, 255> taken{};
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, "SELECT address FROM wireguard_peers"};
    while (statement.step_row()) {
        const auto address = statement.text(0);
        const auto address_host = address.substr(0, address.find('/'));
        const auto address_dot = address_host.rfind('.');
        if (address_dot == std::string::npos ||
            address_host.substr(0, address_dot) != base) {
            continue;
        }
        try {
            const auto octet = std::stoul(address_host.substr(address_dot + 1U));
            if (octet < taken.size()) {
                taken[octet] = true;
            }
        } catch (const std::exception&) {
        }
    }
    for (std::size_t octet = 2; octet <= 254; ++octet) {
        if (!taken[octet]) {
            return base + "." + std::to_string(octet) + "/24";
        }
    }
    throw ConflictError("No available IPs in subnet");
}

void Store::create_one_time_link(const std::string& token,
                                 const std::string& peer_id,
                                 const std::string& expires_at) {
    if (!find_wireguard_peer(peer_id).has_value()) {
        throw NotFoundError("Peer not found");
    }
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement insert{
        database_.handle_,
        "INSERT INTO one_time_links "
        "(id, peer_id, expires_at, used, created_at) "
        "VALUES (?1, ?2, ?3, 0, datetime('now'))"};
    insert.bind(1, token);
    insert.bind(2, peer_id);
    insert.bind(3, expires_at);
    insert.step_done();
}

nlohmann::json Store::export_backup() const {
    return {
        {"proxy_nodes", list_proxy_nodes()},
        {"wireguard_peers", list_wireguard_peers()},
        {"subscriptions", list_subscriptions()},
        {"app_settings", app_settings()},
    };
}

nlohmann::json Store::restore_backup(const nlohmann::json& backup) {
    if (!backup.is_object()) {
        throw ValidationError("backup must be a JSON object");
    }
    const auto settings = backup.find("app_settings");
    const auto subscriptions = backup.find("subscriptions");
    const auto nodes = backup.find("proxy_nodes");
    const auto peers = backup.find("wireguard_peers");
    if (settings != backup.end() && !settings->is_object()) {
        throw ValidationError("backup app_settings must be an object");
    }
    if ((subscriptions != backup.end() && !subscriptions->is_array()) ||
        (nodes != backup.end() && !nodes->is_array()) ||
        (peers != backup.end() && !peers->is_array())) {
        throw ValidationError("backup row sections must be arrays");
    }

    std::size_t settings_count{};
    std::size_t subscription_count{};
    std::size_t node_count{};
    std::size_t peer_count{};
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};

    if (settings != backup.end()) {
        for (const auto& [key, value] : settings->items()) {
            sqlite::Statement row{
                database_.handle_,
                "INSERT INTO app_settings (key, value, updated_at) "
                "VALUES (?1, ?2, datetime('now')) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = datetime('now')"};
            row.bind(1, key);
            row.bind(2, value.dump());
            row.step_done();
            ++settings_count;
        }
    }

    if (subscriptions != backup.end()) {
        for (const auto& value : *subscriptions) {
            if (!value.is_object()) {
                continue;
            }
            const auto id = value.value("id", "");
            const auto url = value.value("url", "");
            if (id.empty() || url.empty()) {
                continue;
            }
            sqlite::Statement row{
                database_.handle_,
                "INSERT OR REPLACE INTO subscriptions "
                "(id, name, url, enabled, refresh_interval, last_fetched_at, "
                "last_fetch_result, created_at, updated_at) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
                "COALESCE(NULLIF(?8, ''), datetime('now')), datetime('now'))"};
            row.bind(1, id);
            row.bind(2, value.value("name", ""));
            row.bind(3, url);
            row.bind(4, value.value("enabled", true));
            row.bind(5, value.value<std::int64_t>("refresh_interval", 3'600));
            row.bind(6, value.contains("last_fetched_at") &&
                                value["last_fetched_at"].is_string()
                            ? std::optional<std::string>{
                                  value["last_fetched_at"].get<std::string>()}
                            : std::nullopt);
            row.bind(7, value.contains("last_fetch_result") &&
                                value["last_fetch_result"].is_string()
                            ? std::optional<std::string>{
                                  value["last_fetch_result"].get<std::string>()}
                            : std::nullopt);
            row.bind(8, value.value("created_at", ""));
            row.step_done();
            ++subscription_count;
        }
    }

    if (nodes != backup.end()) {
        for (const auto& value : *nodes) {
            if (!value.is_object()) {
                continue;
            }
            const auto id = value.value("id", "");
            const auto tag = value.value("tag", "");
            if (id.empty() || tag.empty()) {
                continue;
            }
            auto protocol = value.value("protocol_config", json::object());
            const auto protocol_text =
                protocol.is_string() ? protocol.get<std::string>() :
                                       protocol.dump();
            sqlite::Statement row{
                database_.handle_,
                "INSERT OR REPLACE INTO proxy_nodes "
                "(id, tag, node_type, enabled, server, server_port, "
                "protocol_config, subscription_id, fingerprint, latency, "
                "last_latency_test, created_at, updated_at) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                "COALESCE(NULLIF(?12, ''), datetime('now')), datetime('now'))"};
            row.bind(1, id);
            row.bind(2, tag);
            row.bind(3, value.value("node_type", ""));
            row.bind(4, value.value("enabled", true));
            row.bind(5, value.value("server", ""));
            row.bind(6, value.value<std::int64_t>("server_port", 0));
            row.bind(7, protocol_text);
            row.bind(8, value.contains("subscription_id") &&
                                value["subscription_id"].is_string()
                            ? std::optional<std::string>{
                                  value["subscription_id"].get<std::string>()}
                            : std::nullopt);
            row.bind(9, value.value("fingerprint", ""));
            row.bind(10, value.contains("latency") &&
                                 value["latency"].is_number()
                             ? std::optional<double>{
                                   value["latency"].get<double>()}
                             : std::nullopt);
            row.bind(11, value.contains("last_latency_test") &&
                                 value["last_latency_test"].is_string()
                             ? std::optional<std::string>{
                                   value["last_latency_test"].get<std::string>()}
                             : std::nullopt);
            row.bind(12, value.value("created_at", ""));
            row.step_done();
            ++node_count;
        }
    }

    if (peers != backup.end()) {
        for (const auto& value : *peers) {
            if (!value.is_object()) {
                continue;
            }
            const auto id = value.value("id", "");
            const auto address = value.value("address", "");
            if (id.empty() || address.empty()) {
                continue;
            }
            sqlite::Statement row{
                database_.handle_,
                "INSERT OR REPLACE INTO wireguard_peers "
                "(id, name, private_key, public_key, preshared_key, address, dns, "
                "enabled, persistent_keepalive, allowed_ips, expire_at, "
                "quota_bytes, created_at, updated_at, notes, host_id) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                "COALESCE(NULLIF(?13, ''), datetime('now')), datetime('now'), "
                "?14, ?15)"};
            row.bind(1, id);
            row.bind(2, value.value("name", ""));
            row.bind(3, value.value("private_key", ""));
            row.bind(4, value.value("public_key", ""));
            row.bind(5, value.contains("preshared_key") &&
                                value["preshared_key"].is_string()
                            ? std::optional<std::string>{
                                  value["preshared_key"].get<std::string>()}
                            : std::nullopt);
            row.bind(6, address);
            row.bind(7, value.value("dns", "10.59.32.1"));
            row.bind(8, value.value("enabled", true));
            row.bind(9,
                     value.value<std::int64_t>("persistent_keepalive", 25));
            row.bind(10, value.value("allowed_ips", "0.0.0.0/0, ::/0"));
            row.bind(11, value.contains("expire_at") &&
                                 value["expire_at"].is_string()
                             ? std::optional<std::string>{
                                   value["expire_at"].get<std::string>()}
                             : std::nullopt);
            row.bind(12, value.value<std::int64_t>("quota_bytes", 0));
            row.bind(13, value.value("created_at", ""));
            row.bind(14, value.contains("notes") && value["notes"].is_string()
                             ? std::optional<std::string>{
                                   value["notes"].get<std::string>()}
                             : std::nullopt);
            row.bind(15, value.contains("host_id") &&
                                 value["host_id"].is_string()
                             ? std::optional<std::string>{
                                   value["host_id"].get<std::string>()}
                             : std::nullopt);
            row.step_done();
            ++peer_count;
        }
    }
    transaction.commit();
    return {
        {"app_settings", settings_count},
        {"subscriptions", subscription_count},
        {"proxy_nodes", node_count},
        {"wireguard_peers", peer_count},
    };
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

AgentEnrollment Store::create_agent_enrollment(const std::string& host_id) {
    const auto host = find_host(host_id);
    if (!host.has_value()) {
        throw NotFoundError("Host not found");
    }
    if (host->id == "self" || !host->enabled) {
        throw ValidationError("Enrollment requires an enabled remote host");
    }

    AgentEnrollment enrollment{
        .id = uuid_v4(),
        .host_id = host_id,
        .code = new_agent_token(),
        .expires_at = {},
    };
    const auto code_hash = sha256_hex(enrollment.code);
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement expire_previous{
        database_.handle_,
        "UPDATE agent_enrollments SET expires_at = datetime('now') "
        "WHERE host_id = ?1 AND redeemed_at IS NULL"};
    expire_previous.bind(1, host_id);
    expire_previous.step_done();

    sqlite::Statement insert{
        database_.handle_,
        "INSERT INTO agent_enrollments "
        "(id, host_id, code_hash, expires_at) "
        "VALUES (?1, ?2, ?3, datetime('now', '+10 minutes'))"};
    insert.bind(1, enrollment.id);
    insert.bind(2, host_id);
    insert.bind(3, code_hash);
    insert.step_done();

    sqlite::Statement read{
        database_.handle_,
        "SELECT expires_at FROM agent_enrollments WHERE id = ?1"};
    read.bind(1, enrollment.id);
    if (!read.step_row()) {
        throw std::runtime_error("Created enrollment could not be read");
    }
    enrollment.expires_at = read.text(0);
    transaction.commit();
    return enrollment;
}

AgentEnrollmentResult
Store::redeem_agent_enrollment(const std::string& code,
                               const nlohmann::json& device) {
    if (code.size() < 32U || !device.is_object()) {
        throw ValidationError("A valid enrollment code and device are required");
    }
    const auto code_hash = sha256_hex(code);
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement read{
        database_.handle_,
        "SELECT e.id, h.id, h.name, h.agent_token, "
        "COALESCE(h.profile_id, 'default'), p.name, h.capabilities "
        "FROM agent_enrollments e "
        "JOIN hosts h ON h.id = e.host_id "
        "JOIN config_profiles p ON p.id = COALESCE(h.profile_id, 'default') "
        "WHERE e.code_hash = ?1 AND e.redeemed_at IS NULL "
        "AND e.expires_at > datetime('now') AND h.enabled = 1"};
    read.bind(1, code_hash);
    if (!read.step_row()) {
        throw ValidationError("Enrollment code is invalid or expired");
    }

    const auto enrollment_id = read.text(0);
    AgentEnrollmentResult result{
        .host_id = read.text(1),
        .host_name = read.text(2),
        .agent_token = read.text(3),
        .profile_id = read.text(4),
        .profile_name = read.text(5),
    };
    auto capabilities = parse_object_or_empty(read.text(6));
    capabilities["platform"] = "android";
    for (const auto* key : {"app_version", "core_version", "install_id", "model"}) {
        const auto found = device.find(key);
        if (found != device.end() && found->is_string()) {
            capabilities[key] = *found;
        }
    }

    sqlite::Statement redeem{
        database_.handle_,
        "UPDATE agent_enrollments SET redeemed_at = datetime('now') "
        "WHERE id = ?1 AND redeemed_at IS NULL"};
    redeem.bind(1, enrollment_id);
    redeem.step_done();
    if (sqlite3_changes(database_.handle_) != 1) {
        throw ConflictError("Enrollment code was already redeemed");
    }

    sqlite::Statement update_host{
        database_.handle_,
        "UPDATE hosts SET capabilities = ?1, last_seen = datetime('now'), "
        "updated_at = datetime('now') WHERE id = ?2"};
    update_host.bind(1, capabilities.dump());
    update_host.bind(2, result.host_id);
    update_host.step_done();
    transaction.commit();
    return result;
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

void Store::update_proxy_latency(const std::string& id,
                                 const std::optional<double>& latency) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "UPDATE proxy_nodes SET latency = ?1, "
                                "last_latency_test = datetime('now') WHERE id = ?2"};
    statement.bind(1, latency);
    statement.bind(2, id);
    statement.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Node not found");
    }
}

std::vector<ProxyRecord> Store::list_proxy_nodes() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, "SELECT id, tag, node_type, enabled, server, server_port, "
                           "protocol_config, subscription_id, fingerprint, latency, "
                           "last_latency_test, created_at, updated_at "
                           "FROM proxy_nodes ORDER BY node_type, tag"};
    std::vector<ProxyRecord> nodes;
    while (statement.step_row()) {
        nodes.push_back(read_proxy_record(statement));
    }
    return nodes;
}

std::optional<ProxyRecord> Store::find_proxy_node(const std::string& id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_, "SELECT id, tag, node_type, enabled, server, server_port, "
                           "protocol_config, subscription_id, fingerprint, latency, "
                           "last_latency_test, created_at, updated_at "
                           "FROM proxy_nodes WHERE id = ?1"};
    statement.bind(1, id);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_proxy_record(statement);
}

ProxyRecord Store::create_proxy_node(ProxyRecord node) {
    validate_proxy(node);
    if (node.id.empty()) {
        node.id = uuid_v4();
    }
    node.fingerprint =
        ParsedProxyNode{
            .node_type = node.node_type,
            .tag = node.tag,
            .server = node.server,
            .server_port = node.server_port,
            .protocol_config = node.protocol_config,
        }
            .fingerprint();

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement duplicate{
            database_.handle_,
            "SELECT 1 FROM proxy_nodes WHERE tag = ?1 OR fingerprint = ?2 LIMIT 1"};
        duplicate.bind(1, node.tag);
        duplicate.bind(2, node.fingerprint);
        if (duplicate.step_row()) {
            throw ValidationError(
                "A proxy with the same tag or fingerprint already exists");
        }
        sqlite::Statement statement{
            database_.handle_,
            "INSERT INTO proxy_nodes "
            "(id, tag, node_type, enabled, server, server_port, protocol_config, "
            "subscription_id, fingerprint, latency, last_latency_test, "
            "created_at, updated_at) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
            "datetime('now'), datetime('now'))"};
        statement.bind(1, node.id);
        statement.bind(2, node.tag);
        statement.bind(3, node.node_type);
        statement.bind(4, node.enabled);
        statement.bind(5, node.server);
        statement.bind(6, static_cast<std::int64_t>(node.server_port));
        statement.bind(7, node.protocol_config.dump());
        statement.bind(8, node.subscription_id);
        statement.bind(9, node.fingerprint);
        statement.bind(10, node.latency);
        statement.bind(11, node.last_latency_test);
        statement.step_done();
    }
    return *find_proxy_node(node.id);
}

ProxyRecord Store::update_proxy_node(ProxyRecord node) {
    validate_proxy(node);
    if (node.id.empty()) {
        throw ValidationError("Proxy id is required");
    }
    node.fingerprint =
        ParsedProxyNode{
            .node_type = node.node_type,
            .tag = node.tag,
            .server = node.server,
            .server_port = node.server_port,
            .protocol_config = node.protocol_config,
        }
            .fingerprint();

    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement duplicate{database_.handle_,
                                    "SELECT 1 FROM proxy_nodes WHERE id != ?1 "
                                    "AND (tag = ?2 OR fingerprint = ?3) LIMIT 1"};
        duplicate.bind(1, node.id);
        duplicate.bind(2, node.tag);
        duplicate.bind(3, node.fingerprint);
        if (duplicate.step_row()) {
            throw ValidationError(
                "A proxy with the same tag or fingerprint already exists");
        }
        sqlite::Statement statement{
            database_.handle_,
            "UPDATE proxy_nodes SET tag = ?1, node_type = ?2, enabled = ?3, "
            "server = ?4, server_port = ?5, protocol_config = ?6, "
            "subscription_id = ?7, fingerprint = ?8, updated_at = datetime('now') "
            "WHERE id = ?9"};
        statement.bind(1, node.tag);
        statement.bind(2, node.node_type);
        statement.bind(3, node.enabled);
        statement.bind(4, node.server);
        statement.bind(5, static_cast<std::int64_t>(node.server_port));
        statement.bind(6, node.protocol_config.dump());
        statement.bind(7, node.subscription_id);
        statement.bind(8, node.fingerprint);
        statement.bind(9, node.id);
        statement.step_done();
        if (sqlite3_changes(database_.handle_) == 0) {
            throw NotFoundError("Node not found");
        }
    }
    return *find_proxy_node(node.id);
}

void Store::delete_proxy_node(const std::string& id) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Transaction transaction{database_.handle_};
    sqlite::Statement assignments{database_.handle_,
                                  "DELETE FROM host_outbounds WHERE node_id = ?1"};
    assignments.bind(1, id);
    assignments.step_done();
    sqlite::Statement node{database_.handle_, "DELETE FROM proxy_nodes WHERE id = ?1"};
    node.bind(1, id);
    node.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Node not found");
    }
    transaction.commit();
}

ProxyUpsertResult
Store::upsert_proxy_nodes(const std::vector<ParsedProxyNode>& nodes,
                          const std::optional<std::string>& subscription_id) {
    ProxyUpsertResult result;
    const std::scoped_lock lock{database_.mutex_};
    if (subscription_id.has_value()) {
        sqlite::Statement subscription{database_.handle_,
                                       "SELECT 1 FROM subscriptions WHERE id = ?1"};
        subscription.bind(1, *subscription_id);
        if (!subscription.step_row()) {
            throw NotFoundError("Subscription not found");
        }
    }

    sqlite::Transaction transaction{database_.handle_};
    for (const auto& node : nodes) {
        try {
            ProxyRecord candidate;
            candidate.tag = node.tag;
            candidate.node_type = node.node_type;
            candidate.enabled = true;
            candidate.server = node.server;
            candidate.server_port = node.server_port;
            candidate.protocol_config = node.protocol_config;
            validate_proxy(candidate);
            const auto fingerprint = node.fingerprint();

            std::optional<std::string> existing_id;
            {
                sqlite::Statement existing{
                    database_.handle_,
                    "SELECT id FROM proxy_nodes WHERE fingerprint = ?1 "
                    "UNION ALL "
                    "SELECT id FROM proxy_nodes WHERE tag = ?2 "
                    "AND fingerprint != ?1 LIMIT 1"};
                existing.bind(1, fingerprint);
                existing.bind(2, node.tag);
                if (existing.step_row()) {
                    existing_id = existing.text(0);
                }
            }

            if (existing_id.has_value()) {
                sqlite::Statement update{
                    database_.handle_,
                    "UPDATE proxy_nodes SET tag = ?1, node_type = ?2, "
                    "server = ?3, server_port = ?4, protocol_config = ?5, "
                    "fingerprint = ?6, subscription_id = ?7, "
                    "updated_at = datetime('now') WHERE id = ?8"};
                update.bind(1, node.tag);
                update.bind(2, node.node_type);
                update.bind(3, node.server);
                update.bind(4, static_cast<std::int64_t>(node.server_port));
                update.bind(5, node.protocol_config.dump());
                update.bind(6, fingerprint);
                update.bind(7, subscription_id);
                update.bind(8, *existing_id);
                update.step_done();
                ++result.updated;
            } else {
                sqlite::Statement insert{
                    database_.handle_,
                    "INSERT INTO proxy_nodes "
                    "(id, tag, node_type, enabled, server, server_port, "
                    "protocol_config, subscription_id, fingerprint, "
                    "created_at, updated_at) "
                    "VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, "
                    "datetime('now'), datetime('now'))"};
                insert.bind(1, uuid_v4());
                insert.bind(2, node.tag);
                insert.bind(3, node.node_type);
                insert.bind(4, node.server);
                insert.bind(5, static_cast<std::int64_t>(node.server_port));
                insert.bind(6, node.protocol_config.dump());
                insert.bind(7, subscription_id);
                insert.bind(8, fingerprint);
                insert.step_done();
                ++result.added;
            }
        } catch (const std::exception& error) {
            result.errors.push_back("Failed to import " + node.tag + ": " +
                                    error.what());
        }
    }
    transaction.commit();
    return result;
}

std::vector<Subscription> Store::list_subscriptions() const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        "SELECT id, name, url, enabled, refresh_interval, last_fetched_at, "
        "last_fetch_result, created_at, updated_at "
        "FROM subscriptions ORDER BY name"};
    std::vector<Subscription> subscriptions;
    while (statement.step_row()) {
        subscriptions.push_back(read_subscription(statement));
    }
    return subscriptions;
}

std::optional<Subscription> Store::find_subscription(const std::string& id) const {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        "SELECT id, name, url, enabled, refresh_interval, last_fetched_at, "
        "last_fetch_result, created_at, updated_at "
        "FROM subscriptions WHERE id = ?1"};
    statement.bind(1, id);
    if (!statement.step_row()) {
        return std::nullopt;
    }
    return read_subscription(statement);
}

Subscription Store::create_subscription(Subscription subscription) {
    if (subscription.name.empty() || subscription.url.empty() ||
        subscription.refresh_interval <= 0) {
        throw ValidationError(
            "Subscription name, URL, and positive refresh interval are required");
    }
    if (subscription.id.empty()) {
        subscription.id = uuid_v4();
    }
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{
            database_.handle_,
            "INSERT INTO subscriptions "
            "(id, name, url, enabled, refresh_interval, last_fetched_at, "
            "last_fetch_result, created_at, updated_at) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
            "datetime('now'), datetime('now'))"};
        statement.bind(1, subscription.id);
        statement.bind(2, subscription.name);
        statement.bind(3, subscription.url);
        statement.bind(4, subscription.enabled);
        statement.bind(5, subscription.refresh_interval);
        statement.bind(6, subscription.last_fetched_at);
        statement.bind(7, subscription.last_fetch_result);
        statement.step_done();
    }
    return *find_subscription(subscription.id);
}

Subscription Store::update_subscription(Subscription subscription) {
    if (subscription.id.empty() || subscription.name.empty() ||
        subscription.url.empty() || subscription.refresh_interval <= 0) {
        throw ValidationError(
            "Subscription id, name, URL, and positive refresh interval are required");
    }
    {
        const std::scoped_lock lock{database_.mutex_};
        sqlite::Statement statement{
            database_.handle_,
            "UPDATE subscriptions SET name = ?1, url = ?2, enabled = ?3, "
            "refresh_interval = ?4, updated_at = datetime('now') WHERE id = ?5"};
        statement.bind(1, subscription.name);
        statement.bind(2, subscription.url);
        statement.bind(3, subscription.enabled);
        statement.bind(4, subscription.refresh_interval);
        statement.bind(5, subscription.id);
        statement.step_done();
        if (sqlite3_changes(database_.handle_) == 0) {
            throw NotFoundError("Subscription not found");
        }
    }
    return *find_subscription(subscription.id);
}

void Store::delete_subscription(const std::string& id) {
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{database_.handle_,
                                "DELETE FROM subscriptions WHERE id = ?1"};
    statement.bind(1, id);
    statement.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Subscription not found");
    }
}

void Store::record_subscription_fetch(const std::string& id,
                                      const SubscriptionFetchResult& result) {
    const json metadata{
        {"added", result.added},     {"updated", result.updated},
        {"skipped", result.skipped}, {"total", result.found},
        {"errors", result.errors},
    };
    const std::scoped_lock lock{database_.mutex_};
    sqlite::Statement statement{
        database_.handle_,
        "UPDATE subscriptions SET last_fetched_at = datetime('now'), "
        "last_fetch_result = ?1 WHERE id = ?2"};
    statement.bind(1, metadata.dump());
    statement.bind(2, id);
    statement.step_done();
    if (sqlite3_changes(database_.handle_) == 0) {
        throw NotFoundError("Subscription not found");
    }
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
