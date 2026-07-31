#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/database.hpp"
#include "sbeasy/proxy_parser.hpp"

namespace sbeasy {

class StoreError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class NotFoundError final : public StoreError {
  public:
    using StoreError::StoreError;
};

class ValidationError final : public StoreError {
  public:
    using StoreError::StoreError;
};

struct ConfigProfile {
    std::string id;
    std::string name;
    nlohmann::json profile = nlohmann::json::object();
    ProfileMode mode{ProfileMode::managed};
    std::string rule_script;
    bool rule_script_enabled{false};
    std::string created_at;
    std::string updated_at;
};

void to_json(nlohmann::json& value, const ConfigProfile& profile);

struct Host {
    std::string id;
    std::string name;
    std::string agent_token;
    nlohmann::json capabilities = nlohmann::json::object();
    std::optional<std::string> profile_id;
    std::optional<std::string> wg_address;
    std::optional<std::string> wg_public_key;
    std::optional<std::string> wg_endpoint;
    std::optional<std::string> clash_api;
    std::string clash_secret;
    std::optional<std::string> last_seen;
    std::optional<std::string> singbox_state;
    bool enabled{true};
    std::string created_at;
    std::string updated_at;
    std::size_t assigned_outbounds{};
};

/// Serializes the public host representation. Agent and Clash secrets are
/// deliberately omitted.
void to_json(nlohmann::json& value, const Host& host);

struct HostCommand {
    std::string id;
    std::string host_id;
    std::string command;
    std::string status;
    std::optional<std::string> result;
    std::string created_at;
    std::optional<std::string> acked_at;
};

void to_json(nlohmann::json& value, const HostCommand& command);

struct ProxyRecord {
    std::string id;
    std::string tag;
    std::string node_type;
    bool enabled{true};
    std::string server;
    std::uint16_t server_port{};
    nlohmann::json protocol_config = nlohmann::json::object();
    std::optional<std::string> subscription_id;
    std::string fingerprint;
    std::optional<double> latency;
    std::optional<std::string> last_latency_test;
    std::string created_at;
    std::string updated_at;
};

void to_json(nlohmann::json& value, const ProxyRecord& node);

struct Subscription {
    std::string id;
    std::string name;
    std::string url;
    bool enabled{true};
    std::int64_t refresh_interval{3'600};
    std::optional<std::string> last_fetched_at;
    std::optional<std::string> last_fetch_result;
    std::string created_at;
    std::string updated_at;
};

void to_json(nlohmann::json& value, const Subscription& subscription);

struct ProxyUpsertResult {
    std::size_t added{};
    std::size_t updated{};
    std::vector<std::string> errors;
};

struct SubscriptionFetchResult {
    std::size_t added{};
    std::size_t updated{};
    std::size_t skipped{};
    std::size_t found{};
    std::vector<std::string> errors;
};

void to_json(nlohmann::json& value, const SubscriptionFetchResult& result);

/// Repository facade for the first C++ parity slice.
///
/// It deliberately uses the existing schema and query semantics instead of
/// introducing a new ORM-owned data model.
class Store final {
  public:
    Store(const std::filesystem::path& database_path,
          const std::filesystem::path& migration_directory);

    [[nodiscard]] std::vector<ConfigProfile> list_profiles() const;
    [[nodiscard]] std::optional<ConfigProfile>
    find_profile(const std::string& id) const;
    [[nodiscard]] ConfigProfile create_profile(ConfigProfile profile);
    [[nodiscard]] ConfigProfile update_profile(ConfigProfile profile);
    void delete_profile(const std::string& id);

    [[nodiscard]] std::vector<Host> list_hosts() const;
    [[nodiscard]] std::optional<Host> find_host(const std::string& id) const;
    [[nodiscard]] Host create_host(Host host);
    [[nodiscard]] Host update_host(Host host);
    void delete_host(const std::string& id);

    [[nodiscard]] std::vector<std::string>
    host_outbounds(const std::string& host_id) const;
    void set_host_outbounds(const std::string& host_id,
                            const std::vector<std::string>& node_ids);
    [[nodiscard]] std::string rotate_agent_token(const std::string& host_id);

    [[nodiscard]] std::optional<Host>
    find_enabled_host_by_token(const std::string& token) const;
    void touch_host(const std::string& host_id);
    void update_agent_status(const std::string& host_id, const nlohmann::json& state);

    [[nodiscard]] HostCommand enqueue_host_command(const std::string& host_id,
                                                   const std::string& command);
    [[nodiscard]] std::vector<HostCommand>
    list_host_commands(const std::string& host_id, bool pending_only = false) const;
    [[nodiscard]] bool
    acknowledge_host_command(const std::string& host_id, const std::string& command_id,
                             const std::string& status,
                             const std::optional<std::string>& result);

    [[nodiscard]] std::size_t update_proxy_latencies(const nlohmann::json& results);
    void update_proxy_latency(const std::string& id,
                              const std::optional<double>& latency);

    [[nodiscard]] std::vector<ProxyRecord> list_proxy_nodes() const;
    [[nodiscard]] std::optional<ProxyRecord>
    find_proxy_node(const std::string& id) const;
    [[nodiscard]] ProxyRecord create_proxy_node(ProxyRecord node);
    [[nodiscard]] ProxyRecord update_proxy_node(ProxyRecord node);
    void delete_proxy_node(const std::string& id);
    [[nodiscard]] ProxyUpsertResult
    upsert_proxy_nodes(const std::vector<ParsedProxyNode>& nodes,
                       const std::optional<std::string>& subscription_id);

    [[nodiscard]] std::vector<Subscription> list_subscriptions() const;
    [[nodiscard]] std::optional<Subscription>
    find_subscription(const std::string& id) const;
    [[nodiscard]] Subscription create_subscription(Subscription subscription);
    [[nodiscard]] Subscription update_subscription(Subscription subscription);
    void delete_subscription(const std::string& id);
    void record_subscription_fetch(const std::string& id,
                                   const SubscriptionFetchResult& result);

    [[nodiscard]] RenderRequest
    render_request_for_host(const std::string& host_id) const;

    [[nodiscard]] Database& database() noexcept {
        return database_;
    }

  private:
    Database database_;
};

} // namespace sbeasy
