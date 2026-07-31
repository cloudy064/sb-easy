#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/database.hpp"

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

    [[nodiscard]] RenderRequest
    render_request_for_host(const std::string& host_id) const;

    [[nodiscard]] Database& database() noexcept {
        return database_;
    }

  private:
    Database database_;
};

} // namespace sbeasy
