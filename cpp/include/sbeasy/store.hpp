#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/database.hpp"

namespace sbeasy {

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

    [[nodiscard]] RenderRequest
    render_request_for_host(const std::string& host_id) const;

    [[nodiscard]] Database& database() noexcept {
        return database_;
    }

  private:
    Database database_;
};

} // namespace sbeasy
