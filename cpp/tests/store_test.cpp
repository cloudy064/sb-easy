#include "test_support.hpp"

#include <filesystem>
#include <random>
#include <string>
#include <system_error>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/store.hpp"

namespace {

class TemporaryDatabase final {
  public:
    TemporaryDatabase()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-cpp-" + std::to_string(std::random_device{}()) + ".db")) {}

    ~TemporaryDatabase() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        std::filesystem::remove(path_.string() + "-shm", ignored);
        std::filesystem::remove(path_.string() + "-wal", ignored);
    }

    TemporaryDatabase(const TemporaryDatabase&) = delete;
    TemporaryDatabase& operator=(const TemporaryDatabase&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

[[nodiscard]] std::filesystem::path migration_directory() {
    return SB_EASY_MIGRATIONS_DIR;
}

} // namespace

SB_EASY_TEST("SQLite runner applies the canonical migrations idempotently") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::test::require(store.database().applied_migration_count() == 6,
                          "all canonical migrations should be recorded");
    store.database().migrate(migration_directory());
    sbeasy::test::require(store.database().applied_migration_count() == 6,
                          "re-running migrations must be idempotent");
}

SB_EASY_TEST("SQLite runner rejects dirty, missing, and changed migrations") {
    {
        const TemporaryDatabase database;
        sbeasy::Store store{database.path(), migration_directory()};
        store.database().execute(
            "INSERT INTO _sqlx_migrations "
            "(version, description, success, checksum, execution_time) "
            "VALUES (999, 'dirty', FALSE, X'00', 0)");
        sbeasy::test::require_throws<std::runtime_error>(
            [&] { store.database().migrate(migration_directory()); },
            "a dirty SQLx migration must stop startup");

        store.database().execute("UPDATE _sqlx_migrations SET success = TRUE "
                                 "WHERE version = 999");
        sbeasy::test::require_throws<std::runtime_error>(
            [&] { store.database().migrate(migration_directory()); },
            "an applied migration missing from source must stop startup");
    }

    {
        const TemporaryDatabase database;
        sbeasy::Store store{database.path(), migration_directory()};
        store.database().execute("UPDATE _sqlx_migrations SET checksum = X'00' "
                                 "WHERE version = 6");
        sbeasy::test::require_throws<std::runtime_error>(
            [&] { store.database().migrate(migration_directory()); },
            "a changed migration checksum must stop startup");
    }
}

SB_EASY_TEST("profile scripts persist and render through the host repository") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    auto profile = store.find_profile("default");
    sbeasy::test::require(profile.has_value(),
                          "migration should seed the default profile");
    profile->rule_script = R"JS(
function buildRules(context) {
  if (context.host.id !== "self") {
    throw new Error("unexpected host");
  }
  return [{ domain_suffix: [".example.com"], outbound: "direct" }];
}
)JS";
    profile->rule_script_enabled = true;
    const auto saved = store.update_profile(*profile);
    sbeasy::test::require(saved.rule_script_enabled,
                          "script enabled flag should round-trip");

    const auto request = store.render_request_for_host("self");
    sbeasy::test::require(request.rule_script.has_value(),
                          "enabled profile script should reach the renderer");
    sbeasy::test::require(request.host_context.at("id") == "self",
                          "script context should contain the host");

    const sbeasy::ConfigRenderer renderer;
    const auto rendered = renderer.render(request);
    sbeasy::test::require(rendered.at("route").at("rules").at(0).at("outbound") ==
                              "direct",
                          "profile script should replace route rules");
    sbeasy::test::require(
        rendered.at("experimental").at("clash_api").at("external_controller") ==
            "0.0.0.0:9090",
        "host render should inject the controlled Clash endpoint");
}

SB_EASY_TEST("profile CRUD uses the existing config_profiles schema") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::ConfigProfile profile;
    profile.name = "Full profile";
    profile.profile = {{"log", {{"level", "warn"}}}};
    profile.mode = sbeasy::ProfileMode::full;
    const auto created = store.create_profile(std::move(profile));
    sbeasy::test::require(!created.id.empty(), "created profile should receive an id");
    sbeasy::test::require(created.mode == sbeasy::ProfileMode::full,
                          "profile mode should round-trip");

    store.database().execute("UPDATE hosts SET profile_id = '" + created.id +
                             "' WHERE id = 'self'");
    store.database().execute("INSERT INTO proxy_nodes "
                             "(id, tag, node_type, enabled, server, server_port, "
                             "protocol_config, fingerprint) VALUES "
                             "('bad-port', 'bad-port', 'shadowsocks', TRUE, "
                             "'127.0.0.1', 70000, '{}', 'bad-port')");
    const auto full_request = store.render_request_for_host("self");
    sbeasy::test::require(full_request.nodes.empty(),
                          "full profiles must not load managed proxy nodes");

    auto updated = created;
    updated.name = "Renamed profile";
    const auto saved = store.update_profile(std::move(updated));
    sbeasy::test::require(saved.name == "Renamed profile",
                          "updated profile should be returned");
}

SB_EASY_TEST("host CRUD hides secrets and manages outbound assignments") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::Host host;
    host.name = "Remote node";
    host.capabilities = {
        {"runs_singbox", true},
        {"is_wg_member", false},
    };
    host.clash_secret = "do-not-serialize";
    const auto created = store.create_host(std::move(host));
    sbeasy::test::require(!created.id.empty(), "created host should receive an id");
    sbeasy::test::require(created.agent_token.size() == 64,
                          "created host should receive a 64-character token");
    sbeasy::test::require(created.profile_id == "default",
                          "created host should use the default profile");

    const nlohmann::json public_host = created;
    sbeasy::test::require(!public_host.contains("agent_token"),
                          "public host JSON must hide the agent token");
    sbeasy::test::require(!public_host.contains("clash_secret"),
                          "public host JSON must hide the Clash secret");
    sbeasy::test::require(public_host.at("has_token") == true,
                          "public host JSON should expose token presence");

    store.database().execute(
        "INSERT INTO proxy_nodes "
        "(id, tag, node_type, enabled, server, server_port, "
        "protocol_config, fingerprint) VALUES "
        "('node-a', 'a', 'shadowsocks', TRUE, '127.0.0.1', 1001, "
        "'{\"method\":\"aes-128-gcm\",\"password\":\"a\"}', 'node-a'),"
        "('node-b', 'b', 'trojan', TRUE, '127.0.0.1', 1002, "
        "'{\"password\":\"b\"}', 'node-b')");
    store.set_host_outbounds(created.id, {"node-b", "node-a", "node-a"});
    const auto assignments = store.host_outbounds(created.id);
    sbeasy::test::require(assignments == std::vector<std::string>{"node-a", "node-b"},
                          "outbound assignments should be replaced and deduplicated");

    auto found = store.find_host(created.id);
    sbeasy::test::require(found.has_value() && found->assigned_outbounds == 2,
                          "host reads should include the assigned count");
    const auto old_token = found->agent_token;
    const auto new_token = store.rotate_agent_token(created.id);
    sbeasy::test::require(new_token.size() == 64 && new_token != old_token,
                          "token rotation should replace the token");

    found = store.find_host(created.id);
    found->name = "Renamed remote";
    found->enabled = false;
    const auto updated = store.update_host(*found);
    sbeasy::test::require(updated.name == "Renamed remote" && !updated.enabled,
                          "host updates should round-trip");

    store.delete_host(created.id);
    sbeasy::test::require(!store.find_host(created.id).has_value(),
                          "deleted host should disappear");
    sbeasy::test::require_throws<sbeasy::NotFoundError>(
        [&] { static_cast<void>(store.host_outbounds(created.id)); },
        "outbound reads for a deleted host should fail");
    sbeasy::test::require_throws<sbeasy::ValidationError>(
        [&] { store.delete_host("self"); }, "the self host must be protected");
}

SB_EASY_TEST("profile deletion resets assigned hosts to default") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::ConfigProfile profile;
    profile.name = "Temporary profile";
    profile.profile = nlohmann::json::object();
    const auto created_profile = store.create_profile(std::move(profile));
    sbeasy::Host host;
    host.name = "Profile consumer";
    host.capabilities = nlohmann::json::object();
    host.profile_id = created_profile.id;
    const auto created_host = store.create_host(std::move(host));

    store.delete_profile(created_profile.id);
    const auto reloaded = store.find_host(created_host.id);
    sbeasy::test::require(reloaded.has_value() && reloaded->profile_id == "default",
                          "profile consumers should fall back to default");
    sbeasy::test::require(!store.find_profile(created_profile.id).has_value(),
                          "deleted profile should disappear");
    sbeasy::test::require_throws<sbeasy::ValidationError>(
        [&] { store.delete_profile("default"); },
        "the default profile must be protected");
}
