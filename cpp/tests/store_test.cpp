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

    sbeasy::ConfigProfile profile{
        .name = "Full profile",
        .profile = {{"log", {{"level", "warn"}}}},
        .mode = sbeasy::ProfileMode::full,
    };
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
