#include "test_support.hpp"

#include <filesystem>
#include <random>
#include <string>
#include <system_error>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/proxy_parser.hpp"
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

SB_EASY_TEST("agent repository isolates tokens, status, commands, and latency") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::Host host;
    host.name = "Agent repository host";
    host.capabilities = nlohmann::json::object();
    const auto created = store.create_host(std::move(host));
    const auto authenticated = store.find_enabled_host_by_token(created.agent_token);
    sbeasy::test::require(authenticated.has_value() && authenticated->id == created.id,
                          "an enabled host token should resolve its owner");
    sbeasy::test::require(!store.find_enabled_host_by_token("").has_value() &&
                              !store.find_enabled_host_by_token("wrong").has_value(),
                          "empty and invalid tokens must not resolve");

    store.update_agent_status(
        created.id, {{"version", "1.12.0"}, {"running", true}, {"etag", "\"etag\""}});
    const auto reported = store.find_host(created.id);
    sbeasy::test::require(reported.has_value() && reported->last_seen.has_value() &&
                              reported->singbox_state.has_value(),
                          "status reports should persist state and liveness");

    const auto command = store.enqueue_host_command(created.id, "reload");
    sbeasy::test::require(store.list_host_commands(created.id, true).size() == 1U,
                          "pending command queries should return queued work");
    sbeasy::test::require(!store.acknowledge_host_command("self", command.id, "done",
                                                          std::string{"wrong host"}),
                          "command acknowledgements must be scoped to their host");
    sbeasy::test::require(store.acknowledge_host_command(created.id, command.id, "done",
                                                         std::string{"reloaded"}),
                          "the owning host should acknowledge its command");
    const auto history = store.list_host_commands(created.id);
    sbeasy::test::require(
        history.size() == 1U && history.front().status == "done" &&
            history.front().result == "reloaded" &&
            history.front().acked_at.has_value(),
        "command history should retain result and acknowledgement time");

    store.database().execute("INSERT INTO proxy_nodes "
                             "(id, tag, node_type, enabled, server, server_port, "
                             "protocol_config, fingerprint) VALUES "
                             "('latency-node', 'latency-node', 'shadowsocks', TRUE, "
                             "'127.0.0.1', 8388, "
                             "'{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                             "'latency-node')");
    sbeasy::test::require(store.update_proxy_latencies(
                              {{"latency-node", 12.5}, {"missing-node", nullptr}}) ==
                              1U,
                          "latency reports should count only matching nodes");
    store.update_proxy_latency("latency-node", 7.25);
    const auto measured = store.find_proxy_node("latency-node");
    sbeasy::test::require(
        measured.has_value() && measured->latency == 7.25 &&
            measured->last_latency_test.has_value(),
        "panel latency tests should update a node by id and record the test time");
    sbeasy::test::require_throws<sbeasy::NotFoundError>(
        [&] { store.update_proxy_latency("missing-node", std::nullopt); },
        "panel latency updates should reject an unknown node id");

    auto disabled = *store.find_host(created.id);
    disabled.enabled = false;
    static_cast<void>(store.update_host(std::move(disabled)));
    sbeasy::test::require(
        !store.find_enabled_host_by_token(created.agent_token).has_value(),
        "disabled hosts must lose agent API access immediately");
}

SB_EASY_TEST("proxy repository CRUD and imports preserve Rust API shape") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::ProxyRecord manual;
    manual.tag = "Manual SS";
    manual.node_type = "shadowsocks";
    manual.enabled = true;
    manual.server = "manual.example.com";
    manual.server_port = 8388;
    manual.protocol_config = {
        {"method", "aes-256-gcm"},
        {"password", "manual-secret"},
    };
    const auto created = store.create_proxy_node(std::move(manual));
    sbeasy::test::require(created.fingerprint.size() == 64U,
                          "manual proxy should receive a fingerprint");
    const nlohmann::json serialized = created;
    sbeasy::test::require(serialized.at("node_type") == "shadowsocks" &&
                              serialized.at("protocol_config").is_string(),
                          "proxy JSON should match the Rust model contract");

    auto updated = created;
    updated.tag = "Manual SS renamed";
    updated.enabled = false;
    const auto saved = store.update_proxy_node(std::move(updated));
    sbeasy::test::require(saved.tag == "Manual SS renamed" && !saved.enabled,
                          "proxy updates should round-trip");

    const auto imported = sbeasy::parse_subscription_body(
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@rotate.example.com:443#Provider");
    auto first = store.upsert_proxy_nodes(imported, std::nullopt);
    sbeasy::test::require(first.added == 1U && first.updated == 0U &&
                              first.errors.empty(),
                          "first provider import should insert a node");

    const auto rotated = sbeasy::parse_subscription_body(
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@new.example.com:443#Provider");
    auto second = store.upsert_proxy_nodes(rotated, std::nullopt);
    sbeasy::test::require(second.added == 0U && second.updated == 1U &&
                              second.errors.empty(),
                          "rotated provider addresses should reconcile by tag");
    const auto nodes = store.list_proxy_nodes();
    sbeasy::test::require(nodes.size() == 2U && nodes.at(1).server == "new.example.com",
                          "proxy list should expose the reconciled node");

    store.delete_proxy_node(created.id);
    sbeasy::test::require(!store.find_proxy_node(created.id).has_value(),
                          "deleted proxy should disappear");
}

SB_EASY_TEST("subscription repository records source attribution and fetch results") {
    const TemporaryDatabase database;
    sbeasy::Store store{database.path(), migration_directory()};

    sbeasy::Subscription subscription;
    subscription.name = "Provider";
    subscription.url = "https://provider.example/sub";
    subscription.refresh_interval = 1'800;
    const auto created = store.create_subscription(std::move(subscription));
    const auto parsed = sbeasy::parse_subscription_body(
        "trojan://secret@trojan.example.com:443#Provider-Trojan");
    const auto imported = store.upsert_proxy_nodes(parsed, created.id);
    sbeasy::test::require(imported.added == 1U,
                          "subscription import should insert its node");

    const sbeasy::SubscriptionFetchResult result{
        .added = imported.added,
        .updated = imported.updated,
        .skipped = 0,
        .found = parsed.size(),
        .errors = imported.errors,
    };
    store.record_subscription_fetch(created.id, result);
    const auto reloaded = store.find_subscription(created.id);
    sbeasy::test::require(reloaded.has_value() &&
                              reloaded->last_fetched_at.has_value() &&
                              reloaded->last_fetch_result.has_value(),
                          "fetch metadata should persist on the subscription");
    const auto metadata = nlohmann::json::parse(*reloaded->last_fetch_result);
    sbeasy::test::require(metadata.at("total") == 1,
                          "fetch metadata should retain parsed total");
    const auto nodes = store.list_proxy_nodes();
    sbeasy::test::require(nodes.size() == 1U &&
                              nodes.front().subscription_id == created.id,
                          "imported nodes should retain source attribution");

    auto disabled = *reloaded;
    disabled.enabled = false;
    disabled.refresh_interval = 7'200;
    const auto saved = store.update_subscription(std::move(disabled));
    sbeasy::test::require(!saved.enabled && saved.refresh_interval == 7'200,
                          "subscription updates should round-trip");
    store.delete_subscription(created.id);
    sbeasy::test::require(!store.find_subscription(created.id).has_value(),
                          "deleted subscription should disappear");
}
