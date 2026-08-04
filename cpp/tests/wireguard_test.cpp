#include "test_support.hpp"

#include <filesystem>
#include <random>
#include <string>
#include <system_error>

#include "sbeasy/store.hpp"
#include "sbeasy/wireguard.hpp"

namespace {

class WireGuardFixture final {
  public:
    WireGuardFixture()
        : directory_(make_directory()),
          database_(directory_ / "store.db"),
          store_(std::make_shared<sbeasy::Store>(
              database_, std::filesystem::path{SB_EASY_MIGRATIONS_DIR})) {}

    ~WireGuardFixture() {
        store_.reset();
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& directory() const noexcept {
        return directory_;
    }

    [[nodiscard]] const std::shared_ptr<sbeasy::Store>& store() const noexcept {
        return store_;
    }

  private:
    [[nodiscard]] static std::filesystem::path make_directory() {
        auto path = std::filesystem::temp_directory_path() /
                    ("sb-easy-wireguard-" +
                     std::to_string(std::random_device{}()));
        std::filesystem::create_directories(path);
        return path;
    }

    std::filesystem::path directory_;
    std::filesystem::path database_;
    std::shared_ptr<sbeasy::Store> store_;
};

} // namespace

SB_EASY_TEST("WireGuard keys configs stats and peer repository are compatible") {
    WireGuardFixture fixture;
    const auto keys = sbeasy::WireGuardService::generate_keypair();
    sbeasy::test::require(
        keys.private_key.size() == 44U && keys.public_key.size() == 44U &&
            sbeasy::WireGuardService::public_key_from_private(keys.private_key) ==
                keys.public_key,
        "X25519 WireGuard public keys must derive from the persisted private key");

    sbeasy::WireGuardPeer peer{
        .id = {},
        .name = "Phone client",
        .private_key = keys.private_key,
        .public_key = keys.public_key,
        .preshared_key =
            sbeasy::WireGuardService::generate_preshared_key(),
        .address =
            fixture.store()->next_wireguard_address("10.59.32.1/24"),
        .dns = "10.59.32.1",
        .enabled = true,
        .persistent_keepalive = 25,
        .allowed_ips = "0.0.0.0/0, ::/0",
        .expire_at = std::nullopt,
        .quota_bytes = 0,
        .created_at = {},
        .updated_at = {},
        .notes = "fixture",
        .host_id = std::nullopt,
    };
    peer = fixture.store()->create_wireguard_peer(std::move(peer));
    sbeasy::test::require(
        peer.address == "10.59.32.2/24" &&
            fixture.store()->next_wireguard_address("10.59.32.1/24") ==
                "10.59.32.3/24",
        "peer allocation should skip addresses already used in the /24");

    sbeasy::WireGuardService service(
        fixture.store(),
        {
            .enabled = false,
            .interface = "wg-test",
            .port = 51'820,
            .address = "10.59.32.1/24",
            .dns = "10.59.32.1",
            .mtu = 1'380,
            .external_hostname = "vpn.example.com",
            .config_directory = fixture.directory(),
        });
    const auto client = service.client_config(peer);
    sbeasy::test::require(
        client.find("PrivateKey = " + keys.private_key) != std::string::npos &&
            client.find("Endpoint = vpn.example.com:51820") !=
                std::string::npos &&
            client.find("MTU = 1420") != std::string::npos,
        "client configs should contain peer credentials and runtime endpoint");
    const auto qr = service.qr_svg(peer);
    sbeasy::test::require(
        qr.starts_with("<?xml") && qr.find("<svg") != std::string::npos &&
            qr.find("<path") != std::string::npos,
        "WireGuard QR responses should be real SVG matrices");
    const auto server = service.server_config();
    sbeasy::test::require(
        server.find("PublicKey = " + keys.public_key) != std::string::npos &&
            service.server_public_key() ==
                sbeasy::WireGuardService(fixture.store(), {}).server_public_key(),
        "server configs should include peers and persist the server keypair");

    peer.enabled = false;
    peer.notes = "updated";
    peer = fixture.store()->update_wireguard_peer(std::move(peer));
    sbeasy::test::require(!peer.enabled && peer.notes == "updated",
                          "WireGuard peer updates should round-trip");
    fixture.store()->set_wireguard_peer_enabled(peer.id, true);
    sbeasy::test::require(fixture.store()->find_wireguard_peer(peer.id)->enabled,
                          "WireGuard enable toggles should persist");

    const auto stats = sbeasy::WireGuardService::parse_stats(
        "server-private\tserver-public\t51820\toff\n"
        "peer-public\tpsk\t198.51.100.1:1234\t10.0.0.2/32\t"
        "1700000000\t123\t456\t25\n");
    sbeasy::test::require(
        stats.size() == 1U && stats.front().public_key == "peer-public" &&
            stats.front().endpoint == "198.51.100.1:1234" &&
            stats.front().transfer_rx == 123 &&
            stats.front().transfer_tx == 456,
        "wg dump parser should expose peer endpoint, handshake, and counters");

    fixture.store()->delete_wireguard_peer(peer.id);
    sbeasy::test::require(fixture.store()->list_wireguard_peers().empty(),
                          "WireGuard peer deletion should persist");
}

SB_EASY_TEST("managed devices reuse standalone peers as sing-box endpoints") {
    WireGuardFixture fixture;
    sbeasy::Host host;
    host.name = "Phone client";
    host.capabilities = {
        {"platform", "android"},
        {"runs_singbox", true},
    };
    host = fixture.store()->create_host(std::move(host));

    const auto keys = sbeasy::WireGuardService::generate_keypair();
    auto peer = fixture.store()->create_wireguard_peer({
        .id = {},
        .name = host.name,
        .private_key = keys.private_key,
        .public_key = keys.public_key,
        .preshared_key = sbeasy::WireGuardService::generate_preshared_key(),
        .address = "10.59.32.4/24",
        .dns = "10.59.32.1",
        .enabled = true,
        .persistent_keepalive = 25,
        .allowed_ips = "0.0.0.0/0, ::/0",
        .expire_at = std::nullopt,
        .quota_bytes = 0,
        .created_at = {},
        .updated_at = {},
        .notes = std::nullopt,
        .host_id = std::nullopt,
    });
    sbeasy::WireGuardService service(fixture.store(),
                                     {
                                         .enabled = false,
                                         .port = 51'820,
                                         .address = "10.59.32.1/24",
                                         .mtu = 1'420,
                                         .external_hostname = "vpn.example.com",
                                         .config_directory = fixture.directory(),
                                     });

    host = service.provision_host(std::move(host), false);
    const auto peers = fixture.store()->list_wireguard_peers();
    const auto endpoint = service.client_endpoint(host);
    sbeasy::test::require(
        peers.size() == 1U && peers.front().id == peer.id &&
            peers.front().host_id == host.id &&
            peers.front().allowed_ips == "10.59.32.0/24",
        "unified enrollment should link the existing peer without changing keys");
    sbeasy::test::require(
        endpoint.has_value() && endpoint->at("type") == "wireguard" &&
            endpoint->at("address") == nlohmann::json::array({"10.59.32.4/24"}) &&
            endpoint->at("peers")[0]["address"] == "vpn.example.com" &&
            endpoint->at("peers")[0]["allowed_ips"] ==
                nlohmann::json::array({"10.59.32.0/24"}),
        "sing-box endpoint should carry the linked peer and intranet route");
}
