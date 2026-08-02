#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "sbeasy/store.hpp"

namespace sbeasy {

struct WireGuardOptions {
    bool enabled{false};
    std::string interface{"wg0"};
    std::uint16_t port{51820};
    std::string address{"10.59.32.1/24"};
    std::string dns{"10.59.32.1"};
    std::uint32_t mtu{1420};
    std::string external_hostname{"127.0.0.1"};
    std::string egress_interface{"eth0"};
    std::filesystem::path config_directory{"/etc/wireguard"};
};

struct WireGuardKeyPair {
    std::string private_key;
    std::string public_key;
};

struct WireGuardPeerStats {
    std::string public_key;
    std::optional<std::string> endpoint;
    std::optional<std::int64_t> latest_handshake;
    std::int64_t transfer_rx{};
    std::int64_t transfer_tx{};
};

void to_json(nlohmann::json& value, const WireGuardPeerStats& stats);

/// Builds a self-contained QR code SVG for enrollment and WireGuard exports.
[[nodiscard]] std::string qr_svg_for_text(const std::string& text);

class WireGuardService final {
  public:
    WireGuardService(std::shared_ptr<Store> store, WireGuardOptions options);

    [[nodiscard]] static WireGuardKeyPair generate_keypair();
    [[nodiscard]] static std::string generate_preshared_key();
    [[nodiscard]] static std::string
    public_key_from_private(const std::string& private_key);
    [[nodiscard]] static bool peer_expired(const WireGuardPeer& peer);
    [[nodiscard]] static std::vector<WireGuardPeerStats>
    parse_stats(std::string_view dump);

    [[nodiscard]] WireGuardOptions runtime_options() const;
    [[nodiscard]] std::string server_public_key();
    [[nodiscard]] std::vector<WireGuardPeerStats> stats() const;
    [[nodiscard]] std::string
    client_config(const WireGuardPeer& peer);
    [[nodiscard]] std::string qr_svg(const WireGuardPeer& peer);
    [[nodiscard]] std::string server_config();
    [[nodiscard]] Host provision_host(Host host, bool set_default_clash);
    void deprovision_host(const std::string& host_id);
    [[nodiscard]] std::string host_config(const Host& host);

    void startup();
    void sync();
    void shutdown() noexcept;
    void remove_peer(const std::string& public_key) noexcept;

  private:
    [[nodiscard]] WireGuardKeyPair server_keypair();

    std::shared_ptr<Store> store_;
    WireGuardOptions options_;
};

} // namespace sbeasy
