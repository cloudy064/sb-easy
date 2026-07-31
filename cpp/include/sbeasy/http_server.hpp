#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace sbeasy {

class Store;

struct HttpServerOptions {
    std::string address{"127.0.0.1"};
    std::uint16_t port{51821};
    std::size_t threads{1};
    std::string public_server;
    std::string config_hash_seed;
    std::string legacy_agent_token;
    std::string jwt_secret;
    std::string admin_password{"admin"};
    std::string clash_api_url{"http://127.0.0.1:9090"};
    std::string clash_api_secret;
    bool singbox_managed{false};
    std::string singbox_binary{"sing-box"};
    std::string self_singbox_config_path;
    std::uint64_t self_singbox_interval_seconds{10};
    bool singbox_validate_config{true};
    bool wireguard_enabled{false};
    std::string wireguard_interface{"wg0"};
    std::uint16_t wireguard_port{51820};
    std::string wireguard_address{"10.59.32.1/24"};
    std::string wireguard_dns{"10.59.32.1"};
    std::uint32_t wireguard_mtu{1420};
    std::string wireguard_egress{"eth0"};
    std::string external_hostname{"127.0.0.1"};
    std::string wireguard_config_directory{"/etc/wireguard"};
    std::string static_directory{"frontend/dist"};
    std::string cors_origins;
};

void register_http_routes(const std::shared_ptr<Store>& store,
                          const HttpServerOptions& options = {});
void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options);

} // namespace sbeasy
