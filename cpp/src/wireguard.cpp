#include "sbeasy/wireguard.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <spawn.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <qrcodegen.hpp>
#include <sys/wait.h>
#include <unistd.h>

#include "sbeasy/atomic_file.hpp"

extern char** environ;

namespace sbeasy {
namespace {

using nlohmann::json;

struct CommandResult {
    int exit_code{-1};
    std::string output;
};

[[nodiscard]] std::vector<char*>
native_arguments(const std::vector<std::string>& arguments) {
    std::vector<char*> result;
    result.reserve(arguments.size() + 1U);
    for (const auto& argument : arguments) {
        result.push_back(const_cast<char*>(argument.c_str()));
    }
    result.push_back(nullptr);
    return result;
}

[[nodiscard]] CommandResult
run_command(const std::vector<std::string>& arguments, bool check = true) {
    if (arguments.empty() || arguments.front().empty()) {
        throw std::invalid_argument("process command is empty");
    }
    std::array<int, 2> output_pipe{};
    if (::pipe2(output_pipe.data(), O_CLOEXEC) != 0) {
        throw std::runtime_error(std::string{"create process pipe failed: "} +
                                 std::strerror(errno));
    }

    posix_spawn_file_actions_t actions{};
    const int init_error = ::posix_spawn_file_actions_init(&actions);
    if (init_error != 0) {
        ::close(output_pipe[0]);
        ::close(output_pipe[1]);
        throw std::runtime_error(std::string{"initialize process failed: "} +
                                 std::strerror(init_error));
    }
    static_cast<void>(::posix_spawn_file_actions_adddup2(
        &actions, output_pipe[1], STDOUT_FILENO));
    static_cast<void>(::posix_spawn_file_actions_adddup2(
        &actions, output_pipe[1], STDERR_FILENO));
    static_cast<void>(
        ::posix_spawn_file_actions_addclose(&actions, output_pipe[0]));
    static_cast<void>(
        ::posix_spawn_file_actions_addclose(&actions, output_pipe[1]));

    auto native = native_arguments(arguments);
    pid_t process{};
    const int spawn_error =
        ::posix_spawnp(&process, native.front(), &actions, nullptr,
                       native.data(), environ);
    ::posix_spawn_file_actions_destroy(&actions);
    ::close(output_pipe[1]);
    if (spawn_error != 0) {
        ::close(output_pipe[0]);
        throw std::runtime_error(arguments.front() + ": " +
                                 std::strerror(spawn_error));
    }

    std::string output;
    std::array<char, 4'096> buffer{};
    while (true) {
        const auto count =
            ::read(output_pipe[0], buffer.data(), buffer.size());
        if (count > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(output_pipe[0]);

    int status{};
    while (::waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            throw std::runtime_error(arguments.front() + ": wait failed");
        }
    }
    const auto exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (check && exit_code != 0) {
        throw std::runtime_error(arguments.front() + " exited with code " +
                                 std::to_string(exit_code) + ": " + output);
    }
    return {.exit_code = exit_code, .output = std::move(output)};
}

[[nodiscard]] std::string base64_encode(
    const std::array<unsigned char, 32>& bytes) {
    std::array<unsigned char, 45> encoded{};
    const auto length = EVP_EncodeBlock(encoded.data(), bytes.data(),
                                        static_cast<int>(bytes.size()));
    if (length <= 0) {
        throw std::runtime_error("WireGuard base64 encoding failed");
    }
    return {reinterpret_cast<const char*>(encoded.data()),
            static_cast<std::size_t>(length)};
}

[[nodiscard]] std::array<unsigned char, 32>
base64_decode(const std::string& value) {
    if (value.size() != 44U) {
        throw ValidationError("WireGuard key must encode 32 bytes");
    }
    std::array<unsigned char, 36> decoded{};
    const auto length = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (length != 33 || value.back() != '=') {
        throw ValidationError("Invalid WireGuard key");
    }
    std::array<unsigned char, 32> result{};
    std::copy_n(decoded.begin(), result.size(), result.begin());
    return result;
}

[[nodiscard]] std::string subnet_cidr(const std::string& address) {
    const auto slash = address.find('/');
    if (slash == std::string::npos) {
        return address;
    }
    auto host = address.substr(0, slash);
    const auto prefix = address.substr(slash + 1U);
    if (prefix == "24") {
        if (const auto dot = host.rfind('.'); dot != std::string::npos) {
            host.replace(dot + 1U, std::string::npos, "0");
        }
    }
    return host + "/" + prefix;
}

[[nodiscard]] std::string peer_ip(const std::string& address) {
    return address.substr(0, address.find('/'));
}

[[nodiscard]] std::optional<std::uint16_t>
endpoint_port(const std::optional<std::string>& endpoint) {
    if (!endpoint.has_value()) {
        return std::nullopt;
    }
    const auto colon = endpoint->rfind(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    std::uint16_t port{};
    const auto text = std::string_view{*endpoint}.substr(colon + 1U);
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), port);
    return error == std::errc{} && end == text.data() + text.size() &&
                   port > 0U
               ? std::optional<std::uint16_t>{port}
               : std::nullopt;
}

[[nodiscard]] bool parse_number(std::string_view value,
                                std::int64_t& output) {
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), output);
    return error == std::errc{} && end == value.data() + value.size();
}

[[nodiscard]] std::optional<std::chrono::system_clock::time_point>
parse_rfc3339(std::string value) {
    if (value.size() < 19U) {
        return std::nullopt;
    }
    std::tm parsed{};
    std::istringstream input{value.substr(0, 19)};
    input >> std::get_time(&parsed, "%Y-%m-%dT%H:%M:%S");
    if (input.fail()) {
        return std::nullopt;
    }
    auto seconds = ::timegm(&parsed);
    auto zone = value.find_first_of("Z+-", 19U);
    if (zone != std::string::npos && value[zone] != 'Z' &&
        zone + 5U < value.size() && value[zone + 3U] == ':') {
        int hours{};
        int minutes{};
        const auto hour_text = value.substr(zone + 1U, 2U);
        const auto minute_text = value.substr(zone + 4U, 2U);
        const auto [hour_end, hour_error] = std::from_chars(
            hour_text.data(), hour_text.data() + hour_text.size(), hours);
        const auto [minute_end, minute_error] = std::from_chars(
            minute_text.data(), minute_text.data() + minute_text.size(), minutes);
        if (hour_error != std::errc{} ||
            hour_end != hour_text.data() + hour_text.size() ||
            minute_error != std::errc{} ||
            minute_end != minute_text.data() + minute_text.size()) {
            return std::nullopt;
        }
        const auto offset = hours * 3'600 + minutes * 60;
        seconds += value[zone] == '+' ? -offset : offset;
    }
    return std::chrono::system_clock::from_time_t(seconds);
}

[[nodiscard]] std::string svg_for_text(const std::string& text) {
    const auto code = qrcodegen::QrCode::encodeText(
        text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    constexpr int border = 4;
    const auto size = code.getSize();
    std::ostringstream svg;
    svg << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 "
        << size + border * 2 << ' ' << size + border * 2
        << "\" shape-rendering=\"crispEdges\">"
           "<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>"
           "<path d=\"";
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            if (code.getModule(x, y)) {
                svg << "M" << x + border << ',' << y + border << "h1v1h-1z";
            }
        }
    }
    svg << "\" fill=\"#000\"/></svg>";
    return svg.str();
}

} // namespace

std::string qr_svg_for_text(const std::string& text) {
    return svg_for_text(text);
}

void to_json(nlohmann::json& value, const WireGuardPeerStats& stats) {
    value = {
        {"public_key", stats.public_key},
        {"endpoint", stats.endpoint},
        {"latest_handshake", stats.latest_handshake},
        {"transfer_rx", stats.transfer_rx},
        {"transfer_tx", stats.transfer_tx},
    };
}

WireGuardService::WireGuardService(std::shared_ptr<Store> store,
                                   WireGuardOptions options)
    : store_(std::move(store)), options_(std::move(options)) {
    if (!store_) {
        throw std::invalid_argument("WireGuard store is required");
    }
}

WireGuardKeyPair WireGuardService::generate_keypair() {
    std::array<unsigned char, 32> private_bytes{};
    if (RAND_bytes(private_bytes.data(),
                   static_cast<int>(private_bytes.size())) != 1) {
        throw std::runtime_error("WireGuard key generation failed");
    }
    const auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>{
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                     private_bytes.data(), private_bytes.size()),
        EVP_PKEY_free};
    if (!key) {
        throw std::runtime_error("WireGuard X25519 private key failed");
    }
    std::array<unsigned char, 32> public_bytes{};
    std::size_t public_size = public_bytes.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), public_bytes.data(),
                                    &public_size) != 1 ||
        public_size != public_bytes.size()) {
        throw std::runtime_error("WireGuard public key derivation failed");
    }
    return {
        .private_key = base64_encode(private_bytes),
        .public_key = base64_encode(public_bytes),
    };
}

std::string WireGuardService::generate_preshared_key() {
    std::array<unsigned char, 32> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("WireGuard preshared key generation failed");
    }
    return base64_encode(bytes);
}

std::string
WireGuardService::public_key_from_private(const std::string& private_key) {
    const auto private_bytes = base64_decode(private_key);
    const auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>{
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                     private_bytes.data(), private_bytes.size()),
        EVP_PKEY_free};
    if (!key) {
        throw ValidationError("Invalid WireGuard private key");
    }
    std::array<unsigned char, 32> public_bytes{};
    std::size_t public_size = public_bytes.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), public_bytes.data(),
                                    &public_size) != 1 ||
        public_size != public_bytes.size()) {
        throw ValidationError("Invalid WireGuard private key");
    }
    return base64_encode(public_bytes);
}

bool WireGuardService::peer_expired(const WireGuardPeer& peer) {
    if (!peer.expire_at.has_value() || peer.expire_at->empty()) {
        return false;
    }
    const auto expiration = parse_rfc3339(*peer.expire_at);
    return expiration.has_value() &&
           *expiration < std::chrono::system_clock::now();
}

std::vector<WireGuardPeerStats>
WireGuardService::parse_stats(std::string_view dump) {
    std::vector<WireGuardPeerStats> stats;
    std::istringstream lines{std::string{dump}};
    std::string line;
    while (std::getline(lines, line)) {
        std::vector<std::string_view> fields;
        std::string_view remaining{line};
        while (true) {
            const auto tab = remaining.find('\t');
            fields.push_back(remaining.substr(0, tab));
            if (tab == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(tab + 1U);
        }
        if (fields.size() < 8U) {
            continue;
        }
        std::int64_t handshake{};
        std::int64_t received{};
        std::int64_t transmitted{};
        static_cast<void>(parse_number(fields[4], handshake));
        static_cast<void>(parse_number(fields[5], received));
        static_cast<void>(parse_number(fields[6], transmitted));
        stats.push_back({
            .public_key = std::string{fields[0]},
            .endpoint =
                fields[2].empty() || fields[2] == "(none)"
                    ? std::nullopt
                    : std::optional<std::string>{std::string{fields[2]}},
            .latest_handshake =
                handshake > 0 ? std::optional<std::int64_t>{handshake} :
                                std::nullopt,
            .transfer_rx = received,
            .transfer_tx = transmitted,
        });
    }
    return stats;
}

WireGuardOptions WireGuardService::runtime_options() const {
    auto runtime = options_;
    const auto saved = store_->app_setting("wireguard_interface");
    if (!saved.has_value() || !saved->is_object()) {
        return runtime;
    }
    runtime.interface = saved->value("interface", runtime.interface);
    runtime.address = saved->value("address", runtime.address);
    runtime.dns = saved->value("dns", runtime.dns);
    const auto port = saved->value("listen_port",
                                   static_cast<std::uint64_t>(runtime.port));
    const auto mtu = saved->value("mtu",
                                  static_cast<std::uint64_t>(runtime.mtu));
    if (port > 0U && port <= 65'535U) {
        runtime.port = static_cast<std::uint16_t>(port);
    }
    if (mtu <= 65'535U) {
        runtime.mtu = static_cast<std::uint32_t>(mtu);
    }
    return runtime;
}

WireGuardKeyPair WireGuardService::server_keypair() {
    if (const auto saved = store_->app_setting("wg_server_key");
        saved.has_value() && saved->is_object()) {
        const auto private_key = saved->value("private_key", "");
        const auto public_key = saved->value("public_key", "");
        if (!private_key.empty()) {
            return {
                .private_key = private_key,
                .public_key = public_key.empty()
                                  ? public_key_from_private(private_key)
                                  : public_key,
            };
        }
    }
    auto generated = generate_keypair();
    store_->set_app_setting(
        "wg_server_key",
        json{{"private_key", generated.private_key},
             {"public_key", generated.public_key}});
    return generated;
}

std::string WireGuardService::server_public_key() {
    return server_keypair().public_key;
}

std::vector<WireGuardPeerStats> WireGuardService::stats() const {
    const auto runtime = runtime_options();
    return parse_stats(
        run_command({"wg", "show", runtime.interface, "dump"}).output);
}

std::string WireGuardService::client_config(const WireGuardPeer& peer) {
    const auto runtime = runtime_options();
    std::ostringstream config;
    config << "# Client: " << peer.name << "\n[Interface]\n"
           << "PrivateKey = " << peer.private_key << '\n'
           << "Address = " << peer.address << '\n'
           << "DNS = " << peer.dns << '\n';
    if (runtime.mtu > 0U) {
        config << "MTU = " << runtime.mtu << '\n';
    }
    config << "\n[Peer]\n"
           << "PublicKey = " << server_public_key() << '\n';
    if (peer.preshared_key.has_value() && !peer.preshared_key->empty()) {
        config << "PresharedKey = " << *peer.preshared_key << '\n';
    }
    config << "AllowedIPs = " << peer.allowed_ips << '\n'
           << "Endpoint = " << runtime.external_hostname << ':' << runtime.port
           << '\n';
    if (peer.persistent_keepalive > 0) {
        config << "PersistentKeepalive = " << peer.persistent_keepalive << '\n';
    }
    return config.str();
}

std::optional<json> WireGuardService::client_endpoint(const Host& host) {
    const auto peers = store_->list_wireguard_peers();
    const auto found = std::ranges::find(peers, std::optional<std::string>{host.id},
                                         &WireGuardPeer::host_id);
    if (found == peers.end() || !found->enabled || peer_expired(*found)) {
        return std::nullopt;
    }

    const auto runtime = runtime_options();
    json endpoint{
        {"type", "wireguard"},
        {"tag", "sb-easy-network"},
        {"address", json::array({found->address})},
        {"private_key", found->private_key},
        {"peers",
         json::array({
             {
                 {"address", runtime.external_hostname},
                 {"port", runtime.port},
                 {"public_key", server_public_key()},
                 {"allowed_ips", json::array({subnet_cidr(runtime.address)})},
                 {"persistent_keepalive_interval", found->persistent_keepalive},
             },
         })},
    };
    if (runtime.mtu > 0U) {
        endpoint["mtu"] = runtime.mtu;
    }
    if (found->preshared_key.has_value() && !found->preshared_key->empty()) {
        endpoint["peers"][0]["pre_shared_key"] = *found->preshared_key;
    }
    return endpoint;
}

std::string WireGuardService::qr_svg(const WireGuardPeer& peer) {
    return qr_svg_for_text(client_config(peer));
}

std::string WireGuardService::server_config() {
    const auto runtime = runtime_options();
    std::vector<WireGuardPeerStats> current_stats;
    try {
        current_stats = stats();
    } catch (const std::exception&) {
    }
    std::ostringstream config;
    config << "# Generated by sb-easy\n\n[Interface]\n"
           << "PrivateKey = " << server_keypair().private_key << '\n'
           << "ListenPort = " << runtime.port << '\n';
    for (const auto& peer : store_->list_wireguard_peers()) {
        if (!peer.enabled || peer_expired(peer)) {
            continue;
        }
        const auto found =
            std::ranges::find(current_stats, peer.public_key,
                              &WireGuardPeerStats::public_key);
        if (peer.quota_bytes > 0 && found != current_stats.end() &&
            found->transfer_rx + found->transfer_tx >= peer.quota_bytes) {
            continue;
        }
        config << "\n# Client: " << peer.name << "\n[Peer]\n"
               << "PublicKey = " << peer.public_key << '\n';
        if (peer.preshared_key.has_value() && !peer.preshared_key->empty()) {
            config << "PresharedKey = " << *peer.preshared_key << '\n';
        }
        config << "AllowedIPs = " << peer_ip(peer.address) << "/32\n";
        if (peer.persistent_keepalive > 0) {
            config << "PersistentKeepalive = " << peer.persistent_keepalive
                   << '\n';
        }
    }
    return config.str();
}

Host WireGuardService::provision_host(Host host, bool set_default_clash) {
    auto existing = store_->list_wireguard_peers();
    auto found = std::ranges::find(existing, host.id,
                                   &WireGuardPeer::host_id);
    WireGuardPeer peer;
    if (found != existing.end()) {
        peer = *found;
    } else {
        const auto runtime = runtime_options();
        // A device may already have a standalone WireGuard identity created
        // before unified enrollment existed. Reuse an exact-name, unlinked
        // peer instead of silently allocating a second address and keypair.
        found = std::ranges::find_if(existing, [&host](const auto& candidate) {
            return !candidate.host_id.has_value() && candidate.name == host.name;
        });
        if (found != existing.end()) {
            peer = *found;
            peer.host_id = host.id;
            peer.allowed_ips = subnet_cidr(runtime.address);
            peer.enabled = true;
            peer = store_->update_wireguard_peer(std::move(peer));
        } else {
            const auto keys = generate_keypair();
            const auto allocated = store_->next_wireguard_address(runtime.address);
            const auto ip = peer_ip(allocated);
            peer = store_->create_wireguard_peer({
                .id = {},
                .name = "host: " + host.name,
                .private_key = keys.private_key,
                .public_key = keys.public_key,
                .preshared_key = generate_preshared_key(),
                .address = ip + "/32",
                .dns = "",
                .enabled = true,
                .persistent_keepalive = 25,
                .allowed_ips = subnet_cidr(runtime.address),
                .expire_at = std::nullopt,
                .quota_bytes = 0,
                .created_at = {},
                .updated_at = {},
                .notes = std::nullopt,
                .host_id = host.id,
            });
        }
    }
    host.wg_address = peer.address;
    host.wg_public_key = peer.public_key;
    if (set_default_clash && !host.clash_api.has_value()) {
        host.clash_api = "http://" + peer_ip(peer.address) + ":9090";
    }
    return store_->update_host(std::move(host));
}

void WireGuardService::deprovision_host(const std::string& host_id) {
    const auto peers = store_->list_wireguard_peers();
    const auto found =
        std::ranges::find(peers, std::optional<std::string>{host_id},
                          &WireGuardPeer::host_id);
    if (found == peers.end()) {
        return;
    }
    remove_peer(found->public_key);
    store_->delete_wireguard_peer(found->id);
}

std::string WireGuardService::host_config(const Host& host) {
    const auto peers = store_->list_wireguard_peers();
    const auto found =
        std::ranges::find(peers, std::optional<std::string>{host.id},
                          &WireGuardPeer::host_id);
    if (found == peers.end()) {
        throw NotFoundError("Host has no WireGuard peer");
    }
    const auto runtime = runtime_options();
    std::ostringstream config;
    auto label = found->name;
    if (label.starts_with("host: ")) {
        label.erase(0, 6);
    }
    config << "# sb-easy managed host: " << label << "\n[Interface]\n"
           << "PrivateKey = " << found->private_key << '\n'
           << "Address = " << found->address << '\n';
    if (runtime.mtu > 0U) {
        config << "MTU = " << runtime.mtu << '\n';
    }
    if (const auto port = endpoint_port(host.wg_endpoint); port.has_value()) {
        config << "ListenPort = " << *port << '\n';
    }
    config << "\n# Hub (central server)\n[Peer]\n"
           << "PublicKey = " << server_public_key() << '\n';
    if (found->preshared_key.has_value() && !found->preshared_key->empty()) {
        config << "PresharedKey = " << *found->preshared_key << '\n';
    }
    config << "AllowedIPs = " << subnet_cidr(runtime.address) << '\n'
           << "Endpoint = " << runtime.external_hostname << ':' << runtime.port
           << "\nPersistentKeepalive = 25\n";

    const auto this_has_endpoint = endpoint_port(host.wg_endpoint).has_value();
    for (const auto& other : store_->list_hosts()) {
        if (other.id == host.id || !other.enabled ||
            !other.wg_public_key.has_value() ||
            !other.wg_address.has_value()) {
            continue;
        }
        const auto other_has_endpoint =
            endpoint_port(other.wg_endpoint).has_value();
        if (!other_has_endpoint && !this_has_endpoint) {
            continue;
        }
        config << "\n# Mesh: " << other.name << "\n[Peer]\n"
               << "PublicKey = " << *other.wg_public_key << '\n'
               << "AllowedIPs = " << peer_ip(*other.wg_address) << "/32\n";
        if (other_has_endpoint) {
            config << "Endpoint = " << *other.wg_endpoint << '\n';
        }
        config << "PersistentKeepalive = 25\n";
    }
    return config.str();
}

void WireGuardService::sync() {
    if (!options_.enabled) {
        return;
    }
    const auto runtime = runtime_options();
    std::filesystem::create_directories(runtime.config_directory);
    const auto path =
        runtime.config_directory / (runtime.interface + ".conf");
    atomic_replace_file(path, server_config());
    static_cast<void>(
        run_command({"wg", "syncconf", runtime.interface, path.string()}));
}

void WireGuardService::startup() {
    if (!options_.enabled) {
        return;
    }
    const auto runtime = runtime_options();
    std::filesystem::create_directories(runtime.config_directory);
    const auto path =
        runtime.config_directory / (runtime.interface + ".conf");
    atomic_replace_file(path, server_config());
    const auto exists =
        run_command({"ip", "link", "show", runtime.interface}, false).exit_code == 0;
    if (exists) {
        static_cast<void>(
            run_command({"wg", "syncconf", runtime.interface, path.string()}));
    } else {
        static_cast<void>(run_command(
            {"ip", "link", "add", runtime.interface, "type", "wireguard"}));
        if (runtime.mtu > 0U) {
            static_cast<void>(
                run_command({"ip", "link", "set", runtime.interface, "mtu",
                             std::to_string(runtime.mtu)}));
        }
        static_cast<void>(run_command({"ip", "address", "add", runtime.address,
                                       "dev", runtime.interface}));
        static_cast<void>(
            run_command({"ip", "link", "set", "up", runtime.interface}));
        static_cast<void>(
            run_command({"wg", "setconf", runtime.interface, path.string()}));
    }

    static_cast<void>(
        run_command({"sysctl", "-w", "net.ipv4.ip_forward=1"}, false));
    const auto subnet = subnet_cidr(runtime.address);
    const std::vector<std::string> masquerade{
        "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet,
        "-o", runtime.egress_interface, "-j", "MASQUERADE"};
    if (run_command(masquerade, false).exit_code != 0) {
        auto add = masquerade;
        add[3] = "-A";
        static_cast<void>(run_command(add, false));
    }
    for (const auto& direction : {std::string{"-i"}, std::string{"-o"}}) {
        const std::vector<std::string> check{
            "iptables", "-C", "FORWARD", direction, runtime.interface,
            "-j", "ACCEPT"};
        if (run_command(check, false).exit_code != 0) {
            auto add = check;
            add[1] = "-A";
            static_cast<void>(run_command(add, false));
        }
    }
}

void WireGuardService::shutdown() noexcept {
    if (!options_.enabled) {
        return;
    }
    try {
        const auto runtime = runtime_options();
        const auto subnet = subnet_cidr(runtime.address);
        static_cast<void>(run_command(
            {"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet,
             "-o", runtime.egress_interface, "-j", "MASQUERADE"},
            false));
        for (const auto& direction : {std::string{"-i"}, std::string{"-o"}}) {
            static_cast<void>(
                run_command({"iptables", "-D", "FORWARD", direction,
                             runtime.interface, "-j", "ACCEPT"},
                            false));
        }
        static_cast<void>(
            run_command({"ip", "link", "delete", runtime.interface}, false));
    } catch (const std::exception&) {
    }
}

void WireGuardService::remove_peer(const std::string& public_key) noexcept {
    if (!options_.enabled) {
        return;
    }
    try {
        const auto runtime = runtime_options();
        static_cast<void>(
            run_command({"wg", "set", runtime.interface, "peer", public_key,
                         "remove"},
                        false));
    } catch (const std::exception&) {
    }
}

} // namespace sbeasy
