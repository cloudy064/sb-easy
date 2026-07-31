#include <charconv>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "sbeasy/http_server.hpp"
#include "sbeasy/store.hpp"

namespace {

[[nodiscard]] std::string environment(const char* name,
                                      std::string fallback = {}) {
    const auto* value = std::getenv(name);
    return value == nullptr ? std::move(fallback) : std::string{value};
}

[[nodiscard]] bool environment_flag(const char* name, bool fallback) {
    auto value = environment(name);
    if (value.empty()) {
        return fallback;
    }
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

[[nodiscard]] std::uint64_t environment_integer(const char* name,
                                                std::uint64_t fallback) {
    const auto value = environment(name);
    if (value.empty()) {
        return fallback;
    }
    std::uint64_t parsed{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::invalid_argument(std::string{name} + " must be an integer");
    }
    return parsed;
}

[[nodiscard]] std::uint16_t parse_port(std::string_view input,
                                       std::string_view source) {
    std::uint32_t port{};
    const auto [end, error] =
        std::from_chars(input.data(), input.data() + input.size(), port);
    if (error != std::errc{} || end != input.data() + input.size() ||
        port == 0 || port > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument(std::string{source} + " port is out of range");
    }
    return static_cast<std::uint16_t>(port);
}

void apply_bind_address(std::string bind, sbeasy::HttpServerOptions& options) {
    if (bind.starts_with('[')) {
        const auto closing = bind.find(']');
        if (closing == std::string::npos || closing + 1U >= bind.size() ||
            bind[closing + 1U] != ':') {
            throw std::invalid_argument(
                "BIND_ADDR must use [IPv6]:port syntax");
        }
        options.address = bind.substr(1U, closing - 1U);
        options.port =
            parse_port(std::string_view{bind}.substr(closing + 2U), "BIND_ADDR");
        return;
    }
    const auto separator = bind.rfind(':');
    if (separator == std::string::npos || separator == 0U ||
        separator + 1U >= bind.size()) {
        throw std::invalid_argument("BIND_ADDR must use address:port syntax");
    }
    options.address = bind.substr(0U, separator);
    options.port =
        parse_port(std::string_view{bind}.substr(separator + 1U), "BIND_ADDR");
}

[[nodiscard]] std::filesystem::path database_path_from_environment() {
    auto value =
        environment("DATABASE_URL", "sqlite:/app/data/sb-easy.db?mode=rwc");
    constexpr std::string_view prefix{"sqlite:"};
    if (value.starts_with(prefix)) {
        value.erase(0U, prefix.size());
    }
    if (const auto query = value.find('?'); query != std::string::npos) {
        value.erase(query);
    }
    if (value.empty()) {
        throw std::invalid_argument("DATABASE_URL does not contain a database path");
    }
    return value;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 1 && (argc < 3 || argc > 6)) {
            std::cerr << "Usage: " << argv[0]
                      << " <database.db> <migration-directory> "
                         "[address] [port] [public-server]\n"
                         "   or: configure DATABASE_URL, MIGRATIONS_DIR, and "
                         "BIND_ADDR, then run without arguments\n";
            return 2;
        }
        sbeasy::HttpServerOptions options;
        std::filesystem::path database_path;
        std::filesystem::path migration_directory;
        if (argc == 1) {
            database_path = database_path_from_environment();
            migration_directory =
                environment("MIGRATIONS_DIR", "/app/migrations");
            apply_bind_address(
                environment("BIND_ADDR", "0.0.0.0:51821"), options);
            options.public_server = environment("PUBLIC_SERVER");
        } else {
            database_path = argv[1];
            migration_directory = argv[2];
            if (argc >= 4) {
                options.address = argv[3];
            }
            if (argc >= 5) {
                options.port = parse_port(argv[4], "command-line");
            }
            if (argc >= 6) {
                options.public_server = argv[5];
            }
        }
        if (const auto* seed = std::getenv("CONFIG_HASH_SEED"); seed != nullptr) {
            options.config_hash_seed = seed;
        }
        if (const auto* token = std::getenv("AGENT_TOKEN"); token != nullptr) {
            options.legacy_agent_token = token;
        }
        if (const auto* secret = std::getenv("JWT_SECRET");
            secret != nullptr && std::string_view{secret}.size() > 0U) {
            options.jwt_secret = secret;
        } else {
            throw std::invalid_argument("JWT_SECRET must be set");
        }
        if (const auto* password = std::getenv("ADMIN_PASSWORD"); password != nullptr) {
            options.admin_password = password;
        }
        if (const auto* url = std::getenv("SINGBOX_API_URL"); url != nullptr) {
            options.clash_api_url = url;
        }
        if (const auto* secret = std::getenv("SINGBOX_API_SECRET"); secret != nullptr) {
            options.clash_api_secret = secret;
        }
        options.singbox_managed =
            environment_flag("SINGBOX_MANAGED", false);
        options.singbox_binary = environment("SINGBOX_BIN", "sing-box");
        options.self_singbox_config_path =
            environment("SELF_SINGBOX_CONFIG_PATH");
        options.self_singbox_interval_seconds =
            std::max<std::uint64_t>(
                environment_integer("SELF_SINGBOX_INTERVAL", 10), 2U);
        options.singbox_validate_config =
            environment_flag("SINGBOX_VALIDATE_CONFIG", true);
        options.wireguard_enabled =
            environment_flag("WG_ENABLED", true);
        options.wireguard_interface =
            environment("WG_INTERFACE", "wg0");
        const auto wireguard_port =
            environment_integer("WG_PORT", 51'820);
        if (wireguard_port == 0U ||
            wireguard_port > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("WG_PORT is out of range");
        }
        options.wireguard_port =
            static_cast<std::uint16_t>(wireguard_port);
        options.wireguard_address =
            environment("WG_ADDRESS", "10.59.32.1/24");
        options.wireguard_dns =
            environment("WG_DNS", "10.59.32.1");
        const auto wireguard_mtu =
            environment_integer("WG_MTU", 1'420);
        if (wireguard_mtu >
            std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("WG_MTU is out of range");
        }
        options.wireguard_mtu =
            static_cast<std::uint32_t>(wireguard_mtu);
        options.wireguard_egress =
            environment("WG_EGRESS", "eth0");
        options.external_hostname =
            environment("EXTERNAL_HOSTNAME", "127.0.0.1");
        if (options.public_server.empty()) {
            options.public_server =
                environment("PUBLIC_SERVER", options.external_hostname);
        }
        options.wireguard_config_directory =
            environment("WG_CONFIG_DIRECTORY", "/etc/wireguard");
        options.static_directory =
            environment("STATIC_DIR", "frontend/dist");
        options.cors_origins =
            environment("CORS_ORIGINS");
        options.log_level =
            environment("LOG_LEVEL", "info");
        auto store = std::make_shared<sbeasy::Store>(database_path,
                                                     migration_directory);
        sbeasy::run_http_server(store, options);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
