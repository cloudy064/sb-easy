#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

#include "sbeasy/http_server.hpp"
#include "sbeasy/store.hpp"

int main(int argc, char** argv) {
    try {
        if (argc < 3 || argc > 6) {
            std::cerr << "Usage: " << argv[0]
                      << " <database.db> <migration-directory> "
                         "[address] [port] [public-server]\n";
            return 2;
        }
        sbeasy::HttpServerOptions options;
        if (argc >= 4) {
            options.address = argv[3];
        }
        if (argc >= 5) {
            std::uint32_t port{};
            const std::string input{argv[4]};
            const auto [end, error] =
                std::from_chars(input.data(), input.data() + input.size(), port);
            if (error != std::errc{} || end != input.data() + input.size() ||
                port == 0 || port > std::numeric_limits<std::uint16_t>::max()) {
                throw std::invalid_argument("port is out of range");
            }
            options.port = static_cast<std::uint16_t>(port);
        }
        if (argc >= 6) {
            options.public_server = argv[5];
        }
        if (const auto* seed = std::getenv("CONFIG_HASH_SEED"); seed != nullptr) {
            options.config_hash_seed = seed;
        }
        if (const auto* token = std::getenv("AGENT_TOKEN"); token != nullptr) {
            options.legacy_agent_token = token;
        }
        if (const auto* url = std::getenv("SINGBOX_API_URL"); url != nullptr) {
            options.clash_api_url = url;
        }
        if (const auto* secret = std::getenv("SINGBOX_API_SECRET"); secret != nullptr) {
            options.clash_api_secret = secret;
        }
        auto store = std::make_shared<sbeasy::Store>(std::filesystem::path{argv[1]},
                                                     std::filesystem::path{argv[2]});
        sbeasy::run_http_server(store, options);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
