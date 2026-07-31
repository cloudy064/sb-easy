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
    std::string clash_api_url{"http://127.0.0.1:9090"};
    std::string clash_api_secret;
};

void register_http_routes(const std::shared_ptr<Store>& store,
                          const HttpServerOptions& options = {});
void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options);

} // namespace sbeasy
