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
};

void register_http_routes(const std::shared_ptr<Store>& store,
                          std::string public_server = {});
void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options);

} // namespace sbeasy
