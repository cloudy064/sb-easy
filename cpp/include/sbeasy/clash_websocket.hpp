#pragma once

#include <memory>
#include <string>

namespace sbeasy {

class Store;

void register_clash_websocket_routes(const std::shared_ptr<Store>& store,
                                     const std::string& local_clash_api,
                                     const std::string& local_clash_secret);

} // namespace sbeasy
