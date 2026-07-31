#pragma once

#include <string>
#include <string_view>

namespace sbeasy {

/// Produces the quoted SHA-256 ETag used by the Rust agent API:
/// SHA256(host_id || pretty_config || seed).
[[nodiscard]] std::string config_etag(std::string_view host_id,
                                      std::string_view pretty_config,
                                      std::string_view seed);

} // namespace sbeasy
