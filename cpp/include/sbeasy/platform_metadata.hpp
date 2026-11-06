#pragma once

#include <nlohmann/json.hpp>

namespace sbeasy {

class PlatformMetadata {
  public:
    virtual ~PlatformMetadata() = default;

    /// Enrollment metadata and capability flags. Secrets must never be present.
    [[nodiscard]] virtual nlohmann::json device_metadata() const = 0;
};

} // namespace sbeasy
