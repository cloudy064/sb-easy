#pragma once

#include <string>

namespace sbeasy {

class PlatformClock {
  public:
    virtual ~PlatformClock() = default;

    /// Returns a UTC timestamp suitable for status and telemetry payloads.
    [[nodiscard]] virtual std::string now_iso8601() const = 0;
};

} // namespace sbeasy
