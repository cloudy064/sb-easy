#include "sbeasy/platform_adapters.hpp"

#include <array>
#include <chrono>
#include <ctime>

namespace sbeasy {

std::string SystemClock::now_iso8601() const {
    const auto now = std::chrono::system_clock::now();
    const auto value = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    if (::gmtime_r(&value, &utc) == nullptr) {
        return {};
    }
    std::array<char, 32> buffer{};
    if (std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) {
        return {};
    }
    return buffer.data();
}

} // namespace sbeasy
