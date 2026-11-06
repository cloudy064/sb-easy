#include "sbeasy/platform_adapters.hpp"

#include <array>
#include <cstdlib>
#include <string>
#include <utility>

#include <sys/utsname.h>
#include <unistd.h>

#include "sbeasy/version.hpp"

namespace sbeasy {
namespace {

[[nodiscard]] std::string environment(const char* name, std::string fallback = {}) {
    const auto* value = std::getenv(name);
    return value == nullptr ? std::move(fallback) : std::string{value};
}

} // namespace

nlohmann::json PosixPlatformMetadata::device_metadata() const {
    std::array<char, 256> hostname{};
    std::string hostname_value;
    if (::gethostname(hostname.data(), hostname.size()) == 0) {
        hostname.back() = '\0';
        hostname_value = hostname.data();
    }

    struct utsname system_information{};
    std::string operating_system{"linux"};
    std::string architecture;
    if (::uname(&system_information) == 0) {
        operating_system = system_information.sysname;
        architecture = system_information.machine;
    }

    return {
        {"platform", environment("AGENT_PLATFORM", "linux")},
        {"agent_version", "sb-easy-cpp-agent/" + std::string{application_version}},
        {"hostname", hostname_value},
        {"architecture", architecture},
        {"os", operating_system},
        {"interactive_client", false},
        {"supports_proxy_selection", false},
    };
}

} // namespace sbeasy
