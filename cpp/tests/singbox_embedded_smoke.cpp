#include <filesystem>
#include <iostream>
#include <string>

#include <unistd.h>

#include "sbeasy/singbox_supervisor.hpp"

int main() {
    const auto config = std::filesystem::temp_directory_path() /
                        ("sb-easy-embedded-singbox-" +
                         std::to_string(static_cast<long long>(::getpid())) + ".json");
    try {
        sbeasy::SingBoxSupervisor supervisor({
            .binary = "embedded",
            .config_path = config,
            .validate_config = true,
        });
        supervisor.apply_config(R"({
          "log": {"level": "error"},
          "inbounds": [],
          "outbounds": [{"type": "direct", "tag": "direct"}],
          "route": {"final": "direct"}
        })");
        if (!supervisor.running() || !supervisor.pid().has_value() ||
            *supervisor.pid() != ::getpid()) {
            std::cerr << "embedded sing-box did not run in the owning process\n";
            return 1;
        }
        supervisor.reload();
        supervisor.stop();
        if (supervisor.running()) {
            std::cerr << "embedded sing-box did not stop\n";
            return 1;
        }
        std::error_code ignored;
        std::filesystem::remove(config, ignored);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::error_code ignored;
        std::filesystem::remove(config, ignored);
        return 1;
    }
}
