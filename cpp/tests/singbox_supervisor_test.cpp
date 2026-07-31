#include "test_support.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include <signal.h>
#include <sys/stat.h>

#include "sbeasy/singbox_supervisor.hpp"

namespace {

class TemporaryDirectory final {
  public:
    TemporaryDirectory()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-supervisor-" +
                 std::to_string(std::random_device{}()))) {
        std::filesystem::create_directories(path_);
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

void write_fake_singbox(const std::filesystem::path& path) {
    std::ofstream output{path};
    output << R"SH(#!/bin/sh
if [ "$1" = "check" ]; then
    if grep -q INVALID "$3"; then
        exit 23
    fi
    exit 0
fi
if [ "$1" = "run" ]; then
    config="$3"
    echo "$$" > "${config}.pid"
    trap 'echo hup >> "${config}.events"' HUP
    trap 'exit 0' TERM INT
    while :; do
        sleep 0.05
    done
fi
exit 2
)SH";
    output.close();
    if (!output) {
        throw std::runtime_error("could not write fake sing-box");
    }
    if (::chmod(path.c_str(), static_cast<mode_t>(0700)) != 0) {
        throw std::runtime_error("could not make fake sing-box executable");
    }
}

[[nodiscard]] std::string read(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

void wait_until(const std::function<bool()>& predicate, const char* message) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    throw std::runtime_error(message);
}

[[nodiscard]] pid_t read_pid(const std::filesystem::path& path) {
    return static_cast<pid_t>(std::stoll(read(path)));
}

} // namespace

SB_EASY_TEST("managed sing-box validates reloads restarts and respawns") {
    const TemporaryDirectory directory;
    const auto binary = directory.path() / "fake-sing-box";
    const auto config = directory.path() / "sing-box.json";
    const auto pid_file = std::filesystem::path{config.string() + ".pid"};
    const auto events_file = std::filesystem::path{config.string() + ".events"};
    write_fake_singbox(binary);

    sbeasy::SingBoxSupervisor supervisor({
        .binary = binary.string(),
        .config_path = config,
        .validate_config = true,
        .restart_backoff = std::chrono::milliseconds{30},
        .shutdown_timeout = std::chrono::seconds{1},
    });
    supervisor.apply_config(R"({"version":1})");
    wait_until([&] { return std::filesystem::exists(pid_file); },
               "managed sing-box should start after the first config");
    const auto first_pid = read_pid(pid_file);
    sbeasy::test::require(supervisor.running() &&
                              supervisor.pid() == first_pid,
                          "supervisor should track the running child");

    sbeasy::test::require_throws<std::runtime_error>(
        [&] { supervisor.apply_config("INVALID"); },
        "invalid configs must fail before installation");
    sbeasy::test::require(read(config) == R"({"version":1})" &&
                              supervisor.pid() == first_pid,
                          "validation failure must preserve config and child");

    supervisor.apply_config(R"({"version":2})");
    wait_until(
        [&] {
            return std::filesystem::exists(events_file) &&
                   read(events_file).find("hup") != std::string::npos;
        },
        "config updates should SIGHUP the live child");
    sbeasy::test::require(supervisor.pid() == first_pid,
                          "reload should preserve the child pid");

    if (::kill(first_pid, SIGKILL) != 0) {
        throw std::runtime_error("could not crash the fake sing-box");
    }
    pid_t replacement{};
    wait_until(
        [&] {
            supervisor.ensure_alive();
            const auto current = supervisor.pid();
            if (current.has_value() && *current != first_pid) {
                replacement = *current;
                return true;
            }
            return false;
        },
        "an unexpectedly exited child should respawn after backoff");

    supervisor.restart();
    wait_until(
        [&] {
            const auto current = supervisor.pid();
            return current.has_value() && *current != replacement;
        },
        "hard restart should replace the child process");
}
