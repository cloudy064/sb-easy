#include "sbeasy/singbox_supervisor.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sbeasy/atomic_file.hpp"

extern char** environ;

namespace sbeasy {
namespace {

struct ProcessResult {
    bool success{false};
    std::string detail;
};

[[nodiscard]] std::vector<char*>
native_arguments(const std::vector<std::string>& arguments) {
    std::vector<char*> result;
    result.reserve(arguments.size() + 1U);
    for (const auto& argument : arguments) {
        result.push_back(const_cast<char*>(argument.c_str()));
    }
    result.push_back(nullptr);
    return result;
}

[[nodiscard]] ProcessResult
run_program(const std::vector<std::string>& arguments) {
    auto native = native_arguments(arguments);
    pid_t process{};
    const int spawn_error =
        ::posix_spawnp(&process, native.front(), nullptr, nullptr, native.data(),
                       environ);
    if (spawn_error != 0) {
        return {
            .success = false,
            .detail = std::string{"spawn failed: "} + std::strerror(spawn_error),
        };
    }

    int status{};
    while (::waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            return {
                .success = false,
                .detail = std::string{"wait failed: "} + std::strerror(errno),
            };
        }
    }
    if (WIFEXITED(status)) {
        const auto code = WEXITSTATUS(status);
        return {
            .success = code == 0,
            .detail = "exit code " + std::to_string(code),
        };
    }
    if (WIFSIGNALED(status)) {
        return {
            .success = false,
            .detail = "terminated by signal " + std::to_string(WTERMSIG(status)),
        };
    }
    return {.success = false, .detail = "process ended without an exit status"};
}

[[nodiscard]] std::string child_exit_detail(int status) {
    if (WIFEXITED(status)) {
        return "sing-box exited with code " + std::to_string(WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
        return "sing-box terminated by signal " +
               std::to_string(WTERMSIG(status));
    }
    return "sing-box exited without a status";
}

} // namespace

SingBoxSupervisor::SingBoxSupervisor(SingBoxSupervisorOptions options)
    : options_(std::move(options)) {
    if (options_.binary.empty()) {
        throw std::invalid_argument("sing-box binary is required");
    }
    if (options_.config_path.empty() || options_.config_path.filename().empty()) {
        throw std::invalid_argument("sing-box config path must name a file");
    }
    if (options_.restart_backoff < std::chrono::milliseconds::zero() ||
        options_.shutdown_timeout < std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("sing-box process durations cannot be negative");
    }
}

SingBoxSupervisor::~SingBoxSupervisor() {
    stop();
}

void SingBoxSupervisor::validate(const std::filesystem::path& path) const {
    if (!options_.validate_config) {
        return;
    }
    const auto result =
        run_program({options_.binary, "check", "-c", path.string()});
    if (!result.success) {
        throw std::runtime_error("sing-box config validation failed: " +
                                 result.detail);
    }
}

void SingBoxSupervisor::reap() {
    if (child_ <= 0) {
        return;
    }
    int status{};
    const auto result = ::waitpid(child_, &status, WNOHANG);
    if (result == 0) {
        return;
    }
    if (result == child_) {
        child_ = -1;
        last_error_ = child_exit_detail(status);
        next_start_ =
            std::chrono::steady_clock::now() + options_.restart_backoff;
        return;
    }
    if (result < 0 && errno == EINTR) {
        return;
    }
    if (result < 0 && errno == ECHILD) {
        child_ = -1;
        last_error_ = "sing-box child could not be reaped";
        next_start_ =
            std::chrono::steady_clock::now() + options_.restart_backoff;
        return;
    }
    if (result < 0) {
        last_error_ =
            std::string{"sing-box wait failed: "} + std::strerror(errno);
    }
}

void SingBoxSupervisor::start(bool ignore_backoff) {
    reap();
    if (child_ > 0) {
        return;
    }
    if (!ignore_backoff && std::chrono::steady_clock::now() < next_start_) {
        return;
    }
    if (!std::filesystem::is_regular_file(options_.config_path)) {
        return;
    }

    std::vector<std::string> arguments{
        options_.binary,
        "run",
        "-c",
        options_.config_path.string(),
    };
    auto native = native_arguments(arguments);
    posix_spawn_file_actions_t actions{};
    const int actions_error = ::posix_spawn_file_actions_init(&actions);
    if (actions_error != 0) {
        throw std::runtime_error(
            std::string{"initialize sing-box spawn actions failed: "} +
            std::strerror(actions_error));
    }
    const int stdin_error = ::posix_spawn_file_actions_addopen(
        &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (stdin_error != 0) {
        ::posix_spawn_file_actions_destroy(&actions);
        throw std::runtime_error(
            std::string{"configure sing-box stdin failed: "} +
            std::strerror(stdin_error));
    }

    pid_t process{};
    const int spawn_error =
        ::posix_spawnp(&process, native.front(), &actions, nullptr,
                       native.data(), environ);
    ::posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        child_ = -1;
        has_started_ = true;
        next_start_ =
            std::chrono::steady_clock::now() + options_.restart_backoff;
        last_error_ =
            std::string{"start sing-box failed: "} + std::strerror(spawn_error);
        throw std::runtime_error(*last_error_);
    }
    child_ = process;
    has_started_ = true;
    next_start_ = {};
    last_error_.reset();
}

void SingBoxSupervisor::apply_config(std::string_view contents) {
    atomic_replace_file(options_.config_path, contents,
                        [this](const std::filesystem::path& temporary) {
                            validate(temporary);
                        });
    reap();
    if (child_ > 0) {
        if (::kill(child_, SIGHUP) == 0) {
            last_error_.reset();
            return;
        }
        if (errno != ESRCH) {
            throw std::runtime_error(
                std::string{"reload sing-box failed: "} + std::strerror(errno));
        }
        reap();
    }
    start(true);
}

void SingBoxSupervisor::ensure_alive() {
    const auto previous = child_;
    reap();
    if (previous > 0 && child_ <= 0) {
        has_started_ = true;
    }
    if (has_started_ && child_ <= 0) {
        try {
            start(false);
        } catch (const std::exception& error) {
            last_error_ = error.what();
        }
    }
}

void SingBoxSupervisor::reload() {
    reap();
    if (child_ <= 0) {
        start(true);
        return;
    }
    if (::kill(child_, SIGHUP) != 0) {
        if (errno == ESRCH) {
            reap();
            start(true);
            return;
        }
        throw std::runtime_error(
            std::string{"reload sing-box failed: "} + std::strerror(errno));
    }
    last_error_.reset();
}

void SingBoxSupervisor::restart() {
    stop();
    has_started_ = true;
    start(true);
}

void SingBoxSupervisor::stop() noexcept {
    if (child_ <= 0) {
        return;
    }
    const auto process = child_;
    if (::kill(process, SIGTERM) != 0 && errno != ESRCH) {
        last_error_ =
            std::string{"stop sing-box failed: "} + std::strerror(errno);
    }
    const auto deadline =
        std::chrono::steady_clock::now() + options_.shutdown_timeout;
    int status{};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto result = ::waitpid(process, &status, WNOHANG);
        if (result == process || (result < 0 && errno == ECHILD)) {
            child_ = -1;
            has_started_ = false;
            return;
        }
        if (result < 0 && errno != EINTR) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    static_cast<void>(::kill(process, SIGKILL));
    while (::waitpid(process, &status, 0) < 0 && errno == EINTR) {
    }
    child_ = -1;
    has_started_ = false;
}

bool SingBoxSupervisor::running() {
    reap();
    return child_ > 0;
}

std::optional<pid_t> SingBoxSupervisor::pid() {
    reap();
    return child_ > 0 ? std::optional<pid_t>{child_} : std::nullopt;
}

const std::optional<std::string>&
SingBoxSupervisor::last_error() const noexcept {
    return last_error_;
}

} // namespace sbeasy
