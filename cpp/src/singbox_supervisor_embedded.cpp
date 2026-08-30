#include "sbeasy/singbox_supervisor.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

#include <unistd.h>

#include "libsb_easy_singbox.h"
#include "sbeasy/atomic_file.hpp"

namespace sbeasy {
namespace {

[[nodiscard]] std::optional<std::string> bridge_error(char* value) {
    if (value == nullptr) {
        return std::nullopt;
    }
    std::string message{value};
    SBEasySingBoxFree(value);
    return message;
}

void throw_bridge_error(std::string_view operation, char* value) {
    if (auto error = bridge_error(value); error.has_value()) {
        throw std::runtime_error(std::string{operation} + ": " + *error);
    }
}

// cgo emits `char*` for Go's C string input even though C.GoString never
// modifies it. Keep the const removal isolated at the generated ABI boundary.
[[nodiscard]] char* bridge_path(const std::filesystem::path& path) {
    return const_cast<char*>(path.c_str());
}

} // namespace

SingBoxSupervisor::SingBoxSupervisor(SingBoxSupervisorOptions options)
    : options_(std::move(options)) {
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
    throw_bridge_error("sing-box config validation failed",
                       SBEasySingBoxCheck(bridge_path(path)));
}

void SingBoxSupervisor::reap() {
    if (running_ && SBEasySingBoxRunning() == 0) {
        running_ = false;
        last_error_ = "embedded sing-box stopped unexpectedly";
        next_start_ = std::chrono::steady_clock::now() + options_.restart_backoff;
    }
}

void SingBoxSupervisor::start(bool ignore_backoff) {
    reap();
    if (running_) {
        return;
    }
    if (!ignore_backoff && std::chrono::steady_clock::now() < next_start_) {
        return;
    }
    if (!std::filesystem::is_regular_file(options_.config_path)) {
        return;
    }
    has_started_ = true;
    if (auto error = bridge_error(SBEasySingBoxStart(bridge_path(options_.config_path)));
        error.has_value()) {
        next_start_ = std::chrono::steady_clock::now() + options_.restart_backoff;
        last_error_ = "start embedded sing-box failed: " + *error;
        throw std::runtime_error(*last_error_);
    }
    running_ = true;
    next_start_ = {};
    last_error_.reset();
}

void SingBoxSupervisor::apply_config(std::string_view contents) {
    atomic_replace_file(options_.config_path, contents,
                        [this](const std::filesystem::path& temporary) {
                            validate(temporary);
                        });
    if (!running()) {
        start(true);
        return;
    }
    throw_bridge_error("reload embedded sing-box failed",
                       SBEasySingBoxReload(bridge_path(options_.config_path)));
    running_ = true;
    last_error_.reset();
}

void SingBoxSupervisor::ensure_alive() {
    reap();
    if (has_started_ && !running_) {
        try {
            start(false);
        } catch (const std::exception& error) {
            last_error_ = error.what();
        }
    }
}

void SingBoxSupervisor::reload() {
    if (!running()) {
        start(true);
        return;
    }
    throw_bridge_error("reload embedded sing-box failed",
                       SBEasySingBoxReload(bridge_path(options_.config_path)));
    running_ = true;
    last_error_.reset();
}

void SingBoxSupervisor::restart() {
    stop();
    has_started_ = true;
    start(true);
}

void SingBoxSupervisor::stop() noexcept {
    if (!running_ && SBEasySingBoxRunning() == 0) {
        return;
    }
    if (auto error = bridge_error(SBEasySingBoxStop()); error.has_value()) {
        last_error_ = "stop embedded sing-box failed: " + *error;
    }
    running_ = false;
    has_started_ = false;
}

bool SingBoxSupervisor::running() {
    reap();
    return running_;
}

std::optional<pid_t> SingBoxSupervisor::pid() {
    return running() ? std::optional<pid_t>{::getpid()} : std::nullopt;
}

const std::optional<std::string>& SingBoxSupervisor::last_error() const noexcept {
    return last_error_;
}

} // namespace sbeasy
