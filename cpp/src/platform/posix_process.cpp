#include "sbeasy/platform_adapters.hpp"

#include <cerrno>
#include <cstring>
#include <spawn.h>
#include <sys/wait.h>

extern char** environ;

namespace sbeasy {

ProcessResult PosixProcess::run(const std::vector<std::string>& arguments) {
    if (arguments.empty() || arguments.front().empty()) {
        return {.success = false, .detail = "command is empty"};
    }
    std::vector<char*> native_arguments;
    native_arguments.reserve(arguments.size() + 1U);
    for (const auto& argument : arguments) {
        native_arguments.push_back(const_cast<char*>(argument.c_str()));
    }
    native_arguments.push_back(nullptr);

    pid_t process{};
    const int spawn_error = ::posix_spawnp(&process, native_arguments.front(), nullptr,
                                           nullptr, native_arguments.data(), environ);
    if (spawn_error != 0) {
        return {.success = false,
                .detail = std::string{"spawn failed: "} + std::strerror(spawn_error)};
    }
    int status{};
    while (::waitpid(process, &status, 0) < 0) {
        if (errno != EINTR) {
            return {.success = false,
                    .detail = std::string{"wait failed: "} + std::strerror(errno)};
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

} // namespace sbeasy
