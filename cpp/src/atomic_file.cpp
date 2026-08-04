#include "sbeasy/atomic_file.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbeasy {
namespace {

[[nodiscard]] std::filesystem::path
temporary_path_for(const std::filesystem::path& destination) {
    std::array<unsigned char, 8> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw std::runtime_error("secure temporary filename generation failed");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string suffix;
    suffix.reserve(random.size() * 2U);
    for (const auto byte : random) {
        suffix.push_back(digits[byte >> 4U]);
        suffix.push_back(digits[byte & 0x0fU]);
    }
    return destination.parent_path() /
           (destination.filename().string() + ".tmp." + suffix);
}

[[noreturn]] void throw_system_error(const char* operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}

class TemporaryFile final {
  public:
    explicit TemporaryFile(std::filesystem::path path, mode_t mode)
        : path_(std::move(path)) {
        descriptor_ =
            ::open(path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
        if (descriptor_ < 0) {
            throw_system_error("create temporary config");
        }
    }

    ~TemporaryFile() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
        if (!committed_) {
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
        }
    }

    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    void write_all(std::string_view contents) {
        std::size_t written{};
        while (written < contents.size()) {
            const auto result = ::write(descriptor_, contents.data() + written,
                                        contents.size() - written);
            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw_system_error("write temporary config");
            }
            if (result == 0) {
                throw std::runtime_error("write temporary config made no progress");
            }
            written += static_cast<std::size_t>(result);
        }
        if (::fsync(descriptor_) != 0) {
            throw_system_error("fsync temporary config");
        }
        if (::close(descriptor_) != 0) {
            descriptor_ = -1;
            throw_system_error("close temporary config");
        }
        descriptor_ = -1;
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

    void mark_committed() noexcept {
        committed_ = true;
    }

  private:
    std::filesystem::path path_;
    int descriptor_{-1};
    bool committed_{false};
};

[[nodiscard]] mode_t destination_mode(const std::filesystem::path& destination) {
    struct stat information{};
    if (::stat(destination.c_str(), &information) == 0) {
        return information.st_mode & static_cast<mode_t>(0777);
    }
    if (errno != ENOENT) {
        throw_system_error("inspect destination config");
    }
    return static_cast<mode_t>(0600);
}

void fsync_directory(const std::filesystem::path& directory) {
    const int descriptor =
        ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) {
        throw_system_error("open config directory");
    }
    if (::fsync(descriptor) != 0) {
        const int error = errno;
        ::close(descriptor);
        errno = error;
        throw_system_error("fsync config directory");
    }
    if (::close(descriptor) != 0) {
        throw_system_error("close config directory");
    }
}

} // namespace

void atomic_replace_file(const std::filesystem::path& destination,
                         std::string_view contents, const FileValidator& validator) {
    if (destination.empty() || destination.filename().empty()) {
        throw std::invalid_argument("config destination must name a file");
    }
    auto directory = destination.parent_path();
    if (directory.empty()) {
        directory = ".";
    }
    std::filesystem::create_directories(directory);

    TemporaryFile temporary{temporary_path_for(destination),
                            destination_mode(destination)};
    temporary.write_all(contents);
    if (validator) {
        validator(temporary.path());
    }
    if (::rename(temporary.path().c_str(), destination.c_str()) != 0) {
        throw_system_error("replace config");
    }
    temporary.mark_committed();
    fsync_directory(directory);
}

} // namespace sbeasy
