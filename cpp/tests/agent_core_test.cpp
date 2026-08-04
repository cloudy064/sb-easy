#include "test_support.hpp"

#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>

#include "sbeasy/atomic_file.hpp"
#include "sbeasy/config_etag.hpp"

namespace {

class TemporaryDirectory final {
  public:
    TemporaryDirectory()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-atomic-" + std::to_string(std::random_device{}()))) {
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

[[nodiscard]] std::string read(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

} // namespace

SB_EASY_TEST("agent ETags match the Rust SHA-256 contract") {
    sbeasy::test::require(
        sbeasy::config_etag("self", R"({"x":1})", "seed") ==
            "\"9a2dc88545b38167826a8b4cc550dc2c91dec71f743cd03abd46c6729572d5f7\"",
        "ETag must hash host, body, and seed in order and retain quotes");
}

SB_EASY_TEST("atomic config replacement validates before rename") {
    const TemporaryDirectory directory;
    const auto destination = directory.path() / "nested" / "config.json";

    sbeasy::atomic_replace_file(destination, "old");
    bool validated = false;
    sbeasy::atomic_replace_file(
        destination, "new", [&](const std::filesystem::path& temporary) {
            validated = true;
            sbeasy::test::require(read(temporary) == "new",
                                  "validator should inspect complete temp content");
            sbeasy::test::require(
                read(destination) == "old",
                "destination must remain unchanged during validation");
        });
    sbeasy::test::require(validated && read(destination) == "new",
                          "validated content should atomically replace old data");

    sbeasy::test::require_throws<std::runtime_error>(
        [&] {
            sbeasy::atomic_replace_file(destination, "invalid",
                                        [](const std::filesystem::path&) {
                                            throw std::runtime_error("rejected");
                                        });
        },
        "validator failures should propagate");
    sbeasy::test::require(read(destination) == "new",
                          "validator failure must preserve the last good config");

    std::size_t temporary_files{};
    for (const auto& entry :
         std::filesystem::directory_iterator{destination.parent_path()}) {
        if (entry.path() != destination) {
            ++temporary_files;
        }
    }
    sbeasy::test::require(temporary_files == 0U,
                          "temporary config files should be cleaned up");
}
