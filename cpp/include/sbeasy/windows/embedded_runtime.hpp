#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/embedded_runtime.hpp is only available on Windows"
#endif

#include <filesystem>

namespace sbeasy::win {

struct EmbeddedRuntimePaths final {
    std::filesystem::path sing_box;
    std::filesystem::path wintun;
};

/// Verifies the pinned PE resources and atomically materializes them below the
/// protected service data directory. Existing files are reused only when their
/// SHA-256 digests match the embedded release pins.
[[nodiscard]] EmbeddedRuntimePaths materialize_embedded_runtime(
    const std::filesystem::path& service_data_directory,
    void* resource_module = nullptr,
    bool restrict_acl = true);

} // namespace sbeasy::win
