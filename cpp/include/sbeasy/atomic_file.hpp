#pragma once

#include <filesystem>
#include <functional>
#include <string_view>

namespace sbeasy {

using FileValidator = std::function<void(const std::filesystem::path& temporary_path)>;

/// Writes and fsyncs a same-directory temporary file, optionally validates it,
/// then atomically renames it over the destination.
void atomic_replace_file(const std::filesystem::path& destination,
                         std::string_view contents,
                         const FileValidator& validator = {});

} // namespace sbeasy
