#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace sbeasy {

using StorageValidator =
    std::function<void(const std::filesystem::path& temporary_path)>;

/// Durable service-owned storage. replace() must leave the previous file
/// intact when validation or installation fails.
class PlatformStorage {
  public:
    virtual ~PlatformStorage() = default;

    [[nodiscard]] virtual std::optional<std::string>
    read(const std::filesystem::path& path) const = 0;
    virtual void replace(const std::filesystem::path& path, std::string_view contents,
                         const StorageValidator& validator = {}) = 0;
};

} // namespace sbeasy
