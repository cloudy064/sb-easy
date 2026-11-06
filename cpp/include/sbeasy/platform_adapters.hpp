#pragma once

#include "sbeasy/platform_clock.hpp"
#include "sbeasy/platform_metadata.hpp"
#include "sbeasy/platform_process.hpp"
#include "sbeasy/platform_storage.hpp"

namespace sbeasy {

class PosixProcess final : public PlatformProcess {
  public:
    [[nodiscard]] ProcessResult run(const std::vector<std::string>& arguments) override;
};

class PosixStorage final : public PlatformStorage {
  public:
    [[nodiscard]] std::optional<std::string>
    read(const std::filesystem::path& path) const override;
    void replace(const std::filesystem::path& path, std::string_view contents,
                 const StorageValidator& validator = {}) override;
};

class SystemClock final : public PlatformClock {
  public:
    [[nodiscard]] std::string now_iso8601() const override;
};

class PosixPlatformMetadata final : public PlatformMetadata {
  public:
    [[nodiscard]] nlohmann::json device_metadata() const override;
};

} // namespace sbeasy
