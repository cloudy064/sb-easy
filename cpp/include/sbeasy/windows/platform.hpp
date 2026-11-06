#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/platform.hpp is only available on Windows"
#endif

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sbeasy/platform_clock.hpp"
#include "sbeasy/platform_metadata.hpp"
#include "sbeasy/platform_process.hpp"
#include "sbeasy/platform_storage.hpp"

namespace sbeasy::win {

class WindowsProcess final : public PlatformProcess {
  public:
    explicit WindowsProcess(std::chrono::milliseconds timeout =
                                std::chrono::seconds{30});

    [[nodiscard]] ProcessResult
    run(const std::vector<std::string>& arguments) override;

  private:
    std::chrono::milliseconds timeout_;
};

/// Same-directory, write-through replacement. Service-owned files receive a
/// protected DACL that grants full access only to LocalSystem and administrators.
class WindowsStorage final : public PlatformStorage {
  public:
    explicit WindowsStorage(bool restrict_acl = true);

    [[nodiscard]] std::optional<std::string>
    read(const std::filesystem::path& path) const override;
    void replace(const std::filesystem::path& path, std::string_view contents,
                 const StorageValidator& validator = {}) override;

    void remove(const std::filesystem::path& path) const;

  private:
    bool restrict_acl_;
};

/// Machine-bound credential persistence. DPAPI is an additional boundary;
/// the backing file is also protected by WindowsStorage's restricted DACL.
class DpapiCredentialStore final {
  public:
    explicit DpapiCredentialStore(std::filesystem::path path,
                                  bool restrict_acl = true);

    [[nodiscard]] std::optional<std::string> read() const;
    void replace(std::string_view plaintext);
    void remove();
    [[nodiscard]] const std::filesystem::path& path() const noexcept;

  private:
    std::filesystem::path path_;
    WindowsStorage storage_;
};

class WindowsClock final : public PlatformClock {
  public:
    [[nodiscard]] std::string now_iso8601() const override;
};

class WindowsMetadata final : public PlatformMetadata {
  public:
    [[nodiscard]] nlohmann::json device_metadata() const override;
};

[[nodiscard]] std::filesystem::path program_data_directory();
[[nodiscard]] std::filesystem::path executable_directory();
void prepare_service_directory(const std::filesystem::path& path);

} // namespace sbeasy::win
