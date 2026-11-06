#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/log.hpp is only available on Windows"
#endif

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace sbeasy::win {

class RollingLog final {
  public:
    explicit RollingLog(std::filesystem::path path,
                        std::size_t maximum_bytes = 5U * 1024U * 1024U,
                        std::size_t retained_files = 3U,
                        bool mirror_console = false,
                        bool restrict_acl = true);
    ~RollingLog();

    RollingLog(const RollingLog&) = delete;
    RollingLog& operator=(const RollingLog&) = delete;

    void write(std::string_view severity, std::string_view message);
    [[nodiscard]] std::vector<std::string> tail(std::size_t maximum_lines) const;
    void clear();
    void set_retained_files(std::size_t retained_files);
    [[nodiscard]] const std::filesystem::path& path() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

[[nodiscard]] std::string redact_log_message(std::string value);

} // namespace sbeasy::win
