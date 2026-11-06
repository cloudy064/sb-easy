#include "sbeasy/windows/log.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>

#include "sbeasy/windows/platform.hpp"

namespace sbeasy::win {
namespace {

class Handle final {
  public:
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            static_cast<void>(::CloseHandle(value_));
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(value_, nullptr);
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE value_;
};

void redact_json_value(std::string& value, std::string_view key) {
    std::size_t position{};
    const std::string needle = "\"" + std::string{key} + "\"";
    while ((position = value.find(needle, position)) != std::string::npos) {
        const auto colon = value.find(':', position + needle.size());
        if (colon == std::string::npos) {
            return;
        }
        const auto quote = value.find('"', colon + 1U);
        if (quote == std::string::npos) {
            position = colon + 1U;
            continue;
        }
        auto end = quote + 1U;
        bool escaped{};
        while (end < value.size()) {
            const char character = value[end];
            if (character == '"' && !escaped) {
                break;
            }
            escaped = character == '\\' && !escaped;
            if (character != '\\') {
                escaped = false;
            }
            ++end;
        }
        if (end >= value.size()) {
            return;
        }
        value.replace(quote + 1U, end - quote - 1U, "***");
        position = quote + 4U;
    }
}

void redact_assignment(std::string& value, std::string_view key) {
    std::size_t search{};
    while (search < value.size()) {
        auto normalized = value;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                       [](char item) {
                           return static_cast<char>(
                               std::tolower(static_cast<unsigned char>(item)));
                       });
        const auto position = normalized.find(key, search);
        if (position == std::string::npos) {
            return;
        }
        const bool left_boundary =
            position == 0U ||
            (std::isalnum(static_cast<unsigned char>(normalized[position - 1U])) ==
                 0 &&
             normalized[position - 1U] != '_');
        auto delimiter = position + key.size();
        while (delimiter < value.size() &&
               std::isspace(static_cast<unsigned char>(value[delimiter])) != 0) {
            ++delimiter;
        }
        if (!left_boundary || delimiter >= value.size() ||
            (value[delimiter] != '=' && value[delimiter] != ':')) {
            search = position + key.size();
            continue;
        }
        ++delimiter;
        while (delimiter < value.size() &&
               std::isspace(static_cast<unsigned char>(value[delimiter])) != 0) {
            ++delimiter;
        }
        const char quote = delimiter < value.size() &&
                                   (value[delimiter] == '"' ||
                                    value[delimiter] == '\'')
                               ? value[delimiter++]
                               : '\0';
        auto end = delimiter;
        while (end < value.size()) {
            const char item = value[end];
            if ((quote != '\0' && item == quote) ||
                (quote == '\0' &&
                 (std::isspace(static_cast<unsigned char>(item)) != 0 ||
                  item == ',' || item == ';' || item == '&' || item == '}'))) {
                break;
            }
            ++end;
        }
        if (end > delimiter) {
            value.replace(delimiter, end - delimiter, "***");
        }
        search = delimiter + 3U;
    }
}

} // namespace

std::string redact_log_message(std::string value) {
    static constexpr std::array<std::string_view, 8> keys{
        "agent_token", "token", "password", "secret", "uuid", "private_key",
        "code", "authorization"};
    for (const auto key : keys) {
        redact_json_value(value, key);
    }
    constexpr std::string_view bearer{"Bearer "};
    std::size_t bearer_position{};
    while ((bearer_position = value.find(bearer, bearer_position)) !=
           std::string::npos) {
        const auto start = bearer_position + bearer.size();
        auto end = value.find_first_of(" \t\r\n\"", start);
        if (end == std::string::npos) {
            end = value.size();
        }
        value.replace(start, end - start, "***");
        bearer_position = start + 3U;
    }
    static constexpr std::array<std::string_view, 7> assignment_keys{
        "agent_token", "token", "password", "secret", "uuid", "private_key",
        "code"};
    for (const auto key : assignment_keys) {
        redact_assignment(value, key);
    }
    std::size_t scheme{};
    while ((scheme = value.find("://", scheme)) != std::string::npos) {
        const auto query = value.find('?', scheme + 3U);
        const auto url_end = value.find_first_of(" \t\r\n", scheme + 3U);
        if (query == std::string::npos ||
            (url_end != std::string::npos && query >= url_end)) {
            scheme += 3U;
            continue;
        }
        value.replace(query, url_end == std::string::npos ? std::string::npos
                                                           : url_end - query,
                      "?<redacted>");
        scheme = query + 11U;
    }
    return value;
}

class RollingLog::Impl final {
  public:
    Impl(std::filesystem::path path, std::size_t maximum_bytes,
         std::size_t retained_files, bool mirror_console, bool restrict_acl)
        : path_(std::move(path)), maximum_bytes_(maximum_bytes),
          retained_files_(retained_files), mirror_console_(mirror_console),
          storage_(restrict_acl) {
        if (path_.empty() || path_.filename().empty() || maximum_bytes_ == 0U ||
            retained_files_ == 0U) {
            throw std::invalid_argument("rolling log options are invalid");
        }
        if (!storage_.read(path_).has_value()) {
            storage_.replace(path_, {});
        }
    }

    void write(std::string_view severity, std::string_view message) {
        const auto line = clock_.now_iso8601() + " [" + std::string{severity} +
                          "] " + redact_log_message(std::string{message}) + "\r\n";
        std::lock_guard lock{mutex_};
        std::error_code error;
        const auto current_size = std::filesystem::file_size(path_, error);
        if (!error && current_size + line.size() > maximum_bytes_) {
            rotate_locked();
        }
        Handle file{::CreateFileW(path_.c_str(), FILE_APPEND_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE |
                                      FILE_SHARE_DELETE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                  nullptr)};
        if (!file) {
            throw std::runtime_error("open rolling log failed with error " +
                                     std::to_string(::GetLastError()));
        }
        DWORD written{};
        if (line.size() > std::numeric_limits<DWORD>::max() ||
            ::WriteFile(file.get(), line.data(), static_cast<DWORD>(line.size()),
                        &written, nullptr) == FALSE ||
            written != line.size()) {
            throw std::runtime_error("write rolling log failed");
        }
        if (mirror_console_) {
            std::cerr << line;
        }
        const std::wstring source_name{L"sb-easy"};
        Handle source{::RegisterEventSourceW(nullptr, source_name.c_str())};
        if (source) {
            const auto wide_line = std::wstring{line.begin(), line.end()};
            const wchar_t* messages[] = {wide_line.c_str()};
            const WORD type = severity == "error" ? EVENTLOG_ERROR_TYPE
                                                   : EVENTLOG_INFORMATION_TYPE;
            static_cast<void>(::ReportEventW(source.get(), type, 0, 0, nullptr, 1, 0,
                                             messages, nullptr));
            static_cast<void>(::DeregisterEventSource(source.get()));
            static_cast<void>(source.release());
        }
    }

    [[nodiscard]] std::vector<std::string> tail(std::size_t maximum_lines) const {
        if (maximum_lines == 0U) {
            return {};
        }
        std::lock_guard lock{mutex_};
        const auto contents = storage_.read(path_).value_or(std::string{});
        std::vector<std::string> lines;
        std::size_t start{};
        while (start < contents.size()) {
            const auto end = contents.find('\n', start);
            auto line = contents.substr(start, end == std::string::npos
                                                   ? std::string::npos
                                                   : end - start);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            lines.push_back(redact_log_message(std::move(line)));
            if (end == std::string::npos) {
                break;
            }
            start = end + 1U;
        }
        if (lines.size() > maximum_lines) {
            lines.erase(lines.begin(), lines.end() -
                                           static_cast<std::ptrdiff_t>(maximum_lines));
        }
        return lines;
    }

    void clear() {
        std::lock_guard lock{mutex_};
        storage_.replace(path_, {});
        for (std::size_t index = 1U; index <= retained_files_; ++index) {
            storage_.remove(rotated_path(index));
        }
    }

    void set_retained_files(std::size_t retained_files) {
        if (retained_files == 0U || retained_files > 10U) {
            throw std::invalid_argument("rolling log retention is invalid");
        }
        std::lock_guard lock{mutex_};
        if (retained_files < retained_files_) {
            for (std::size_t index = retained_files + 1U;
                 index <= retained_files_; ++index) {
                storage_.remove(rotated_path(index));
            }
        }
        retained_files_ = retained_files;
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    [[nodiscard]] std::filesystem::path rotated_path(std::size_t index) const {
        return std::filesystem::path{path_.wstring() + L"." +
                                     std::to_wstring(index)};
    }

    void rotate_locked() {
        storage_.remove(rotated_path(retained_files_));
        for (std::size_t index = retained_files_; index > 1U; --index) {
            const auto source = rotated_path(index - 1U);
            const auto destination = rotated_path(index);
            if (::MoveFileExW(source.c_str(), destination.c_str(),
                              MOVEFILE_REPLACE_EXISTING |
                                  MOVEFILE_WRITE_THROUGH) == FALSE) {
                const DWORD error = ::GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    throw std::runtime_error("rotate service log failed with error " +
                                             std::to_string(error));
                }
            }
        }
        if (::MoveFileExW(path_.c_str(), rotated_path(1U).c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ==
            FALSE) {
            throw std::runtime_error("rotate active service log failed with error " +
                                     std::to_string(::GetLastError()));
        }
        storage_.replace(path_, {});
    }

    std::filesystem::path path_;
    std::size_t maximum_bytes_;
    std::size_t retained_files_;
    bool mirror_console_;
    mutable std::mutex mutex_;
    WindowsStorage storage_;
    WindowsClock clock_;
};

RollingLog::RollingLog(std::filesystem::path path, std::size_t maximum_bytes,
                       std::size_t retained_files, bool mirror_console,
                       bool restrict_acl)
    : implementation_(std::make_unique<Impl>(std::move(path), maximum_bytes,
                                             retained_files, mirror_console,
                                             restrict_acl)) {}
RollingLog::~RollingLog() = default;
void RollingLog::write(std::string_view severity, std::string_view message) {
    implementation_->write(severity, message);
}
std::vector<std::string> RollingLog::tail(std::size_t maximum_lines) const {
    return implementation_->tail(maximum_lines);
}
void RollingLog::clear() {
    implementation_->clear();
}
void RollingLog::set_retained_files(std::size_t retained_files) {
    implementation_->set_retained_files(retained_files);
}
const std::filesystem::path& RollingLog::path() const noexcept {
    return implementation_->path();
}

} // namespace sbeasy::win
