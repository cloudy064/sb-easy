#include "sbeasy/windows/platform.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#include <aclapi.h>
#include <dpapi.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include "sbeasy/version.hpp"

namespace sbeasy::win {
namespace {

class Handle final {
  public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() {
        reset();
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(value_, nullptr);
    }
    void reset(HANDLE value = nullptr) noexcept {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            static_cast<void>(::CloseHandle(value_));
        }
        value_ = value;
    }
    explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE value_{nullptr};
};

[[nodiscard]] std::string utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const auto input_size = static_cast<int>(value.size());
    const int required = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                                value.data(), input_size, nullptr, 0,
                                                nullptr, nullptr);
    if (required <= 0) {
        throw std::runtime_error("UTF-16 to UTF-8 conversion failed");
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size,
                              result.data(), required, nullptr, nullptr) != required) {
        throw std::runtime_error("UTF-16 to UTF-8 conversion failed");
    }
    return result;
}

[[nodiscard]] std::wstring wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const auto input_size = static_cast<int>(value.size());
    const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                value.data(), input_size, nullptr, 0);
    if (required <= 0) {
        throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size,
                              result.data(), required) != required) {
        throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
    }
    return result;
}

[[noreturn]] void throw_windows_error(std::string_view operation,
                                      DWORD error = ::GetLastError()) {
    LPWSTR buffer{};
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string detail;
    if (length != 0U && buffer != nullptr) {
        detail = utf8(std::wstring_view{buffer, length});
        static_cast<void>(::LocalFree(buffer));
        while (!detail.empty() &&
               (detail.back() == '\r' || detail.back() == '\n' ||
                detail.back() == ' ')) {
            detail.pop_back();
        }
    }
    throw std::runtime_error(std::string{operation} + " failed (" +
                             std::to_string(error) +"): " + detail);
}

[[nodiscard]] std::wstring quote_argument(std::wstring_view argument) {
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring{argument};
    }
    std::wstring result{L'"'};
    std::size_t slashes{};
    for (const wchar_t character : argument) {
        if (character == L'\\') {
            ++slashes;
            continue;
        }
        if (character == L'"') {
            result.append(slashes * 2U + 1U, L'\\');
            result.push_back(L'"');
        } else {
            result.append(slashes, L'\\');
            result.push_back(character);
        }
        slashes = 0U;
    }
    result.append(slashes * 2U, L'\\');
    result.push_back(L'"');
    return result;
}

[[nodiscard]] std::wstring command_line(const std::vector<std::string>& arguments) {
    std::wstring result;
    for (const auto& argument : arguments) {
        if (!result.empty()) {
            result.push_back(L' ');
        }
        result += quote_argument(wide(argument));
    }
    return result;
}

void apply_restricted_acl(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR raw_descriptor{};
    constexpr wchar_t descriptor[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, &raw_descriptor, nullptr) == FALSE) {
        throw_windows_error("create restricted security descriptor");
    }
    const std::unique_ptr<void, decltype(&::LocalFree)> security_descriptor{
        raw_descriptor, &::LocalFree};
    BOOL present{};
    BOOL defaulted{};
    PACL dacl{};
    if (::GetSecurityDescriptorDacl(security_descriptor.get(), &present, &dacl,
                                    &defaulted) == FALSE || present == FALSE) {
        throw_windows_error("read restricted DACL");
    }
    const DWORD result = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
        nullptr, dacl, nullptr);
    if (result != ERROR_SUCCESS) {
        throw_windows_error("apply restricted DACL", result);
    }
}

void ensure_parent(const std::filesystem::path& path, bool restrict_acl) {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return;
    }
    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        throw std::runtime_error("create data directory failed: " + error.message());
    }
    if (restrict_acl) {
        apply_restricted_acl(parent);
    }
}

[[nodiscard]] std::filesystem::path temporary_path_for(
    const std::filesystem::path& target) {
    std::array<unsigned char, 8> random{};
    if (::BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("generate temporary filename failed");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string suffix;
    suffix.reserve(random.size() * 2U);
    for (const auto value : random) {
        suffix.push_back(digits[value >> 4U]);
        suffix.push_back(digits[value & 0x0fU]);
    }
    return target.parent_path() /
           (target.filename().string() + ".tmp-" + std::move(suffix));
}

void write_all(HANDLE file, std::string_view contents) {
    std::size_t offset{};
    while (offset < contents.size()) {
        const auto remaining = contents.size() - offset;
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            remaining, static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD written{};
        if (::WriteFile(file, contents.data() + offset, requested, &written, nullptr) ==
                FALSE ||
            written == 0U) {
            throw_windows_error("write service-owned file");
        }
        offset += written;
    }
}

[[nodiscard]] std::optional<std::string>
read_file(const std::filesystem::path& path) {
    Handle file{::CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!file) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return std::nullopt;
        }
        throw_windows_error("open service-owned file", error);
    }
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(file.get(), &size) == FALSE) {
        throw_windows_error("read service-owned file size");
    }
    if (size.QuadPart < 0 ||
        static_cast<unsigned long long>(size.QuadPart) >
            static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("service-owned file is too large");
    }
    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    std::size_t offset{};
    while (offset < result.size()) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            result.size() - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD received{};
        if (::ReadFile(file.get(), result.data() + offset, requested, &received,
                       nullptr) == FALSE) {
            throw_windows_error("read service-owned file");
        }
        if (received == 0U) {
            result.resize(offset);
            break;
        }
        offset += received;
    }
    return result;
}

[[nodiscard]] std::string architecture_name(WORD architecture) {
    switch (architecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return "x86_64";
    case PROCESSOR_ARCHITECTURE_ARM64:
        return "aarch64";
    case PROCESSOR_ARCHITECTURE_INTEL:
        return "x86";
    default:
        return "unknown";
    }
}

} // namespace

WindowsProcess::WindowsProcess(std::chrono::milliseconds timeout) : timeout_(timeout) {
    if (timeout_ <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("process timeout must be positive");
    }
}

ProcessResult WindowsProcess::run(const std::vector<std::string>& arguments) {
    if (arguments.empty() || arguments.front().empty()) {
        return {.success = false, .detail = "executable is required"};
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE read_raw{};
    HANDLE write_raw{};
    if (::CreatePipe(&read_raw, &write_raw, &attributes, 0) == FALSE) {
        throw_windows_error("create process output pipe");
    }
    Handle read_pipe{read_raw};
    Handle write_pipe{write_raw};
    if (::SetHandleInformation(read_pipe.get(), HANDLE_FLAG_INHERIT, 0) == FALSE) {
        throw_windows_error("protect process output pipe");
    }

    auto command = command_line(arguments);
    auto application = wide(arguments.front());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_pipe.get();
    startup.hStdError = write_pipe.get();
    PROCESS_INFORMATION process_info{};
    if (::CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                         &process_info) == FALSE) {
        return {.success = false,
                .detail = "CreateProcess failed: " +
                          std::to_string(::GetLastError())};
    }
    Handle process{process_info.hProcess};
    Handle thread{process_info.hThread};
    write_pipe.reset();

    std::string output;
    std::thread reader{[&output, handle = read_pipe.get()] {
        std::array<char, 4096> buffer{};
        DWORD received{};
        while (::ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                          &received, nullptr) != FALSE &&
               received != 0U) {
            constexpr std::size_t maximum = 1024U * 1024U;
            if (output.size() < maximum) {
                const auto accepted = std::min<std::size_t>(
                    received, maximum - output.size());
                output.append(buffer.data(), accepted);
            }
        }
    }};

    const auto timeout_value = static_cast<unsigned long long>(timeout_.count());
    const DWORD wait_timeout = static_cast<DWORD>(std::min<unsigned long long>(
        timeout_value, static_cast<unsigned long long>(INFINITE - 1U)));
    const DWORD wait = ::WaitForSingleObject(process.get(), wait_timeout);
    bool timed_out = false;
    if (wait == WAIT_TIMEOUT) {
        timed_out = true;
        static_cast<void>(::TerminateProcess(process.get(), ERROR_TIMEOUT));
        static_cast<void>(::WaitForSingleObject(process.get(), 5'000));
    } else if (wait != WAIT_OBJECT_0) {
        static_cast<void>(::TerminateProcess(process.get(), ERROR_PROCESS_ABORTED));
        static_cast<void>(::WaitForSingleObject(process.get(), 5'000));
    }
    DWORD exit_code{};
    if (::GetExitCodeProcess(process.get(), &exit_code) == FALSE) {
        exit_code = ERROR_PROCESS_ABORTED;
    }
    process.reset();
    reader.join();
    read_pipe.reset();
    if (timed_out) {
        return {.success = false, .detail = "process timed out"};
    }
    if (wait != WAIT_OBJECT_0) {
        return {.success = false, .detail = "wait for process failed"};
    }
    return {.success = exit_code == 0U,
            .detail = output.empty() ? "exit code " + std::to_string(exit_code)
                                     : std::move(output)};
}

WindowsStorage::WindowsStorage(bool restrict_acl) : restrict_acl_(restrict_acl) {}

std::optional<std::string>
WindowsStorage::read(const std::filesystem::path& path) const {
    return read_file(path);
}

void WindowsStorage::replace(const std::filesystem::path& path,
                             std::string_view contents,
                             const StorageValidator& validator) {
    if (path.empty() || path.filename().empty()) {
        throw std::invalid_argument("storage path must name a file");
    }
    ensure_parent(path, restrict_acl_);
    const auto temporary = temporary_path_for(path);
    try {
        Handle file{::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW,
                                  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
                                  nullptr)};
        if (!file) {
            throw_windows_error("create temporary service-owned file");
        }
        write_all(file.get(), contents);
        if (::FlushFileBuffers(file.get()) == FALSE) {
            throw_windows_error("flush temporary service-owned file");
        }
        file.reset();
        if (restrict_acl_) {
            apply_restricted_acl(temporary);
        }
        if (validator) {
            validator(temporary);
        }
        if (::ReplaceFileW(path.c_str(), temporary.c_str(), nullptr,
                           REPLACEFILE_WRITE_THROUGH, nullptr, nullptr) == FALSE) {
            const DWORD replace_error = ::GetLastError();
            if ((replace_error != ERROR_FILE_NOT_FOUND &&
                 replace_error != ERROR_PATH_NOT_FOUND) ||
                ::MoveFileExW(temporary.c_str(), path.c_str(),
                              MOVEFILE_REPLACE_EXISTING |
                                  MOVEFILE_WRITE_THROUGH) == FALSE) {
                throw_windows_error("atomically replace service-owned file");
            }
        }
        if (restrict_acl_) {
            apply_restricted_acl(path);
        }
    } catch (...) {
        static_cast<void>(::DeleteFileW(temporary.c_str()));
        throw;
    }
}

void WindowsStorage::remove(const std::filesystem::path& path) const {
    if (::DeleteFileW(path.c_str()) == FALSE) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            throw_windows_error("remove service-owned file", error);
        }
    }
}

DpapiCredentialStore::DpapiCredentialStore(std::filesystem::path path,
                                           bool restrict_acl)
    : path_(std::move(path)), storage_(restrict_acl) {
    if (path_.empty() || path_.filename().empty()) {
        throw std::invalid_argument("credential path must name a file");
    }
}

std::optional<std::string> DpapiCredentialStore::read() const {
    const auto encrypted = storage_.read(path_);
    if (!encrypted.has_value()) {
        return std::nullopt;
    }
    constexpr std::string_view magic{"SBEASY-DPAPI-1\0", 15U};
    if (!encrypted->starts_with(magic)) {
        throw std::runtime_error("credential file has an invalid header");
    }
    auto* payload = reinterpret_cast<BYTE*>(
        const_cast<char*>(encrypted->data() + magic.size()));
    const auto payload_size = encrypted->size() - magic.size();
    if (payload_size > std::numeric_limits<DWORD>::max()) {
        throw std::runtime_error("credential file is too large");
    }
    DATA_BLOB input{static_cast<DWORD>(payload_size), payload};
    constexpr std::array<BYTE, 16> entropy{
        0x73, 0x62, 0x2d, 0x65, 0x61, 0x73, 0x79, 0x2d,
        0x77, 0x69, 0x6e, 0x2d, 0x76, 0x31, 0x00, 0x01};
    DATA_BLOB optional_entropy{static_cast<DWORD>(entropy.size()),
                               const_cast<BYTE*>(entropy.data())};
    DATA_BLOB output{};
    if (::CryptUnprotectData(&input, nullptr, &optional_entropy, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN, &output) == FALSE) {
        throw_windows_error("decrypt device credential");
    }
    std::string plaintext{reinterpret_cast<const char*>(output.pbData),
                          output.cbData};
    ::SecureZeroMemory(output.pbData, output.cbData);
    static_cast<void>(::LocalFree(output.pbData));
    return plaintext;
}

void DpapiCredentialStore::replace(std::string_view plaintext) {
    if (plaintext.size() > std::numeric_limits<DWORD>::max()) {
        throw std::invalid_argument("credential is too large");
    }
    DATA_BLOB input{static_cast<DWORD>(plaintext.size()),
                    reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()))};
    constexpr std::array<BYTE, 16> entropy{
        0x73, 0x62, 0x2d, 0x65, 0x61, 0x73, 0x79, 0x2d,
        0x77, 0x69, 0x6e, 0x2d, 0x76, 0x31, 0x00, 0x01};
    DATA_BLOB optional_entropy{static_cast<DWORD>(entropy.size()),
                               const_cast<BYTE*>(entropy.data())};
    DATA_BLOB output{};
    if (::CryptProtectData(&input, L"sb-easy device credential",
                           &optional_entropy, nullptr, nullptr,
                           CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                           &output) == FALSE) {
        throw_windows_error("encrypt device credential");
    }
    constexpr std::string_view magic{"SBEASY-DPAPI-1\0", 15U};
    std::string serialized{magic};
    serialized.append(reinterpret_cast<const char*>(output.pbData), output.cbData);
    ::SecureZeroMemory(output.pbData, output.cbData);
    static_cast<void>(::LocalFree(output.pbData));
    storage_.replace(path_, serialized);
    ::SecureZeroMemory(serialized.data(), serialized.size());
}

void DpapiCredentialStore::remove() {
    storage_.remove(path_);
}

const std::filesystem::path& DpapiCredentialStore::path() const noexcept {
    return path_;
}

std::string WindowsClock::now_iso8601() const {
    SYSTEMTIME value{};
    ::GetSystemTime(&value);
    std::array<char, 32> result{};
    const int written = ::snprintf(result.data(), result.size(),
                                   "%04u-%02u-%02uT%02u:%02u:%02uZ", value.wYear,
                                   value.wMonth, value.wDay, value.wHour, value.wMinute,
                                   value.wSecond);
    return written > 0 ? std::string{result.data()} : std::string{};
}

nlohmann::json WindowsMetadata::device_metadata() const {
    DWORD length{};
    static_cast<void>(::GetComputerNameExW(ComputerNameDnsHostname, nullptr, &length));
    std::wstring hostname(static_cast<std::size_t>(length), L'\0');
    if (length == 0U ||
        ::GetComputerNameExW(ComputerNameDnsHostname, hostname.data(), &length) ==
            FALSE) {
        hostname = L"windows-device";
    } else {
        hostname.resize(length);
    }
    SYSTEM_INFO system{};
    ::GetNativeSystemInfo(&system);
    return {
        {"platform", "windows"},
        {"hostname", utf8(hostname)},
        {"architecture", architecture_name(system.wProcessorArchitecture)},
        {"agent_version", "sb-easy-windows/" +
                              std::string{application_version}},
        {"interactive_client", true},
        {"supports_proxy_selection", true},
    };
}

std::filesystem::path program_data_directory() {
    PWSTR raw{};
    const HRESULT result = ::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr,
                                                   &raw);
    if (FAILED(result) || raw == nullptr) {
        throw std::runtime_error("resolve ProgramData directory failed");
    }
    const std::unique_ptr<wchar_t, decltype(&::CoTaskMemFree)> value{
        raw, &::CoTaskMemFree};
    return std::filesystem::path{value.get()} / L"sb-easy";
}

std::filesystem::path executable_directory() {
    std::wstring value(260U, L'\0');
    for (;;) {
        const DWORD length = ::GetModuleFileNameW(
            nullptr, value.data(), static_cast<DWORD>(value.size()));
        if (length == 0U) {
            throw_windows_error("resolve executable path");
        }
        if (length < value.size() - 1U) {
            value.resize(length);
            return std::filesystem::path{value}.parent_path();
        }
        value.resize(value.size() * 2U);
    }
}

void prepare_service_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        throw std::invalid_argument("service data directory must not be empty");
    }
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        throw std::runtime_error("create service data directory failed: " +
                                 error.message());
    }
    apply_restricted_acl(path);
}

} // namespace sbeasy::win
