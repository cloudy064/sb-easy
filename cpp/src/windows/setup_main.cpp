// sb-easy Windows setup launcher.
//
// The product ships a WiX Burn bootstrapper, which extracts its bootstrapper
// application into the invoking user's temporary directory and starts it from
// there. On affected machines, images under the temporary directory run at
// low integrity, and a low-integrity process cannot open the
// medium-integrity named pipe the Burn engine creates for its bootstrapper
// application. The engine then waits for a connection that can never happen and
// fails the whole setup with ERROR_TIMEOUT (0x800705B4) before any install work
// starts.
//
// This launcher gives the bootstrapper a private temporary directory that is
// not the user's temporary directory, so the extracted bootstrapper application
// keeps the caller's integrity level and the engine pipe works as designed.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <shellapi.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t bundle_file_name[] = L"sb-easy-windows-bootstrapper.exe";
constexpr wchar_t product_directory_name[] = L"sb-easy";
constexpr wchar_t work_directory_name[] = L"setup-work";

[[noreturn]] void throw_windows_error(std::string_view description) {
    throw std::runtime_error(std::string{description} + " failed with error " +
                             std::to_string(::GetLastError()));
}

std::wstring widen(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int required = ::MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }
    std::wstring value(static_cast<std::size_t>(required), L'\0');
    static_cast<void>(::MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), value.data(),
        required));
    return value;
}

std::filesystem::path known_folder(REFKNOWNFOLDERID identifier) {
    PWSTR raw{};
    const HRESULT result =
        ::SHGetKnownFolderPath(identifier, KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(result) || raw == nullptr) {
        if (raw != nullptr) {
            ::CoTaskMemFree(raw);
        }
        throw std::runtime_error("resolve a known folder failed");
    }
    const std::filesystem::path value{raw};
    ::CoTaskMemFree(raw);
    return value;
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

// Quote one argument the way CommandLineToArgvW will parse it back.
std::wstring quote_argument(const std::wstring& value) {
    if (!value.empty() && value.find_first_of(L" \t\"") == std::wstring::npos) {
        return value;
    }
    std::wstring quoted(1U, L'"');
    std::size_t backslashes = 0U;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'"') {
            quoted.append(backslashes * 2U + 1U, L'\\');
            quoted.push_back(L'"');
            backslashes = 0U;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0U;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2U, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

std::vector<std::wstring> parse_arguments() {
    int count = 0;
    LPWSTR* raw = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    if (raw == nullptr) {
        throw_windows_error("parse command line");
    }
    std::vector<std::wstring> arguments;
    arguments.reserve(static_cast<std::size_t>(count));
    for (int index = 0; index < count; ++index) {
        arguments.emplace_back(raw[index] == nullptr ? L"" : raw[index]);
    }
    ::LocalFree(raw);
    return arguments;
}

// Copies the current environment, replacing TEMP and TMP with work_directory.
std::wstring environment_block(const std::filesystem::path& work_directory) {
    LPWCH raw = ::GetEnvironmentStringsW();
    if (raw == nullptr) {
        throw_windows_error("read the process environment");
    }
    const auto free_environment = [](wchar_t* value) {
        ::FreeEnvironmentStringsW(value);
    };
    const std::unique_ptr<wchar_t, decltype(free_environment)> environment{
        raw, free_environment};
    const std::wstring temp_directory = work_directory.wstring();
    const auto variable_name = [](std::wstring_view entry) {
        // Preserve Windows' hidden drive entries, such as =C:=C:\\work.
        return entry.substr(0U, entry.find(L'=', 1U));
    };
    std::vector<std::wstring> entries;
    // GetEnvironmentStringsW returns multiple NUL-terminated entries followed
    // by an extra NUL. A string_view of raw alone stops at the first entry.
    for (const wchar_t* cursor = raw; *cursor != L'\0';) {
        const std::wstring_view entry{cursor};
        cursor += entry.size() + 1U;
        const std::wstring_view name = variable_name(entry);
        if ((name.size() == 4U &&
             ::CompareStringOrdinal(name.data(), 4, L"TEMP", 4, TRUE) ==
                 CSTR_EQUAL) ||
            (name.size() == 3U &&
             ::CompareStringOrdinal(name.data(), 3, L"TMP", 3, TRUE) ==
                 CSTR_EQUAL)) {
            continue;
        }
        entries.emplace_back(entry);
    }
    for (const wchar_t* name : {L"TEMP", L"TMP"}) {
        entries.emplace_back(std::wstring{name} + L'=' + temp_directory);
    }
    std::sort(entries.begin(), entries.end(), [&](const auto& left, const auto& right) {
        const auto left_name = variable_name(left);
        const auto right_name = variable_name(right);
        return ::CompareStringOrdinal(
                   left_name.data(), static_cast<int>(left_name.size()),
                   right_name.data(), static_cast<int>(right_name.size()), TRUE) ==
               CSTR_LESS_THAN;
    });
    std::wstring block;
    for (const auto& entry : entries) {
        block.append(entry);
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

struct BundleInvocation {
    std::filesystem::path bundle;
    std::vector<std::wstring> forwarded;
};

BundleInvocation resolve_invocation(const std::vector<std::wstring>& arguments) {
    BundleInvocation invocation;
    for (std::size_t index = 1U; index < arguments.size(); ++index) {
        const std::wstring& argument = arguments[index];
        if (argument == L"--bundle") {
            if (index + 1U >= arguments.size()) {
                throw std::invalid_argument("--bundle requires a path");
            }
            invocation.bundle = std::filesystem::path{arguments[++index]};
            continue;
        }
        if (argument.rfind(L"--bundle=", 0U) == 0U) {
            invocation.bundle = std::filesystem::path{argument.substr(9U)};
            continue;
        }
        invocation.forwarded.push_back(argument);
    }
    if (invocation.bundle.empty()) {
        invocation.bundle = executable_directory() / bundle_file_name;
    }
    return invocation;
}

void report_failure(const std::wstring& message) {
    const std::wstring command_line = ::GetCommandLineW() == nullptr
                                          ? std::wstring{}
                                          : std::wstring{::GetCommandLineW()};
    std::wstring lowered = command_line;
    ::CharLowerBuffW(lowered.data(), static_cast<DWORD>(lowered.size()));
    const bool silent = lowered.find(L"/quiet") != std::wstring::npos ||
                        lowered.find(L"/qn") != std::wstring::npos;
    if (silent) {
        const std::string narrow = message.size() == 0U
                                       ? std::string{}
                                       : [&message] {
                                             const int required =
                                                 ::WideCharToMultiByte(
                                                     CP_UTF8, 0, message.data(),
                                                     static_cast<int>(
                                                         message.size()),
                                                     nullptr, 0, nullptr,
                                                     nullptr);
                                             if (required <= 0) {
                                                 return std::string{};
                                             }
                                             std::string value(
                                                 static_cast<std::size_t>(
                                                     required),
                                                 '\0');
                                             static_cast<void>(
                                                 ::WideCharToMultiByte(
                                                     CP_UTF8, 0, message.data(),
                                                     static_cast<int>(
                                                         message.size()),
                                                     value.data(), required,
                                                     nullptr, nullptr));
                                             return value;
                                         }();
        const std::string line = narrow + "\n";
        static_cast<void>(::fwrite(line.data(), 1U, line.size(), stderr));
        return;
    }
    ::MessageBoxW(nullptr, message.c_str(), L"sb-easy Setup",
                  MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
}

int run(const std::vector<std::wstring>& arguments) {
    const BundleInvocation invocation = resolve_invocation(arguments);
    if (!std::filesystem::is_regular_file(invocation.bundle)) {
        report_failure(L"sb-easy Setup could not find its installer payload:\n\n" +
                       invocation.bundle.wstring() +
                       L"\n\nKeep the setup launcher and the bootstrapper in the "
                       L"same folder.");
        return 2;
    }

    const std::filesystem::path work_directory =
        known_folder(FOLDERID_LocalAppData) / product_directory_name /
        work_directory_name / (std::to_wstring(::GetCurrentProcessId()) + L"-" +
                               std::to_wstring(::GetTickCount64()));
    std::error_code error;
    std::filesystem::create_directories(work_directory, error);
    if (error) {
        report_failure(
            L"sb-easy Setup could not create its working directory:\n\n" +
            work_directory.wstring() + L"\n\n" + widen(error.message()));
        return 3;
    }

    std::wstring command_line = quote_argument(invocation.bundle.wstring());
    for (const std::wstring& argument : invocation.forwarded) {
        command_line.push_back(L' ');
        command_line.append(quote_argument(argument));
    }
    std::wstring environment = environment_block(work_directory);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (::CreateProcessW(invocation.bundle.c_str(), command_line.data(), nullptr,
                         nullptr, TRUE, CREATE_UNICODE_ENVIRONMENT,
                         environment.data(), nullptr, &startup,
                         &process) == FALSE) {
        throw_windows_error("start the sb-easy bootstrapper");
    }
    ::CloseHandle(process.hThread);
    const DWORD wait = ::WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1U;
    if (wait != WAIT_OBJECT_0 || ::GetExitCodeProcess(process.hProcess, &exit_code) ==
                                     FALSE) {
        ::CloseHandle(process.hProcess);
        throw_windows_error("wait for the sb-easy bootstrapper");
    }
    ::CloseHandle(process.hProcess);

    // Burn removes its own staging area; anything left is best-effort cleanup.
    std::filesystem::remove_all(work_directory, error);
    return static_cast<int>(exit_code & 0x7FFFFFFFU);
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    try {
        return run(parse_arguments());
    } catch (const std::exception& failure) {
        report_failure(L"sb-easy Setup failed: " + widen(failure.what()));
        return 1;
    }
}
