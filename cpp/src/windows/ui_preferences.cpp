#include "sbeasy/windows/ui_preferences.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace sbeasy::win {
namespace {

constexpr wchar_t preferences_key[] = L"Software\\sb-easy\\Client";
constexpr wchar_t run_key[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t run_value[] = L"sb-easy";

class RegistryKey final {
  public:
    RegistryKey() = default;
    explicit RegistryKey(HKEY value) : value_(value) {}
    ~RegistryKey() {
        if (value_ != nullptr) {
            static_cast<void>(::RegCloseKey(value_));
        }
    }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;
    RegistryKey(RegistryKey&& other) noexcept
        : value_(std::exchange(other.value_, nullptr)) {}
    [[nodiscard]] HKEY get() const noexcept {
        return value_;
    }
    [[nodiscard]] HKEY* output() noexcept {
        return &value_;
    }

  private:
    HKEY value_{};
};

[[nodiscard]] std::wstring executable_path() {
    std::wstring value(32'768U, L'\0');
    const DWORD length = ::GetModuleFileNameW(
        nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length == 0U || length >= value.size()) {
        throw std::runtime_error("resolve UI executable path failed");
    }
    value.resize(length);
    return value;
}

[[nodiscard]] std::wstring launch_command() {
    return L"\"" + executable_path() + L"\" --background";
}

[[nodiscard]] bool read_dword(HKEY key, const wchar_t* name,
                              bool fallback) noexcept {
    DWORD value{};
    DWORD size = sizeof(value);
    DWORD type{};
    return ::RegQueryValueExW(key, name, nullptr, &type,
                              reinterpret_cast<BYTE*>(&value), &size) ==
                   ERROR_SUCCESS &&
               type == REG_DWORD && size == sizeof(value)
           ? value != 0U
           : fallback;
}

void write_dword(HKEY key, const wchar_t* name, bool value) {
    const DWORD serialized = value ? 1U : 0U;
    const LSTATUS result = ::RegSetValueExW(
        key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&serialized),
        sizeof(serialized));
    if (result != ERROR_SUCCESS) {
        throw std::runtime_error("write UI preference failed with error " +
                                 std::to_string(result));
    }
}

[[nodiscard]] bool launch_at_logon_enabled() noexcept {
    try {
        RegistryKey key;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, run_key, 0, KEY_QUERY_VALUE,
                            key.output()) != ERROR_SUCCESS) {
            return false;
        }
        DWORD bytes{};
        DWORD type{};
        if (::RegQueryValueExW(key.get(), run_value, nullptr, &type, nullptr,
                               &bytes) != ERROR_SUCCESS ||
            (type != REG_SZ && type != REG_EXPAND_SZ) ||
            bytes < sizeof(wchar_t) || bytes > 65'536U) {
            return false;
        }
        std::vector<wchar_t> value(bytes / sizeof(wchar_t), L'\0');
        if (::RegQueryValueExW(key.get(), run_value, nullptr, &type,
                               reinterpret_cast<BYTE*>(value.data()), &bytes) !=
            ERROR_SUCCESS) {
            return false;
        }
        return std::wstring_view{value.data()} == launch_command();
    } catch (const std::exception&) {
        return false;
    }
}

void set_launch_at_logon(bool enabled) {
    RegistryKey key;
    DWORD disposition{};
    const LSTATUS opened = ::RegCreateKeyExW(
        HKEY_CURRENT_USER, run_key, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE, nullptr, key.output(), &disposition);
    if (opened != ERROR_SUCCESS) {
        throw std::runtime_error("open user logon settings failed with error " +
                                 std::to_string(opened));
    }
    static_cast<void>(disposition);
    if (!enabled) {
        const LSTATUS removed = ::RegDeleteValueW(key.get(), run_value);
        if (removed != ERROR_SUCCESS && removed != ERROR_FILE_NOT_FOUND) {
            throw std::runtime_error("remove UI logon entry failed with error " +
                                     std::to_string(removed));
        }
        return;
    }
    const auto command = launch_command();
    const auto bytes = static_cast<DWORD>((command.size() + 1U) * sizeof(wchar_t));
    const LSTATUS written = ::RegSetValueExW(
        key.get(), run_value, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(command.c_str()), bytes);
    if (written != ERROR_SUCCESS) {
        throw std::runtime_error("write UI logon entry failed with error " +
                                 std::to_string(written));
    }
}

} // namespace

UiPreferences load_ui_preferences() noexcept {
    UiPreferences result;
    result.launch_at_logon = launch_at_logon_enabled();
    RegistryKey key;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, preferences_key, 0, KEY_QUERY_VALUE,
                        key.output()) != ERROR_SUCCESS) {
        return result;
    }
    result.close_to_tray =
        read_dword(key.get(), L"CloseToTray", result.close_to_tray);
    result.minimize_to_tray =
        read_dword(key.get(), L"MinimizeToTray", result.minimize_to_tray);
    result.update_notifications = read_dword(
        key.get(), L"UpdateNotifications", result.update_notifications);
    return result;
}

void save_ui_preferences(const UiPreferences& preferences) {
    set_launch_at_logon(preferences.launch_at_logon);
    RegistryKey key;
    DWORD disposition{};
    const LSTATUS opened = ::RegCreateKeyExW(
        HKEY_CURRENT_USER, preferences_key, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, key.output(),
        &disposition);
    if (opened != ERROR_SUCCESS) {
        throw std::runtime_error("open UI preferences failed with error " +
                                 std::to_string(opened));
    }
    static_cast<void>(disposition);
    write_dword(key.get(), L"CloseToTray", preferences.close_to_tray);
    write_dword(key.get(), L"MinimizeToTray", preferences.minimize_to_tray);
    write_dword(key.get(), L"UpdateNotifications",
                preferences.update_notifications);
}

} // namespace sbeasy::win
