#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/ui_preferences.hpp is only available on Windows"
#endif

namespace sbeasy::win {

struct UiPreferences {
    bool launch_at_logon{false};
    bool close_to_tray{true};
    bool minimize_to_tray{false};
    bool update_notifications{true};
};

/// Loads ordinary-user UI preferences from HKCU. Missing or unreadable values
/// fall back to safe defaults and never affect the Service connection state.
[[nodiscard]] UiPreferences load_ui_preferences() noexcept;

/// Persists UI preferences beneath HKCU and maintains only this application's
/// own Run value. This function is called solely after an explicit UI action.
void save_ui_preferences(const UiPreferences& preferences);

} // namespace sbeasy::win
