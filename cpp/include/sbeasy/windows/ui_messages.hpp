#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/ui_messages.hpp is only available on Windows"
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace sbeasy::win {

inline constexpr UINT tray_message = WM_APP + 40U;
inline constexpr UINT rpc_response_message = WM_APP + 41U;
inline constexpr UINT show_window_message = WM_APP + 42U;
inline constexpr UINT exit_ui_message = WM_APP + 43U;
inline constexpr ULONG_PTR enrollment_copy_data = 0x53424531U;

inline constexpr UINT tray_open_command = 30'001U;
inline constexpr UINT tray_exit_command = 30'002U;

} // namespace sbeasy::win
