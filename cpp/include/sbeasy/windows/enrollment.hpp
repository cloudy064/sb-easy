#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/enrollment.hpp is only available on Windows"
#endif

#include <string>
#include <string_view>

namespace sbeasy::win {

struct EnrollmentPreview {
    std::string server;
    std::string code;
};

/// Parse the protocol payload without redeeming it. Only an HTTP(S) origin and
/// a 64-hex-character one-time code are accepted.
[[nodiscard]] EnrollmentPreview parse_enrollment_uri(std::string_view input);

} // namespace sbeasy::win
