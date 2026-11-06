#pragma once

#include <string>
#include <vector>

namespace sbeasy {

struct ProcessResult {
    bool success{false};
    std::string detail;
};

/// Runs bounded, pre-tokenized platform commands. Implementations must not
/// invoke a shell; callers supply the executable as the first argument.
class PlatformProcess {
  public:
    virtual ~PlatformProcess() = default;

    [[nodiscard]] virtual ProcessResult
    run(const std::vector<std::string>& arguments) = 0;
};

} // namespace sbeasy
