#pragma once

#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace sbeasy {

class ScriptError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

struct ScriptLimits {
    std::size_t memory_bytes{16U * 1024U * 1024U};
    std::size_t stack_bytes{256U * 1024U};
    std::size_t source_bytes{128U * 1024U};
    std::size_t output_bytes{2U * 1024U * 1024U};
    std::chrono::milliseconds timeout{50};
};

/// Executes a deterministic `buildRules(context)` JavaScript function.
///
/// Each call creates a fresh QuickJS runtime. No filesystem, network, process,
/// module loader, or QuickJS std/os bindings are installed.
class RuleScriptEngine final {
  public:
    explicit RuleScriptEngine(ScriptLimits limits = {});

    [[nodiscard]] nlohmann::json build_rules(const std::string& source,
                                             const nlohmann::json& context) const;

  private:
    ScriptLimits limits_;
};

} // namespace sbeasy
