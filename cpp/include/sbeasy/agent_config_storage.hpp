#pragma once

#include <filesystem>

#include "sbeasy/agent_config.hpp"

namespace sbeasy {

/// Legacy POSIX-agent settings persistence. New service runtimes should use
/// PlatformStorage so credentials and generated configuration share the
/// platform's durability and access-control implementation.
[[nodiscard]] AgentConfigTransformOptions
load_agent_config_transform_options(const std::filesystem::path& path,
                                    const AgentConfigTransformOptions& defaults = {});

void save_agent_config_transform_options(const std::filesystem::path& path,
                                         const AgentConfigTransformOptions& options);

} // namespace sbeasy
