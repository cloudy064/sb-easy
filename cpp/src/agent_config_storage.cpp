#include "sbeasy/agent_config_storage.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

#include "sbeasy/atomic_file.hpp"

namespace sbeasy {

AgentConfigTransformOptions
load_agent_config_transform_options(const std::filesystem::path& path,
                                    const AgentConfigTransformOptions& defaults) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        if (!std::filesystem::exists(path)) {
            return defaults;
        }
        throw std::runtime_error("cannot read agent settings: " + path.string());
    }
    try {
        return agent_config_transform_options_from_json(nlohmann::json::parse(input),
                                                        defaults);
    } catch (const std::exception& error) {
        throw std::invalid_argument("invalid agent settings " + path.string() + ": " +
                                    error.what());
    }
}

void save_agent_config_transform_options(const std::filesystem::path& path,
                                         const AgentConfigTransformOptions& options) {
    atomic_replace_file(path,
                        agent_config_transform_options_to_json(options).dump(2) + '\n');
}

} // namespace sbeasy
