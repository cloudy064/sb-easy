#include "sbeasy/platform_adapters.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

#include "sbeasy/atomic_file.hpp"

namespace sbeasy {

std::optional<std::string> PosixStorage::read(const std::filesystem::path& path) const {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        std::error_code error;
        if (!std::filesystem::exists(path, error) && !error) {
            return std::nullopt;
        }
        throw std::runtime_error("cannot read file: " + path.string());
    }
    return std::string{std::istreambuf_iterator<char>{input},
                       std::istreambuf_iterator<char>{}};
}

void PosixStorage::replace(const std::filesystem::path& path, std::string_view contents,
                           const StorageValidator& validator) {
    atomic_replace_file(path, contents, validator);
}

} // namespace sbeasy
