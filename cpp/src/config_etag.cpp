#include "sbeasy/config_etag.hpp"

#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

namespace sbeasy {
namespace {

void update_digest(EVP_MD_CTX* context, std::string_view value) {
    if (value.empty()) {
        return;
    }
    if (EVP_DigestUpdate(context, value.data(), value.size()) != 1) {
        throw std::runtime_error("SHA-256 ETag update failed");
    }
}

} // namespace

std::string config_etag(std::string_view host_id, std::string_view pretty_config,
                        std::string_view seed) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 ETag initialization failed");
    }
    update_digest(context.get(), host_id);
    update_digest(context.get(), pretty_config);
    update_digest(context.get(), seed);

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size{};
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1 || size != 32U) {
        throw std::runtime_error("SHA-256 ETag finalization failed");
    }

    std::ostringstream output;
    output << '"' << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    output << '"';
    return output.str();
}

} // namespace sbeasy
