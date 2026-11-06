#include "sbeasy/windows/embedded_runtime.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

#include "runtime_resources.h"
#include "sbeasy/windows/platform.hpp"

namespace sbeasy::win {
namespace {

constexpr std::string_view sing_box_sha256 =
    "64b1dfaed6fa758295233fd0bec8b32cf2115f29773adbf38e0f026c3c7986f2";
constexpr std::string_view wintun_sha256 =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

class Algorithm final {
  public:
    Algorithm() {
        if (::BCryptOpenAlgorithmProvider(&value_, BCRYPT_SHA256_ALGORITHM,
                                          nullptr, 0U) < 0) {
            throw std::runtime_error("open SHA-256 provider failed");
        }
    }
    ~Algorithm() {
        if (value_ != nullptr) {
            static_cast<void>(::BCryptCloseAlgorithmProvider(value_, 0U));
        }
    }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept {
        return value_;
    }

  private:
    BCRYPT_ALG_HANDLE value_{};
};

class Hash final {
  public:
    explicit Hash(BCRYPT_ALG_HANDLE algorithm) {
        if (::BCryptCreateHash(algorithm, &value_, nullptr, 0U, nullptr, 0U,
                               0U) < 0) {
            throw std::runtime_error("create SHA-256 hash failed");
        }
    }
    ~Hash() {
        if (value_ != nullptr) {
            static_cast<void>(::BCryptDestroyHash(value_));
        }
    }
    Hash(const Hash&) = delete;
    Hash& operator=(const Hash&) = delete;
    [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept {
        return value_;
    }

  private:
    BCRYPT_HASH_HANDLE value_{};
};

[[nodiscard]] std::string sha256(std::string_view bytes) {
    Algorithm algorithm;
    Hash hash{algorithm.get()};
    constexpr std::size_t maximum_chunk = 16U * 1024U * 1024U;
    for (std::size_t offset = 0U; offset < bytes.size();) {
        const auto count = static_cast<ULONG>(
            std::min(maximum_chunk, bytes.size() - offset));
        auto* data = reinterpret_cast<PUCHAR>(
            const_cast<char*>(bytes.data() + offset));
        if (::BCryptHashData(hash.get(), data, count, 0U) < 0) {
            throw std::runtime_error("hash embedded runtime failed");
        }
        offset += count;
    }
    std::array<unsigned char, 32> digest{};
    if (::BCryptFinishHash(hash.get(), digest.data(),
                           static_cast<ULONG>(digest.size()), 0U) < 0) {
        throw std::runtime_error("finish embedded runtime hash failed");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2U);
    for (const auto value : digest) {
        result.push_back(digits[value >> 4U]);
        result.push_back(digits[value & 0x0fU]);
    }
    return result;
}

[[nodiscard]] std::string_view resource_bytes(HMODULE module,
                                              unsigned identifier) {
    const HRSRC resource = ::FindResourceW(
        module, MAKEINTRESOURCEW(identifier), RT_RCDATA);
    if (resource == nullptr) {
        throw std::runtime_error("embedded Windows runtime resource is missing");
    }
    const DWORD size = ::SizeofResource(module, resource);
    const HGLOBAL loaded = ::LoadResource(module, resource);
    const void* bytes = loaded == nullptr ? nullptr : ::LockResource(loaded);
    if (bytes == nullptr || size == 0U) {
        throw std::runtime_error("load embedded Windows runtime resource failed");
    }
    return {static_cast<const char*>(bytes), static_cast<std::size_t>(size)};
}

void materialize_one(WindowsStorage& storage,
                     const std::filesystem::path& path,
                     std::string_view bytes,
                     std::string_view expected_sha256) {
    if (sha256(bytes) != expected_sha256) {
        throw std::runtime_error("embedded Windows runtime digest is invalid");
    }
    const auto existing = storage.read(path);
    if (existing.has_value() && sha256(*existing) == expected_sha256) {
        return;
    }
    storage.replace(path, bytes);
    const auto installed = storage.read(path);
    if (!installed.has_value() || sha256(*installed) != expected_sha256) {
        throw std::runtime_error("materialized Windows runtime digest is invalid");
    }
}

} // namespace

EmbeddedRuntimePaths materialize_embedded_runtime(
    const std::filesystem::path& service_data_directory,
    void* resource_module,
    bool restrict_acl) {
    const auto runtime_directory = service_data_directory / L"runtime";
    if (restrict_acl) {
        prepare_service_directory(runtime_directory);
    } else {
        std::error_code error;
        std::filesystem::create_directories(runtime_directory, error);
        if (error) {
            throw std::runtime_error("create test runtime directory failed: " +
                                     error.message());
        }
    }
    const EmbeddedRuntimePaths result{
        .sing_box = runtime_directory / L"sing-box-1.13.12.exe",
        .wintun = runtime_directory / L"wintun.dll",
    };
    WindowsStorage storage{restrict_acl};
    materialize_one(storage, result.sing_box,
                    resource_bytes(static_cast<HMODULE>(resource_module),
                                   SB_EASY_RESOURCE_SING_BOX),
                    sing_box_sha256);
    materialize_one(storage, result.wintun,
                    resource_bytes(static_cast<HMODULE>(resource_module),
                                   SB_EASY_RESOURCE_WINTUN),
                    wintun_sha256);
    return result;
}

} // namespace sbeasy::win
