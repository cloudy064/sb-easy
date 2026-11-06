#pragma once

#if !defined(_WIN32)
#error "sbeasy/windows/route_stats.hpp is only available on Windows"
#endif

#include <filesystem>
#include <memory>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sbeasy::win {

/// Durable, local-only aggregation of the connection snapshots exposed by the
/// protected Clash API. Raw connection records are never persisted.
class RouteStatistics final {
  public:
    explicit RouteStatistics(std::filesystem::path database_path);
    ~RouteStatistics();

    RouteStatistics(const RouteStatistics&) = delete;
    RouteStatistics& operator=(const RouteStatistics&) = delete;

    void observe(const nlohmann::json& connections);
    void activate_policy(std::string_view label);
    [[nodiscard]] nlohmann::json query(std::string_view period) const;

  private:
    class Impl;
    std::unique_ptr<Impl> implementation_;
};

} // namespace sbeasy::win
