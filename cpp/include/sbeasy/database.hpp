#pragma once

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>

struct sqlite3;

namespace sbeasy {

class Store;

/// A serialized SQLite connection compatible with the existing sqlx database.
class Database final {
  public:
    explicit Database(const std::filesystem::path& path);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&) = delete;
    Database& operator=(Database&&) = delete;

    void migrate(const std::filesystem::path& directory);
    void execute(const std::string& sql);

    [[nodiscard]] std::size_t applied_migration_count() const;

  private:
    friend class Store;

    sqlite3* handle_{nullptr};
    mutable std::mutex mutex_;
};

} // namespace sbeasy
