#include "sbeasy/database.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <sqlite3.h>

#include "sqlite_utils.hpp"

namespace sbeasy {
namespace {

struct Migration {
    std::int64_t version{};
    std::string description;
    std::string sql;
    std::vector<unsigned char> checksum;
};

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        throw std::runtime_error("cannot read migration: " + path.string());
    }
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

[[nodiscard]] std::vector<unsigned char> sha384(const std::string& value) {
    std::array<unsigned char, SHA384_DIGEST_LENGTH> digest{};
    if (SHA384(reinterpret_cast<const unsigned char*>(value.data()), value.size(),
               digest.data()) == nullptr) {
        throw std::runtime_error("SHA-384 migration checksum failed");
    }
    return {digest.begin(), digest.end()};
}

[[nodiscard]] std::vector<Migration>
load_migrations(const std::filesystem::path& directory) {
    if (!std::filesystem::is_directory(directory)) {
        throw std::runtime_error("migration directory does not exist: " +
                                 directory.string());
    }

    const std::regex filename_pattern{R"(^([0-9]+)_(.+)\.sql$)"};
    std::vector<Migration> migrations;
    for (const auto& entry : std::filesystem::directory_iterator{directory}) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto filename = entry.path().filename().string();
        std::smatch match;
        if (!std::regex_match(filename, match, filename_pattern)) {
            continue;
        }

        auto description = match[2].str();
        std::ranges::replace(description, '_', ' ');
        auto sql = read_file(entry.path());
        migrations.push_back(Migration{
            .version = std::stoll(match[1].str()),
            .description = std::move(description),
            .sql = sql,
            .checksum = sha384(sql),
        });
    }
    std::ranges::sort(migrations, {},
                      [](const Migration& migration) { return migration.version; });
    std::set<std::int64_t> versions;
    for (const auto& migration : migrations) {
        if (!versions.insert(migration.version).second) {
            throw std::runtime_error("duplicate migration version: " +
                                     std::to_string(migration.version));
        }
    }
    return migrations;
}

} // namespace

Database::Database(const std::filesystem::path& path) {
    const int code = sqlite3_open_v2(
        path.string().c_str(), &handle_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (code != SQLITE_OK) {
        const std::string message =
            handle_ == nullptr ? "unknown sqlite error" : sqlite3_errmsg(handle_);
        if (handle_ != nullptr) {
            sqlite3_close(handle_);
            handle_ = nullptr;
        }
        throw std::runtime_error("open SQLite database failed: " + message);
    }

    try {
        const int timeout_code = sqlite3_busy_timeout(handle_, 5'000);
        if (timeout_code != SQLITE_OK) {
            sqlite::fail(handle_, "configure SQLite busy timeout", timeout_code);
        }
        sqlite::execute(handle_, "PRAGMA foreign_keys = ON");
        sqlite::execute(handle_, "PRAGMA journal_mode = WAL");
    } catch (...) {
        sqlite3_close(handle_);
        handle_ = nullptr;
        throw;
    }
}

Database::~Database() {
    if (handle_ != nullptr) {
        sqlite3_close(handle_);
    }
}

void Database::execute(const std::string& sql) {
    const std::scoped_lock lock{mutex_};
    sqlite::execute(handle_, sql);
}

void Database::migrate(const std::filesystem::path& directory) {
    const auto migrations = load_migrations(directory);
    const std::scoped_lock lock{mutex_};

    sqlite::execute(handle_, R"SQL(
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
)
)SQL");

    sqlite::Statement dirty{
        handle_, "SELECT version FROM _sqlx_migrations WHERE success = FALSE "
                 "ORDER BY version LIMIT 1"};
    if (dirty.step_row()) {
        throw std::runtime_error("migration " + std::to_string(dirty.integer(0)) +
                                 " is partially applied");
    }

    std::set<std::int64_t> available_versions;
    for (const auto& migration : migrations) {
        available_versions.insert(migration.version);
    }
    sqlite::Statement applied{handle_,
                              "SELECT version FROM _sqlx_migrations ORDER BY version"};
    while (applied.step_row()) {
        const auto version = applied.integer(0);
        if (!available_versions.contains(version)) {
            throw std::runtime_error("applied migration " + std::to_string(version) +
                                     " is missing from the migration directory");
        }
    }

    for (const auto& migration : migrations) {
        sqlite::Statement existing{handle_, "SELECT checksum FROM _sqlx_migrations "
                                            "WHERE version = ?1"};
        existing.bind(1, migration.version);
        if (existing.step_row()) {
            if (existing.blob(0) != migration.checksum) {
                throw std::runtime_error(
                    "migration " + std::to_string(migration.version) +
                    " checksum differs from the applied sqlx migration");
            }
            continue;
        }

        if (migration.sql.starts_with("-- no-transaction")) {
            throw std::runtime_error("non-transactional migrations are not supported");
        }

        const auto started = std::chrono::steady_clock::now();
        sqlite::Transaction transaction{handle_};
        sqlite::execute(handle_, migration.sql);

        sqlite::Statement insert{
            handle_, "INSERT INTO _sqlx_migrations "
                     "(version, description, success, checksum, execution_time) "
                     "VALUES (?1, ?2, TRUE, ?3, -1)"};
        insert.bind(1, migration.version);
        insert.bind(2, migration.description);
        insert.bind_blob(3, migration.checksum);
        insert.step_done();
        transaction.commit();

        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started);
        sqlite::Statement update{handle_,
                                 "UPDATE _sqlx_migrations SET execution_time = ?1 "
                                 "WHERE version = ?2"};
        update.bind(1, elapsed.count());
        update.bind(2, migration.version);
        update.step_done();
    }
}

std::size_t Database::applied_migration_count() const {
    const std::scoped_lock lock{mutex_};
    sqlite::Statement statement{
        handle_, "SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE"};
    if (!statement.step_row()) {
        return 0;
    }
    return static_cast<std::size_t>(statement.integer(0));
}

} // namespace sbeasy
