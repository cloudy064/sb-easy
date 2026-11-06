#include "sbeasy/windows/route_stats.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace sbeasy::win {
namespace {

using nlohmann::json;

struct ObservedConnection {
    std::string route_key;
    std::int64_t uplink{};
    std::int64_t downlink{};
};

class Statement final {
  public:
    Statement(sqlite3* database, const char* sql) {
        if (::sqlite3_prepare_v2(database, sql, -1, &value_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(::sqlite3_errmsg(database));
        }
    }
    ~Statement() {
        static_cast<void>(::sqlite3_finalize(value_));
    }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    [[nodiscard]] sqlite3* database() const noexcept {
        return ::sqlite3_db_handle(value_);
    }
    [[nodiscard]] sqlite3_stmt* get() const noexcept {
        return value_;
    }

  private:
    sqlite3_stmt* value_{};
};

void execute(sqlite3* database, const char* sql) {
    char* message{};
    if (::sqlite3_exec(database, sql, nullptr, nullptr, &message) != SQLITE_OK) {
        const std::string detail = message == nullptr ? ::sqlite3_errmsg(database)
                                                       : message;
        ::sqlite3_free(message);
        throw std::runtime_error(detail);
    }
}

[[nodiscard]] bool has_column(sqlite3* database, std::string_view table,
                              std::string_view column) {
    const auto sql = "PRAGMA table_info(" + std::string{table} + ")";
    Statement statement{database, sql.c_str()};
    for (;;) {
        const int result = ::sqlite3_step(statement.get());
        if (result == SQLITE_DONE) {
            return false;
        }
        if (result != SQLITE_ROW) {
            throw std::runtime_error(::sqlite3_errmsg(database));
        }
        const auto* name = ::sqlite3_column_text(statement.get(), 1);
        if (name != nullptr &&
            std::string_view{reinterpret_cast<const char*>(name)} == column) {
            return true;
        }
    }
}

[[nodiscard]] std::string text(const json* value, const char* field) {
    if (value == nullptr) {
        return {};
    }
    const auto found = value->find(field);
    return found != value->end() && found->is_string()
               ? found->get<std::string>()
               : std::string{};
}

[[nodiscard]] std::int64_t nonnegative(const json& value, const char* field) {
    const auto found = value.find(field);
    if (found == value.end() ||
        !(found->is_number_integer() || found->is_number_unsigned())) {
        return 0;
    }
    return std::max<std::int64_t>(found->get<std::int64_t>(), 0);
}

[[nodiscard]] json identity(const json& connection) {
    const auto metadata_value = connection.find("metadata");
    const auto* metadata = metadata_value != connection.end() &&
                                   metadata_value->is_object()
                               ? &*metadata_value
                               : nullptr;
    auto domain = text(metadata, "host");
    if (domain.empty()) {
        domain = text(metadata, "destinationIP");
    }
    if (domain.empty()) {
        domain = "unknown";
    }
    while (domain.ends_with('.')) {
        domain.pop_back();
    }
    std::transform(domain.begin(), domain.end(), domain.begin(), [](char value) {
        return static_cast<char>(
            std::tolower(static_cast<unsigned char>(value)));
    });
    domain.resize(std::min<std::size_t>(domain.size(), 512U));

    json chain = json::array();
    if (const auto chains = connection.find("chains");
        chains != connection.end() && chains->is_array()) {
        for (const auto& tag : *chains) {
            if (tag.is_string() && chain.size() < 16U) {
                auto value = tag.get<std::string>();
                value.resize(std::min<std::size_t>(value.size(), 256U));
                chain.push_back(std::move(value));
            }
        }
    }
    const auto outbound =
        chain.empty() ? std::string{} : chain.front().get<std::string>();
    auto normalized = outbound;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](char value) {
                       return static_cast<char>(
                           std::tolower(static_cast<unsigned char>(value)));
                   });
    const auto outbound_type =
        normalized == "direct"
            ? "direct"
            : ((normalized == "block" || normalized == "reject")
                   ? "block"
                   : (normalized.empty() ? "unknown" : "proxy"));
    auto rule = text(&connection, "rule");
    const auto payload = text(&connection, "rulePayload");
    if (!payload.empty()) {
        rule += (rule.empty() ? "" : ": ") + payload;
    }
    rule.resize(std::min<std::size_t>(rule.size(), 512U));
    return {{"domain", std::move(domain)},
            {"outbound", outbound},
            {"outbound_type", outbound_type},
            {"rule", std::move(rule)},
            {"chain", std::move(chain)}};
}

void bind_text(Statement& statement, int index, std::string_view value) {
    if (::sqlite3_bind_text(statement.get(), index, value.data(),
                            static_cast<int>(value.size()), SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        throw std::runtime_error(::sqlite3_errmsg(statement.database()));
    }
}

void bind_integer(Statement& statement, int index, std::int64_t value) {
    if (::sqlite3_bind_int64(statement.get(), index, value) != SQLITE_OK) {
        throw std::runtime_error(::sqlite3_errmsg(statement.database()));
    }
}

[[nodiscard]] std::string column_text(sqlite3_stmt* statement, int column) {
    const auto* value = ::sqlite3_column_text(statement, column);
    return value == nullptr
               ? std::string{}
               : std::string{reinterpret_cast<const char*>(value)};
}

[[nodiscard]] std::int64_t now_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::int64_t epoch_day(std::int64_t milliseconds) {
    constexpr std::int64_t day_ms = 86'400'000;
    return milliseconds / day_ms;
}

} // namespace

class RouteStatistics::Impl final {
  public:
    explicit Impl(const std::filesystem::path& path) {
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) {
            throw std::runtime_error("create route database directory failed: " +
                                     error.message());
        }
        if (::sqlite3_open16(path.c_str(), &database_) != SQLITE_OK) {
            const std::string detail = database_ == nullptr
                                           ? "open route database failed"
                                           : ::sqlite3_errmsg(database_);
            if (database_ != nullptr) {
                static_cast<void>(::sqlite3_close(database_));
                database_ = nullptr;
            }
            throw std::runtime_error(detail);
        }
        static_cast<void>(::sqlite3_busy_timeout(database_, 5'000));
        execute(database_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; "
                           "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;");
        execute(database_,
                "CREATE TABLE IF NOT EXISTS domain_route_stats ("
                "day INTEGER NOT NULL, route_key TEXT NOT NULL, generation "
                "INTEGER NOT NULL DEFAULT 0, domain TEXT NOT NULL, outbound TEXT "
                "NOT NULL, outbound_type TEXT NOT NULL, rule "
                "TEXT NOT NULL, chain TEXT NOT NULL, connection_count INTEGER NOT "
                "NULL, uplink_total INTEGER NOT NULL, downlink_total INTEGER NOT "
                "NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, "
                "PRIMARY KEY(day, route_key));"
                "CREATE INDEX IF NOT EXISTS idx_domain_route_stats_last_seen ON "
                "domain_route_stats(last_seen DESC);");
        if (!has_column(database_, "domain_route_stats", "generation")) {
            execute(database_,
                    "ALTER TABLE domain_route_stats ADD COLUMN generation "
                    "INTEGER NOT NULL DEFAULT 0");
        }
        execute(database_,
                "CREATE TABLE IF NOT EXISTS route_stats_meta (key TEXT PRIMARY "
                "KEY, value INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO route_stats_meta(key, value) VALUES("
                "'policy_generation', 0);");
        Statement generation{
            database_,
            "SELECT value FROM route_stats_meta WHERE key='policy_generation'"};
        if (::sqlite3_step(generation.get()) != SQLITE_ROW) {
            throw std::runtime_error("route policy generation is unavailable");
        }
        generation_ = std::max<std::int64_t>(
            ::sqlite3_column_int64(generation.get(), 0), 0);
    }

    void activate_policy(std::string_view) {
        std::lock_guard lock{mutex_};
        if (generation_ == std::numeric_limits<std::int64_t>::max()) {
            throw std::overflow_error("route policy generation overflow");
        }
        execute(database_, "BEGIN IMMEDIATE");
        try {
            ++generation_;
            Statement update{
                database_,
                "UPDATE route_stats_meta SET value=?1 WHERE "
                "key='policy_generation'"};
            bind_integer(update, 1, generation_);
            if (::sqlite3_step(update.get()) != SQLITE_DONE) {
                throw std::runtime_error(::sqlite3_errmsg(database_));
            }
            execute(database_, "COMMIT");
            observed_.clear();
        } catch (...) {
            --generation_;
            try {
                execute(database_, "ROLLBACK");
            } catch (const std::exception&) {
            }
            throw;
        }
    }

    ~Impl() {
        if (database_ != nullptr) {
            static_cast<void>(::sqlite3_close(database_));
        }
    }

    void observe(const json& connections) {
        if (!connections.is_array()) {
            throw std::invalid_argument("route observations must be an array");
        }
        std::lock_guard lock{mutex_};
        const auto now = now_milliseconds();
        const auto day = epoch_day(now);
        std::unordered_set<std::string> seen;
        execute(database_, "BEGIN IMMEDIATE");
        try {
            for (const auto& connection : connections) {
                if (!connection.is_object()) {
                    continue;
                }
                const auto id_value = connection.find("id");
                if (id_value == connection.end() || !id_value->is_string() ||
                    id_value->get_ref<const std::string&>().empty()) {
                    continue;
                }
                const auto id = id_value->get<std::string>();
                seen.insert(id);
                const auto route = identity(connection);
                const auto route_key = std::to_string(generation_) + '\n' +
                                       route.dump();
                const auto uplink = nonnegative(connection, "upload");
                const auto downlink = nonnegative(connection, "download");
                auto found = observed_.find(id);
                std::int64_t connection_delta{};
                std::int64_t uplink_delta{};
                std::int64_t downlink_delta{};
                if (found == observed_.end() ||
                    found->second.route_key != route_key) {
                    connection_delta = 1;
                    uplink_delta = uplink;
                    downlink_delta = downlink;
                    observed_[id] = {route_key, uplink, downlink};
                } else {
                    uplink_delta =
                        std::max(uplink - found->second.uplink, std::int64_t{});
                    downlink_delta =
                        std::max(downlink - found->second.downlink, std::int64_t{});
                    found->second.uplink = std::max(found->second.uplink, uplink);
                    found->second.downlink =
                        std::max(found->second.downlink, downlink);
                }
                if (connection_delta == 0 && uplink_delta == 0 &&
                    downlink_delta == 0) {
                    continue;
                }
                upsert(day, route_key, route, connection_delta, uplink_delta,
                       downlink_delta, now);
            }
            std::erase_if(observed_, [&seen](const auto& item) {
                return !seen.contains(item.first);
            });
            Statement expired{database_,
                              "DELETE FROM domain_route_stats WHERE day < ?1"};
            bind_integer(expired, 1, day - 89);
            if (::sqlite3_step(expired.get()) != SQLITE_DONE) {
                throw std::runtime_error(::sqlite3_errmsg(database_));
            }
            execute(database_,
                    "DELETE FROM domain_route_stats WHERE rowid NOT IN (SELECT "
                    "rowid FROM domain_route_stats ORDER BY last_seen DESC LIMIT "
                    "100000)");
            execute(database_, "COMMIT");
        } catch (...) {
            try {
                execute(database_, "ROLLBACK");
            } catch (const std::exception&) {
            }
            throw;
        }
    }

    [[nodiscard]] json query(std::string_view period) const {
        std::int64_t minimum_day{};
        const auto today = epoch_day(now_milliseconds());
        if (period == "today") {
            minimum_day = today;
        } else if (period == "7d") {
            minimum_day = today - 6;
        } else if (period == "all") {
            minimum_day = std::numeric_limits<std::int64_t>::min();
        } else {
            throw std::invalid_argument("route statistics period is invalid");
        }
        std::lock_guard lock{mutex_};
        Statement query{
            database_,
            "SELECT generation, domain, outbound, outbound_type, rule, chain, "
            "SUM(connection_count), SUM(uplink_total), SUM(downlink_total), "
            "MIN(first_seen), MAX(last_seen) FROM domain_route_stats WHERE day "
            ">= ?1 GROUP BY route_key, generation, domain, outbound, "
            "outbound_type, rule, "
            "chain ORDER BY SUM(connection_count) DESC, "
            "SUM(uplink_total + downlink_total) DESC LIMIT 1000"};
        bind_integer(query, 1, minimum_day);
        json rows = json::array();
        for (;;) {
            const int result = ::sqlite3_step(query.get());
            if (result == SQLITE_DONE) {
                break;
            }
            if (result != SQLITE_ROW) {
                throw std::runtime_error(::sqlite3_errmsg(database_));
            }
            auto chain = json::parse(column_text(query.get(), 5), nullptr, false);
            if (!chain.is_array()) {
                chain = json::array();
            }
            rows.push_back({
                {"policy_generation", ::sqlite3_column_int64(query.get(), 0)},
                {"domain", column_text(query.get(), 1)},
                {"outbound", column_text(query.get(), 2)},
                {"outbound_type", column_text(query.get(), 3)},
                {"kind", column_text(query.get(), 3)},
                {"rule", column_text(query.get(), 4)},
                {"chain", std::move(chain)},
                {"connection_count", ::sqlite3_column_int64(query.get(), 6)},
                {"uplink_total", ::sqlite3_column_int64(query.get(), 7)},
                {"downlink_total", ::sqlite3_column_int64(query.get(), 8)},
                {"first_seen", ::sqlite3_column_int64(query.get(), 9)},
                {"last_seen", ::sqlite3_column_int64(query.get(), 10)},
            });
        }
        return rows;
    }

  private:
    void upsert(std::int64_t day, const std::string& route_key,
                const json& route, std::int64_t connections,
                std::int64_t uplink, std::int64_t downlink,
                std::int64_t now) {
        Statement statement{
            database_,
            "INSERT INTO domain_route_stats(day, route_key, generation, domain, outbound, "
            "outbound_type, rule, chain, connection_count, uplink_total, "
            "downlink_total, first_seen, last_seen) VALUES(?1,?2,?3,?4,?5,?6,"
            "?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(day, route_key) DO UPDATE SET "
            "connection_count=connection_count+excluded.connection_count, "
            "uplink_total=uplink_total+excluded.uplink_total, "
            "downlink_total=downlink_total+excluded.downlink_total, "
            "first_seen=MIN(first_seen,excluded.first_seen), "
            "last_seen=MAX(last_seen,excluded.last_seen)"};
        bind_integer(statement, 1, day);
        bind_text(statement, 2, route_key);
        bind_integer(statement, 3, generation_);
        bind_text(statement, 4, route.at("domain").get_ref<const std::string&>());
        bind_text(statement, 5,
                  route.at("outbound").get_ref<const std::string&>());
        bind_text(statement, 6,
                  route.at("outbound_type").get_ref<const std::string&>());
        bind_text(statement, 7, route.at("rule").get_ref<const std::string&>());
        const auto chain = route.at("chain").dump();
        bind_text(statement, 8, chain);
        bind_integer(statement, 9, connections);
        bind_integer(statement, 10, uplink);
        bind_integer(statement, 11, downlink);
        bind_integer(statement, 12, now);
        bind_integer(statement, 13, now);
        if (::sqlite3_step(statement.get()) != SQLITE_DONE) {
            throw std::runtime_error(::sqlite3_errmsg(database_));
        }
    }

    sqlite3* database_{};
    mutable std::mutex mutex_;
    std::int64_t generation_{};
    std::unordered_map<std::string, ObservedConnection> observed_;
};

RouteStatistics::RouteStatistics(std::filesystem::path database_path)
    : implementation_(std::make_unique<Impl>(database_path)) {}
RouteStatistics::~RouteStatistics() = default;
void RouteStatistics::observe(const nlohmann::json& connections) {
    implementation_->observe(connections);
}
void RouteStatistics::activate_policy(std::string_view label) {
    implementation_->activate_policy(label);
}
nlohmann::json RouteStatistics::query(std::string_view period) const {
    return implementation_->query(period);
}

} // namespace sbeasy::win
