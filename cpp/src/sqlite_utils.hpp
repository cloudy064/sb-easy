#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sqlite3.h>

namespace sbeasy::sqlite {

[[noreturn]] inline void fail(sqlite3* database, std::string_view operation, int code) {
    throw std::runtime_error(std::string{operation} + " failed (" +
                             std::to_string(code) + "): " + sqlite3_errmsg(database));
}

class Statement final {
  public:
    Statement(sqlite3* database, const std::string& sql) : database_(database) {
        const int code = sqlite3_prepare_v2(
            database, sql.c_str(), static_cast<int>(sql.size()), &statement_, nullptr);
        if (code != SQLITE_OK) {
            fail(database, "prepare SQL", code);
        }
    }

    ~Statement() {
        sqlite3_finalize(statement_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    void bind(int index, const std::string& value) {
        const int code =
            sqlite3_bind_text(statement_, index, value.c_str(),
                              static_cast<int>(value.size()), SQLITE_TRANSIENT);
        if (code != SQLITE_OK) {
            fail(database_, "bind text", code);
        }
    }

    void bind(int index, const char* value) {
        bind(index, std::string{value});
    }

    void bind(int index, const std::optional<std::string>& value) {
        if (!value.has_value()) {
            const int code = sqlite3_bind_null(statement_, index);
            if (code != SQLITE_OK) {
                fail(database_, "bind null", code);
            }
            return;
        }
        bind(index, *value);
    }

    void bind(int index, std::int64_t value) {
        const int code = sqlite3_bind_int64(statement_, index, value);
        if (code != SQLITE_OK) {
            fail(database_, "bind integer", code);
        }
    }

    void bind(int index, bool value) {
        bind(index, static_cast<std::int64_t>(value ? 1 : 0));
    }

    void bind(int index, double value) {
        const int code = sqlite3_bind_double(statement_, index, value);
        if (code != SQLITE_OK) {
            fail(database_, "bind real", code);
        }
    }

    void bind(int index, const std::optional<double>& value) {
        if (!value.has_value()) {
            const int code = sqlite3_bind_null(statement_, index);
            if (code != SQLITE_OK) {
                fail(database_, "bind null", code);
            }
            return;
        }
        bind(index, *value);
    }

    void bind_blob(int index, const std::vector<unsigned char>& value) {
        const int code =
            sqlite3_bind_blob(statement_, index, value.data(),
                              static_cast<int>(value.size()), SQLITE_TRANSIENT);
        if (code != SQLITE_OK) {
            fail(database_, "bind blob", code);
        }
    }

    [[nodiscard]] bool step_row() {
        const int code = sqlite3_step(statement_);
        if (code == SQLITE_ROW) {
            return true;
        }
        if (code == SQLITE_DONE) {
            return false;
        }
        fail(database_, "step SQL", code);
    }

    void step_done() {
        const int code = sqlite3_step(statement_);
        if (code != SQLITE_DONE) {
            fail(database_, "execute SQL", code);
        }
    }

    [[nodiscard]] std::string text(int column) const {
        const auto* value = sqlite3_column_text(statement_, column);
        if (value == nullptr) {
            return {};
        }
        const auto size = sqlite3_column_bytes(statement_, column);
        return {reinterpret_cast<const char*>(value), static_cast<std::size_t>(size)};
    }

    [[nodiscard]] std::optional<std::string> optional_text(int column) const {
        if (sqlite3_column_type(statement_, column) == SQLITE_NULL) {
            return std::nullopt;
        }
        return text(column);
    }

    [[nodiscard]] std::int64_t integer(int column) const {
        return sqlite3_column_int64(statement_, column);
    }

    [[nodiscard]] std::vector<unsigned char> blob(int column) const {
        const auto* data =
            static_cast<const unsigned char*>(sqlite3_column_blob(statement_, column));
        const auto size = sqlite3_column_bytes(statement_, column);
        if (data == nullptr || size == 0) {
            return {};
        }
        return {data, data + size};
    }

  private:
    sqlite3* database_;
    sqlite3_stmt* statement_{nullptr};
};

inline void execute(sqlite3* database, const std::string& sql) {
    char* message = nullptr;
    const int code = sqlite3_exec(database, sql.c_str(), nullptr, nullptr, &message);
    if (code != SQLITE_OK) {
        const std::string detail =
            message == nullptr ? sqlite3_errmsg(database) : std::string{message};
        sqlite3_free(message);
        throw std::runtime_error("execute SQL failed (" + std::to_string(code) +
                                 "): " + detail);
    }
}

class Transaction final {
  public:
    explicit Transaction(sqlite3* database) : database_(database) {
        execute(database_, "BEGIN");
    }

    ~Transaction() {
        if (!committed_) {
            try {
                execute(database_, "ROLLBACK");
            } catch (...) {
            }
        }
    }

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    void commit() {
        execute(database_, "COMMIT");
        committed_ = true;
    }

  private:
    sqlite3* database_;
    bool committed_{false};
};

} // namespace sbeasy::sqlite
