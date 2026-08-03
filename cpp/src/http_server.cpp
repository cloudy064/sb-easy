#include "sbeasy/http_server.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <functional>
#include <future>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
#include <drogon/drogon.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include "sbeasy/auth.hpp"
#include "sbeasy/clash_client.hpp"
#include "sbeasy/clash_websocket.hpp"
#include "sbeasy/config_etag.hpp"
#include "sbeasy/config_renderer.hpp"
#include "sbeasy/proxy_parser.hpp"
#include "sbeasy/singbox_supervisor.hpp"
#include "sbeasy/store.hpp"
#include "sbeasy/subscription_fetcher.hpp"
#include "sbeasy/version.hpp"
#include "sbeasy/wireguard.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;
using ResponseCallback = std::function<void(const drogon::HttpResponsePtr&)>;

class ServerLogBuffer final {
  public:
    void append(std::string_view text) {
        std::scoped_lock lock{mutex_};
        std::size_t start{};
        while (start < text.size()) {
            const auto end = text.find('\n', start);
            auto line = std::string{
                text.substr(start, end == std::string_view::npos
                                       ? text.size() - start
                                       : end - start)};
            if (!line.empty()) {
                if (lines_.size() >= capacity_) {
                    lines_.pop_front();
                }
                lines_.push_back(std::move(line));
            }
            if (end == std::string_view::npos) {
                break;
            }
            start = end + 1U;
        }
    }

    [[nodiscard]] std::vector<std::string> lines() const {
        const std::scoped_lock lock{mutex_};
        return {lines_.begin(), lines_.end()};
    }

  private:
    static constexpr std::size_t capacity_{1'000};
    mutable std::mutex mutex_;
    std::deque<std::string> lines_;
};

class UnauthorizedError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class ServiceUnavailableError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class ForbiddenError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] drogon::HttpResponsePtr
json_response(json body, drogon::HttpStatusCode status = drogon::k200OK) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(status);
    response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    response->setBody(body.dump());
    return response;
}

template <typename Function>
void handle_response(ResponseCallback&& callback, Function&& function) {
    try {
        callback(std::forward<Function>(function)());
    } catch (const UnauthorizedError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k401Unauthorized));
    } catch (const ServiceUnavailableError& error) {
        callback(
            json_response({{"error", error.what()}}, drogon::k503ServiceUnavailable));
    } catch (const ForbiddenError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k403Forbidden));
    } catch (const NotFoundError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k404NotFound));
    } catch (const ConflictError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k409Conflict));
    } catch (const ValidationError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k400BadRequest));
    } catch (const ScriptError& error) {
        callback(json_response({{"error", error.what()}, {"kind", "rule_script"}},
                               drogon::k422UnprocessableEntity));
    } catch (const json::exception& error) {
        callback(json_response(
            {{"error", std::string{"Invalid JSON request: "} + error.what()}},
            drogon::k400BadRequest));
    } catch (const std::invalid_argument& error) {
        callback(json_response({{"error", error.what()}}, drogon::k400BadRequest));
    } catch (const std::exception& error) {
        LOG_ERROR << "HTTP handler failed: " << error.what();
        callback(json_response({{"error", "Internal server error"}},
                               drogon::k500InternalServerError));
    }
}

template <typename Function>
void handle(ResponseCallback&& callback, Function&& function) {
    handle_response(std::move(callback),
                    [&] { return json_response(std::forward<Function>(function)()); });
}

[[nodiscard]] json request_object(const drogon::HttpRequestPtr& request) {
    auto body = json::parse(request->body(), nullptr, false);
    if (!body.is_object()) {
        throw ValidationError("Request body must be a JSON object");
    }
    return body;
}

[[nodiscard]] std::string required_string(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || !found->is_string() ||
        found->get_ref<const std::string&>().empty()) {
        throw ValidationError(std::string{field} + " must be a non-empty string");
    }
    return found->get<std::string>();
}

[[nodiscard]] json required_object(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || !found->is_object()) {
        throw ValidationError(std::string{field} + " must be a JSON object");
    }
    return *found;
}

[[nodiscard]] ProfileMode profile_mode(const json& body) {
    return body.value("mode", "managed") == "full" ? ProfileMode::full
                                                   : ProfileMode::managed;
}

void assign_optional_string(const json& body, const char* field,
                            std::optional<std::string>& destination) {
    const auto found = body.find(field);
    if (found == body.end() || found->is_null()) {
        return;
    }
    if (!found->is_string()) {
        throw ValidationError(std::string{field} + " must be a string");
    }
    destination = found->get<std::string>();
}

void assign_string(const json& body, const char* field,
                   std::string& destination) {
    const auto found = body.find(field);
    if (found == body.end() || found->is_null()) {
        return;
    }
    if (!found->is_string()) {
        throw ValidationError(std::string{field} + " must be a string");
    }
    destination = found->get<std::string>();
}

void assign_boolean(const json& body, const char* field, bool& destination) {
    const auto found = body.find(field);
    if (found == body.end() || found->is_null()) {
        return;
    }
    if (!found->is_boolean()) {
        throw ValidationError(std::string{field} + " must be a boolean");
    }
    destination = found->get<bool>();
}

[[nodiscard]] std::vector<std::string> required_string_array(const json& body,
                                                             const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || !found->is_array()) {
        throw ValidationError(std::string{field} + " must be an array");
    }
    std::vector<std::string> values;
    values.reserve(found->size());
    for (const auto& value : *found) {
        if (!value.is_string()) {
            throw ValidationError(std::string{field} + " must contain only strings");
        }
        values.push_back(value.get<std::string>());
    }
    return values;
}

[[nodiscard]] std::string trim(std::string value) {
    const auto is_space = [](unsigned char character) {
        return std::isspace(character) != 0;
    };
    const auto first = std::ranges::find_if_not(value, is_space);
    const auto last =
        std::ranges::find_if_not(value | std::views::reverse, is_space).base();
    if (first >= last) {
        return {};
    }
    return {first, last};
}

[[nodiscard]] std::string trim_trailing_slashes(std::string value) {
    value = trim(std::move(value));
    while (value.ends_with('/')) {
        value.pop_back();
    }
    return value;
}

class CorsPolicy final {
  public:
    explicit CorsPolicy(std::string configured_origins) {
        configured_origins = trim(std::move(configured_origins));
        wildcard_ = configured_origins.empty() || configured_origins == "*";
        std::size_t start{};
        while (!wildcard_ && start <= configured_origins.size()) {
            const auto end = configured_origins.find(',', start);
            auto origin = trim(configured_origins.substr(
                start, end == std::string::npos
                           ? configured_origins.size() - start
                           : end - start));
            if (origin == "*") {
                wildcard_ = true;
                origins_.clear();
                break;
            }
            if (!origin.empty()) {
                origins_.push_back(std::move(origin));
            }
            if (end == std::string::npos) {
                break;
            }
            start = end + 1U;
        }
    }

    [[nodiscard]] std::optional<std::string>
    allowed_origin(const drogon::HttpRequestPtr& request) const {
        auto origin = trim(request->getHeader("origin"));
        if (origin.empty()) {
            return std::nullopt;
        }
        if (wildcard_) {
            return "*";
        }
        if (std::ranges::find(origins_, origin) == origins_.end()) {
            return std::nullopt;
        }
        return origin;
    }

    void apply(const drogon::HttpRequestPtr& request,
               const drogon::HttpResponsePtr& response) const {
        if (!response->getHeader("access-control-allow-origin").empty()) {
            return;
        }
        const auto origin = allowed_origin(request);
        if (!origin.has_value()) {
            return;
        }
        response->addHeader("Access-Control-Allow-Origin", *origin);
        response->addHeader("Access-Control-Allow-Methods",
                            "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        auto headers = trim(request->getHeader("access-control-request-headers"));
        response->addHeader("Access-Control-Allow-Headers",
                            headers.empty() ? "Authorization, Content-Type"
                                            : std::move(headers));
        response->addHeader("Access-Control-Expose-Headers",
                            "ETag, Content-Disposition, X-SB-Easy-Rule-Source, "
                            "X-SB-Easy-Profile-Id, X-SB-Easy-Profile-Name");
        response->addHeader("Access-Control-Max-Age", "600");
        if (!wildcard_) {
            response->addHeader("Vary", "Origin");
        }
    }

  private:
    bool wildcard_{false};
    std::vector<std::string> origins_;
};

[[nodiscard]] bool safe_static_relative_path(const std::string& value) {
    if (value.empty() || value.front() == '/' ||
        value.find('\0') != std::string::npos) {
        return false;
    }
    const std::filesystem::path path{value};
    return !path.is_absolute() &&
           std::ranges::none_of(path, [](const auto& component) {
               return component == "..";
           });
}

[[nodiscard]] drogon::HttpResponsePtr
static_file_response(const std::filesystem::path& path, bool immutable) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error) {
        return json_response({{"error", "Static resource not found"}},
                             drogon::k404NotFound);
    }
    auto response = drogon::HttpResponse::newFileResponse(path.string());
    response->addHeader("Cache-Control",
                        immutable ? "public, max-age=31536000, immutable"
                                  : "no-cache");
    return response;
}

[[nodiscard]] trantor::Logger::LogLevel
log_level(std::string configured) {
    configured = trim(std::move(configured));
    std::ranges::transform(configured, configured.begin(),
                           [](unsigned char character) {
                               return static_cast<char>(std::tolower(character));
                           });
    if (configured == "trace") {
        return trantor::Logger::kTrace;
    }
    if (configured == "debug") {
        return trantor::Logger::kDebug;
    }
    if (configured == "warn" || configured == "warning") {
        return trantor::Logger::kWarn;
    }
    if (configured == "error") {
        return trantor::Logger::kError;
    }
    if (configured == "fatal") {
        return trantor::Logger::kFatal;
    }
    if (configured.empty() || configured == "info") {
        return trantor::Logger::kInfo;
    }
    throw std::invalid_argument(
        "LOG_LEVEL must be trace, debug, info, warn, error, or fatal");
}

[[nodiscard]] std::string clash_controller_address(std::string url) {
    url = trim_trailing_slashes(std::move(url));
    if (url.starts_with("https://")) {
        url.erase(0, 8);
    } else if (url.starts_with("http://")) {
        url.erase(0, 7);
    } else if (url.starts_with("wss://")) {
        url.erase(0, 6);
    } else if (url.starts_with("ws://")) {
        url.erase(0, 5);
    }
    return url;
}

[[nodiscard]] std::string encode_component(std::string_view value) {
    static constexpr std::string_view hexadecimal{"0123456789ABCDEF"};
    std::string encoded;
    encoded.reserve(value.size());
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (std::isalnum(byte) != 0 || character == '-' || character == '_' ||
            character == '.' || character == '~') {
            encoded.push_back(character);
        } else {
            encoded.push_back('%');
            encoded.push_back(hexadecimal[byte >> 4U]);
            encoded.push_back(hexadecimal[byte & 0x0fU]);
        }
    }
    return encoded;
}

[[nodiscard]] std::string secure_token(std::size_t bytes) {
    std::vector<unsigned char> random(bytes);
    if (bytes == 0U ||
        RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw std::runtime_error("secure token generation failed");
    }
    static constexpr std::string_view digits{"0123456789abcdef"};
    std::string value;
    value.reserve(bytes * 2U);
    for (const auto byte : random) {
        value.push_back(digits[byte >> 4U]);
        value.push_back(digits[byte & 0x0fU]);
    }
    return value;
}

[[nodiscard]] std::string normalized_command(const json& body) {
    auto command = trim(required_string(body, "command"));
    std::ranges::transform(command, command.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    if (command != "reload" && command != "restart") {
        throw ValidationError("Unknown command: " + command);
    }
    return command;
}

[[nodiscard]] bool safe_method(drogon::HttpMethod method) {
    return method == drogon::Get || method == drogon::Head || method == drogon::Options;
}

[[nodiscard]] bool public_api_path(std::string_view path) {
    return path == "/api/health" || path == "/api/system/status" ||
           path == "/api/devices/enroll" || path.starts_with("/api/auth/") ||
           path.starts_with("/api/agent/");
}

[[nodiscard]] bool clash_websocket_path(std::string_view path) {
    constexpr std::string_view prefix{"/api/sing-box/ws/"};
    if (!path.starts_with(prefix)) {
        return false;
    }
    const auto kind = path.substr(prefix.size());
    return kind == "traffic" || kind == "logs" || kind == "connections" ||
           kind == "memory";
}

[[nodiscard]] std::optional<std::string>
bearer_token(const drogon::HttpRequestPtr& request) {
    constexpr std::string_view prefix{"Bearer "};
    const auto authorization = request->getHeader("authorization");
    if (!authorization.starts_with(prefix)) {
        return std::nullopt;
    }
    auto token = trim(authorization.substr(prefix.size()));
    return token.empty() ? std::nullopt : std::optional<std::string>{std::move(token)};
}

constexpr std::string_view claims_attribute{"sb-easy.auth.claims"};

[[nodiscard]] const AuthClaims& request_claims(const drogon::HttpRequestPtr& request) {
    if (!request->attributes()->find(std::string{claims_attribute})) {
        throw UnauthorizedError("Invalid or expired token");
    }
    return request->attributes()->get<AuthClaims>(std::string{claims_attribute});
}

void require_admin(const AuthClaims& claims) {
    if (claims.role != "admin") {
        throw ForbiddenError("Admin role required");
    }
}

[[nodiscard]] std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    if (::gmtime_r(&time, &utc) == nullptr) {
        throw std::runtime_error("UTC timestamp conversion failed");
    }
    std::ostringstream value;
    value << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return value.str();
}

[[nodiscard]] json default_telemetry() {
    return {
        {"at", ""},
        {"up", 0},
        {"down", 0},
        {"up_total", 0},
        {"down_total", 0},
        {"conn_count", 0},
        {"connections", nullptr},
        {"logs", json::array()},
    };
}

[[nodiscard]] std::int64_t integer_field(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end()) {
        return 0;
    }
    if (!found->is_number_integer()) {
        throw ValidationError(std::string{field} + " must be an integer");
    }
    return found->get<std::int64_t>();
}

[[nodiscard]] json normalize_telemetry(const json& body) {
    auto telemetry = default_telemetry();
    telemetry["at"] = utc_now();
    telemetry["up"] = integer_field(body, "up");
    telemetry["down"] = integer_field(body, "down");
    telemetry["up_total"] = integer_field(body, "up_total");
    telemetry["down_total"] = integer_field(body, "down_total");

    const auto count = integer_field(body, "conn_count");
    if (count < 0) {
        throw ValidationError("conn_count must not be negative");
    }
    telemetry["conn_count"] = count;
    if (const auto connections = body.find("connections"); connections != body.end()) {
        telemetry["connections"] = *connections;
    }
    if (const auto logs = body.find("logs"); logs != body.end()) {
        if (!logs->is_array()) {
            throw ValidationError("logs must be an array");
        }
        json normalized = json::array();
        const auto start = logs->size() > 500U ? logs->size() - 500U : 0U;
        for (std::size_t index = start; index < logs->size(); ++index) {
            if (!(*logs)[index].is_string()) {
                throw ValidationError("logs must contain only strings");
            }
            normalized.push_back((*logs)[index]);
        }
        telemetry["logs"] = std::move(normalized);
    }
    return telemetry;
}

class TelemetryStore final {
  public:
    void put(const std::string& host_id, json telemetry) {
        const std::scoped_lock lock{mutex_};
        values_.insert_or_assign(host_id, std::move(telemetry));
    }

    [[nodiscard]] json get(const std::string& host_id) const {
        const std::scoped_lock lock{mutex_};
        const auto found = values_.find(host_id);
        return found == values_.end() ? default_telemetry() : found->second;
    }

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, json> values_;
};

[[nodiscard]] ConfigProfile
profile_from_request(const json& body,
                     std::optional<ConfigProfile> existing = std::nullopt) {
    ConfigProfile profile = existing.value_or(ConfigProfile{});
    profile.name = required_string(body, "name");
    profile.profile = required_object(body, "template");
    profile.mode = profile_mode(body);

    if (const auto script = body.find("rule_script"); script != body.end()) {
        if (!script->is_string()) {
            throw ValidationError("rule_script must be a string");
        }
        profile.rule_script = script->get<std::string>();
    }
    if (const auto enabled = body.find("rule_script_enabled"); enabled != body.end()) {
        if (!enabled->is_boolean()) {
            throw ValidationError("rule_script_enabled must be a boolean");
        }
        profile.rule_script_enabled = enabled->get<bool>();
    }
    if (profile.rule_script_enabled && trim(profile.rule_script).empty()) {
        throw ValidationError(
            "rule_script must not be empty when rule_script_enabled is true");
    }
    return profile;
}

[[nodiscard]] Host host_from_create_request(const json& body) {
    Host host;
    host.name = required_string(body, "name");
    if (const auto capabilities = body.find("capabilities");
        capabilities != body.end() && !capabilities->is_null()) {
        if (!capabilities->is_object()) {
            throw ValidationError("capabilities must be a JSON object");
        }
        host.capabilities = *capabilities;
    } else {
        host.capabilities = {
            {"runs_singbox", true},
            {"is_wg_member", true},
            {"is_wg_hub", false},
            {"is_self", false},
        };
    }

    assign_optional_string(body, "profile_id", host.profile_id);
    assign_optional_string(body, "wg_address", host.wg_address);
    assign_optional_string(body, "wg_endpoint", host.wg_endpoint);
    assign_optional_string(body, "clash_api", host.clash_api);
    if (host.wg_endpoint.has_value() && host.wg_endpoint->empty()) {
        host.wg_endpoint = std::nullopt;
    }
    if (const auto secret = body.find("clash_secret");
        secret != body.end() && !secret->is_null()) {
        if (!secret->is_string()) {
            throw ValidationError("clash_secret must be a string");
        }
        host.clash_secret = secret->get<std::string>();
    }
    return host;
}

[[nodiscard]] Host host_from_update_request(Host host, const json& body) {
    if (const auto name = body.find("name"); name != body.end() && !name->is_null()) {
        if (!name->is_string() || name->get_ref<const std::string&>().empty()) {
            throw ValidationError("name must be a non-empty string");
        }
        host.name = name->get<std::string>();
    }
    if (const auto capabilities = body.find("capabilities");
        capabilities != body.end() && !capabilities->is_null()) {
        if (!capabilities->is_object()) {
            throw ValidationError("capabilities must be a JSON object");
        }
        host.capabilities = *capabilities;
    }
    assign_optional_string(body, "profile_id", host.profile_id);
    assign_optional_string(body, "wg_address", host.wg_address);
    assign_optional_string(body, "wg_public_key", host.wg_public_key);
    assign_optional_string(body, "wg_endpoint", host.wg_endpoint);
    assign_optional_string(body, "clash_api", host.clash_api);
    if (const auto secret = body.find("clash_secret");
        secret != body.end() && !secret->is_null()) {
        if (!secret->is_string()) {
            throw ValidationError("clash_secret must be a string");
        }
        host.clash_secret = secret->get<std::string>();
    }
    if (const auto enabled = body.find("enabled");
        enabled != body.end() && !enabled->is_null()) {
        if (!enabled->is_boolean()) {
            throw ValidationError("enabled must be a boolean");
        }
        host.enabled = enabled->get<bool>();
    }
    return host;
}

[[nodiscard]] ConfigProfile require_profile(Store& store, const std::string& id) {
    auto profile = store.find_profile(id);
    if (!profile.has_value()) {
        throw NotFoundError("Profile not found");
    }
    return std::move(*profile);
}

[[nodiscard]] ProxyRecord require_proxy(Store& store, const std::string& id) {
    auto node = store.find_proxy_node(id);
    if (!node.has_value()) {
        throw NotFoundError("Node not found");
    }
    return std::move(*node);
}

[[nodiscard]] Subscription require_subscription(Store& store, const std::string& id) {
    auto subscription = store.find_subscription(id);
    if (!subscription.has_value()) {
        throw NotFoundError("Subscription not found");
    }
    return std::move(*subscription);
}

[[nodiscard]] std::uint16_t required_port(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || !found->is_number_integer()) {
        throw ValidationError(std::string{field} + " must be an integer");
    }
    const auto value = found->get<std::int64_t>();
    if (value <= 0 || value > 65'535) {
        throw ValidationError(std::string{field} + " must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] ProxyRecord proxy_from_create_request(const json& body) {
    ProxyRecord node;
    node.tag = required_string(body, "tag");
    node.node_type = required_string(body, "node_type");
    node.enabled = body.value("enabled", true);
    node.server = required_string(body, "server");
    node.server_port = required_port(body, "server_port");
    node.protocol_config = required_object(body, "protocol_config");
    return node;
}

[[nodiscard]] ProxyRecord proxy_from_update_request(ProxyRecord node,
                                                    const json& body) {
    if (const auto tag = body.find("tag"); tag != body.end() && !tag->is_null()) {
        node.tag = required_string(body, "tag");
    }
    if (const auto server = body.find("server");
        server != body.end() && !server->is_null()) {
        node.server = required_string(body, "server");
    }
    if (const auto port = body.find("server_port");
        port != body.end() && !port->is_null()) {
        node.server_port = required_port(body, "server_port");
    }
    if (const auto config = body.find("protocol_config");
        config != body.end() && !config->is_null()) {
        if (!config->is_object()) {
            throw ValidationError("protocol_config must be a JSON object");
        }
        node.protocol_config = *config;
    }
    if (const auto enabled = body.find("enabled");
        enabled != body.end() && !enabled->is_null()) {
        if (!enabled->is_boolean()) {
            throw ValidationError("enabled must be a boolean");
        }
        node.enabled = enabled->get<bool>();
    }
    return node;
}

[[nodiscard]] std::string default_subscription_name(const std::string& url) {
    const auto separator = url.find("://");
    const auto start = separator == std::string::npos ? 0U : separator + 3U;
    const auto end = url.find('/', start);
    auto authority =
        url.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (const auto at = authority.rfind('@'); at != std::string::npos) {
        authority.erase(0, at + 1U);
    }
    if (authority.starts_with('[')) {
        if (const auto close = authority.find(']'); close != std::string::npos) {
            authority = authority.substr(1, close - 1U);
        }
    } else if (const auto colon = authority.rfind(':'); colon != std::string::npos) {
        authority.erase(colon);
    }
    return authority.empty() ? "Subscription" : authority;
}

[[nodiscard]] std::int64_t refresh_interval(const json& body, std::int64_t fallback) {
    const auto found = body.find("refresh_interval");
    if (found == body.end() || found->is_null()) {
        return fallback;
    }
    if (!found->is_number_integer()) {
        throw ValidationError("refresh_interval must be an integer");
    }
    const auto value = found->get<std::int64_t>();
    if (value <= 0) {
        throw ValidationError("refresh_interval must be positive");
    }
    return value;
}

[[nodiscard]] Subscription subscription_from_create_request(const json& body) {
    const auto url = required_string(body, "url");
    if (!body.contains("name") || !body["name"].is_string()) {
        throw ValidationError("name must be a string");
    }
    auto name = trim(body["name"].get<std::string>());
    if (name.empty()) {
        name = default_subscription_name(url);
    }
    Subscription subscription;
    subscription.name = std::move(name);
    subscription.url = url;
    subscription.enabled = true;
    subscription.refresh_interval = refresh_interval(body, 3'600);
    return subscription;
}

[[nodiscard]] Subscription subscription_from_update_request(Subscription subscription,
                                                            const json& body) {
    if (const auto name = body.find("name"); name != body.end() && !name->is_null()) {
        subscription.name = trim(required_string(body, "name"));
    }
    if (const auto url = body.find("url"); url != body.end() && !url->is_null()) {
        subscription.url = required_string(body, "url");
    }
    if (const auto enabled = body.find("enabled");
        enabled != body.end() && !enabled->is_null()) {
        if (!enabled->is_boolean()) {
            throw ValidationError("enabled must be a boolean");
        }
        subscription.enabled = enabled->get<bool>();
    }
    subscription.refresh_interval =
        refresh_interval(body, subscription.refresh_interval);
    return subscription;
}

[[nodiscard]] SubscriptionFetchResult
fetch_subscription(Store& store, SubscriptionFetcher& fetcher,
                   const Subscription& subscription) {
    std::string body;
    try {
        body = fetcher.fetch(subscription.url);
    } catch (const std::exception& error) {
        throw ValidationError("Failed to fetch subscription: " +
                              std::string{error.what()});
    }
    const auto nodes = parse_subscription_body(body);
    const auto upsert = store.upsert_proxy_nodes(nodes, subscription.id);
    SubscriptionFetchResult result{
        .added = upsert.added,
        .updated = upsert.updated,
        .skipped = 0,
        .found = nodes.size(),
        .errors = upsert.errors,
    };
    store.record_subscription_fetch(subscription.id, result);
    return result;
}

[[nodiscard]] ClashTarget resolve_clash_target(Store& store,
                                               const drogon::HttpRequestPtr& request,
                                               const std::string& local_url,
                                               const std::string& local_secret) {
    const auto host_id = trim(request->getParameter("host"));
    if (!host_id.empty() && host_id != "self") {
        if (const auto host = store.find_host(host_id);
            host.has_value() && host->clash_api.has_value()) {
            auto url = trim_trailing_slashes(*host->clash_api);
            if (!url.empty()) {
                return {
                    .base_url = std::move(url),
                    .secret = host->clash_secret,
                };
            }
        }
    }
    return {
        .base_url = trim_trailing_slashes(local_url),
        .secret = local_secret,
    };
}

template <typename Function>
[[nodiscard]] ClashResponse request_clash(const ClashTarget& target,
                                          Function&& function) {
    if (target.base_url.empty()) {
        throw ServiceUnavailableError("No sing-box Clash API URL is configured");
    }
    try {
        auto response = std::forward<Function>(function)();
        if (response.status == 401) {
            throw ServiceUnavailableError(
                "sing-box Clash API authentication failed for " + target.base_url +
                "; check the configured secret");
        }
        return response;
    } catch (const ClashRequestError& error) {
        throw ServiceUnavailableError("Could not reach sing-box Clash API (" +
                                      target.base_url + "): " + error.what());
    }
}

template <typename Function>
[[nodiscard]] json call_clash(const ClashTarget& target, Function&& function) {
    return request_clash(target, std::forward<Function>(function)).body;
}

[[nodiscard]] std::optional<double> test_proxy_latency(ClashClient& client,
                                                       const ClashTarget& target,
                                                       const std::string& tag) {
    if (target.base_url.empty()) {
        return std::nullopt;
    }
    try {
        const auto path = "/proxies/" + encode_component(tag) + "/delay?url=" +
                          encode_component("https://www.gstatic.com/generate_204") +
                          "&timeout=5000";
        const auto response = client.get(target, path);
        if (response.status < 200 || response.status >= 300) {
            return std::nullopt;
        }
        const auto delay = response.body.find("delay");
        if (delay != response.body.end() && delay->is_number()) {
            return delay->get<double>();
        }
    } catch (const ClashRequestError&) {
        // A failed dial is represented as a null latency, matching the Rust API.
    }
    return std::nullopt;
}

[[nodiscard]] ProxyNode renderer_node(const ProxyRecord& node) {
    return ProxyNode{
        .id = node.id,
        .tag = node.tag,
        .type = node.node_type,
        .enabled = node.enabled,
        .server = node.server,
        .server_port = node.server_port,
        .protocol_config = node.protocol_config,
    };
}

[[nodiscard]] Host require_host(Store& store, const std::string& id) {
    auto host = store.find_host(id);
    if (!host.has_value()) {
        throw NotFoundError("Host not found");
    }
    return std::move(*host);
}

[[nodiscard]] std::string agent_token(const drogon::HttpRequestPtr& request) {
    const auto authorization = request->getHeader("authorization");
    constexpr std::string_view prefix{"Bearer "};
    if (!authorization.starts_with(prefix)) {
        throw UnauthorizedError("Missing agent token");
    }
    auto token = trim(authorization.substr(prefix.size()));
    if (token.empty()) {
        throw UnauthorizedError("Missing agent token");
    }
    return token;
}

[[nodiscard]] Host resolve_agent_host(Store& store,
                                      const drogon::HttpRequestPtr& request,
                                      const std::string& legacy_agent_token) {
    const auto token = agent_token(request);
    if (auto host = store.find_enabled_host_by_token(token); host.has_value()) {
        return std::move(*host);
    }
    if (!legacy_agent_token.empty() && token == legacy_agent_token) {
        if (auto host = store.find_host("self"); host.has_value()) {
            return std::move(*host);
        }
    }
    throw UnauthorizedError("Invalid agent token");
}

[[nodiscard]] json optional_string_field(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || found->is_null()) {
        return nullptr;
    }
    if (!found->is_string()) {
        throw ValidationError(std::string{field} + " must be a string or null");
    }
    return *found;
}

[[nodiscard]] json optional_boolean_field(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() || found->is_null()) {
        return nullptr;
    }
    if (!found->is_boolean()) {
        throw ValidationError(std::string{field} + " must be a boolean or null");
    }
    return *found;
}

[[nodiscard]] std::optional<std::string> optional_result(const json& body) {
    const auto found = body.find("result");
    if (found == body.end() || found->is_null()) {
        return std::nullopt;
    }
    if (!found->is_string()) {
        throw ValidationError("result must be a string or null");
    }
    return found->get<std::string>();
}

[[nodiscard]] WireGuardOptions
wireguard_options(const HttpServerOptions& options) {
    return {
        .enabled = options.wireguard_enabled,
        .interface = options.wireguard_interface,
        .port = options.wireguard_port,
        .address = options.wireguard_address,
        .dns = options.wireguard_dns,
        .mtu = options.wireguard_mtu,
        .external_hostname = options.external_hostname,
        .egress_interface = options.wireguard_egress,
        .config_directory = options.wireguard_config_directory,
    };
}

void sync_wireguard_best_effort(const std::shared_ptr<WireGuardService>& service) {
    try {
        service->sync();
    } catch (const std::exception& error) {
        LOG_ERROR << "WireGuard sync failed: " << error.what();
    }
}

[[nodiscard]] bool uses_embedded_managed_network(const Host& host) {
    if (!host.capabilities.is_object()) {
        return false;
    }
    return host.capabilities.value("embedded_wireguard", false) ||
           host.capabilities.value("platform", "") == "android";
}

[[nodiscard]] RenderRequest managed_render_request(Store& store,
                                                   WireGuardService& wireguard,
                                                   Host& host,
                                                   bool provision_network_identity) {
    if (uses_embedded_managed_network(host) && provision_network_identity &&
        !host.wg_address.has_value()) {
        host = wireguard.provision_host(std::move(host), false);
    }

    auto request = store.render_request_for_host(host.id);
    if (!uses_embedded_managed_network(host)) {
        return request;
    }
    // Android controls libbox through its in-process CommandServer. A TCP
    // Clash controller is redundant there and makes hot reload race the old
    // service for 0.0.0.0:9090. Remove both the repository default and any
    // controller accidentally persisted in the profile template.
    request.clash_controller.clear();
    if (request.profile.contains("experimental") &&
        request.profile["experimental"].is_object()) {
        request.profile["experimental"].erase("clash_api");
    }
    auto endpoint = wireguard.client_endpoint(host);
    if (!endpoint.has_value()) {
        return request;
    }

    auto& endpoints = request.profile["endpoints"];
    if (!endpoints.is_array()) {
        endpoints = json::array();
    }
    auto tag = endpoint->value("tag", "sb-easy-network");
    const auto tag_in_use = [&request, &endpoints](const std::string& candidate) {
        const auto in_endpoints =
            std::ranges::any_of(endpoints, [&candidate](const auto& value) {
                return value.is_object() && value.value("tag", "") == candidate;
            });
        const auto in_nodes =
            std::ranges::any_of(request.nodes, [&candidate](const auto& node) {
                return node.tag == candidate;
            });
        return in_endpoints || in_nodes;
    };
    while (tag_in_use(tag)) {
        tag += " group";
    }
    (*endpoint)["tag"] = tag;
    endpoints.push_back(std::move(*endpoint));
    request.external_route_tags.push_back(tag);

    const auto& allowed_ips = endpoints.back().at("peers").at(0).at("allowed_ips");
    request.priority_route_rules.push_back({
        {"ip_cidr", allowed_ips},
        {"outbound", tag},
    });
    return request;
}

[[nodiscard]] std::string utc_after(std::chrono::minutes offset) {
    const auto time = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + offset);
    std::tm utc{};
    if (::gmtime_r(&time, &utc) == nullptr) {
        throw std::runtime_error("UTC timestamp conversion failed");
    }
    std::ostringstream value;
    value << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return value.str();
}

void run_self_singbox(std::stop_token stop,
                      const std::shared_ptr<Store>& store,
                      HttpServerOptions options) {
    auto config_path = trim(options.self_singbox_config_path);
    if (config_path.empty()) {
        config_path = "data/sing-box.gen.json";
    }
    const auto logged_config_path = config_path;
    SingBoxSupervisor supervisor({
        .binary = options.singbox_binary,
        .config_path = std::move(config_path),
        .validate_config = options.singbox_validate_config,
    });
    const auto interval = std::chrono::seconds{
        std::max<std::uint64_t>(options.self_singbox_interval_seconds, 2U)};
    std::optional<std::string> last_etag;
    std::optional<std::string> logged_error;
    std::mutex wait_mutex;
    std::condition_variable_any wakeup;

    LOG_INFO << "managed sing-box enabled: binary=" << options.singbox_binary
             << " config=" << logged_config_path
             << " interval=" << interval.count() << "s";
    while (!stop.stop_requested()) {
        try {
            const auto host = store->find_host("self");
            if (host.has_value() && host->enabled &&
                host->capabilities.value("runs_singbox", false)) {
                auto request = store->render_request_for_host("self");
                request.clash_controller =
                    clash_controller_address(options.clash_api_url);
                request.clash_secret = options.clash_api_secret;
                const ConfigRenderer renderer;
                const auto body = renderer.render(request).dump(2);
                const auto etag =
                    config_etag("self", body, options.config_hash_seed);
                if (!last_etag.has_value() || *last_etag != etag) {
                    supervisor.apply_config(body);
                    last_etag = etag;
                    LOG_INFO << "managed sing-box config applied: " << etag;
                }
            }
            supervisor.ensure_alive();
            if (supervisor.last_error().has_value() &&
                supervisor.last_error() != logged_error) {
                LOG_ERROR << *supervisor.last_error();
                logged_error = supervisor.last_error();
            } else if (!supervisor.last_error().has_value()) {
                logged_error.reset();
            }
        } catch (const std::exception& error) {
            const std::string message{error.what()};
            if (!logged_error.has_value() || *logged_error != message) {
                LOG_ERROR << "managed sing-box cycle failed: " << message;
                logged_error = message;
            }
        }

        std::unique_lock lock{wait_mutex};
        static_cast<void>(
            wakeup.wait_for(lock, stop, interval, [] { return false; }));
    }
    supervisor.stop();
}

} // namespace

void register_http_routes(const std::shared_ptr<Store>& store,
                          const HttpServerOptions& options) {
    if (!store) {
        throw std::invalid_argument("HTTP store is required");
    }

    store->ensure_default_admin(options.admin_password);
    const auto auth = std::make_shared<AuthService>(options.jwt_secret);
    const auto telemetry = std::make_shared<TelemetryStore>();
    const auto subscription_fetcher = std::make_shared<SubscriptionFetcher>();
    const auto clash_client = std::make_shared<ClashClient>();
    const auto wireguard = std::make_shared<WireGuardService>(
        store, wireguard_options(options));
    const auto server_logs = std::make_shared<ServerLogBuffer>();
    trantor::Logger::setOutputFunction(
        [server_logs](const char* message, std::uint64_t length) {
            static_cast<void>(
                std::fwrite(message, 1U, static_cast<std::size_t>(length), stdout));
            server_logs->append(
                std::string_view{message, static_cast<std::size_t>(length)});
        },
        [] { static_cast<void>(std::fflush(stdout)); });
    LOG_INFO << "sb-easy C++ HTTP routes registered";
    const auto public_server = options.public_server;
    auto enrollment_server = trim_trailing_slashes(public_server);
    if (!enrollment_server.starts_with("http://") &&
        !enrollment_server.starts_with("https://")) {
        if (enrollment_server.find(':') == std::string::npos ||
            (enrollment_server.starts_with('[') && enrollment_server.ends_with(']'))) {
            enrollment_server += ":" + std::to_string(options.port);
        }
        enrollment_server = "http://" + enrollment_server;
    }
    const auto config_hash_seed = options.config_hash_seed;
    const auto legacy_agent_token = trim(options.legacy_agent_token);
    const auto local_clash_api = options.clash_api_url;
    const auto local_clash_secret = options.clash_api_secret;
    const auto wireguard_interface = options.wireguard_interface;
    const auto wireguard_port = options.wireguard_port;
    const auto wireguard_address = options.wireguard_address;
    const auto wireguard_dns = options.wireguard_dns;
    const auto wireguard_mtu = options.wireguard_mtu;
    const auto static_directory =
        std::filesystem::path{options.static_directory};
    const auto cors =
        std::make_shared<CorsPolicy>(options.cors_origins);
    auto& application = drogon::app();
    application.registerPreRoutingAdvice(
        [cors](const drogon::HttpRequestPtr& request,
               drogon::AdviceCallback&& reject,
               drogon::AdviceChainCallback&& proceed) {
            if (request->method() != drogon::Options ||
                request->getHeader("access-control-request-method").empty()) {
                proceed();
                return;
            }
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k204NoContent);
            cors->apply(request, response);
            reject(std::move(response));
        });
    application.registerPreRoutingAdvice([auth](const drogon::HttpRequestPtr& request,
                                                drogon::AdviceCallback&& reject,
                                                drogon::AdviceChainCallback&& proceed) {
        if (clash_websocket_path(request->path())) {
            const auto token = trim(request->getParameter("token"));
            const auto claims =
                token.empty() ? std::nullopt : auth->verify_token(token);
            if (!claims.has_value()) {
                reject(json_response({{"error", "Invalid or expired token"}},
                                     drogon::k401Unauthorized));
                return;
            }
            request->attributes()->insert(std::string{claims_attribute}, *claims);
            proceed();
            return;
        }
        if (!request->path().starts_with("/api/") || public_api_path(request->path())) {
            proceed();
            return;
        }
        const auto token = bearer_token(request);
        const auto claims =
            token.has_value() ? auth->verify_token(*token) : std::nullopt;
        if (!claims.has_value()) {
            reject(json_response({{"error", "Invalid or expired token"}},
                                 drogon::k401Unauthorized));
            return;
        }
        if (claims->role == "viewer" && !safe_method(request->method())) {
            reject(json_response({{"error", "Viewer role is read-only"}},
                                 drogon::k403Forbidden));
            return;
        }
        request->attributes()->insert(std::string{claims_attribute}, *claims);
        proceed();
    });
    application.registerPostHandlingAdvice(
        [store](const drogon::HttpRequestPtr& request,
                const drogon::HttpResponsePtr& response) {
            if (safe_method(request->method()) ||
                !request->attributes()->find(std::string{claims_attribute}) ||
                response->statusCode() < 200 || response->statusCode() >= 300) {
                return;
            }
            const auto& claims =
                request->attributes()->get<AuthClaims>(std::string{claims_attribute});
            try {
                store->record_audit(claims.username,
                                    std::string{request->methodString()},
                                    request->path());
            } catch (const std::exception& error) {
                LOG_ERROR << "audit write failed: " << error.what();
            }
        });
    application.registerPreSendingAdvice(
        [cors](const drogon::HttpRequestPtr& request,
               const drogon::HttpResponsePtr& response) {
            cors->apply(request, response);
        });
    register_clash_websocket_routes(store, local_clash_api, local_clash_secret);
    application.registerHandler(
        "/api/health",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({{"status", "ok"}, {"service", "sb-easy-cpp"}}));
        },
        {drogon::Get});
    application.registerHandler(
        "/api/system/status",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                return json{
                    {"version", application_version},
                    {"status", "running"},
                    {"wireguard",
                     {{"peer_count", store->list_wireguard_peers().size()}}},
                    {"sing_box", {{"node_count", store->list_proxy_nodes().size()}}},
                    {"subscriptions", {{"count", store->list_subscriptions().size()}}},
                };
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/system/logs",
        [server_logs](const drogon::HttpRequestPtr&,
                      ResponseCallback&& callback) {
            callback(json_response({{"lines", server_logs->lines()}}));
        },
        {drogon::Get});
    application.registerHandler(
        "/api/system/migrate/wg-easy",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response(
                {{"status", "not_implemented"},
                 {"message",
                  "wg-easy migration coming in a future update. Use manual "
                  "import for now."}}));
        },
        {drogon::Post});
    application.registerHandler(
        "/api/auth/login",
        [store, auth](const drogon::HttpRequestPtr& request,
                      ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                auto username = std::string{"admin"};
                if (const auto found = body.find("username");
                    found != body.end() && !found->is_null()) {
                    if (!found->is_string()) {
                        throw ValidationError("username must be a string");
                    }
                    username = found->get<std::string>();
                }
                const auto password = required_string(body, "password");
                const auto user = store->find_user_by_username(username);
                if (!user.has_value() ||
                    !verify_password(password, user->password_hash)) {
                    throw UnauthorizedError("Invalid credentials");
                }
                return json{
                    {"token", auth->create_token(user->id, user->username, user->role)},
                    {"username", user->username},
                    {"role", user->role},
                };
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/auth/session",
        [auth](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto token = bearer_token(request);
                const auto claims =
                    token.has_value() ? auth->verify_token(*token) : std::nullopt;
                if (!claims.has_value()) {
                    throw UnauthorizedError("Invalid or expired token");
                }
                return json{
                    {"username", claims->username},
                    {"role", claims->role},
                    {"authenticated", true},
                };
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/users/audit",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                require_admin(request_claims(request));
                return json(store->list_audit());
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/users",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                require_admin(request_claims(request));
                return json(store->list_users());
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/users",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                require_admin(request_claims(request));
                const auto body = request_object(request);
                const auto username = required_string(body, "username");
                const auto password = required_string(body, "password");
                auto role = std::string{"viewer"};
                if (const auto found = body.find("role");
                    found != body.end() && !found->is_null()) {
                    if (!found->is_string()) {
                        throw ValidationError("role must be a string");
                    }
                    role = found->get<std::string>();
                }
                if (trim(username).empty() || password.size() < 4U) {
                    throw ValidationError(
                        "Username required, password must be at least 4 characters");
                }
                if (role != "admin" && role != "viewer") {
                    throw ValidationError("Role must be admin or viewer");
                }
                return json(
                    store->create_user(username, hash_password(password), role));
            });
        },
        {drogon::Post});
    application.registerHandler("/api/users/{id}",
                                [store](const drogon::HttpRequestPtr& request,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        const auto& claims = request_claims(request);
                                        require_admin(claims);
                                        store->delete_user(claims.subject, id);
                                        return json{{"success", true}};
                                    });
                                },
                                {drogon::Delete});
    application.registerHandler(
        "/api/users/{id}/password",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                require_admin(request_claims(request));
                const auto password =
                    required_string(request_object(request), "password");
                if (password.size() < 4U) {
                    throw ValidationError("Password must be at least 4 characters");
                }
                store->reset_user_password(id, hash_password(password));
                return json{{"success", true}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/settings",
        [store, wireguard_interface, wireguard_port, wireguard_address, wireguard_dns,
         wireguard_mtu](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                auto settings = store->app_settings();
                json wireguard_settings{
                    {"interface", wireguard_interface},
                    {"listen_port", wireguard_port},
                    {"address", wireguard_address},
                    {"dns", wireguard_dns},
                    {"mtu", wireguard_mtu},
                };
                if (const auto saved = settings.find("wireguard_interface");
                    saved != settings.end() && saved->is_object()) {
                    for (const auto& [key, value] : saved->items()) {
                        if (!value.is_null()) {
                            wireguard_settings[key] = value;
                        }
                    }
                }
                settings["wireguard_interface"] =
                    std::move(wireguard_settings);
                return settings;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/settings",
        [store, wireguard, wireguard_interface, wireguard_port, wireguard_address,
         wireguard_dns, wireguard_mtu](const drogon::HttpRequestPtr& request,
                        ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                store->update_app_settings(request_object(request));
                sync_wireguard_best_effort(wireguard);
                auto settings = store->app_settings();
                json wireguard_settings{
                    {"interface", wireguard_interface},
                    {"listen_port", wireguard_port},
                    {"address", wireguard_address},
                    {"dns", wireguard_dns},
                    {"mtu", wireguard_mtu},
                };
                if (const auto saved = settings.find("wireguard_interface");
                    saved != settings.end() && saved->is_object()) {
                    for (const auto& [key, value] : saved->items()) {
                        if (!value.is_null()) {
                            wireguard_settings[key] = value;
                        }
                    }
                }
                settings["wireguard_interface"] =
                    std::move(wireguard_settings);
                return settings;
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/settings/backup",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                auto backup = store->export_backup();
                backup["version"] = 1;
                backup["exported_at"] = utc_now();
                return backup;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/settings/restore",
        [store, wireguard](const drogon::HttpRequestPtr& request,
                           ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto restored =
                    store->restore_backup(request_object(request));
                sync_wireguard_best_effort(wireguard);
                return json{{"restored", restored}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/wireguard/peers",
        [store, wireguard](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                std::vector<WireGuardPeerStats> stats;
                try {
                    stats = wireguard->stats();
                } catch (const std::exception&) {
                }
                json result = json::array();
                for (const auto& peer : store->list_wireguard_peers()) {
                    auto value = json(peer);
                    value["expired"] = WireGuardService::peer_expired(peer);
                    value["kind"] = peer.host_id.has_value() ? "agent" : "wg";
                    if (peer.host_id.has_value()) {
                        const auto host = store->find_host(*peer.host_id);
                        value["host_name"] =
                            host.has_value() ? json(host->name) : json(nullptr);
                    }
                    const auto live =
                        std::ranges::find(stats, peer.public_key,
                                          &WireGuardPeerStats::public_key);
                    if (live != stats.end()) {
                        value["endpoint"] = live->endpoint;
                        value["latest_handshake"] = live->latest_handshake;
                        value["transfer_rx"] = live->transfer_rx;
                        value["transfer_tx"] = live->transfer_tx;
                    }
                    result.push_back(std::move(value));
                }
                return result;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/wireguard/peers",
        [store, wireguard](const drogon::HttpRequestPtr& request,
                           ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                const auto runtime = wireguard->runtime_options();
                const auto keys = WireGuardService::generate_keypair();
                WireGuardPeer peer{
                    .id = {},
                    .name = trim(required_string(body, "name")),
                    .private_key = keys.private_key,
                    .public_key = keys.public_key,
                    .preshared_key =
                        WireGuardService::generate_preshared_key(),
                    .address = body.contains("address") &&
                                       body["address"].is_string()
                                   ? body["address"].get<std::string>()
                                   : store->next_wireguard_address(runtime.address),
                    .dns = body.value("dns", runtime.dns),
                    .enabled = true,
                    .persistent_keepalive =
                        body.value("persistent_keepalive", 25),
                    .allowed_ips =
                        body.value("allowed_ips", "0.0.0.0/0, ::/0"),
                    .expire_at =
                        body.contains("expire_at") && body["expire_at"].is_string()
                            ? std::optional<std::string>{
                                  body["expire_at"].get<std::string>()}
                            : std::nullopt,
                    .quota_bytes = body.value("quota_bytes", 0),
                    .created_at = {},
                    .updated_at = {},
                    .notes =
                        body.contains("notes") && body["notes"].is_string()
                            ? std::optional<std::string>{
                                  body["notes"].get<std::string>()}
                            : std::nullopt,
                    .host_id = std::nullopt,
                };
                auto created =
                    store->create_wireguard_peer(std::move(peer));
                sync_wireguard_best_effort(wireguard);
                return json(created);
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/wireguard/peers/{id}",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                const auto peer = store->find_wireguard_peer(id);
                if (!peer.has_value()) {
                    throw NotFoundError("Peer not found");
                }
                return json(*peer);
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/wireguard/peers/{id}",
        [store, wireguard](const drogon::HttpRequestPtr& request,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle(std::move(callback), [&] {
                auto peer = store->find_wireguard_peer(id);
                if (!peer.has_value()) {
                    throw NotFoundError("Peer not found");
                }
                const auto body = request_object(request);
                assign_string(body, "name", peer->name);
                assign_string(body, "dns", peer->dns);
                assign_boolean(body, "enabled", peer->enabled);
                assign_string(body, "allowed_ips", peer->allowed_ips);
                if (const auto found = body.find("persistent_keepalive");
                    found != body.end() && !found->is_null()) {
                    peer->persistent_keepalive =
                        found->get<std::int32_t>();
                }
                if (const auto found = body.find("quota_bytes");
                    found != body.end() && !found->is_null()) {
                    peer->quota_bytes = found->get<std::int64_t>();
                }
                if (const auto found = body.find("expire_at");
                    found != body.end() && found->is_string()) {
                    peer->expire_at = found->get<std::string>();
                }
                if (const auto found = body.find("notes");
                    found != body.end() && found->is_string()) {
                    peer->notes = found->get<std::string>();
                }
                auto updated =
                    store->update_wireguard_peer(std::move(*peer));
                sync_wireguard_best_effort(wireguard);
                return json(updated);
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/wireguard/peers/{id}",
        [store, wireguard](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle(std::move(callback), [&] {
                const auto peer = store->find_wireguard_peer(id);
                if (!peer.has_value()) {
                    throw NotFoundError("Peer not found");
                }
                wireguard->remove_peer(peer->public_key);
                store->delete_wireguard_peer(id);
                return json{{"success", true}};
            });
        },
        {drogon::Delete});
    for (const auto& [path, enabled] :
         {std::pair{"/api/wireguard/peers/{id}/enable", true},
          std::pair{"/api/wireguard/peers/{id}/disable", false}}) {
        application.registerHandler(
            path,
            [store, wireguard, enabled](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                handle(std::move(callback), [&] {
                    store->set_wireguard_peer_enabled(id, enabled);
                    sync_wireguard_best_effort(wireguard);
                    return json{{"success", true}};
                });
            },
            {drogon::Post});
    }
    application.registerHandler(
        "/api/wireguard/peers/{id}/config",
        [store, wireguard](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle_response(std::move(callback), [&] {
                const auto peer = store->find_wireguard_peer(id);
                if (!peer.has_value()) {
                    throw NotFoundError("Peer not found");
                }
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k200OK);
                response->setContentTypeCode(drogon::CT_APPLICATION_OCTET_STREAM);
                auto filename = peer->name;
                std::ranges::replace(filename, ' ', '_');
                response->addHeader(
                    "Content-Disposition",
                    "attachment; filename=\"" + filename + ".conf\"");
                response->setBody(wireguard->client_config(*peer));
                return response;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/wireguard/peers/{id}/qr",
        [store, wireguard](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle_response(std::move(callback), [&] {
                const auto peer = store->find_wireguard_peer(id);
                if (!peer.has_value()) {
                    throw NotFoundError("Peer not found");
                }
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k200OK);
                response->setContentTypeString("image/svg+xml");
                response->setBody(wireguard->qr_svg(*peer));
                return response;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/wireguard/peers/{id}/one-time-link",
        [store, external_hostname = options.external_hostname](
            const drogon::HttpRequestPtr&, ResponseCallback&& callback,
            const std::string& id) {
            handle(std::move(callback), [&] {
                if (!store->find_wireguard_peer(id).has_value()) {
                    throw NotFoundError("Peer not found");
                }
                const auto token = secure_token(16U);
                const auto expires = utc_after(std::chrono::minutes{5});
                store->create_one_time_link(token, id, expires);
                return json{
                    {"url", "https://" + external_hostname +
                                "/api/one-time/" + token},
                    {"expires_at", expires},
                };
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/wireguard/stats",
        [wireguard](const drogon::HttpRequestPtr&,
                    ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                try {
                    return json{{"peers", wireguard->stats()}};
                } catch (const std::exception&) {
                    return json{{"peers", json::array()}};
                }
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/wireguard/sync",
        [wireguard](const drogon::HttpRequestPtr&,
                    ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                wireguard->sync();
                return json{{"success", true}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/config/sing-box/full",
        [store, local_clash_api, local_clash_secret](
            const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                auto request = store->render_request_for_host("self");
                request.clash_controller =
                    clash_controller_address(local_clash_api);
                request.clash_secret = local_clash_secret;
                const ConfigRenderer renderer;
                return renderer.render(request);
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/config/sing-box/outbounds",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                std::vector<ProxyNode> nodes;
                for (const auto& record : store->list_proxy_nodes()) {
                    nodes.push_back(renderer_node(record));
                }
                return ConfigRenderer::generate_outbounds(nodes);
            });
        },
        {drogon::Get});
    application.registerHandler("/api/config/sing-box/outbound/{id}",
                                [store](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        return ConfigRenderer::generate_outbound(
                                            renderer_node(require_proxy(*store, id)));
                                    });
                                },
                                {drogon::Get});

    application.registerHandler(
        "/api/sing-box/proxies",
        [store, clash_client, local_clash_api, local_clash_secret](
            const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                return call_clash(
                    target, [&] { return clash_client->get(target, "/proxies"); });
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/sing-box/proxies/{name}",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& name) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                return call_clash(target, [&] {
                    return clash_client->get(target,
                                             "/proxies/" + encode_component(name));
                });
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/sing-box/proxies/{name}",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& name) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                const auto response = request_clash(target, [&] {
                    return clash_client->put(target,
                                             "/proxies/" + encode_component(name),
                                             request_object(request));
                });
                if (response.status < 200 || response.status >= 300) {
                    throw ValidationError("sing-box returned HTTP " +
                                          std::to_string(response.status));
                }
                return json{{"success", true}};
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/sing-box/proxies/{name}/delay",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& name) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                auto url = request->getParameter("url");
                auto timeout = request->getParameter("timeout");
                if (url.empty()) {
                    url = "https://www.gstatic.com/generate_204";
                }
                if (timeout.empty()) {
                    timeout = "5000";
                }
                const auto path = "/proxies/" + encode_component(name) +
                                  "/delay?url=" + encode_component(url) +
                                  "&timeout=" + encode_component(timeout);
                return call_clash(target,
                                  [&] { return clash_client->get(target, path); });
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/sing-box/group/{name}/delay",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& name) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                auto url = request->getParameter("url");
                auto timeout = request->getParameter("timeout");
                if (url.empty()) {
                    url = "https://www.gstatic.com/generate_204";
                }
                if (timeout.empty()) {
                    timeout = "5000";
                }
                const auto path = "/group/" + encode_component(name) +
                                  "/delay?url=" + encode_component(url) +
                                  "&timeout=" + encode_component(timeout);
                return call_clash(target,
                                  [&] { return clash_client->get(target, path); });
            });
        },
        {drogon::Get});
    for (const auto& [route, upstream] :
         std::array<std::pair<std::string, std::string>, 3>{
             std::pair{"/api/sing-box/rules", "/rules"},
             std::pair{"/api/sing-box/connections", "/connections"},
             std::pair{"/api/sing-box/version", "/version"},
         }) {
        application.registerHandler(
            route,
            [store, clash_client, local_clash_api, local_clash_secret, upstream](
                const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
                handle(std::move(callback), [&] {
                    const auto target = resolve_clash_target(
                        *store, request, local_clash_api, local_clash_secret);
                    return call_clash(
                        target, [&] { return clash_client->get(target, upstream); });
                });
            },
            {drogon::Get});
    }
    application.registerHandler(
        "/api/sing-box/connections",
        [store, clash_client, local_clash_api, local_clash_secret](
            const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                return call_clash(target, [&] {
                    return clash_client->remove(target, "/connections");
                });
            });
        },
        {drogon::Delete});
    application.registerHandler(
        "/api/sing-box/connections/{id}",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& id) {
            handle(std::move(callback), [&] {
                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                return call_clash(target, [&] {
                    return clash_client->remove(target,
                                                "/connections/" + encode_component(id));
                });
            });
        },
        {drogon::Delete});

    application.registerHandler(
        "/api/proxy/nodes",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback),
                   [&] { return json(store->list_proxy_nodes()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/proxy/nodes",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                return json(store->create_proxy_node(
                    proxy_from_create_request(request_object(request))));
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/proxy/nodes/import",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                json config;
                if (const auto profile_id = body.find("profile_id");
                    profile_id != body.end() && profile_id->is_string() &&
                    !profile_id->get_ref<const std::string&>().empty()) {
                    config =
                        require_profile(*store, profile_id->get<std::string>()).profile;
                } else if (const auto raw = body.find("config");
                           raw != body.end() && raw->is_string()) {
                    config =
                        json::parse(raw->get_ref<const std::string&>(), nullptr, false);
                    if (config.is_discarded()) {
                        throw ValidationError("Pasted config is not valid JSON");
                    }
                } else {
                    throw ValidationError("Provide either profile_id or config");
                }
                const auto parsed = parse_outbound_config(config);
                const auto result =
                    store->upsert_proxy_nodes(parsed.nodes, std::nullopt);
                return json{
                    {"found", parsed.nodes.size()}, {"added", result.added},
                    {"updated", result.updated},    {"skipped", parsed.skipped},
                    {"errors", result.errors},
                };
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/proxy/nodes/test-all",
        [store, clash_client, local_clash_api, local_clash_secret](
            const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto host_id = trim(request->getParameter("host"));
                if (!host_id.empty() && host_id != "self") {
                    static_cast<void>(require_host(*store, host_id));
                    static_cast<void>(
                        store->enqueue_host_command(host_id, "test-proxies"));
                    return json{{"queued", true}, {"host", host_id}};
                }

                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                json results = json::object();
                std::size_t tested{};
                std::vector<ProxyRecord> nodes;
                for (const auto& node : store->list_proxy_nodes()) {
                    if (node.enabled) {
                        nodes.push_back(node);
                    }
                }
                constexpr std::size_t concurrency{8U};
                for (std::size_t offset = 0U; offset < nodes.size();
                     offset += concurrency) {
                    using Measurement = std::pair<ProxyRecord, std::optional<double>>;
                    std::vector<std::future<Measurement>> pending;
                    const auto end = std::min(nodes.size(), offset + concurrency);
                    pending.reserve(end - offset);
                    for (auto index = offset; index < end; ++index) {
                        pending.push_back(
                            std::async(std::launch::async, [clash_client, target,
                                                            node = nodes[index]] {
                                return Measurement{
                                    node,
                                    test_proxy_latency(*clash_client, target, node.tag),
                                };
                            }));
                    }
                    for (auto& future : pending) {
                        auto [node, latency] = future.get();
                        store->update_proxy_latency(node.id, latency);
                        results[node.tag] =
                            latency.has_value() ? json(*latency) : json(nullptr);
                        ++tested;
                    }
                }
                return json{
                    {"tested", tested},
                    {"results", std::move(results)},
                    {"tested_at", utc_now()},
                };
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/proxy/nodes/{id}/test-latency",
        [store, clash_client, local_clash_api,
         local_clash_secret](const drogon::HttpRequestPtr& request,
                             ResponseCallback&& callback, const std::string& id) {
            handle(std::move(callback), [&] {
                const auto node = require_proxy(*store, id);
                const auto host_id = trim(request->getParameter("host"));
                if (!host_id.empty() && host_id != "self") {
                    static_cast<void>(require_host(*store, host_id));
                    const auto command =
                        "test-proxies " + json::array({node.tag}).dump();
                    static_cast<void>(store->enqueue_host_command(host_id, command));
                    return json{{"queued", true}, {"host", host_id}};
                }

                const auto target = resolve_clash_target(
                    *store, request, local_clash_api, local_clash_secret);
                const auto latency =
                    test_proxy_latency(*clash_client, target, node.tag);
                store->update_proxy_latency(node.id, latency);
                return json{
                    {"node_id", node.id},
                    {"latency", latency.has_value() ? json(*latency) : json(nullptr)},
                    {"tested_at", utc_now()},
                };
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/proxy/nodes/{id}",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback),
                   [&] { return json(require_proxy(*store, id)); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/proxy/nodes/{id}",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                auto node = require_proxy(*store, id);
                return json(store->update_proxy_node(proxy_from_update_request(
                    std::move(node), request_object(request))));
            });
        },
        {drogon::Put});
    application.registerHandler("/api/proxy/nodes/{id}",
                                [store](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        store->delete_proxy_node(id);
                                        return json{{"success", true}};
                                    });
                                },
                                {drogon::Delete});

    application.registerHandler(
        "/api/subscriptions",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback),
                   [&] { return json(store->list_subscriptions()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/subscriptions",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                return json(store->create_subscription(
                    subscription_from_create_request(request_object(request))));
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/subscriptions/fetch-all",
        [store, subscription_fetcher](const drogon::HttpRequestPtr&,
                                      ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                json results = json::array();
                for (const auto& subscription : store->list_subscriptions()) {
                    if (!subscription.enabled) {
                        continue;
                    }
                    try {
                        const auto result = fetch_subscription(
                            *store, *subscription_fetcher, subscription);
                        results.push_back({
                            {"id", subscription.id},
                            {"name", subscription.name},
                            {"added", result.added},
                            {"updated", result.updated},
                            {"found", result.found},
                            {"errors", result.errors},
                        });
                    } catch (const std::exception& error) {
                        results.push_back({
                            {"id", subscription.id},
                            {"name", subscription.name},
                            {"error", error.what()},
                        });
                    }
                }
                return results;
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/subscriptions/{id}",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback),
                   [&] { return json(require_subscription(*store, id)); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/subscriptions/{id}",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                auto subscription = require_subscription(*store, id);
                return json(store->update_subscription(subscription_from_update_request(
                    std::move(subscription), request_object(request))));
            });
        },
        {drogon::Put});
    application.registerHandler("/api/subscriptions/{id}",
                                [store](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        store->delete_subscription(id);
                                        return json{{"success", true}};
                                    });
                                },
                                {drogon::Delete});
    application.registerHandler(
        "/api/subscriptions/{id}/fetch",
        [store, subscription_fetcher](const drogon::HttpRequestPtr&,
                                      ResponseCallback&& callback,
                                      const std::string& id) {
            handle(std::move(callback), [&] {
                return json(fetch_subscription(*store, *subscription_fetcher,
                                               require_subscription(*store, id)));
            });
        },
        {drogon::Post});

    application.registerHandler(
        "/api/hosts/profiles",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] { return json(store->list_profiles()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/profiles",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                return json(store->create_profile(
                    profile_from_request(request_object(request))));
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/hosts/rule-script/test",
        [](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                const auto script = required_string(body, "rule_script");
                auto context = body.value("context", json::object());
                if (!context.is_object()) {
                    throw ValidationError("context must be a JSON object");
                }
                if (!context.contains("host")) {
                    context["host"] = {
                        {"id", "preview"},
                        {"name", "QuickJS preview"},
                        {"capabilities", json::object()},
                    };
                }
                if (!context.contains("outboundTags")) {
                    context["outboundTags"] = json::array({"Proxy", "direct", "block"});
                }
                if (!context.contains("currentRules")) {
                    context["currentRules"] = json::array();
                }
                if (!context["host"].is_object() ||
                    !context["outboundTags"].is_array() ||
                    !context["currentRules"].is_array()) {
                    throw ValidationError(
                        "context host/outboundTags/currentRules have invalid types");
                }
                RuleScriptEngine engine;
                auto rules = engine.build_rules(script, context);
                return json{{"success", true},
                            {"count", rules.size()},
                            {"rules", std::move(rules)}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/hosts/profiles/{id}",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback),
                   [&] { return json(require_profile(*store, id)); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/profiles/{id}",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                auto profile = require_profile(*store, id);
                return json(store->update_profile(
                    profile_from_request(request_object(request), std::move(profile))));
            });
        },
        {drogon::Put});
    application.registerHandler("/api/hosts/profiles/{id}",
                                [store](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        store->delete_profile(id);
                                        return json{{"success", true}};
                                    });
                                },
                                {drogon::Delete});

    application.registerHandler(
        "/api/hosts",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle(std::move(callback), [&] { return json(store->list_hosts()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts",
        [store, wireguard](const drogon::HttpRequestPtr& request,
                           ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                auto host =
                    store->create_host(host_from_create_request(body));
                if (host.id != "self" &&
                    host.capabilities.value("is_wg_member", false)) {
                    try {
                        host = wireguard->provision_host(
                            host, !body.contains("clash_api"));
                        sync_wireguard_best_effort(wireguard);
                    } catch (const std::exception& error) {
                        LOG_ERROR << "managed host WireGuard provisioning failed: "
                                  << error.what();
                    }
                }
                return json(host);
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/hosts/{id}",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] { return json(require_host(*store, id)); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}",
        [store, wireguard](const drogon::HttpRequestPtr& request,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle(std::move(callback), [&] {
                auto host = require_host(*store, id);
                const auto was_member =
                    host.capabilities.value("is_wg_member", false);
                host = store->update_host(host_from_update_request(
                    std::move(host), request_object(request)));
                const auto is_member =
                    host.capabilities.value("is_wg_member", false);
                if (is_member && !was_member && id != "self") {
                    try {
                        host = wireguard->provision_host(
                            host, !host.clash_api.has_value());
                        sync_wireguard_best_effort(wireguard);
                    } catch (const std::exception& error) {
                        LOG_ERROR << "managed host WireGuard provisioning failed: "
                                  << error.what();
                    }
                } else if (!is_member && was_member) {
                    wireguard->deprovision_host(id);
                    sync_wireguard_best_effort(wireguard);
                }
                return json(host);
            });
        },
        {drogon::Put});
    application.registerHandler("/api/hosts/{id}",
                                [store, wireguard](
                                    const drogon::HttpRequestPtr&,
                                    ResponseCallback&& callback,
                                    const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        wireguard->deprovision_host(id);
                                        store->delete_host(id);
                                        sync_wireguard_best_effort(wireguard);
                                        return json{{"success", true}};
                                    });
                                },
                                {drogon::Delete});

    application.registerHandler("/api/hosts/{id}/telemetry",
                                [store, telemetry](const drogon::HttpRequestPtr&,
                                                   ResponseCallback&& callback,
                                                   const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        static_cast<void>(require_host(*store, id));
                                        return telemetry->get(id);
                                    });
                                },
                                {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}/commands",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback),
                   [&] { return json(store->list_host_commands(id)); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}/commands",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                const auto host = require_host(*store, id);
                if (host.id == "self") {
                    throw ValidationError("The self host has no remote agent");
                }
                const auto command = store->enqueue_host_command(
                    id, normalized_command(request_object(request)));
                return json{{"id", command.id},
                            {"command", command.command},
                            {"status", command.status}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/hosts/{id}/outbounds",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                return json{{"host_id", id},
                            {"node_ids", store->host_outbounds(id)},
                            {"uses_all_when_empty", true}};
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}/outbounds",
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                auto node_ids =
                    required_string_array(request_object(request), "node_ids");
                store->set_host_outbounds(id, node_ids);
                return json{{"host_id", id}, {"node_ids", std::move(node_ids)}};
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/hosts/{id}/config",
        [store, wireguard](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                           const std::string& id) {
            handle(std::move(callback), [&] {
                auto host = require_host(*store, id);
                const ConfigRenderer renderer;
                return renderer.render(
                    managed_render_request(*store, *wireguard, host, false));
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}/wg-config",
        [store, wireguard](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback,
                           const std::string& id) {
            handle_response(std::move(callback), [&] {
                const auto host = require_host(*store, id);
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k200OK);
                response->setContentTypeCode(
                    drogon::CT_APPLICATION_OCTET_STREAM);
                auto filename = host.name;
                std::ranges::replace(filename, ' ', '_');
                response->addHeader(
                    "Content-Disposition",
                    "attachment; filename=\"" + filename + "-wg.conf\"");
                response->setBody(wireguard->host_config(host));
                return response;
            });
        },
        {drogon::Get});
    application.registerHandler("/api/hosts/{id}/token",
                                [store, public_server](const drogon::HttpRequestPtr&,
                                                       ResponseCallback&& callback,
                                                       const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        const auto host = require_host(*store, id);
                                        return json{{"host_id", host.id},
                                                    {"agent_token", host.agent_token},
                                                    {"server", public_server}};
                                    });
                                },
                                {drogon::Get});
    application.registerHandler(
        "/api/hosts/{id}/rotate-token",
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                return json{{"host_id", id},
                            {"agent_token", store->rotate_agent_token(id)}};
            });
        },
        {drogon::Post});
    const auto create_device_enrollment =
        [store, enrollment_server](const drogon::HttpRequestPtr&,
                                   ResponseCallback&& callback,
                                   const std::string& id) {
            handle(std::move(callback), [&] {
                const auto enrollment = store->create_agent_enrollment(id);
                const auto uri =
                    "sbeasy://enroll?server=" + encode_component(enrollment_server) +
                    "&code=" + encode_component(enrollment.code);
                return json{{"host_id", enrollment.host_id},
                            {"server", enrollment_server},
                            {"code", enrollment.code},
                            {"expires_at", enrollment.expires_at},
                            {"enrollment_uri", uri},
                            {"qr_svg", qr_svg_for_text(uri)}};
            });
        };
    application.registerHandler(
        "/api/devices/{id}/enrollment-codes",
        [create_device_enrollment](const drogon::HttpRequestPtr& request,
                                   ResponseCallback&& callback,
                                   const std::string& id) {
            create_device_enrollment(request, std::move(callback), id);
        },
        {drogon::Post});
    // Backward-compatible alias for older panels and Android releases.
    application.registerHandler(
        "/api/hosts/{id}/enrollment-codes",
        [create_device_enrollment](const drogon::HttpRequestPtr& request,
                                   ResponseCallback&& callback,
                                   const std::string& id) {
            create_device_enrollment(request, std::move(callback), id);
        },
        {drogon::Post});

    application.registerHandler(
        "/api/agent/health",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({{"status", "ok"}}));
        },
        {drogon::Get});
    const auto redeem_device_enrollment =
        [store, enrollment_server](const drogon::HttpRequestPtr& request,
                                   ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto body = request_object(request);
                const auto device = body.value("device", json::object());
                const auto enrollment = store->redeem_agent_enrollment(
                    required_string(body, "code"), device);
                return json{{"server", enrollment_server},
                            {"host_id", enrollment.host_id},
                            {"host_name", enrollment.host_name},
                            {"agent_token", enrollment.agent_token},
                            {"profile",
                             {{"id", enrollment.profile_id},
                              {"name", enrollment.profile_name}}}};
            });
        };
    application.registerHandler(
        "/api/devices/enroll",
        [redeem_device_enrollment](const drogon::HttpRequestPtr& request,
                                   ResponseCallback&& callback) {
            redeem_device_enrollment(request, std::move(callback));
        },
        {drogon::Post});
    // Backward-compatible alias used by already released Android apps.
    application.registerHandler(
        "/api/agent/enroll",
        [redeem_device_enrollment](const drogon::HttpRequestPtr& request,
                                   ResponseCallback&& callback) {
            redeem_device_enrollment(request, std::move(callback));
        },
        {drogon::Post});
    application.registerHandler(
        "/api/agent/config",
        [store, wireguard, config_hash_seed, legacy_agent_token](
            const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle_response(std::move(callback), [&] {
                auto host = resolve_agent_host(*store, request, legacy_agent_token);
                const auto previous_wireguard_address = host.wg_address;
                const ConfigRenderer renderer;
                const auto render_input =
                    managed_render_request(*store, *wireguard, host, true);
                if (host.wg_address != previous_wireguard_address) {
                    sync_wireguard_best_effort(wireguard);
                }
                const auto profile_id = host.profile_id.value_or("default");
                const auto profile = require_profile(*store, profile_id);
                const auto rule_source =
                    render_input.rule_script.has_value() ? "quickjs" : "profile";
                const auto body = renderer.render(render_input).dump(2);
                const auto etag = config_etag(host.id, body, config_hash_seed);
                store->touch_host(host.id);

                auto response = drogon::HttpResponse::newHttpResponse();
                response->addHeader("ETag", etag);
                response->addHeader("X-SB-Easy-Rule-Source", rule_source);
                response->addHeader("X-SB-Easy-Profile-Id", profile_id);
                response->addHeader("X-SB-Easy-Profile-Name", profile.name);
                if (request->getHeader("if-none-match") == etag) {
                    response->setStatusCode(drogon::k304NotModified);
                    return response;
                }
                response->setStatusCode(drogon::k200OK);
                response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                response->setBody(body);
                return response;
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/agent/status",
        [store, legacy_agent_token](const drogon::HttpRequestPtr& request,
                                    ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto host =
                    resolve_agent_host(*store, request, legacy_agent_token);
                const auto body = request_object(request);
                store->update_agent_status(
                    host.id,
                    {
                        {"version", optional_string_field(body, "singbox_version")},
                        {"app_version", optional_string_field(body, "app_version")},
                        {"running", optional_boolean_field(body, "singbox_running")},
                        {"etag", optional_string_field(body, "config_etag")},
                        {"last_error", optional_string_field(body, "last_error")},
                    });
                return json{{"ok", true}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/agent/commands",
        [store, legacy_agent_token](const drogon::HttpRequestPtr& request,
                                    ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto host =
                    resolve_agent_host(*store, request, legacy_agent_token);
                return json(store->list_host_commands(host.id, true));
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/agent/commands/{command_id}/ack",
        [store, legacy_agent_token](const drogon::HttpRequestPtr& request,
                                    ResponseCallback&& callback,
                                    const std::string& command_id) {
            handle(std::move(callback), [&] {
                const auto host =
                    resolve_agent_host(*store, request, legacy_agent_token);
                const auto body = request_object(request);
                const auto status =
                    body.value("status", "") == "done" ? "done" : "failed";
                static_cast<void>(store->acknowledge_host_command(
                    host.id, command_id, status, optional_result(body)));
                return json{{"ok", true}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/agent/proxy-latency",
        [store, legacy_agent_token](const drogon::HttpRequestPtr& request,
                                    ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                static_cast<void>(
                    resolve_agent_host(*store, request, legacy_agent_token));
                const auto body = request_object(request);
                const auto results = body.find("results");
                const auto updated = results == body.end()
                                         ? 0U
                                         : store->update_proxy_latencies(*results);
                return json{{"ok", true}, {"updated", updated}};
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/agent/telemetry",
        [store, telemetry, legacy_agent_token](const drogon::HttpRequestPtr& request,
                                               ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto host =
                    resolve_agent_host(*store, request, legacy_agent_token);
                telemetry->put(host.id, normalize_telemetry(request_object(request)));
                return json{{"ok", true}};
            });
        },
        {drogon::Post});
    application.registerHandlerViaRegex(
        R"(^/assets/(.*)$)",
        [static_directory](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback,
                           const std::string& relative_path) {
            if (!safe_static_relative_path(relative_path)) {
                callback(json_response({{"error", "Static resource not found"}},
                                       drogon::k404NotFound));
                return;
            }
            callback(static_file_response(
                static_directory / "assets" /
                    std::filesystem::path{relative_path},
                true));
        },
        {drogon::Get, drogon::Head});
    application.registerHandlerViaRegex(
        R"(^/api(?:/.*)?$)",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({{"error", "API route not found"}},
                                   drogon::k404NotFound));
        },
        {drogon::Get, drogon::Post, drogon::Put, drogon::Delete,
         drogon::Patch, drogon::Head});
    application.registerHandlerViaRegex(
        R"(^/(?!api(?:/|$)|assets(?:/|$)|downloads/).*$)",
        [static_directory](const drogon::HttpRequestPtr&,
                           ResponseCallback&& callback) {
            callback(static_file_response(static_directory / "index.html",
                                          false));
        },
        {drogon::Get, drogon::Head});
}

void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options) {
    auto wireguard =
        std::make_shared<WireGuardService>(store, wireguard_options(options));
    wireguard->startup();
    register_http_routes(store, options);
    std::jthread managed_singbox;
    if (options.singbox_managed) {
        managed_singbox =
            std::jthread{run_self_singbox, store, options};
    }
    try {
        drogon::app()
            .addListener(options.address, options.port)
            .setThreadNum(options.threads)
            .setLogLevel(log_level(options.log_level))
            .run();
    } catch (...) {
        if (managed_singbox.joinable()) {
            managed_singbox.request_stop();
        }
        wireguard->shutdown();
        throw;
    }
    if (managed_singbox.joinable()) {
        managed_singbox.request_stop();
    }
    wireguard->shutdown();
}

} // namespace sbeasy
