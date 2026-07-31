#include "sbeasy/http_server.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
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

#include "sbeasy/config_etag.hpp"
#include "sbeasy/config_renderer.hpp"
#include "sbeasy/store.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;
using ResponseCallback = std::function<void(const drogon::HttpResponsePtr&)>;

class UnauthorizedError final : public std::runtime_error {
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
    } catch (const NotFoundError& error) {
        callback(json_response({{"error", error.what()}}, drogon::k404NotFound));
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

} // namespace

void register_http_routes(const std::shared_ptr<Store>& store,
                          const HttpServerOptions& options) {
    if (!store) {
        throw std::invalid_argument("HTTP store is required");
    }

    const auto telemetry = std::make_shared<TelemetryStore>();
    const auto public_server = options.public_server;
    const auto config_hash_seed = options.config_hash_seed;
    const auto legacy_agent_token = trim(options.legacy_agent_token);
    auto& application = drogon::app();
    application.registerHandler(
        "/api/health",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({{"status", "ok"}, {"service", "sb-easy-cpp"}}));
        },
        {drogon::Get});

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
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle(std::move(callback), [&] {
                const auto host = store->create_host(
                    host_from_create_request(request_object(request)));
                json response = host;
                response["agent_token"] = host.agent_token;
                return response;
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
        [store](const drogon::HttpRequestPtr& request, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                auto host = require_host(*store, id);
                return json(store->update_host(host_from_update_request(
                    std::move(host), request_object(request))));
            });
        },
        {drogon::Put});
    application.registerHandler("/api/hosts/{id}",
                                [store](const drogon::HttpRequestPtr&,
                                        ResponseCallback&& callback,
                                        const std::string& id) {
                                    handle(std::move(callback), [&] {
                                        store->delete_host(id);
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
        [store](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                const std::string& id) {
            handle(std::move(callback), [&] {
                const ConfigRenderer renderer;
                return renderer.render(store->render_request_for_host(id));
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

    application.registerHandler(
        "/api/agent/health",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({{"status", "ok"}}));
        },
        {drogon::Get});
    application.registerHandler(
        "/api/agent/config",
        [store, config_hash_seed, legacy_agent_token](
            const drogon::HttpRequestPtr& request, ResponseCallback&& callback) {
            handle_response(std::move(callback), [&] {
                const auto host =
                    resolve_agent_host(*store, request, legacy_agent_token);
                const ConfigRenderer renderer;
                const auto body =
                    renderer.render(store->render_request_for_host(host.id)).dump(2);
                const auto etag = config_etag(host.id, body, config_hash_seed);
                store->touch_host(host.id);

                auto response = drogon::HttpResponse::newHttpResponse();
                response->addHeader("ETag", etag);
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
                        {"running", optional_boolean_field(body, "singbox_running")},
                        {"etag", optional_string_field(body, "config_etag")},
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
}

void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options) {
    register_http_routes(store, options);
    drogon::app()
        .addListener(options.address, options.port)
        .setThreadNum(options.threads)
        .run();
}

} // namespace sbeasy
