#include "sbeasy/http_server.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
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

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/store.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;
using ResponseCallback = std::function<void(const drogon::HttpResponsePtr&)>;

[[nodiscard]] drogon::HttpResponsePtr
json_response(json body, drogon::HttpStatusCode status = drogon::k200OK) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(status);
    response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    response->setBody(body.dump());
    return response;
}

template <typename Function>
void handle(ResponseCallback&& callback, Function&& function) {
    try {
        callback(json_response(std::forward<Function>(function)()));
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

} // namespace

void register_http_routes(const std::shared_ptr<Store>& store,
                          std::string public_server) {
    if (!store) {
        throw std::invalid_argument("HTTP store is required");
    }

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
}

void run_http_server(const std::shared_ptr<Store>& store,
                     const HttpServerOptions& options) {
    register_http_routes(store, options.public_server);
    drogon::app()
        .addListener(options.address, options.port)
        .setThreadNum(options.threads)
        .run();
}

} // namespace sbeasy
