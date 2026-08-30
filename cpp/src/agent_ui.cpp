#include "sbeasy/agent_ui.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/rand.h>

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

#include "sbeasy/version.hpp"

namespace sbeasy {
namespace {

using ResponseCallback = std::function<void(const drogon::HttpResponsePtr& response)>;
using json = nlohmann::json;

constexpr std::size_t maximum_settings_body_size = 512U * 1024U;
constexpr std::string_view session_cookie_name = "sb_easy_agent_session";
constexpr auto session_duration = std::chrono::hours{12};

[[nodiscard]] bool constant_time_equal(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }
    return left.empty() || CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

[[nodiscard]] std::string random_session_token() {
    std::array<unsigned char, 32> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw std::runtime_error("could not generate Agent UI session token");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string token;
    token.reserve(random.size() * 2U);
    for (const auto byte : random) {
        token.push_back(digits[byte >> 4U]);
        token.push_back(digits[byte & 0x0fU]);
    }
    return token;
}

class AuthenticationState final {
  public:
    AuthenticationState(std::string username, std::string password)
        : username_(std::move(username)), password_(std::move(password)) {}

    [[nodiscard]] std::optional<std::string> login(std::string_view username,
                                                   std::string_view password) {
        if (!constant_time_equal(username, username_) ||
            !constant_time_equal(password, password_)) {
            return std::nullopt;
        }
        auto token = random_session_token();
        const auto expires = std::chrono::steady_clock::now() + session_duration;
        std::lock_guard lock{mutex_};
        remove_expired_locked(std::chrono::steady_clock::now());
        sessions_.insert_or_assign(token, expires);
        return token;
    }

    [[nodiscard]] bool authenticated(std::string_view token) {
        if (token.empty()) {
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock{mutex_};
        remove_expired_locked(now);
        const auto found = sessions_.find(std::string{token});
        return found != sessions_.end() && found->second > now;
    }

    void logout(std::string_view token) {
        if (token.empty()) {
            return;
        }
        std::lock_guard lock{mutex_};
        sessions_.erase(std::string{token});
    }

  private:
    void remove_expired_locked(std::chrono::steady_clock::time_point now) {
        for (auto current = sessions_.begin(); current != sessions_.end();) {
            if (current->second <= now) {
                current = sessions_.erase(current);
            } else {
                ++current;
            }
        }
    }

    std::string username_;
    std::string password_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> sessions_;
};

[[nodiscard]] drogon::Cookie session_cookie(std::string value,
                                            int maximum_age_seconds) {
    drogon::Cookie cookie{std::string{session_cookie_name}, std::move(value)};
    cookie.setHttpOnly(true);
    cookie.setSameSite(drogon::Cookie::SameSite::kStrict);
    cookie.setPath("/");
    cookie.setMaxAge(maximum_age_seconds);
    return cookie;
}

[[nodiscard]] drogon::HttpResponsePtr
secure_response(drogon::HttpResponsePtr response,
                std::string_view cache_control = "no-store") {
    response->addHeader("Cache-Control", std::string{cache_control});
    response->addHeader("X-Content-Type-Options", "nosniff");
    response->addHeader("X-Frame-Options", "DENY");
    response->addHeader("Referrer-Policy", "no-referrer");
    response->addHeader(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
    return response;
}

[[nodiscard]] drogon::HttpResponsePtr
json_response(json body, drogon::HttpStatusCode status = drogon::k200OK) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(status);
    response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    response->setBody(body.dump());
    return secure_response(std::move(response));
}

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
static_file_response(const std::filesystem::path& ui_directory,
                     const std::string& relative_path, bool immutable) {
    if (!safe_static_relative_path(relative_path)) {
        return json_response({{"error", "Static resource not found"}},
                             drogon::k404NotFound);
    }
    const auto path = ui_directory / std::filesystem::path{relative_path};
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error) {
        return json_response({{"error", "Static resource not found"}},
                             drogon::k404NotFound);
    }
    auto response = drogon::HttpResponse::newFileResponse(path.string());
    return secure_response(std::move(response),
                           immutable ? "public, max-age=31536000, immutable"
                                     : "no-cache");
}

template <typename Function>
void handle_response(ResponseCallback&& callback, Function&& function) {
    try {
        callback(std::forward<Function>(function)());
    } catch (const json::exception& error) {
        callback(
            json_response({{"error", std::string{"无效的 JSON 请求："} + error.what()}},
                          drogon::k400BadRequest));
    } catch (const std::invalid_argument& error) {
        callback(json_response({{"error", error.what()}}, drogon::k400BadRequest));
    } catch (const std::exception& error) {
        callback(
            json_response({{"error", error.what()}}, drogon::k500InternalServerError));
    }
}

void validate_callbacks(const AgentUiCallbacks& callbacks) {
    if (!callbacks.status || !callbacks.settings || !callbacks.update_settings ||
        !callbacks.config || !callbacks.proxies || !callbacks.select_proxy ||
        !callbacks.test_route || !callbacks.request_action) {
        throw std::invalid_argument("all Agent UI callbacks are required");
    }
}

void register_api_routes(const AgentUiCallbacks& callbacks,
                         const std::shared_ptr<AuthenticationState>& authentication) {
    auto& application = drogon::app();
    application.registerHandler(
        "/health",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(json_response({
                {"service", "sb-easy-agent-ui"},
                {"version", application_version},
                {"status", "ok"},
            }));
        },
        {drogon::Get});
    application.registerHandler(
        "/api/login",
        [authentication](const drogon::HttpRequestPtr& request,
                         ResponseCallback&& callback) {
            handle_response(std::move(callback), [&authentication, &request] {
                if (request->getHeader("x-sb-easy-ui") != "1") {
                    return json_response({{"error", "缺少本地管理界面请求标记"}},
                                         drogon::k403Forbidden);
                }
                const auto value = json::parse(request->body());
                if (!value.is_object()) {
                    throw std::invalid_argument("登录请求必须是 JSON 对象");
                }
                const auto username = value.value("username", std::string{});
                const auto password = value.value("password", std::string{});
                const auto token = authentication->login(username, password);
                if (!token.has_value()) {
                    return json_response({{"error", "用户名或密码错误"}},
                                         drogon::k401Unauthorized);
                }
                auto response =
                    json_response({{"authenticated", true}, {"username", username}});
                response->addCookie(session_cookie(*token, 43'200));
                return response;
            });
        },
        {drogon::Post});
    application.registerHandler(
        "/api/logout",
        [authentication](const drogon::HttpRequestPtr& request,
                         ResponseCallback&& callback) {
            authentication->logout(
                request->getCookie(std::string{session_cookie_name}));
            auto response = json_response({{"authenticated", false}});
            response->addCookie(session_cookie({}, 0));
            callback(std::move(response));
        },
        {drogon::Post});
    application.registerHandler(
        "/api/status",
        [callbacks](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle_response(std::move(callback),
                            [&callbacks] { return json_response(callbacks.status()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/settings",
        [callbacks](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle_response(std::move(callback), [&callbacks] {
                return json_response(callbacks.settings());
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/settings",
        [callbacks](const drogon::HttpRequestPtr& request,
                    ResponseCallback&& callback) {
            handle_response(std::move(callback), [&callbacks, &request] {
                if (request->body().size() > maximum_settings_body_size) {
                    return json_response({{"error", "设置内容超过 512 KiB"}},
                                         drogon::k413RequestEntityTooLarge);
                }
                return json_response(
                    callbacks.update_settings(json::parse(request->body())));
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/config",
        [callbacks](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle_response(std::move(callback),
                            [&callbacks] { return json_response(callbacks.config()); });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/proxies",
        [callbacks](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            handle_response(std::move(callback), [&callbacks] {
                return json_response(callbacks.proxies());
            });
        },
        {drogon::Get});
    application.registerHandler(
        "/api/proxies",
        [callbacks](const drogon::HttpRequestPtr& request,
                    ResponseCallback&& callback) {
            handle_response(std::move(callback), [&callbacks, &request] {
                if (request->body().size() > 8U * 1024U) {
                    return json_response({{"error", "节点切换请求过大"}},
                                         drogon::k413RequestEntityTooLarge);
                }
                const auto value = json::parse(request->body());
                if (!value.is_object()) {
                    throw std::invalid_argument("节点切换请求必须是 JSON 对象");
                }
                const auto group = value.find("group");
                const auto name = value.find("name");
                if (group == value.end() || !group->is_string() ||
                    name == value.end() || !name->is_string() ||
                    group->get_ref<const std::string&>().empty() ||
                    name->get_ref<const std::string&>().empty()) {
                    throw std::invalid_argument("请选择有效的策略组和节点");
                }
                return json_response(callbacks.select_proxy(
                    group->get<std::string>(), name->get<std::string>()));
            });
        },
        {drogon::Put});
    application.registerHandler(
        "/api/route-test",
        [callbacks](const drogon::HttpRequestPtr& request,
                    ResponseCallback&& callback) {
            handle_response(std::move(callback), [&callbacks, &request] {
                if (request->body().size() > 8U * 1024U) {
                    return json_response({{"error", "路由测试请求过大"}},
                                         drogon::k413RequestEntityTooLarge);
                }
                const auto value = json::parse(request->body());
                const auto found = value.find("url");
                if (!value.is_object() || found == value.end() ||
                    !found->is_string()) {
                    throw std::invalid_argument("请输入要测试的 URL");
                }
                return json_response(callbacks.test_route(found->get<std::string>()));
            });
        },
        {drogon::Post});

    const auto register_action = [&application, callbacks](std::string action) {
        const auto path = "/api/actions/" + action;
        application.registerHandler(
            path,
            [callbacks, action = std::move(action)](const drogon::HttpRequestPtr&,
                                                    ResponseCallback&& callback) {
                handle_response(std::move(callback), [&callbacks, &action] {
                    callbacks.request_action(action);
                    return json_response({
                        {"accepted", true},
                        {"action", action},
                    });
                });
            },
            {drogon::Post});
    };
    register_action("refresh");
    register_action("reload");
    register_action("restart");
}

void register_routes(const AgentLocalUiOptions& options,
                     const AgentUiCallbacks& callbacks) {
    validate_callbacks(callbacks);
    const auto authentication =
        std::make_shared<AuthenticationState>(options.username, options.password);
    auto& application = drogon::app();
    application.registerPreRoutingAdvice(
        [authentication](const drogon::HttpRequestPtr& request,
                         drogon::AdviceCallback&& reject,
                         drogon::AdviceChainCallback&& proceed) {
            const auto path = request->path();
            if (path == "/health" || path == "/api/login" ||
                !path.starts_with("/api/")) {
                proceed();
                return;
            }
            if (!authentication->authenticated(
                    request->getCookie(std::string{session_cookie_name}))) {
                reject(json_response({{"error", "本地管理会话已失效，请重新登录"}},
                                     drogon::k401Unauthorized));
                return;
            }
            if ((request->method() == drogon::Post ||
                 request->method() == drogon::Put ||
                 request->method() == drogon::Delete ||
                 request->method() == drogon::Patch) &&
                request->getHeader("x-sb-easy-ui") != "1") {
                reject(json_response({{"error", "缺少本地管理界面请求标记"}},
                                     drogon::k403Forbidden));
                return;
            }
            proceed();
        });

    register_api_routes(callbacks, authentication);
    const auto ui_directory = options.ui_directory;
    if (ui_directory.empty()) {
        application.registerHandlerViaRegex(
            R"(^/(?!api(?:/|$)).*$)",
            [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
                callback(json_response(
                    {{"error",
                      "No Agent UI path is configured; use the JSON API or set "
                      "AGENT_UI_PATH"}},
                    drogon::k404NotFound));
            },
            {drogon::Get, drogon::Head});
        return;
    }
    application.registerHandlerViaRegex(
        R"(^/assets/(.*)$)",
        [ui_directory](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                       const std::string& relative_path) {
            callback(static_file_response(ui_directory,
                                          "assets/" + relative_path, true));
        },
        {drogon::Get, drogon::Head});
    application.registerHandlerViaRegex(
        R"(^/([^/]+\.[A-Za-z0-9]+)$)",
        [ui_directory](const drogon::HttpRequestPtr&, ResponseCallback&& callback,
                       const std::string& relative_path) {
            callback(static_file_response(ui_directory, relative_path, false));
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
        R"(^/(?!api(?:/|$)|assets(?:/|$)).*$)",
        [ui_directory](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            callback(static_file_response(ui_directory, "index.html", false));
        },
        {drogon::Get, drogon::Head});
}

} // namespace

class AgentLocalUi::Implementation final {
  public:
    Implementation(AgentLocalUiOptions options, AgentUiCallbacks callbacks) {
        if (options.address.empty()) {
            throw std::invalid_argument("Agent UI address must not be empty");
        }
        if (options.username.empty()) {
            throw std::invalid_argument("Agent UI username must not be empty");
        }
        if (options.username.find(':') != std::string::npos) {
            throw std::invalid_argument("Agent UI username must not contain ':'");
        }
        if (options.password.empty()) {
            throw std::invalid_argument("Agent UI password must not be empty");
        }
        std::error_code error;
        if (!options.ui_directory.empty() &&
            (!std::filesystem::is_regular_file(options.ui_directory / "index.html",
                                               error) ||
             error)) {
            throw std::invalid_argument(
                "Agent UI path must contain a readable index.html: " +
                options.ui_directory.string());
        }
        register_routes(options, callbacks);
        drogon::app()
            .disableSigtermHandling()
            .setClientMaxBodySize(maximum_settings_body_size)
            .setLogLevel(trantor::Logger::kWarn)
            .addListener(options.address, options.port)
            .setThreadNum(1);
        thread_ = std::thread([] { drogon::app().run(); });
        for (int attempt = 0; attempt < 300; ++attempt) {
            if (drogon::app().isRunning()) {
                const auto listeners = drogon::app().getListeners();
                if (!listeners.empty() && listeners.front().toPort() != 0) {
                    port_ = listeners.front().toPort();
                    return;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        drogon::app().quit();
        if (thread_.joinable()) {
            thread_.join();
        }
        throw std::runtime_error("Agent UI HTTP listener did not start");
    }

    ~Implementation() {
        if (drogon::app().isRunning()) {
            drogon::app().quit();
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    [[nodiscard]] std::uint16_t port() const noexcept {
        return port_;
    }

  private:
    std::thread thread_;
    std::uint16_t port_{};
};

AgentLocalUi::AgentLocalUi(AgentLocalUiOptions options, AgentUiCallbacks callbacks)
    : implementation_(
          std::make_unique<Implementation>(std::move(options), std::move(callbacks))) {}

AgentLocalUi::~AgentLocalUi() = default;

std::uint16_t AgentLocalUi::port() const noexcept {
    return implementation_->port();
}

} // namespace sbeasy
