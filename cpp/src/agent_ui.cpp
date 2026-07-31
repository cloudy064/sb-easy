#include "sbeasy/agent_ui.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
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

#include "agent_ui_page.hpp"
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
        const bool username_matches = constant_time_equal(username, username_);
        const bool password_matches = constant_time_equal(password, password_);
        if (!username_matches || !password_matches) {
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

constexpr std::string_view login_html = R"HTML(<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>登录 · sb-easy Agent</title>
  <style>
    :root{--bg:#171820;--panel:#242631;--surface:#20222c;--line:#393d4a;--text:#f5f6fa;--muted:#9b9fab;--blue:#4d8ff7;--bad:#ff909b;--green:#66d17a;--shadow:0 32px 90px #08091099}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(circle at 7% 5%,#294065 0,transparent 30%),radial-gradient(circle at 93% 94%,#332c50 0,transparent 27%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
    .shell{width:min(920px,100%);min-height:560px;display:grid;grid-template-columns:1.05fr .95fr;overflow:hidden;border:1px solid #353844;border-radius:19px;background:var(--surface);box-shadow:var(--shadow)}
    .intro-panel{position:relative;display:flex;flex-direction:column;padding:39px;background:linear-gradient(145deg,#292d39,#20222c);border-right:1px solid var(--line);overflow:hidden}.intro-panel:after{content:"";position:absolute;width:390px;height:390px;left:-170px;bottom:-230px;border-radius:50%;border:70px solid #4d8ff712;box-shadow:0 0 0 55px #4d8ff709}.brand{display:flex;align-items:center;gap:12px;position:relative;z-index:1}.mark{width:42px;height:42px;border-radius:13px;background:linear-gradient(145deg,#5b9cff,#3d75d7);box-shadow:0 10px 28px #3978df52;display:grid;place-items:center}.mark svg{width:24px;height:24px}.brand b{font-size:18px;letter-spacing:-.3px}.brand span{display:block;color:var(--muted);font-size:11px}
    .pitch{margin:auto 0;position:relative;z-index:1}.pitch h2{max-width:360px;font-size:32px;line-height:1.2;letter-spacing:-1px;margin:0 0 13px}.pitch>p{max-width:360px;color:var(--muted);margin:0}.features{display:grid;gap:10px;margin-top:28px}.feature{display:flex;align-items:center;gap:10px;color:#cfd2da;font-size:12px}.feature i{width:22px;height:22px;border-radius:7px;background:#2c456b;color:#81b0fa;display:grid;place-items:center;font-style:normal;font-weight:900}.local-note{position:relative;z-index:1;display:flex;align-items:center;gap:8px;color:var(--muted);font-size:11px}.local-note i{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 11px #66d17a88}
    .login-panel{display:flex;align-items:center;padding:48px}.card{width:100%}h1{font-size:27px;letter-spacing:-.8px;margin:0 0 7px}.intro{color:var(--muted);margin:0 0 26px}label{display:block;color:#c9ccd4;font-size:12px;font-weight:650;margin:15px 0 7px}input{width:100%;border:1px solid var(--line);border-radius:10px;background:#181a22;color:var(--text);padding:12px 13px;font:15px/1.4 inherit;outline:none;transition:.15s}input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #4d8ff71b}button{width:100%;border:1px solid var(--blue);border-radius:10px;background:var(--blue);color:#fff;padding:12px 16px;margin-top:22px;font:inherit;font-weight:750;cursor:pointer;box-shadow:0 12px 30px #3978df38;transition:.15s}button:hover{transform:translateY(-1px);filter:brightness(1.05)}button:disabled{opacity:.55;cursor:wait;transform:none}#error{min-height:21px;color:var(--bad);margin-top:12px}.foot{color:var(--muted);font-size:11px;margin:20px 0 0;padding-top:16px;border-top:1px solid var(--line)}
    @media(max-width:760px){body{padding:16px}.shell{max-width:440px;min-height:0;display:block}.intro-panel{padding:24px;border-right:0;border-bottom:1px solid var(--line)}.pitch{margin-top:35px}.pitch h2{font-size:25px}.features,.local-note{display:none}.login-panel{padding:30px 24px}}
  </style>
</head>
<body>
  <main class="shell">
    <section class="intro-panel">
      <div class="brand"><div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 15c2.5-5 5-7.5 8-7.5S17.5 10 20 15"/><path d="M6 15.5c1.8 2.2 3.8 3.2 6 3.2s4.2-1 6-3.2"/><path d="M8 8 6.7 4.8 10 7M16 8l1.3-3.2L14 7"/></svg></div><div><b>sb-easy</b><span>Agent Console</span></div></div>
      <div class="pitch"><h2>在本机管理你的代理服务</h2><p>查看 sing-box 状态、实时流量和运行配置，并安全地应用节点覆盖。</p><div class="features"><div class="feature"><i>✓</i>真实 Clash API 流量数据</div><div class="feature"><i>✓</i>中心配置同步与运行控制</div><div class="feature"><i>✓</i>本机设置原子持久化</div></div></div>
      <div class="local-note"><i></i>当前页面由本机 Agent 提供</div>
    </section>
    <section class="login-panel"><div class="card"><h1>欢迎回来</h1><p class="intro">请输入本地控制台凭据。</p><form id="login"><label for="username">用户名</label><input id="username" name="username" autocomplete="username" autofocus required><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required><button id="submit" type="submit">登录本地 Agent</button><div id="error" role="alert"></div></form><p class="foot">凭据仅发送到当前 Agent，不会传给中心服务。</p></div></section>
  </main>
  <script>
  const form=document.getElementById('login'),button=document.getElementById('submit'),error=document.getElementById('error');
  form.addEventListener('submit',async event=>{event.preventDefault();error.textContent='';button.disabled=true;try{const response=await fetch('/api/login',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','Accept':'application/json','X-SB-Easy-UI':'1'},body:JSON.stringify({username:form.username.value,password:form.password.value})});const body=await response.json().catch(()=>({}));if(!response.ok)throw new Error(body.error||'登录失败');window.location.replace('/')}catch(reason){error.textContent=reason.message||'登录失败，请重试';button.disabled=false;form.password.select()}});
  </script>
</body>
</html>)HTML";

[[nodiscard]] drogon::HttpResponsePtr
secure_response(drogon::HttpResponsePtr response) {
    response->addHeader("Cache-Control", "no-store");
    response->addHeader("X-Content-Type-Options", "nosniff");
    response->addHeader("X-Frame-Options", "DENY");
    response->addHeader("Referrer-Policy", "no-referrer");
    response->addHeader(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
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
        !callbacks.config || !callbacks.proxies || !callbacks.request_action) {
        throw std::invalid_argument("all Agent UI callbacks are required");
    }
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
            if (path == "/health" || path == "/login" || path == "/api/login") {
                proceed();
                return;
            }
            if (authentication->authenticated(
                    request->getCookie(std::string{session_cookie_name}))) {
                if ((request->method() == drogon::Post ||
                     request->method() == drogon::Put) &&
                    request->getHeader("x-sb-easy-ui") != "1") {
                    reject(json_response({{"error", "缺少本地管理界面请求标记"}},
                                         drogon::k403Forbidden));
                    return;
                }
                proceed();
                return;
            }
            if (path.starts_with("/api/")) {
                reject(json_response({{"error", "本地管理会话已失效，请重新登录"}},
                                     drogon::k401Unauthorized));
                return;
            }
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k303SeeOther);
            response->addHeader("Location", "/login");
            reject(secure_response(std::move(response)));
        });

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
        "/login",
        [authentication](const drogon::HttpRequestPtr& request,
                         ResponseCallback&& callback) {
            if (authentication->authenticated(
                    request->getCookie(std::string{session_cookie_name}))) {
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k303SeeOther);
                response->addHeader("Location", "/");
                callback(secure_response(std::move(response)));
                return;
            }
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k200OK);
            response->setContentTypeCode(drogon::CT_TEXT_HTML);
            response->setBody(std::string{login_html});
            callback(secure_response(std::move(response)));
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
    application.registerHandler("/api/logout",
                                [authentication](const drogon::HttpRequestPtr& request,
                                                 ResponseCallback&& callback) {
                                    authentication->logout(request->getCookie(
                                        std::string{session_cookie_name}));
                                    auto response =
                                        json_response({{"authenticated", false}});
                                    response->addCookie(session_cookie({}, 0));
                                    callback(std::move(response));
                                },
                                {drogon::Post});
    application.registerHandler(
        "/",
        [](const drogon::HttpRequestPtr&, ResponseCallback&& callback) {
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k200OK);
            response->setContentTypeCode(drogon::CT_TEXT_HTML);
            response->setBody(std::string{detail::agent_interface_html});
            callback(secure_response(std::move(response)));
        },
        {drogon::Get});
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
                    auto response = json_response({{"error", "设置内容超过 512 KiB"}},
                                                  drogon::k413RequestEntityTooLarge);
                    return response;
                }
                const auto value = json::parse(request->body());
                return json_response(callbacks.update_settings(value));
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
