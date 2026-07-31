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
    :root{--bg:#06101d;--card:#101e30;--line:#294058;--text:#eff8ff;--muted:#91a7bc;--brand:#65e3c4;--bad:#ff8191;--shadow:0 30px 90px #0009}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 18% 8%,#17435d 0,transparent 33%),radial-gradient(circle at 88% 92%,#153e38 0,transparent 29%),var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
    .shell{width:min(430px,100%)}.brand{display:flex;align-items:center;gap:13px;margin:0 0 20px 3px}.mark{width:44px;height:44px;border:1px solid #6eecd0;border-radius:14px;background:linear-gradient(145deg,#69e4c6,#2ba78e);box-shadow:0 10px 35px #42d4b64d;display:grid;place-items:center;color:#052a22;font-size:22px;font-weight:900}.brand b{font-size:18px;letter-spacing:-.3px}.brand span{display:block;color:var(--muted);font-size:12px}
    .card{background:linear-gradient(145deg,#14263a,var(--card));border:1px solid var(--line);border-radius:22px;padding:30px;box-shadow:var(--shadow)}h1{font-size:27px;letter-spacing:-.8px;margin:0 0 7px}.intro{color:var(--muted);margin:0 0 24px}
    label{display:block;color:#bed0df;font-size:12px;font-weight:650;margin:15px 0 7px}input{width:100%;border:1px solid var(--line);border-radius:11px;background:#071421;color:var(--text);padding:12px 13px;font:15px/1.4 inherit;outline:none;transition:.15s}input:focus{border-color:var(--brand);box-shadow:0 0 0 3px #65e3c41a}
    button{width:100%;border:0;border-radius:11px;background:var(--brand);color:#05251e;padding:12px 16px;margin-top:22px;font:inherit;font-weight:800;cursor:pointer;box-shadow:0 12px 30px #31b99c35;transition:.15s}button:hover{transform:translateY(-1px);filter:brightness(1.04)}button:disabled{opacity:.55;cursor:wait;transform:none}
    #error{min-height:21px;color:var(--bad);margin-top:13px}.foot{color:var(--muted);font-size:12px;text-align:center;margin:18px 0 0}.lock{display:inline-block;margin-right:5px}
    @media(max-width:480px){body{padding:16px}.card{padding:24px 20px;border-radius:18px}}
  </style>
</head>
<body>
  <main class="shell">
    <div class="brand"><div class="mark">S</div><div><b>sb-easy Agent</b><span>Local control plane</span></div></div>
    <section class="card">
      <h1>欢迎回来</h1>
      <p class="intro">登录后管理本机 sing-box 配置与运行状态。</p>
      <form id="login">
        <label for="username">用户名</label>
        <input id="username" name="username" autocomplete="username" autofocus required>
        <label for="password">密码</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button id="submit" type="submit">登录本地 Agent</button>
        <div id="error" role="alert"></div>
      </form>
    </section>
    <p class="foot"><span class="lock">◆</span>凭据仅发送到当前 Agent，不会传给中心服务</p>
  </main>
  <script>
  const form=document.getElementById('login'),button=document.getElementById('submit'),error=document.getElementById('error');
  form.addEventListener('submit',async event=>{event.preventDefault();error.textContent='';button.disabled=true;try{const response=await fetch('/api/login',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','Accept':'application/json','X-SB-Easy-UI':'1'},body:JSON.stringify({username:form.username.value,password:form.password.value})});const body=await response.json().catch(()=>({}));if(!response.ok)throw new Error(body.error||'登录失败');window.location.replace('/')}catch(reason){error.textContent=reason.message||'登录失败，请重试';button.disabled=false;form.password.select()}});
  </script>
</body>
</html>)HTML";

constexpr std::string_view interface_html = R"HTML(<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>sb-easy Agent</title>
  <style>
    :root{--bg:#07111f;--panel:#101d2e;--panel2:#15253a;--line:#263b54;--text:#eef6ff;--muted:#92a7bd;--brand:#65e3c4;--warn:#ffcc73;--bad:#ff7789;--shadow:0 20px 60px #0006}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 18% 0,#13334b 0,transparent 34%),var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
    main{width:min(1160px,calc(100% - 32px));margin:34px auto 70px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:22px}.top-actions{display:flex;align-items:center;gap:10px}
    h1{font-size:28px;letter-spacing:-.8px;margin:0}.sub,.hint{color:var(--muted)}.badge{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid var(--line);border-radius:999px;background:#0a1727}
    .dot{width:9px;height:9px;border-radius:50%;background:var(--muted)}.dot.ok{background:var(--brand);box-shadow:0 0 16px var(--brand)}.dot.bad{background:var(--bad)}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}.card{grid-column:span 12;background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:var(--shadow)}
    .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{background:#081525aa;border:1px solid var(--line);padding:14px;border-radius:13px}.stat span{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}.stat b{font-size:15px;word-break:break-all}
    h2{font-size:17px;margin:0 0 14px}.actions{display:flex;flex-wrap:wrap;gap:10px}button{border:1px solid #3a536d;background:#1b3148;color:var(--text);border-radius:10px;padding:9px 14px;font:inherit;font-weight:650;cursor:pointer}
    button:hover{border-color:var(--brand);transform:translateY(-1px)}button.primary{background:var(--brand);border-color:var(--brand);color:#05241d}button.danger{border-color:#704253;color:#ffc0ca}button.ghost{background:#0a1727;color:var(--muted)}button:disabled{opacity:.5;cursor:wait;transform:none}
    label{display:block;color:var(--muted);font-size:12px;margin:13px 0 6px}input[type=text],textarea{width:100%;border:1px solid var(--line);border-radius:10px;background:#071321;color:var(--text);padding:10px 12px;font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;outline:none}
    input[type=text]:focus,textarea:focus{border-color:var(--brand)}textarea{min-height:130px;resize:vertical}.row{display:flex;align-items:center;gap:9px}.row label{margin:0;font-size:14px;color:var(--text)}
    .wide{grid-column:span 8}.side{grid-column:span 4}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line)}.table th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
    .scroll{max-height:355px;overflow:auto}pre{margin:0;background:#06111e;border:1px solid var(--line);border-radius:12px;padding:15px;max-height:430px;overflow:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;color:#bfd7ef}
    #toast{position:fixed;right:20px;bottom:20px;max-width:min(420px,calc(100% - 40px));padding:12px 15px;border-radius:11px;background:#153528;border:1px solid #397b64;box-shadow:var(--shadow);opacity:0;transform:translateY(15px);pointer-events:none;transition:.2s}
    #toast.show{opacity:1;transform:none}#toast.error{background:#3b1c27;border-color:#8e455a}.muted{color:var(--muted)}code{color:#b6f5e4}
    @media(max-width:840px){.wide,.side{grid-column:span 12}.stats{grid-template-columns:repeat(2,1fr)}.top{align-items:flex-start;flex-direction:column}}@media(max-width:520px){main{width:min(100% - 20px,1160px);margin-top:20px}.stats{grid-template-columns:1fr}.card{padding:16px}.top-actions{width:100%;justify-content:space-between}}
  </style>
</head>
<body>
<main>
  <div class="top">
    <div><h1>sb-easy Agent</h1><div class="sub">节点本地配置与运行控制</div></div>
    <div class="top-actions"><div class="badge"><i id="health-dot" class="dot"></i><span id="health-text">正在连接…</span></div><button id="logout" class="ghost">退出登录</button></div>
  </div>
  <div class="grid">
    <section class="card">
      <div class="stats">
        <div class="stat"><span>sing-box</span><b id="running">—</b></div>
        <div class="stat"><span>控制服务</span><b id="server">—</b></div>
        <div class="stat"><span>配置 ETag</span><b id="etag">—</b></div>
        <div class="stat"><span>最近同步</span><b id="last-cycle">—</b></div>
      </div>
      <div id="last-error" class="hint" style="margin-top:12px"></div>
    </section>
    <section class="card wide">
      <h2>节点本地设置</h2>
      <div class="row"><input id="local-egress" type="checkbox"><label for="local-egress">代理节点使用本机出口（移除管理隧道 detour）</label></div>
      <label for="default-outbound">默认代理出站 tag（留空则沿用服务端配置）</label>
      <input id="default-outbound" type="text" placeholder="例如：日本Z04">
      <label for="server-overrides">服务器地址覆盖（tag → server JSON 对象）</label>
      <textarea id="server-overrides" spellcheck="false">{}</textarea>
      <label for="outbound-overrides">完整出站覆盖（tag → outbound JSON 对象）</label>
      <textarea id="outbound-overrides" spellcheck="false">{}</textarea>
      <div class="actions" style="margin-top:14px">
        <button id="save" class="primary">保存并应用</button>
        <button id="reset-form">恢复已保存内容</button>
      </div>
      <p class="hint">保存后 Agent 会重新拉取服务端配置，通过 sing-box 校验后安全替换。Agent token 不会通过此界面读取或修改。</p>
    </section>
    <aside class="card side">
      <h2>运行操作</h2>
      <div class="actions">
        <button data-action="refresh">立即拉取配置</button>
        <button data-action="reload">Reload</button>
        <button data-action="restart" class="danger">Restart</button>
      </div>
      <p class="hint">操作会进入 Agent 主循环串行执行。</p>
      <h2 style="margin-top:24px">当前代理</h2>
      <div class="scroll"><table class="table"><thead><tr><th>tag</th><th>类型</th><th>默认</th></tr></thead><tbody id="proxies"></tbody></table></div>
    </aside>
    <section class="card">
      <details><summary style="cursor:pointer;font-weight:650">查看当前生效配置</summary><div style="height:12px"></div><pre id="config">加载中…</pre></details>
    </section>
  </div>
</main>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
let savedSettings=null,timer=null;
function toast(message,error=false){const el=$('toast');el.textContent=message;el.className=(error?'error ':'')+'show';clearTimeout(timer);timer=setTimeout(()=>el.className='',3500)}
async function api(path,options={}){const response=await fetch(path,{cache:'no-store',...options,headers:{'Accept':'application/json','X-SB-Easy-UI':'1',...(options.body?{'Content-Type':'application/json'}:{}),...(options.headers||{})}});if(response.status===401){window.location.replace('/login');throw new Error('登录已失效')}let body=null;try{body=await response.json()}catch{body={error:await response.text()}}if(!response.ok)throw new Error(body.error||`HTTP ${response.status}`);return body}
function pretty(value){return JSON.stringify(value??{},null,2)}
function formFrom(settings){savedSettings=settings;$('local-egress').checked=!!settings.local_proxy_egress;$('default-outbound').value=settings.default_proxy_outbound||'';$('server-overrides').value=pretty(settings.outbound_server_overrides);$('outbound-overrides').value=pretty(settings.outbound_overrides)}
function formValue(){let servers,outbounds;try{servers=JSON.parse($('server-overrides').value||'{}')}catch(e){throw new Error('服务器地址覆盖不是有效 JSON：'+e.message)}try{outbounds=JSON.parse($('outbound-overrides').value||'{}')}catch(e){throw new Error('完整出站覆盖不是有效 JSON：'+e.message)}return{local_proxy_egress:$('local-egress').checked,default_proxy_outbound:$('default-outbound').value.trim()||null,outbound_server_overrides:servers,outbound_overrides:outbounds}}
function text(id,value){$(id).textContent=value??'—'}
async function loadStatus(){try{const s=await api('/api/status');const ok=s.running===true;text('running',s.running==null?'未知':ok?'运行中':'已停止');text('server',s.server);text('etag',s.etag||'尚未获取');text('last-cycle',s.last_cycle||'等待首次同步');$('last-error').textContent=s.last_error?'最近错误：'+s.last_error:'';$('health-dot').className='dot '+(ok?'ok':'bad');text('health-text',ok?'Agent 正常':'需要检查')}catch(e){$('health-dot').className='dot bad';text('health-text','连接失败')}}
async function loadAll(){try{const [settings,proxies,config]=await Promise.all([api('/api/settings'),api('/api/proxies'),api('/api/config')]);formFrom(settings);$('proxies').innerHTML=proxies.map(p=>`<tr><td>${escapeHtml(p.tag)}</td><td>${escapeHtml(p.type)}</td><td>${p.default?'✓':''}</td></tr>`).join('')||'<tr><td colspan="3" class="muted">尚无配置</td></tr>';$('config').textContent=pretty(config)}catch(e){toast(e.message,true)}}
function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
$('save').onclick=async()=>{try{$('save').disabled=true;const settings=await api('/api/settings',{method:'PUT',body:JSON.stringify(formValue())});formFrom(settings);toast('设置已保存，配置刷新已排队')}catch(e){toast(e.message,true)}finally{$('save').disabled=false}};
$('reset-form').onclick=()=>savedSettings&&formFrom(savedSettings);
document.querySelectorAll('[data-action]').forEach(button=>button.onclick=async()=>{try{button.disabled=true;await api('/api/actions/'+button.dataset.action,{method:'POST'});toast('操作已排队：'+button.dataset.action);setTimeout(loadStatus,1200)}catch(e){toast(e.message,true)}finally{button.disabled=false}});
$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'})}finally{window.location.replace('/login')}};
loadStatus();loadAll();setInterval(loadStatus,5000);
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
            response->setBody(std::string{interface_html});
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
