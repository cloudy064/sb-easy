#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
#include <drogon/drogon.h>
#include <drogon/WebSocketClient.h>
#include <drogon/utils/Utilities.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include "sbeasy/http_server.hpp"
#include "sbeasy/store.hpp"

namespace {

using nlohmann::json;

class TemporaryDatabase final {
  public:
    TemporaryDatabase()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-http-" + std::to_string(std::random_device{}()) + ".db")) {}

    ~TemporaryDatabase() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        std::filesystem::remove(path_.string() + "-shm", ignored);
        std::filesystem::remove(path_.string() + "-wal", ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

class TemporaryStaticDirectory final {
  public:
    TemporaryStaticDirectory()
        : path_(std::filesystem::temp_directory_path() /
                ("sb-easy-static-" + std::to_string(std::random_device{}()))) {
        std::filesystem::create_directories(path_ / "assets");
        {
            std::ofstream index{path_ / "index.html"};
            index << "<!doctype html><title>sb-easy contract</title>";
        }
        {
            std::ofstream asset{path_ / "assets" / "contract.js"};
            asset << "window.sbEasyContract = true;\n";
        }
    }

    ~TemporaryStaticDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

class SubscriptionFixture final {
  public:
    SubscriptionFixture() {
        listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener_ < 0) {
            throw std::runtime_error("could not create subscription fixture socket");
        }
        const int reuse = 1;
        if (::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                         static_cast<socklen_t>(sizeof(reuse))) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not configure subscription fixture socket");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<const sockaddr*>(&address),
                   static_cast<socklen_t>(sizeof(address))) != 0 ||
            ::listen(listener_, 1) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not listen for subscription fixture");
        }
        socklen_t size = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size) !=
            0) {
            ::close(listener_);
            throw std::runtime_error("could not resolve subscription fixture port");
        }
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { serve_once(); });
    }

    ~SubscriptionFixture() {
        if (listener_ >= 0) {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    SubscriptionFixture(const SubscriptionFixture&) = delete;
    SubscriptionFixture& operator=(const SubscriptionFixture&) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept {
        return port_;
    }

  private:
    void serve_once() const {
        const auto client = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            return;
        }
        std::array<char, 2'048> request_buffer{};
        static_cast<void>(
            ::recv(client, request_buffer.data(), request_buffer.size(), 0));

        const std::string body =
            "trojan://fixture-secret@fixture.example.com:443#Fixture\n";
        const auto response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        std::size_t sent{};
        while (sent < response.size()) {
            const auto count = ::send(client, response.data() + sent,
                                      response.size() - sent, MSG_NOSIGNAL);
            if (count <= 0) {
                break;
            }
            sent += static_cast<std::size_t>(count);
        }
        ::close(client);
    }

    int listener_{-1};
    std::uint16_t port_{};
    std::thread thread_;
};

class ClashFixture final {
  public:
    ClashFixture() {
        listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener_ < 0) {
            throw std::runtime_error("could not create Clash fixture socket");
        }
        const int reuse = 1;
        if (::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                         static_cast<socklen_t>(sizeof(reuse))) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not configure Clash fixture socket");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<const sockaddr*>(&address),
                   static_cast<socklen_t>(sizeof(address))) != 0 ||
            ::listen(listener_, 8) != 0) {
            ::close(listener_);
            throw std::runtime_error("could not listen for Clash fixture");
        }
        socklen_t size = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size) !=
            0) {
            ::close(listener_);
            throw std::runtime_error("could not resolve Clash fixture port");
        }
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { serve(); });
    }

    ~ClashFixture() {
        if (listener_ >= 0) {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    ClashFixture(const ClashFixture&) = delete;
    ClashFixture& operator=(const ClashFixture&) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept {
        return port_;
    }

  private:
    static void send_all(int client, std::string_view data) {
        std::size_t sent{};
        while (sent < data.size()) {
            const auto count = ::send(client, data.data() + sent, data.size() - sent,
                                      MSG_NOSIGNAL);
            if (count <= 0) {
                break;
            }
            sent += static_cast<std::size_t>(count);
        }
    }

    static std::string header_value(const std::string& request,
                                    const std::string& lower,
                                    std::string_view header) {
        if (const auto start = lower.find(header); start != std::string::npos) {
            const auto value_start = start + header.size();
            const auto end = lower.find("\r\n", value_start);
            auto value = request.substr(value_start, end - value_start);
            while (!value.empty() &&
                   std::isspace(static_cast<unsigned char>(value.front())) != 0) {
                value.erase(value.begin());
            }
            while (!value.empty() &&
                   std::isspace(static_cast<unsigned char>(value.back())) != 0) {
                value.pop_back();
            }
            return value;
        }
        return {};
    }

    static std::string websocket_accept(std::string key) {
        key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digest_size{};
        if (EVP_Digest(key.data(), key.size(), digest.data(), &digest_size,
                       EVP_sha1(), nullptr) != 1) {
            throw std::runtime_error("could not calculate WebSocket accept key");
        }
        return drogon::utils::base64Encode(digest.data(), digest_size);
    }

    static std::string websocket_frame(std::string_view payload) {
        std::string frame;
        frame.push_back(static_cast<char>(0x81));
        if (payload.size() <= 125U) {
            frame.push_back(static_cast<char>(payload.size()));
        } else {
            frame.push_back(static_cast<char>(126));
            frame.push_back(
                static_cast<char>((static_cast<unsigned int>(payload.size()) >> 8U) &
                                  0xffU));
            frame.push_back(
                static_cast<char>(static_cast<unsigned int>(payload.size()) & 0xffU));
        }
        frame.append(payload);
        return frame;
    }

    static void send_response(int client, const std::string& request) {
        std::istringstream first_line{request.substr(0, request.find("\r\n"))};
        std::string method;
        std::string target;
        first_line >> method >> target;

        auto lower = request;
        std::ranges::transform(lower, lower.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        if (lower.find("upgrade: websocket") != std::string::npos) {
            const auto key =
                header_value(request, lower, "sec-websocket-key:");
            const auto response =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: " +
                websocket_accept(key) + "\r\n\r\n";
            send_all(client, response);
            send_all(client, websocket_frame(
                                 json{{"stream", "fixture"}, {"target", target}}.dump()));
            std::this_thread::sleep_for(std::chrono::milliseconds{200});
            return;
        }
        const auto authorization =
            header_value(request, lower, "authorization:");

        json response_body{
            {"method", method},
            {"target", target},
            {"authorization", authorization},
        };
        if (target.ends_with("/proxies")) {
            response_body["proxies"] = {
                {"Fixture Node", {{"type", "Shadowsocks"}}},
                {"Fixture Group",
                 {{"type", "Selector"}, {"all", json::array({"Fixture Node"})}}},
            };
        }
        if (target.find("/delay?") != std::string::npos) {
            response_body["delay"] = 42;
        }
        if (target.ends_with("/connections")) {
            response_body["uploadTotal"] = 1'024;
            response_body["downloadTotal"] = 2'048;
            response_body["connections"] =
                json::array({json{{"id", "fixture-connection"}}});
        }
        const auto body = response_body.dump();
        const auto response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              "Content-Length: " +
                              std::to_string(body.size()) +
                              "\r\nConnection: close\r\n\r\n" + body;
        send_all(client, response);
    }

    void serve() const {
        while (true) {
            const auto client = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) {
                return;
            }
            std::string request;
            std::array<char, 4'096> buffer{};
            while (request.find("\r\n\r\n") == std::string::npos) {
                const auto count = ::recv(client, buffer.data(), buffer.size(), 0);
                if (count <= 0) {
                    break;
                }
                request.append(buffer.data(), static_cast<std::size_t>(count));
            }
            send_response(client, request);
            ::close(client);
        }
    }

    int listener_{-1};
    std::uint16_t port_{};
    std::thread thread_;
};

class RunningServer final {
  public:
    RunningServer() : thread_([] { drogon::app().run(); }) {}

    ~RunningServer() {
        if (drogon::app().isRunning()) {
            drogon::app().quit();
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    RunningServer(const RunningServer&) = delete;
    RunningServer& operator=(const RunningServer&) = delete;

    [[nodiscard]] std::uint16_t wait_for_port() const {
        for (int attempt = 0; attempt < 200; ++attempt) {
            if (drogon::app().isRunning()) {
                const auto listeners = drogon::app().getListeners();
                if (!listeners.empty() && listeners.front().toPort() != 0) {
                    return listeners.front().toPort();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        throw std::runtime_error("HTTP server did not start");
    }

  private:
    std::thread thread_;
};

struct ApiResponse {
    drogon::HttpStatusCode status;
    json body;
    std::string raw_body;
    std::string etag;
    std::string access_control_allow_origin;
};

struct RawResponse {
    drogon::HttpStatusCode status;
    std::string body;
    std::string content_type;
    std::string content_disposition;
    std::string access_control_allow_origin;
};

struct WebSocketResult {
    drogon::ReqResult result;
    drogon::HttpStatusCode status;
    std::string message;
    drogon::WebSocketMessageType type;
};

std::string default_bearer_token;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] ApiResponse
request(const drogon::HttpClientPtr& client, drogon::HttpMethod method,
        std::string path, std::optional<json> body = std::nullopt,
        const std::vector<std::pair<std::string, std::string>>& headers = {}) {
    const auto request_path = path;
    auto http_request = drogon::HttpRequest::newHttpRequest();
    http_request->setMethod(method);
    http_request->setPath(std::move(path));
    http_request->setPathEncode(false);
    if (body.has_value()) {
        http_request->setContentTypeString("application/json");
        http_request->setBody(body->dump());
    }
    const auto has_authorization = std::ranges::any_of(headers, [](const auto& header) {
        auto name = header.first;
        std::ranges::transform(name, name.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return name == "authorization";
    });
    if (!default_bearer_token.empty() && !has_authorization) {
        http_request->addHeader("Authorization", "Bearer " + default_bearer_token);
    }
    for (const auto& [name, value] : headers) {
        http_request->addHeader(name, value);
    }

    auto [result, response] = client->sendRequest(http_request, 2.0);
    if (result != drogon::ReqResult::Ok || !response) {
        throw std::runtime_error("HTTP request failed: " +
                                 std::string{drogon::to_string_view(result)});
    }

    const std::string raw_body{response->body()};
    auto parsed =
        raw_body.empty() ? json{nullptr} : json::parse(raw_body, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("HTTP response is not JSON for " + request_path +
                                 ": " + raw_body);
    }
    return {
        .status = response->statusCode(),
        .body = std::move(parsed),
        .raw_body = raw_body,
        .etag = response->getHeader("etag"),
        .access_control_allow_origin =
            response->getHeader("access-control-allow-origin"),
    };
}

[[nodiscard]] RawResponse
raw_request(
    const drogon::HttpClientPtr& client, std::string path,
    const std::vector<std::pair<std::string, std::string>>& headers = {}) {
    auto http_request = drogon::HttpRequest::newHttpRequest();
    http_request->setMethod(drogon::Get);
    http_request->setPath(std::move(path));
    if (!default_bearer_token.empty()) {
        http_request->addHeader("Authorization",
                                "Bearer " + default_bearer_token);
    }
    for (const auto& [name, value] : headers) {
        http_request->addHeader(name, value);
    }
    auto [result, response] = client->sendRequest(http_request, 2.0);
    if (result != drogon::ReqResult::Ok || !response) {
        throw std::runtime_error("raw HTTP request failed");
    }
    return {
        .status = response->statusCode(),
        .body = std::string{response->body()},
        .content_type = response->getHeader("content-type"),
        .content_disposition = response->getHeader("content-disposition"),
        .access_control_allow_origin =
            response->getHeader("access-control-allow-origin"),
    };
}

[[nodiscard]] WebSocketResult
websocket_request(std::uint16_t port, std::string kind, std::string token,
                  std::string host = {}, std::string level = {}) {
    auto result = std::make_shared<std::promise<WebSocketResult>>();
    auto completed = std::make_shared<std::atomic_bool>(false);
    auto complete = [result, completed](WebSocketResult value) {
        bool expected = false;
        if (completed->compare_exchange_strong(expected, true)) {
            result->set_value(std::move(value));
        }
    };

    auto client = drogon::WebSocketClient::newWebSocketClient(
        "ws://127.0.0.1:" + std::to_string(port));
    client->setMessageHandler(
        [complete](std::string&& message,
                   const drogon::WebSocketClientPtr& websocket,
                   const drogon::WebSocketMessageType& type) {
            complete({
                .result = drogon::ReqResult::Ok,
                .status = drogon::k101SwitchingProtocols,
                .message = std::move(message),
                .type = type,
            });
            websocket->stop();
        });
    client->setConnectionClosedHandler(
        [complete](const drogon::WebSocketClientPtr&) {
            complete({
                .result = drogon::ReqResult::NetworkFailure,
                .status = drogon::k500InternalServerError,
                .message = "connection closed before a message",
                .type = drogon::WebSocketMessageType::Close,
            });
        });

    auto request = drogon::HttpRequest::newHttpRequest();
    request->setPath("/api/sing-box/ws/" + std::move(kind));
    request->setParameter("token", std::move(token));
    if (!host.empty()) {
        request->setParameter("host", std::move(host));
    }
    if (!level.empty()) {
        request->setParameter("level", std::move(level));
    }
    client->connectToServer(
        request,
        [complete](drogon::ReqResult request_result,
                   const drogon::HttpResponsePtr& response,
                   const drogon::WebSocketClientPtr& websocket) {
            if (request_result != drogon::ReqResult::Ok) {
                complete({
                    .result = request_result,
                    .status = response ? response->statusCode() :
                                         drogon::k500InternalServerError,
                    .message = response ? std::string{response->body()} :
                                          std::string{},
                    .type = drogon::WebSocketMessageType::Unknown,
                });
                websocket->stop();
            }
        });

    auto future = result->get_future();
    if (future.wait_for(std::chrono::seconds{3}) != std::future_status::ready) {
        client->stop();
        throw std::runtime_error("WebSocket request timed out");
    }
    return future.get();
}

void run_contract() {
    const TemporaryDatabase database;
    const TemporaryStaticDirectory static_directory;
    const SubscriptionFixture subscription_fixture;
    const ClashFixture clash_fixture;
    auto store = std::make_shared<sbeasy::Store>(
        database.path(), std::filesystem::path{SB_EASY_MIGRATIONS_DIR});
    sbeasy::Host clash_host;
    clash_host.name = "Remote Clash target";
    clash_host.capabilities = nlohmann::json::object();
    clash_host.clash_api =
        "http://127.0.0.1:" + std::to_string(clash_fixture.port()) + "/remote";
    clash_host.clash_secret = "remote-secret";
    const auto remote_clash_host = store->create_host(std::move(clash_host));

    sbeasy::HttpServerOptions options;
    options.public_server = "https://panel.example.com";
    options.config_hash_seed = "contract-seed";
    options.legacy_agent_token = "legacy-self-token";
    options.jwt_secret = "contract-jwt-secret";
    options.admin_password = "contract-admin-password";
    options.clash_api_url =
        "http://127.0.0.1:" + std::to_string(clash_fixture.port()) + "/local";
    options.clash_api_secret = "local-secret";
    options.external_hostname = "vpn.example.com";
    options.static_directory = static_directory.path().string();
    options.cors_origins = "https://allowed.example";
    sbeasy::register_http_routes(store, options);
    drogon::app()
        .setLogLevel(trantor::Logger::kWarn)
        .addListener("127.0.0.1", 0)
        .setThreadNum(1);
    const RunningServer server;
    const auto port = server.wait_for_port();
    const auto client =
        drogon::HttpClient::newHttpClient("http://127.0.0.1:" + std::to_string(port));

    const auto health = request(client, drogon::Get, "/api/health");
    require(health.status == drogon::k200OK &&
                health.body.at("service") == "sb-easy-cpp",
            "health endpoint should identify the C++ service");
    const auto allowed_cors = request(
        client, drogon::Get, "/api/health", std::nullopt,
        {{"Origin", "https://allowed.example"}});
    require(allowed_cors.access_control_allow_origin ==
                "https://allowed.example",
            "configured CORS origins must be reflected on API responses");
    const auto rejected_cors = request(
        client, drogon::Get, "/api/health", std::nullopt,
        {{"Origin", "https://rejected.example"}});
    require(rejected_cors.access_control_allow_origin.empty(),
            "unconfigured CORS origins must not receive an allow header");
    const auto preflight = request(
        client, drogon::Options, "/api/hosts", std::nullopt,
        {{"Origin", "https://allowed.example"},
         {"Access-Control-Request-Method", "GET"},
         {"Access-Control-Request-Headers", "authorization,content-type"}});
    require(preflight.status == drogon::k204NoContent &&
                preflight.access_control_allow_origin ==
                    "https://allowed.example",
            "CORS preflight must complete before JWT authentication");
    const auto root_page = raw_request(client, "/");
    require(root_page.status == drogon::k200OK &&
                root_page.body.find("sb-easy contract") != std::string::npos &&
                root_page.content_type.starts_with("text/html"),
            "the frontend entry point must be served at the root");
    const auto spa_page = raw_request(client, "/devices/example");
    require(spa_page.status == drogon::k200OK &&
                spa_page.body == root_page.body,
            "client-side routes must fall back to the frontend entry point");
    const auto frontend_asset =
        raw_request(client, "/assets/contract.js");
    require(frontend_asset.status == drogon::k200OK &&
                frontend_asset.body.find("sbEasyContract") != std::string::npos,
            "fingerprinted frontend assets must be served from the build directory");
    require(raw_request(client, "/assets/missing.js").status ==
                drogon::k404NotFound,
            "missing frontend assets must not fall back to index.html");
    const auto public_status = request(client, drogon::Get, "/api/system/status");
    require(public_status.status == drogon::k200OK &&
                public_status.body.at("status") == "running",
            "system status must remain public for health dashboards");
    require(request(client, drogon::Get, "/api/hosts").status ==
                drogon::k401Unauthorized,
            "administrative APIs must reject requests without a JWT");
    const auto login =
        request(client, drogon::Post, "/api/auth/login",
                json{{"username", "admin"}, {"password", "contract-admin-password"}});
    require(login.status == drogon::k200OK && login.body.at("role") == "admin" &&
                login.body.at("token").is_string(),
            "the seeded administrator must be able to log in");
    default_bearer_token = login.body.at("token").get<std::string>();
    const auto missing_api =
        request(client, drogon::Get, "/api/not-a-real-route");
    require(missing_api.status == drogon::k404NotFound &&
                missing_api.body.at("error") == "API route not found",
            "unknown API paths must remain structured JSON errors");
    require(
        request(client, drogon::Get,
                "/api/sing-box/ws/traffic?token=invalid-token")
                .status == drogon::k401Unauthorized,
        "Clash WebSocket routes must return 401 for invalid query JWTs");
    const auto rejected_websocket =
        websocket_request(port, "traffic", "invalid-token");
    require(rejected_websocket.result == drogon::ReqResult::BadResponse,
            "Clash WebSocket handshakes must reject invalid JWTs before upgrade");
    const auto local_websocket =
        websocket_request(port, "logs", default_bearer_token, {}, "debug");
    if (local_websocket.message.empty()) {
        throw std::runtime_error(
            "local Clash WebSocket returned no payload: " +
            std::string{drogon::to_string_view(local_websocket.result)} + " / " +
            std::to_string(static_cast<int>(local_websocket.type)));
    }
    const auto local_stream = json::parse(local_websocket.message);
    require(local_websocket.result == drogon::ReqResult::Ok &&
                local_websocket.type == drogon::WebSocketMessageType::Text &&
                local_stream.at("target") ==
                    "/local/logs?level=debug&token=local-secret",
            "local Clash WebSockets must bridge JWT-authenticated log streams");
    const auto remote_websocket =
        websocket_request(port, "traffic", default_bearer_token,
                          remote_clash_host.id);
    if (remote_websocket.message.empty()) {
        throw std::runtime_error(
            "remote Clash WebSocket returned no payload: " +
            std::string{drogon::to_string_view(remote_websocket.result)} + " / " +
            std::to_string(static_cast<int>(remote_websocket.type)));
    }
    const auto remote_stream = json::parse(remote_websocket.message);
    require(remote_websocket.result == drogon::ReqResult::Ok &&
                remote_stream.at("target") ==
                    "/remote/traffic?token=remote-secret",
            "remote Clash WebSockets must select the host target and secret");
    const auto session = request(client, drogon::Get, "/api/auth/session");
    require(session.status == drogon::k200OK &&
                session.body.at("authenticated") == true &&
                session.body.at("username") == "admin",
            "session inspection must return verified JWT claims");
    const auto server_logs =
        request(client, drogon::Get, "/api/system/logs");
    require(server_logs.status == drogon::k200OK &&
                server_logs.body.at("lines").is_array() &&
                !server_logs.body.at("lines").empty(),
            "system logs must expose the bounded C++ server log buffer");
    const auto created_peer =
        request(client, drogon::Post, "/api/wireguard/peers",
                json{{"name", "Contract phone"},
                     {"notes", "created over HTTP"},
                     {"quota_bytes", 1'000'000}});
    require(created_peer.status == drogon::k200OK &&
                created_peer.body.at("address") == "10.59.32.2/24" &&
                created_peer.body.at("private_key").get<std::string>().size() ==
                    44U &&
                created_peer.body.at("public_key").get<std::string>().size() ==
                    44U,
            "WireGuard peer creation must generate keys and allocate an address");
    const auto peer_id = created_peer.body.at("id").get<std::string>();
    const auto peers = request(client, drogon::Get, "/api/wireguard/peers");
    require(peers.status == drogon::k200OK && peers.body.size() == 1U &&
                peers.body.at(0).at("kind") == "wg" &&
                peers.body.at(0).at("expired") == false,
            "WireGuard peer listing must merge classification and expiry state");
    const auto updated_peer =
        request(client, drogon::Put, "/api/wireguard/peers/" + peer_id,
                json{{"name", "Renamed phone"},
                     {"persistent_keepalive", 15},
                     {"allowed_ips", "10.0.0.0/8"}});
    require(updated_peer.body.at("name") == "Renamed phone" &&
                updated_peer.body.at("persistent_keepalive") == 15 &&
                updated_peer.body.at("allowed_ips") == "10.0.0.0/8",
            "WireGuard peer updates must preserve omitted credentials");
    require(request(client, drogon::Post,
                    "/api/wireguard/peers/" + peer_id + "/disable")
                    .status == drogon::k200OK &&
                !store->find_wireguard_peer(peer_id)->enabled,
            "WireGuard disable must persist");
    require(request(client, drogon::Post,
                    "/api/wireguard/peers/" + peer_id + "/enable")
                    .status == drogon::k200OK &&
                store->find_wireguard_peer(peer_id)->enabled,
            "WireGuard enable must persist");
    const auto peer_config =
        raw_request(client, "/api/wireguard/peers/" + peer_id + "/config");
    require(peer_config.status == drogon::k200OK &&
                peer_config.body.find("Endpoint = vpn.example.com:51820") !=
                    std::string::npos &&
                peer_config.content_disposition.find("Renamed_phone.conf") !=
                    std::string::npos,
            "WireGuard config download must contain the deployment endpoint");
    const auto peer_qr =
        raw_request(client, "/api/wireguard/peers/" + peer_id + "/qr");
    require(peer_qr.status == drogon::k200OK &&
                peer_qr.content_type.starts_with("image/svg+xml") &&
                peer_qr.body.find("<svg") != std::string::npos,
            "WireGuard QR endpoint must return an SVG QR code");
    const auto one_time = request(
        client, drogon::Post,
        "/api/wireguard/peers/" + peer_id + "/one-time-link");
    require(one_time.body.at("url")
                    .get<std::string>()
                    .starts_with("https://vpn.example.com/api/one-time/") &&
                one_time.body.at("expires_at").is_string(),
            "WireGuard one-time links must be persisted with a bounded expiry");
    require(request(client, drogon::Get, "/api/wireguard/stats")
                    .body.at("peers")
                    .empty() &&
                request(client, drogon::Post, "/api/wireguard/sync")
                        .status == drogon::k200OK,
            "disabled WireGuard runtime should expose empty stats and safe sync");
    require(request(client, drogon::Get, "/api/system/status")
                    .body.at("wireguard")
                    .at("peer_count") == 1,
            "system status must report persisted WireGuard peers");
    const auto initial_settings = request(client, drogon::Get, "/api/settings");
    require(initial_settings.status == drogon::k200OK &&
                initial_settings.body.at("wireguard_interface").at("interface") ==
                    "wg0",
            "settings must merge persisted values with runtime defaults");
    const auto updated_settings =
        request(client, drogon::Put, "/api/settings",
                json{{"general", {{"app_name", "contract-panel"}}}});
    require(updated_settings.status == drogon::k200OK &&
                updated_settings.body.at("general").at("app_name") == "contract-panel",
            "settings mutations must persist supported sections");

    const auto created_viewer = request(client, drogon::Post, "/api/users",
                                        json{{"username", "contract-viewer"},
                                             {"password", "viewer-password"},
                                             {"role", "viewer"}});
    require(created_viewer.status == drogon::k200OK &&
                created_viewer.body.at("role") == "viewer" &&
                !created_viewer.body.contains("password_hash"),
            "administrators must be able to create viewers without leaking hashes");
    const auto viewer_id = created_viewer.body.at("id").get<std::string>();
    const auto viewer_login =
        request(client, drogon::Post, "/api/auth/login",
                json{{"username", "contract-viewer"}, {"password", "viewer-password"}});
    const std::vector<std::pair<std::string, std::string>> viewer_auth{
        {"Authorization",
         "Bearer " + viewer_login.body.at("token").get<std::string>()}};
    require(request(client, drogon::Get, "/api/proxy/nodes", std::nullopt, viewer_auth)
                    .status == drogon::k200OK,
            "viewers must retain read access to protected APIs");
    require(
        request(client, drogon::Post, "/api/proxy/nodes", json::object(), viewer_auth)
                .status == drogon::k403Forbidden,
        "viewers must be blocked before protected mutations run");
    require(
        request(client, drogon::Get, "/api/users", std::nullopt, viewer_auth).status ==
            drogon::k403Forbidden,
        "user administration must require the admin role");
    require(request(client, drogon::Post, "/api/users/" + viewer_id + "/password",
                    json{{"password", "replacement-password"}})
                    .status == drogon::k200OK,
            "administrators must be able to reset another user's password");
    require(request(client, drogon::Delete,
                    "/api/users/" + store->find_user_by_username("admin")->id)
                    .status == drogon::k400BadRequest,
            "administrators must not delete their own account");
    require(request(client, drogon::Delete, "/api/users/" + viewer_id).status ==
                drogon::k200OK,
            "administrators must be able to remove another user");
    const auto audit = request(client, drogon::Get, "/api/users/audit");
    require(audit.status == drogon::k200OK && audit.body.is_array() &&
                std::ranges::any_of(audit.body,
                                    [](const auto& entry) {
                                        return entry.at("actor") == "admin" &&
                                               entry.at("action") == "POST" &&
                                               entry.at("target") == "/api/users";
                                    }),
            "successful administrative mutations must be audit logged");

    const auto clash_proxies = request(client, drogon::Get, "/api/sing-box/proxies");
    require(clash_proxies.status == drogon::k200OK &&
                clash_proxies.body.at("method") == "GET" &&
                clash_proxies.body.at("target") == "/local/proxies" &&
                clash_proxies.body.at("authorization") == "Bearer local-secret",
            "Clash proxy list should use the local target and bearer secret");
    const auto clash_detail =
        request(client, drogon::Get, "/api/sing-box/proxies/Group%20A");
    if (clash_detail.status != drogon::k200OK ||
        clash_detail.body.at("target") != "/local/proxies/Group%20A") {
        throw std::runtime_error(
            "Clash path parameters should be encoded exactly once: " +
            clash_detail.body.dump());
    }
    const auto clash_switch =
        request(client, drogon::Put, "/api/sing-box/proxies/Group%20A",
                json{{"name", "Node A"}});
    require(clash_switch.status == drogon::k200OK &&
                clash_switch.body.at("success") == true,
            "Clash selector updates should forward successful PUT requests");
    const auto clash_delay =
        request(client, drogon::Get,
                "/api/sing-box/group/Auto/delay?"
                "url=https%3A%2F%2Fexample.com%2F204&timeout=3000");
    require(clash_delay.status == drogon::k200OK &&
                clash_delay.body.at("target") ==
                    "/local/group/Auto/delay?"
                    "url=https%3A%2F%2Fexample.com%2F204&timeout=3000",
            "Clash delay parameters should be normalized and encoded");
    const auto remote_version = request(
        client, drogon::Get, "/api/sing-box/version?host=" + remote_clash_host.id);
    require(remote_version.status == drogon::k200OK &&
                remote_version.body.at("target") == "/remote/version" &&
                remote_version.body.at("authorization") == "Bearer remote-secret",
            "remote hosts should select their own Clash target and secret");
    const auto close_connection =
        request(client, drogon::Delete, "/api/sing-box/connections/connection%201");
    require(close_connection.status == drogon::k200OK &&
                close_connection.body.at("method") == "DELETE" &&
                close_connection.body.at("target") ==
                    "/local/connections/connection%201",
            "connection close should forward DELETE with an encoded id");

    const auto created_node = request(client, drogon::Post, "/api/proxy/nodes",
                                      json{
                                          {"tag", "HTTP SS"},
                                          {"node_type", "shadowsocks"},
                                          {"server", "http-proxy.example.com"},
                                          {"server_port", 8388},
                                          {"protocol_config",
                                           {
                                               {"method", "aes-256-gcm"},
                                               {"password", "http-secret"},
                                           }},
                                      });
    require(created_node.status == drogon::k200OK &&
                created_node.body.at("node_type") == "shadowsocks" &&
                created_node.body.at("protocol_config").is_string(),
            "proxy creation should preserve the Rust response contract");
    const auto node_id = created_node.body.at("id").get<std::string>();
    const auto updated_node =
        request(client, drogon::Put, "/api/proxy/nodes/" + node_id,
                json{{"tag", "HTTP SS renamed"}, {"enabled", false}});
    require(updated_node.status == drogon::k200OK &&
                updated_node.body.at("tag") == "HTTP SS renamed" &&
                updated_node.body.at("enabled") == false,
            "proxy partial updates should preserve omitted fields");
    const auto measured_node =
        request(client, drogon::Post, "/api/proxy/nodes/" + node_id + "/test-latency");
    if (measured_node.status != drogon::k200OK ||
        measured_node.body.at("node_id") != node_id ||
        measured_node.body.at("latency") != 42) {
        throw std::runtime_error(
            "single-node latency tests should persist a Clash delay result: " +
            measured_node.body.dump());
    }
    const auto queued_measurement = request(
        client, drogon::Post,
        "/api/proxy/nodes/" + node_id + "/test-latency?host=" + remote_clash_host.id);
    require(queued_measurement.status == drogon::k200OK &&
                queued_measurement.body.at("queued") == true &&
                store->list_host_commands(remote_clash_host.id, true).front().command ==
                    R"(test-proxies ["HTTP SS renamed"])",
            "remote latency tests should enqueue a targeted agent command");

    const auto imported = request(
        client, drogon::Post, "/api/proxy/nodes/import",
        json{
            {"config",
             R"JSON({"outbounds":[{"type":"vless","tag":"Imported VLESS","server":"vless.example.com","server_port":443,"uuid":"uuid-import","flow":"","packet_encoding":"xudp"}]})JSON"}});
    require(imported.status == drogon::k200OK && imported.body.at("found") == 1 &&
                imported.body.at("added") == 1,
            "sing-box outbound import should add structured nodes");

    const auto created_subscription = request(
        client, drogon::Post, "/api/subscriptions",
        json{{"name", ""},
             {"url", "http://127.0.0.1:" + std::to_string(subscription_fixture.port()) +
                         "/fixture/subscription"},
             {"refresh_interval", 900}});
    require(created_subscription.status == drogon::k200OK &&
                created_subscription.body.at("name") == "127.0.0.1",
            "blank subscription names should derive from the URL host");
    const auto subscription_id = created_subscription.body.at("id").get<std::string>();
    const auto fetched = request(client, drogon::Post,
                                 "/api/subscriptions/" + subscription_id + "/fetch");
    require(fetched.status == drogon::k200OK && fetched.body.at("found") == 1 &&
                fetched.body.at("added") == 1,
            "subscription fetch should pull, parse, and persist nodes");
    const auto fetched_subscription =
        request(client, drogon::Get, "/api/subscriptions/" + subscription_id);
    require(fetched_subscription.status == drogon::k200OK &&
                !fetched_subscription.body.at("last_fetched_at").is_null() &&
                !fetched_subscription.body.at("last_fetch_result").is_null(),
            "subscription fetch should persist result metadata");
    const auto all_nodes = request(client, drogon::Get, "/api/proxy/nodes");
    require(all_nodes.status == drogon::k200OK && all_nodes.body.size() == 3U,
            "proxy list should include manual, imported, and subscribed nodes");
    const auto backup = request(client, drogon::Get, "/api/settings/backup");
    require(backup.status == drogon::k200OK && backup.body.at("version") == 1 &&
                backup.body.at("proxy_nodes").size() == 3U &&
                backup.body.at("wireguard_peers").size() == 1U &&
                backup.body.at("subscriptions").size() == 1U &&
                backup.body.at("app_settings").is_object(),
            "settings backup must export nodes, peers, subscriptions, and settings");
    const auto restored =
        request(client, drogon::Post, "/api/settings/restore", backup.body);
    require(restored.status == drogon::k200OK &&
                restored.body.at("restored").at("proxy_nodes") == 3 &&
                restored.body.at("restored").at("wireguard_peers") == 1 &&
                restored.body.at("restored").at("subscriptions") == 1,
            "backup restore must idempotently upsert every exported data section");
    const auto outbounds =
        request(client, drogon::Get, "/api/config/sing-box/outbounds");
    require(outbounds.status == drogon::k200OK && outbounds.body.is_array() &&
                outbounds.body.size() == 3U,
            "config download must render enabled proxy outbounds and auto group");
    const auto full_config = request(client, drogon::Get, "/api/config/sing-box/full");
    require(full_config.status == drogon::k200OK &&
                full_config.body.at("outbounds").is_array() &&
                full_config.body.at("experimental")
                        .at("clash_api")
                        .at("external_controller") ==
                    "127.0.0.1:" + std::to_string(clash_fixture.port()) +
                        "/local" &&
                full_config.body.at("experimental")
                        .at("clash_api")
                        .at("secret") == "local-secret",
            "full config must render the self profile with runtime Clash settings");
    const auto measured_all =
        request(client, drogon::Post, "/api/proxy/nodes/test-all");
    require(measured_all.status == drogon::k200OK &&
                measured_all.body.at("tested") == 2 &&
                measured_all.body.at("results").size() == 2U,
            "bulk latency tests should measure every enabled node");
    const auto queued_all = request(
        client, drogon::Post, "/api/proxy/nodes/test-all?host=" + remote_clash_host.id);
    require(queued_all.status == drogon::k200OK && queued_all.body.at("queued") == true,
            "remote bulk latency tests should enqueue an agent command");

    const auto profiles = request(client, drogon::Get, "/api/hosts/profiles");
    require(profiles.status == drogon::k200OK && profiles.body.is_array() &&
                !profiles.body.empty(),
            "profile list should include the seeded default");
    require(profiles.body.at(0).at("template").is_string(),
            "profile template must preserve the Rust string contract");

    const std::string rule_script = R"JS(
function buildRules(context) {
  return [{
    domain_suffix: [".example.com"],
    outbound: context.outboundTags.includes("direct") ? "direct" : "block"
  }];
}
)JS";
    const auto created_profile = request(client, drogon::Post, "/api/hosts/profiles",
                                         json{
                                             {"name", "Scripted profile"},
                                             {"template",
                                              {
                                                  {"route",
                                                   {
                                                       {"rules", json::array()},
                                                       {"final", "direct"},
                                                   }},
                                              }},
                                             {"rule_script", rule_script},
                                             {"rule_script_enabled", true},
                                         });
    require(created_profile.status == drogon::k200OK,
            "profile creation should succeed");
    const auto profile_id = created_profile.body.at("id").get<std::string>();

    const auto updated_profile =
        request(client, drogon::Put, "/api/hosts/profiles/" + profile_id,
                json{
                    {"name", "Renamed scripted profile"},
                    {"template",
                     {
                         {"route",
                          {
                              {"rules", json::array()},
                              {"final", "direct"},
                          }},
                     }},
                });
    require(updated_profile.status == drogon::k200OK &&
                updated_profile.body.at("rule_script_enabled") == true &&
                updated_profile.body.at("rule_script") == rule_script,
            "profile updates should preserve omitted script fields");

    const auto created_host = request(client, drogon::Post, "/api/hosts",
                                      json{
                                          {"name", "HTTP test host"},
                                          {"capabilities",
                                           {
                                               {"runs_singbox", true},
                                               {"is_wg_member", false},
                                               {"is_wg_hub", false},
                                               {"is_self", false},
                                           }},
                                          {"profile_id", profile_id},
                                          {"clash_secret", "hidden"},
                                      });
    require(created_host.status == drogon::k200OK, "host creation should succeed");
    require(created_host.body.at("agent_token").get_ref<const std::string&>().size() ==
                64,
            "host creation should return the one-time token");
    require(!created_host.body.contains("clash_secret"),
            "host creation must not expose the Clash secret");
    const auto host_id = created_host.body.at("id").get<std::string>();
    const auto original_token = created_host.body.at("agent_token").get<std::string>();
    const auto joined_wg = request(
        client, drogon::Put, "/api/hosts/" + host_id,
        json{{"capabilities",
              {{"runs_singbox", true},
               {"is_wg_member", true},
               {"is_wg_hub", false},
               {"is_self", false}}}});
    require(joined_wg.body.at("wg_address").is_string() &&
                joined_wg.body.at("wg_public_key").is_string() &&
                joined_wg.body.at("clash_api")
                    .get<std::string>()
                    .starts_with("http://10.59.32."),
            "enabling host WG membership must provision reachback identity");
    const auto host_wg =
        raw_request(client, "/api/hosts/" + host_id + "/wg-config");
    require(host_wg.status == drogon::k200OK &&
                host_wg.body.find("# Hub (central server)") !=
                    std::string::npos &&
                host_wg.body.find("Endpoint = vpn.example.com:51820") !=
                    std::string::npos,
            "managed hosts must be able to download their intranet config");
    const auto left_wg = request(
        client, drogon::Put, "/api/hosts/" + host_id,
        json{{"capabilities",
              {{"runs_singbox", true},
               {"is_wg_member", false},
               {"is_wg_hub", false},
               {"is_self", false}}}});
    require(left_wg.status == drogon::k200OK &&
                store->list_wireguard_peers().size() == 1U,
            "disabling host WG membership must deprovision its peer");

    const auto hosts = request(client, drogon::Get, "/api/hosts");
    require(hosts.status == drogon::k200OK && hosts.body.is_array(),
            "host list should succeed");
    bool found_public_host = false;
    for (const auto& host : hosts.body) {
        if (host.at("id") == host_id) {
            found_public_host = true;
            require(!host.contains("agent_token"),
                    "host list must hide the agent token");
            require(host.at("capabilities").is_object(),
                    "host capabilities must be a JSON object");
        }
    }
    require(found_public_host, "created host should appear in the list");

    store->database().execute("INSERT INTO proxy_nodes "
                              "(id, tag, node_type, enabled, server, server_port, "
                              "protocol_config, fingerprint) VALUES "
                              "('http-node', 'http-node', 'shadowsocks', TRUE, "
                              "'127.0.0.1', 8388, "
                              "'{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                              "'http-node')");
    const auto set_outbounds =
        request(client, drogon::Put, "/api/hosts/" + host_id + "/outbounds",
                json{{"node_ids", json::array({"http-node"})}});
    require(set_outbounds.status == drogon::k200OK,
            "outbound assignment should succeed");
    const auto get_outbounds =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/outbounds");
    require(get_outbounds.body.at("node_ids") == json::array({"http-node"}),
            "outbound assignment should round-trip");

    const auto config =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/config");
    require(config.status == drogon::k200OK &&
                config.body.at("route").at("rules").at(0).at("outbound") == "direct",
            "config preview should execute the profile rule script");

    const auto agent_health = request(client, drogon::Get, "/api/agent/health");
    require(agent_health.status == drogon::k200OK,
            "agent health should remain unauthenticated");
    require(request(client, drogon::Get, "/api/agent/config").status ==
                drogon::k401Unauthorized,
            "agent config should reject missing bearer credentials");
    const std::vector<std::pair<std::string, std::string>> agent_auth{
        {"Authorization", "Bearer " + original_token},
    };
    const auto agent_config =
        request(client, drogon::Get, "/api/agent/config", std::nullopt, agent_auth);
    require(agent_config.status == drogon::k200OK && !agent_config.etag.empty() &&
                agent_config.body.at("route").at("rules").at(0).at("outbound") ==
                    "direct",
            "authenticated agents should receive their rendered config and ETag");
    auto cached_headers = agent_auth;
    cached_headers.emplace_back("If-None-Match", agent_config.etag);
    const auto cached_config =
        request(client, drogon::Get, "/api/agent/config", std::nullopt, cached_headers);
    require(cached_config.status == drogon::k304NotModified &&
                cached_config.raw_body.empty() &&
                cached_config.etag == agent_config.etag,
            "matching agent ETags should produce an empty 304 response");
    const auto touched_host = store->find_host(host_id);
    require(touched_host.has_value() && touched_host->last_seen.has_value(),
            "config polls should update host liveness");

    const auto status_report = request(client, drogon::Post, "/api/agent/status",
                                       json{{"singbox_version", "1.12.0"},
                                            {"singbox_running", true},
                                            {"config_etag", agent_config.etag}},
                                       agent_auth);
    require(status_report.status == drogon::k200OK &&
                status_report.body.at("ok") == true,
            "agent status reports should succeed");
    const auto status_host = store->find_host(host_id);
    require(status_host.has_value() && status_host->singbox_state.has_value() &&
                json::parse(*status_host->singbox_state).at("etag") ==
                    agent_config.etag,
            "agent status should persist the reported ETag");

    const auto enqueued =
        request(client, drogon::Post, "/api/hosts/" + host_id + "/commands",
                json{{"command", " RELOAD "}});
    require(enqueued.status == drogon::k200OK &&
                enqueued.body.at("status") == "pending",
            "administrators should enqueue normalized agent commands");
    const auto command_id = enqueued.body.at("id").get<std::string>();
    const auto pending =
        request(client, drogon::Get, "/api/agent/commands", std::nullopt, agent_auth);
    require(pending.status == drogon::k200OK && pending.body.size() == 1U &&
                pending.body.at(0).at("id") == command_id,
            "agents should only pull their pending commands");
    const std::vector<std::pair<std::string, std::string>> legacy_auth{
        {"Authorization", "Bearer legacy-self-token"},
    };
    require(request(client, drogon::Post, "/api/agent/commands/" + command_id + "/ack",
                    json{{"status", "done"}, {"result", "wrong host"}}, legacy_auth)
                    .status == drogon::k200OK,
            "cross-host command acknowledgements should not leak existence");
    require(store->list_host_commands(host_id, true).size() == 1U,
            "a different host token must not acknowledge the command");
    require(request(client, drogon::Post, "/api/agent/commands/" + command_id + "/ack",
                    json{{"status", "done"}, {"result", "reloaded"}}, agent_auth)
                    .status == drogon::k200OK,
            "the owning agent should acknowledge its command");
    const auto command_history =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/commands");
    require(command_history.body.at(0).at("status") == "done" &&
                command_history.body.at(0).at("result") == "reloaded",
            "administrators should see acknowledged command history");
    require(request(client, drogon::Post, "/api/hosts/self/commands",
                    json{{"command", "reload"}})
                    .status == drogon::k400BadRequest,
            "the built-in self host must reject remote commands");

    json logs = json::array();
    for (int index = 0; index < 502; ++index) {
        logs.push_back(std::to_string(index));
    }
    require(request(client, drogon::Post, "/api/agent/telemetry",
                    json{{"up", 10},
                         {"down", 20},
                         {"up_total", 100},
                         {"down_total", 200},
                         {"conn_count", 1},
                         {"connections", json::array({json{{"id", "connection"}}})},
                         {"logs", std::move(logs)}},
                    agent_auth)
                    .status == drogon::k200OK,
            "agents should relay telemetry");
    const auto telemetry =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/telemetry");
    require(telemetry.body.at("up") == 10 && telemetry.body.at("logs").size() == 500U &&
                telemetry.body.at("logs").at(0) == "2",
            "telemetry should retain the latest snapshot and cap logs");

    const auto latency =
        request(client, drogon::Post, "/api/agent/proxy-latency",
                json{{"results", {{"http-node", 42.5}, {"missing-node", nullptr}}}},
                agent_auth);
    require(latency.status == drogon::k200OK && latency.body.at("updated") == 1,
            "agent latency reports should update matching proxy tags");

    const auto revealed =
        request(client, drogon::Get, "/api/hosts/" + host_id + "/token");
    require(revealed.body.at("agent_token") == original_token &&
                revealed.body.at("server") == "https://panel.example.com",
            "token reveal should preserve its response contract");
    const auto rotated =
        request(client, drogon::Post, "/api/hosts/" + host_id + "/rotate-token");
    require(rotated.body.at("agent_token") != original_token,
            "token rotation should return a replacement");
    require(request(client, drogon::Get, "/api/agent/config", std::nullopt, agent_auth)
                    .status == drogon::k401Unauthorized,
            "rotating a token should immediately revoke the old credential");

    const auto updated_host =
        request(client, drogon::Put, "/api/hosts/" + host_id,
                json{{"name", "Disabled preview host"}, {"enabled", false}});
    require(updated_host.body.at("name") == "Disabled preview host" &&
                updated_host.body.at("enabled") == false,
            "partial host updates should preserve the Rust semantics");
    require(request(client, drogon::Get, "/api/hosts/" + host_id + "/config").status ==
                drogon::k200OK,
            "administrative config preview should work for disabled hosts");

    const auto invalid_profile =
        request(client, drogon::Post, "/api/hosts/profiles",
                json{{"name", "invalid"}, {"template", json::array()}});
    require(invalid_profile.status == drogon::k400BadRequest &&
                invalid_profile.body.contains("error"),
            "invalid profile templates should return structured 400 errors");
    require(request(client, drogon::Get, "/api/hosts/missing").status ==
                drogon::k404NotFound,
            "missing hosts should return structured 404 errors");
    require(request(client, drogon::Get, "/api/hosts/missing/config").status ==
                drogon::k404NotFound,
            "missing host config previews should return structured 404 errors");
    require(request(client, drogon::Delete, "/api/hosts/profiles/default").status ==
                drogon::k400BadRequest,
            "the default profile should be protected over HTTP");

    require(
        request(client, drogon::Delete, "/api/hosts/" + host_id).body.at("success") ==
            true,
        "host deletion should succeed");
}

} // namespace

int main() {
    try {
        run_contract();
        std::cout << "[pass] Drogon hosts/profile HTTP contract\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] Drogon hosts/profile HTTP contract: " << error.what()
                  << '\n';
        return 1;
    }
}
