#include "sbeasy/agent_clash.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "sbeasy/clash_client.hpp"

namespace sbeasy {
namespace {

using nlohmann::json;

struct TrafficSample {
    std::int64_t upload_total{};
    std::int64_t download_total{};
    std::chrono::steady_clock::time_point at;
};

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

void replace_all(std::string& value, std::string_view from, std::string_view to) {
    std::size_t position{};
    while ((position = value.find(from, position)) != std::string::npos) {
        value.replace(position, from.size(), to);
        position += to.size();
    }
}

[[nodiscard]] json read_config(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        throw std::runtime_error("cannot read sing-box config: " + path.string());
    }
    const std::string source{std::istreambuf_iterator<char>{input},
                             std::istreambuf_iterator<char>{}};
    auto config = json::parse(source, nullptr, false);
    if (!config.is_object()) {
        throw std::runtime_error("sing-box config is not a JSON object: " +
                                 path.string());
    }
    return config;
}

[[nodiscard]] std::optional<ClashTarget> read_target(const std::filesystem::path& path,
                                                     bool use_default_controller) {
    const auto config = read_config(path);
    static const json::json_pointer controller_pointer{
        "/experimental/clash_api/external_controller"};
    static const json::json_pointer secret_pointer{"/experimental/clash_api/secret"};
    const auto* controller =
        config.contains(controller_pointer) ? &config.at(controller_pointer) : nullptr;
    std::string address;
    if (controller != nullptr && controller->is_string()) {
        address = controller->get<std::string>();
    } else if (use_default_controller) {
        address = "127.0.0.1:9090";
    } else {
        return std::nullopt;
    }
    if (address.empty()) {
        if (!use_default_controller) {
            return std::nullopt;
        }
        address = "127.0.0.1:9090";
    }
    replace_all(address, "0.0.0.0", "127.0.0.1");
    replace_all(address, "[::]", "127.0.0.1");
    if (!address.starts_with("http://") && !address.starts_with("https://")) {
        address = "http://" + address;
    }
    while (address.ends_with('/')) {
        address.pop_back();
    }

    std::string secret;
    if (config.contains(secret_pointer) && config.at(secret_pointer).is_string()) {
        secret = config.at(secret_pointer).get<std::string>();
    }
    return ClashTarget{
        .base_url = std::move(address),
        .secret = std::move(secret),
    };
}

[[nodiscard]] bool successful(const ClashResponse& response) {
    return response.status >= 200 && response.status < 300;
}

[[nodiscard]] std::int64_t integer_or_zero(const json& body, const char* field) {
    const auto found = body.find(field);
    if (found == body.end() ||
        !(found->is_number_integer() || found->is_number_unsigned())) {
        return 0;
    }
    return found->get<std::int64_t>();
}

} // namespace

class AgentClashService::Impl final {
  public:
    explicit Impl(std::filesystem::path config_path)
        : config_path_(std::move(config_path)),
          client_({.timeout = std::chrono::seconds{8},
                   .maximum_body_bytes = 8U * 1024U * 1024U}) {}

    [[nodiscard]] std::size_t
    test_proxies(const std::optional<std::vector<std::string>>& tags,
                 const LatencyReporter& reporter) {
        const auto target = *read_target(config_path_, true);
        const auto response = client_.get(target, "/proxies");
        if (!successful(response)) {
            throw std::runtime_error("Clash proxy list returned HTTP " +
                                     std::to_string(response.status));
        }

        const auto found = response.body.find("proxies");
        if (found == response.body.end() || !found->is_object()) {
            return 0U;
        }
        static const std::unordered_set<std::string> skipped_types{
            "Selector",   "URLTest", "Fallback", "LoadBalance", "Direct",   "Reject",
            "Compatible", "Pass",    "Dns",      "Block",       "Loopback",
        };
        const std::unordered_set<std::string> wanted =
            tags.has_value()
                ? std::unordered_set<std::string>{tags->begin(), tags->end()}
                : std::unordered_set<std::string>{};

        std::vector<std::string> names;
        for (const auto& [name, proxy] : found->items()) {
            const auto type = proxy.is_object() ? proxy.value("type", "") : "";
            const bool is_group = proxy.is_object() && proxy.contains("all");
            if (!is_group && !skipped_types.contains(type) &&
                (!tags.has_value() || wanted.contains(name))) {
                names.push_back(name);
            }
        }
        std::ranges::sort(names);

        std::size_t tested{};
        for (const auto& name : names) {
            json latency = nullptr;
            try {
                const auto path =
                    "/proxies/" + encode_component(name) + "/delay?url=" +
                    encode_component("https://www.gstatic.com/generate_204") +
                    "&timeout=5000";
                const auto delay = client_.get(target, path);
                if (successful(delay)) {
                    const auto value = delay.body.find("delay");
                    if (value != delay.body.end() && value->is_number()) {
                        latency = *value;
                    }
                }
            } catch (const ClashRequestError&) {
                // An unreachable proxy is a valid null measurement; continue
                // reporting the remaining nodes.
            }
            json result = json::object();
            result[name] = std::move(latency);
            reporter(result);
            ++tested;
        }
        return tested;
    }

    [[nodiscard]] std::optional<json> sample_telemetry() {
        const auto target = read_target(config_path_, false);
        if (!target.has_value()) {
            return std::nullopt;
        }
        const auto response = client_.get(*target, "/connections");
        if (!successful(response)) {
            throw std::runtime_error("Clash connections returned HTTP " +
                                     std::to_string(response.status));
        }

        const auto upload_total = integer_or_zero(response.body, "uploadTotal");
        const auto download_total = integer_or_zero(response.body, "downloadTotal");
        const auto now = std::chrono::steady_clock::now();
        std::int64_t upload_rate{};
        std::int64_t download_rate{};
        if (last_sample_.has_value()) {
            const auto elapsed = std::max(
                std::chrono::duration<double>{now - last_sample_->at}.count(), 0.001);
            const auto upload_delta =
                std::max<std::int64_t>(upload_total - last_sample_->upload_total, 0);
            const auto download_delta = std::max<std::int64_t>(
                download_total - last_sample_->download_total, 0);
            upload_rate =
                static_cast<std::int64_t>(static_cast<double>(upload_delta) / elapsed);
            download_rate = static_cast<std::int64_t>(
                static_cast<double>(download_delta) / elapsed);
        }
        last_sample_ = TrafficSample{
            .upload_total = upload_total,
            .download_total = download_total,
            .at = now,
        };

        auto connections = json::array();
        if (const auto found = response.body.find("connections");
            found != response.body.end()) {
            connections = *found;
        }
        const auto connection_count = connections.is_array() ? connections.size() : 0U;
        return json{
            {"up", upload_rate},
            {"down", download_rate},
            {"up_total", upload_total},
            {"down_total", download_total},
            {"conn_count", connection_count},
            {"connections", std::move(connections)},
            {"logs", json::array()},
        };
    }

  private:
    std::filesystem::path config_path_;
    ClashClient client_;
    std::optional<TrafficSample> last_sample_;
};

AgentClashService::AgentClashService(std::filesystem::path config_path)
    : implementation_(std::make_unique<Impl>(std::move(config_path))) {}

AgentClashService::~AgentClashService() = default;
AgentClashService::AgentClashService(AgentClashService&&) noexcept = default;
AgentClashService& AgentClashService::operator=(AgentClashService&&) noexcept = default;

std::size_t
AgentClashService::test_proxies(const std::optional<std::vector<std::string>>& tags,
                                const LatencyReporter& reporter) {
    if (!reporter) {
        throw std::invalid_argument("proxy latency reporter is required");
    }
    return implementation_->test_proxies(tags, reporter);
}

std::optional<nlohmann::json> AgentClashService::sample_telemetry() {
    return implementation_->sample_telemetry();
}

} // namespace sbeasy
