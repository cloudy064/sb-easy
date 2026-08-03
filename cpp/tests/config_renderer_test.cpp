#include "test_support.hpp"

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"

namespace {

sbeasy::ProxyNode shadowsocks(std::string tag) {
    return sbeasy::ProxyNode{
        .id = "id-" + tag,
        .tag = std::move(tag),
        .type = "shadowsocks",
        .enabled = true,
        .server = "192.0.2.10",
        .server_port = 443,
        .protocol_config =
            {
                {"method", "aes-256-gcm"},
                {"password", "secret"},
            },
    };
}

} // namespace

SB_EASY_TEST("managed rendering injects outbounds and script rules") {
    sbeasy::RenderRequest request;
    request.profile = {
        {"route",
         {
             {"rules", nlohmann::json::array()},
             {"final", "Proxy"},
         }},
    };
    request.nodes = {shadowsocks("hk")};
    request.host_context = {{"id", "edge-1"}, {"name", "edge"}};
    request.rule_script = R"JS(
function buildRules(context) {
  return [{
    domain_suffix: [".example.com"],
    outbound: context.outboundTags.includes("hk") ? "hk" : "direct"
  }];
}
)JS";
    request.clash_controller = "0.0.0.0:9090";
    request.clash_secret = "controller-secret";

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);

    sbeasy::test::require(config["outbounds"].size() == 2,
                          "expected proxy and auto outbounds");
    sbeasy::test::require(config["route"]["final"] == "auto",
                          "legacy final was not normalized");
    sbeasy::test::require(config["route"]["rules"][0]["outbound"] == "hk",
                          "script rules were not installed");
    sbeasy::test::require(config["experimental"]["clash_api"]["secret"] ==
                              "controller-secret",
                          "protected clash API was not injected");
}

SB_EASY_TEST("duplicate proxy tags receive deterministic suffixes") {
    const auto outbounds = sbeasy::ConfigRenderer::generate_outbounds(
        {shadowsocks("hk"), shadowsocks("hk")});
    sbeasy::test::require(outbounds[0]["tag"] == "hk", "first tag changed");
    sbeasy::test::require(outbounds[1]["tag"] == "hk #2",
                          "duplicate tag was not suffixed");
}

SB_EASY_TEST("URLTest interval has a compatible idle timeout") {
    const auto outbounds =
        sbeasy::ConfigRenderer::generate_outbounds({shadowsocks("hk")});
    const auto& automatic = outbounds.back();
    sbeasy::test::require(automatic["type"] == "urltest",
                          "automatic outbound is not URLTest");
    sbeasy::test::require(automatic["interval"] == "24h" &&
                              automatic["idle_timeout"] == "24h",
                          "URLTest interval must not exceed its idle timeout");
}

SB_EASY_TEST("Android managed rendering exposes a selectable proxy group") {
    sbeasy::RenderRequest request;
    request.profile = {
        {"dns",
         {{"servers",
           nlohmann::json::array({
               {{"type", "local"}, {"tag", "local-dns"}},
               {{"type", "https"},
                {"tag", "secure-dns"},
                {"server", "1.1.1.1"},
                {"detour", "Proxy"}},
           })}}},
        {"route", {{"final", "Proxy"}}},
    };
    request.nodes = {shadowsocks("hk"), shadowsocks("us")};
    request.host_context = {
        {"id", "phone"},
        {"capabilities", {{"platform", "android"}}},
    };

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);
    const auto& selector = config["outbounds"].back();
    sbeasy::test::require(selector["type"] == "selector" &&
                              selector["tag"] == "Proxy" &&
                              selector["outbounds"] ==
                                  nlohmann::json::array({"auto", "hk", "us"}),
                          "Android configs should include auto and manual selection");
    sbeasy::test::require(config["route"]["final"] == "Proxy",
                          "Android traffic should enter the selector group");
    sbeasy::test::require(config["dns"]["servers"][1]["detour"] == "Proxy",
                          "secure DNS should follow the Android selector group");
}

SB_EASY_TEST("Android DNS follows a renamed selector when Proxy is a node tag") {
    sbeasy::RenderRequest request;
    request.profile = {
        {"dns",
         {{"servers",
           nlohmann::json::array({
               {{"type", "https"},
                {"tag", "secure-dns"},
                {"server", "1.1.1.1"},
                {"detour", "Proxy"}},
           })}}},
        {"route", {{"final", "Proxy"}}},
    };
    request.nodes = {shadowsocks("Proxy")};
    request.host_context = {{"capabilities", {{"platform", "android"}}}};

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);
    sbeasy::test::require(config["outbounds"].back()["tag"] == "Proxy group" &&
                              config["dns"]["servers"][0]["detour"] ==
                                  "Proxy group",
                          "DNS detour must target the generated selector tag");
}

SB_EASY_TEST("generated rules cannot reference unknown outbounds") {
    sbeasy::RenderRequest request;
    request.profile = {{"route", {{"rules", nlohmann::json::array()}}}};
    request.nodes = {shadowsocks("hk")};
    request.rule_script = "function buildRules() { return [{outbound: 'missing'}]; }";

    const sbeasy::ConfigRenderer renderer;
    sbeasy::test::require_throws<sbeasy::ScriptError>(
        [&renderer, &request] { static_cast<void>(renderer.render(request)); },
        "unknown outbound reference was accepted");
}

SB_EASY_TEST("server priority routes survive QuickJS rule replacement") {
    sbeasy::RenderRequest request;
    request.profile = {{"route", {{"rules", nlohmann::json::array()}}}};
    request.nodes = {shadowsocks("hk")};
    request.external_route_tags = {"sb-easy-network"};
    request.priority_route_rules = nlohmann::json::array({
        {
            {"ip_cidr", nlohmann::json::array({"10.59.32.0/24"})},
            {"outbound", "sb-easy-network"},
        },
    });
    request.rule_script =
        "function buildRules() { return [{ domain_suffix: ['.example.com'], "
        "outbound: 'hk' }]; }";

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);
    sbeasy::test::require(
        config["route"]["rules"].size() == 2U &&
            config["route"]["rules"][0]["outbound"] == "sb-easy-network" &&
            config["route"]["rules"][1]["outbound"] == "hk",
        "managed network routes must remain ahead of script-generated rules");
}

SB_EASY_TEST("control plane route survives QuickJS and uses the exact server host") {
    sbeasy::RenderRequest request;
    request.profile = {{"route", {{"rules", nlohmann::json::array()}}}};
    request.nodes = {shadowsocks("hk")};
    request.control_plane_server = "http://39.108.98.208:51821/api";
    request.rule_script =
        "function buildRules() { return [{ outbound: 'hk' }]; }";

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);
    sbeasy::test::require(
        config["route"]["rules"][0]["ip_cidr"] ==
                nlohmann::json::array({"39.108.98.208/32"}) &&
            config["route"]["rules"][0]["outbound"] == "direct" &&
            config["route"]["rules"][1]["outbound"] == "hk",
        "control-plane direct route must precede script rules");
}

SB_EASY_TEST("empty managed profiles fall back to direct") {
    sbeasy::RenderRequest request;
    request.profile = {{"route", {{"final", "auto"}}}};

    const sbeasy::ConfigRenderer renderer;
    const auto config = renderer.render(request);
    sbeasy::test::require(config["route"]["final"] == "direct",
                          "empty profile did not select direct");
    sbeasy::test::require(config["outbounds"][0]["tag"] == "direct",
                          "direct outbound was not created");
}
