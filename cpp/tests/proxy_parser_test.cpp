#include "test_support.hpp"

#include <string>

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/proxy_parser.hpp"

SB_EASY_TEST("proxy URI parser covers supported credentials and transports") {
    const auto shadowsocks = sbeasy::parse_proxy_uri(
        "ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@server.example.com:443"
        "#Test%20Node");
    sbeasy::test::require(
        shadowsocks.has_value() && shadowsocks->node_type == "shadowsocks" &&
            shadowsocks->tag == "Test Node" &&
            shadowsocks->protocol_config.at("password") == "testpassword",
        "SIP002 Shadowsocks should decode credentials and fragment");

    const auto trojan =
        sbeasy::parse_proxy_uri("trojan://password123@trojan.example.com:443?"
                                "sni=sni.example.com&fp=chrome#Trojan01");
    sbeasy::test::require(
        trojan.has_value() &&
            trojan->protocol_config.at("tls").at("server_name") == "sni.example.com" &&
            trojan->protocol_config.at("tls").at("utls").at("fingerprint") == "chrome",
        "Trojan should normalize TLS and uTLS options");

    const auto vless = sbeasy::parse_proxy_uri(
        "vless://abc123@vless.example.com:443?"
        "security=tls&type=ws&path=%2Fws&host=cdn.example.com#VLESS-WS");
    sbeasy::test::require(
        vless.has_value() &&
            vless->protocol_config.at("transport").at("type") == "ws" &&
            vless->protocol_config.at("transport").at("path") == "/ws" &&
            vless->protocol_config.at("transport").at("headers").at("Host") ==
                "cdn.example.com",
        "VLESS should normalize WebSocket transport options");

    const auto tuic =
        sbeasy::parse_proxy_uri("tuic://uuid-1:secret@tuic.example.com:443?"
                                "sni=tuic.example.com&congestion=bbr#TUIC");
    sbeasy::test::require(tuic.has_value() &&
                              tuic->protocol_config.at("uuid") == "uuid-1" &&
                              tuic->protocol_config.at("password") == "secret",
                          "TUIC should split UUID and password");

    sbeasy::test::require(
        !sbeasy::parse_proxy_uri("vmess://eyJhZGQiOiJlLmV4YW1wbGUiLCJwb3J0Ijo0NDN9")
             .has_value(),
        "nodes without required credentials must be rejected");
}

SB_EASY_TEST("subscription parser supports base64 URI lists and Clash YAML") {
    const auto encoded = sbeasy::parse_subscription_body(
        "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2ZEdWemRIQmhjM04zYjNKa0BzZXJ2ZXIu"
        "ZXhhbXBsZS5jb206NDQzI0VuY29kZWQ=");
    sbeasy::test::require(encoded.size() == 1U && encoded.front().tag == "Encoded",
                          "base64 subscriptions should decode to URI lines");

    const std::string yaml = R"YAML(
port: 7890
proxies:
  - {name: "HK 01", server: hk.example, port: 19274, type: ss, cipher: aes-256-gcm, password: secret-pw}
  - {name: "JP WS", server: jp.example, port: 443, type: vmess, uuid: uuid-123, alterId: 1, cipher: auto, network: ws, ws-opts: {path: /vm, headers: {Host: cdn.example}}, tls: true, servername: cdn.example}
  - {name: bad, server: bad.example, port: 443, type: vmess}
proxy-groups:
  - {name: Proxy, type: select, proxies: ["HK 01"]}
)YAML";
    const auto nodes = sbeasy::parse_subscription_body(yaml);
    sbeasy::test::require(nodes.size() == 2U,
                          "Clash YAML should retain only valid supported nodes");
    sbeasy::test::require(
        nodes.at(1).protocol_config.at("alter_id") == 1 &&
            nodes.at(1).protocol_config.at("transport").at("path") == "/vm" &&
            nodes.at(1).protocol_config.at("tls").at("server_name") == "cdn.example",
        "Clash VMess fields should map to sing-box shape");
    sbeasy::test::require(nodes.front().fingerprint().size() == 64U,
                          "proxy fingerprints should be SHA-256 hex");
}

SB_EASY_TEST("sing-box outbound import preserves renderer fields") {
    const nlohmann::json original{
        {"type", "vless"},
        {"tag", "VLESS"},
        {"server", "vless.example.com"},
        {"server_port", 443},
        {"uuid", "uuid-1"},
        {"flow", "xtls-rprx-vision"},
        {"packet_encoding", "xudp"},
        {"tls",
         {
             {"enabled", true},
             {"server_name", "vless.example.com"},
             {"utls", {{"enabled", true}, {"fingerprint", "chrome"}}},
         }},
        {"transport",
         {
             {"type", "ws"},
             {"path", "/ray"},
             {"headers", {{"Host", "cdn.example.com"}}},
         }},
    };
    const auto parsed = sbeasy::parse_outbound_config(
        {{"outbounds", nlohmann::json::array(
                           {original, {{"type", "selector"}, {"tag", "Proxy"}}})}});
    sbeasy::test::require(parsed.nodes.size() == 1U && parsed.skipped.empty(),
                          "groups should be ignored during outbound import");
    const auto& node = parsed.nodes.front();
    const auto rendered = sbeasy::ConfigRenderer::generate_outbound({
        .id = "imported",
        .tag = node.tag,
        .type = node.node_type,
        .enabled = true,
        .server = node.server,
        .server_port = node.server_port,
        .protocol_config = node.protocol_config,
    });
    sbeasy::test::require(rendered == original,
                          "parsed outbounds should round-trip through the renderer");
}
