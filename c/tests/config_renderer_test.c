#include "test.h"

#include "sb/config_renderer.h"
#include "sb/json.h"
#include "sb/types.h"
#include "sb/util.h"

static void shadowsocks(sb_proxy_node *n, const char *tag) {
    free(n->id);
    n->id = sb_asprintf("id-%s", tag);
    sb_str_set(&n->tag, tag);
    sb_str_set(&n->type, "shadowsocks");
    n->enabled = true;
    sb_str_set(&n->server, "192.0.2.10");
    n->server_port = 443;
    sbj_set_str(n->protocol_config, "method", "aes-256-gcm");
    sbj_set_str(n->protocol_config, "password", "secret");
}

static void set_profile(sb_render_request *r, const char *json) {
    sbj_free(r->profile);
    r->profile = sbj_parse_cstr(json);
}

static void set_host(sb_render_request *r, const char *json) {
    sbj_free(r->host_context);
    r->host_context = sbj_parse_cstr(json);
}

/* Follows a path of object keys / array indices ("route.rules.0.outbound"). */
static const sbj *at(const sbj *v, const char *path) {
    sb_strvec parts = sb_split(path, '.');
    for (size_t i = 0; i < parts.len && v; ++i) {
        const char *p = parts.items[i];
        if (sbj_is_array(v)) {
            v = sbj_arr_at(v, (size_t)atoi(p));
        } else {
            v = sbj_get(v, p);
        }
    }
    sb_strvec_free(&parts);
    return v;
}

static const char *at_str(const sbj *v, const char *path) {
    return sbj_as_str(at(v, path), NULL);
}

static bool at_json(const sbj *v, const char *path, const char *expected) {
    sbj *e = sbj_parse_cstr(expected);
    bool ok = sbj_equal(at(v, path), e);
    sbj_free(e);
    return ok;
}

static sbj *render(const sb_render_request *r, sb_err *err) {
    sb_config_renderer renderer;
    if (sb_config_renderer_init(&renderer, NULL, err) != 0) return NULL;
    return sb_config_renderer_render(&renderer, r, err);
}

TEST(managed_rendering_injects_outbounds_and_script_rules) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"route\":{\"rules\":[],\"final\":\"Proxy\"}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "hk");
    set_host(&r, "{\"id\":\"edge-1\",\"name\":\"edge\"}");
    r.rule_script = sb_strdup(
        "\nfunction buildRules(context) {\n  return [{\n    domain_suffix: [\".example.com\"],\n"
        "    outbound: context.outboundTags.includes(\"hk\") ? \"hk\" : \"direct\"\n  }];\n}\n");
    sb_str_set(&r.clash_controller, "0.0.0.0:9090");
    sb_str_set(&r.clash_secret, "controller-secret");

    sb_err err = {0};
    sbj *config = render(&r, &err);
    REQUIRE(config != NULL);
    CHECK_EQ_INT(sbj_arr_len(at(config, "outbounds")), 3);
    CHECK_STR(at_str(config, "route.final"), "auto");
    CHECK_STR(at_str(config, "route.rules.0.outbound"), "hk");
    CHECK(at_json(config, "route.rules.1.rule_set", "[\"geosite-private\"]"));
    CHECK(at_json(config, "route.rules.3.rule_set", "[\"geosite-cn\"]"));
    CHECK(at_json(config, "route.rules.4.rule_set", "[\"geoip-cn\"]"));
    CHECK_EQ_INT(sbj_arr_len(at(config, "route.rule_set")), 3);
    CHECK(at_json(config, "experimental.cache_file.enabled", "true"));
    CHECK_STR(at_str(config, "experimental.clash_api.secret"), "controller-secret");
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(duplicate_proxy_tags_receive_deterministic_suffixes) {
    sb_proxy_node nodes[2];
    sb_proxy_node_init(&nodes[0]);
    sb_proxy_node_init(&nodes[1]);
    shadowsocks(&nodes[0], "hk");
    shadowsocks(&nodes[1], "hk");
    sbj *outbounds = sb_config_generate_outbounds(nodes, 2, NULL);
    REQUIRE(outbounds != NULL);
    CHECK_STR(at_str(outbounds, "0.tag"), "hk");
    CHECK_STR(at_str(outbounds, "1.tag"), "hk #2");
    sbj_free(outbounds);
    sb_proxy_node_free(&nodes[0]);
    sb_proxy_node_free(&nodes[1]);
}

TEST(urltest_interval_has_a_compatible_idle_timeout) {
    sb_proxy_node node;
    sb_proxy_node_init(&node);
    shadowsocks(&node, "hk");
    sbj *outbounds = sb_config_generate_outbounds(&node, 1, NULL);
    REQUIRE(outbounds != NULL && sbj_arr_len(outbounds) > 0);
    const sbj *automatic = sbj_arr_at(outbounds, sbj_arr_len(outbounds) - 1);
    CHECK_STR(sbj_get_str(automatic, "type", NULL), "urltest");
    CHECK_STR(sbj_get_str(automatic, "interval", NULL), "24h");
    CHECK_STR(sbj_get_str(automatic, "idle_timeout", NULL), "24h");
    sbj_free(outbounds);
    sb_proxy_node_free(&node);
}

TEST(android_managed_rendering_exposes_a_selectable_proxy_group) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"dns\":{\"servers\":[{\"type\":\"local\",\"tag\":\"local-dns\"},"
                    "{\"type\":\"https\",\"tag\":\"secure-dns\",\"server\":\"1.1.1.1\","
                    "\"detour\":\"Proxy\"}]},\"route\":{\"final\":\"Proxy\"}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "hk");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "us");
    set_host(&r, "{\"id\":\"phone\",\"capabilities\":{\"platform\":\"android\"}}");

    sbj *config = render(&r, NULL);
    REQUIRE(config != NULL);
    const sbj *outbounds = at(config, "outbounds");
    const sbj *selector = sbj_arr_at(outbounds, sbj_arr_len(outbounds) - 1);
    CHECK_STR(sbj_get_str(selector, "type", NULL), "selector");
    CHECK_STR(sbj_get_str(selector, "tag", NULL), "Proxy");
    CHECK(at_json(selector, "outbounds", "[\"auto\",\"hk\",\"us\",\"direct\"]"));
    CHECK_STR(at_str(config, "route.final"), "Proxy");
    CHECK_STR(at_str(config, "dns.servers.1.detour"), "Proxy");
    CHECK_EQ_INT(sbj_arr_len(at(config, "route.rules")), 4);
    CHECK(at_json(config, "route.rules.2.rule_set", "[\"geosite-cn\"]"));
    CHECK(at_json(config, "route.rules.3.rule_set", "[\"geoip-cn\"]"));
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(android_dns_follows_a_renamed_selector_when_proxy_is_a_node_tag) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"dns\":{\"servers\":[{\"type\":\"https\",\"tag\":\"secure-dns\","
                    "\"server\":\"1.1.1.1\",\"detour\":\"Proxy\"}]},\"route\":{\"final\":\"Proxy\"}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "Proxy");
    set_host(&r, "{\"capabilities\":{\"platform\":\"android\"}}");

    sbj *config = render(&r, NULL);
    REQUIRE(config != NULL);
    const sbj *outbounds = at(config, "outbounds");
    CHECK_STR(sbj_get_str(sbj_arr_at(outbounds, sbj_arr_len(outbounds) - 1), "tag", NULL),
              "Proxy group");
    CHECK_STR(at_str(config, "dns.servers.0.detour"), "Proxy group");
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(generated_rules_cannot_reference_unknown_outbounds) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"route\":{\"rules\":[]}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "hk");
    r.rule_script = sb_strdup("function buildRules() { return [{outbound: 'missing'}]; }");
    sb_err err = {0};
    sbj *config = render(&r, &err);
    CHECK(config == NULL);
    CHECK(err.code == SB_ERR_SCRIPT);
    CHECK_STR(err.msg, "generated rule references unknown outbound tag: missing");
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(server_priority_routes_survive_quickjs_rule_replacement) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"route\":{\"rules\":[]}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "hk");
    sb_strvec_push(&r.external_route_tags, "sb-easy-network");
    sbj_free(r.priority_route_rules);
    r.priority_route_rules =
        sbj_parse_cstr("[{\"ip_cidr\":[\"10.59.32.0/24\"],\"outbound\":\"sb-easy-network\"}]");
    r.rule_script = sb_strdup("function buildRules() { return [{ domain_suffix: ['.example.com'], "
                              "outbound: 'hk' }]; }");
    sbj *config = render(&r, NULL);
    REQUIRE(config != NULL);
    CHECK(sbj_arr_len(at(config, "route.rules")) >= 6);
    CHECK_STR(at_str(config, "route.rules.0.outbound"), "sb-easy-network");
    CHECK_STR(at_str(config, "route.rules.1.outbound"), "hk");
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(control_plane_route_survives_quickjs_and_uses_the_exact_server_host) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"route\":{\"rules\":[]}}");
    shadowsocks(sb_proxy_node_vec_push(&r.nodes), "hk");
    sb_str_set(&r.control_plane_server, "http://39.108.98.208:51821/api");
    r.rule_script = sb_strdup("function buildRules() { return [{ outbound: 'hk' }]; }");
    sbj *config = render(&r, NULL);
    REQUIRE(config != NULL);
    CHECK(at_json(config, "route.rules.0.ip_cidr", "[\"39.108.98.208/32\"]"));
    CHECK_STR(at_str(config, "route.rules.0.outbound"), "direct");
    CHECK_STR(at_str(config, "route.rules.1.outbound"), "hk");
    sbj_free(config);
    sb_render_request_free(&r);
}

TEST(empty_managed_profiles_fall_back_to_direct) {
    sb_render_request r;
    sb_render_request_init(&r);
    set_profile(&r, "{\"route\":{\"final\":\"auto\"}}");
    sbj *config = render(&r, NULL);
    REQUIRE(config != NULL);
    CHECK_STR(at_str(config, "route.final"), "direct");
    CHECK_STR(at_str(config, "outbounds.0.tag"), "direct");
    sbj_free(config);
    sb_render_request_free(&r);
}
