#include "test.h"
#include "sb/tailscale.h"

TEST(tailscale_validation_is_strict_and_byte_safe) {
    const char *invalid[] = {
        "null", "[]", "{\"enabled\":1}", "{\"accept_routes\":\"true\"}",
        "{\"hostname\":\"-invalid\"}", "{\"hostname\":\"a.b\"}",
        "{\"hostname\":\"valid\\u0000hidden\"}", "{\"auth_key\":\"abc\\nxyz\"}",
        "{\"auth_key\":\"abc\\u0000xyz\"}", "{\"enabled\\u0000x\":true}",
        "{\"control_url\":\"file:///tmp/x\"}", "{\"control_url\":\"https://u:p@example.com\"}",
        "{\"control_url\":\"https://example.com?secret=x\"}",
        "{\"control_url\":\"https://\"}", "{\"control_url\":\"http://example.com\\u0000bad\"}",
        "{\"route_cidrs\":\"10.0.0.0/8\"}", "{\"route_cidrs\":[\"10.0.0.0/33\"]}",
        "{\"route_cidrs\":[\"2001:db8::/129\"]}", "{\"route_cidrs\":[\"10.0.0.0\"]}",
        "{\"route_cidrs\":[\"10.0.0.0/8x\"]}", "{\"route_cidrs\":[\"10.0.0.0/+8\"]}",
        "{\"advertise_routes\":[\"0.0.0.0/0\"]}", "{\"advertise_routes\":[\"::/0\"]}",
        "{\"advertise_routes\":[false]}", "{\"system_interface\":true}"
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        sb_err err = {0};
        sbj *value = sbj_parse_cstr(invalid[i]);
        CHECK(sb_tailscale_validate(value, &err) == -1);
        CHECK_EQ_INT(err.code, SB_ERR_VALIDATION);
        sbj_free(value);
    }
    sbj *valid = sbj_parse_cstr("{\"enabled\":true,\"hostname\":\"node-1\","
        "\"auth_key\":\"tskey-auth-example\",\"control_url\":\"https://headscale.example.com/control\","
        "\"route_cidrs\":[\"10.0.0.0/8\",\"2001:db8::/64\"],\"advertise_routes\":[\"192.168.1.0/24\"]}");
    sb_err err = {0};
    CHECK_EQ_INT(sb_tailscale_validate(valid, &err), 0);
    sbj_free(valid);
}

TEST(tailscale_key_updates_preserve_clear_and_redact) {
    sbj *settings = sbj_object();
    sb_err err = {0};
    sbj *patch = sbj_parse_cstr("{\"enabled\":true,\"auth_key\":\"tskey-auth-private\"}");
    REQUIRE(sb_tailscale_update(&settings, patch, &err) == 0);
    sbj_free(patch);
    patch = sbj_parse_cstr("{\"hostname\":\"renamed\",\"has_auth_key\":false}");
    REQUIRE(sb_tailscale_update(&settings, patch, &err) == 0);
    sbj_free(patch);
    CHECK_STR(sbj_get_str(settings, "auth_key", ""), "tskey-auth-private");
    CHECK(!sbj_has(settings, "has_auth_key"));
    sbj *public = sb_tailscale_public(settings);
    CHECK(!sbj_has(public, "auth_key"));
    CHECK(sbj_get_bool(public, "has_auth_key", false));
    sbj_free(public);
    patch = sbj_parse_cstr("{\"hostname\":\"invalid.name\",\"auth_key\":\"\"}");
    CHECK(sb_tailscale_update(&settings, patch, &err) == -1);
    CHECK_STR(sbj_get_str(settings, "auth_key", ""), "tskey-auth-private");
    sbj_free(patch);
    patch = sbj_parse_cstr("{\"enabled\":false,\"auth_key\":\"\",\"hostname\":\"\",\"control_url\":\"\"}");
    CHECK_EQ_INT(sb_tailscale_update(&settings, patch, &err), 0);
    public = sb_tailscale_public(settings);
    CHECK(!sb_tailscale_enabled(settings));
    CHECK(!sbj_get_bool(public, "has_auth_key", true));
    sbj_free(public); sbj_free(patch); sbj_free(settings);
}

TEST(tailscale_render_protects_routes_and_separates_transports) {
    sb_render_request request;
    sb_render_request_init(&request);
    sbj *settings = sbj_parse_cstr("{\"enabled\":true,\"auth_key\":\"private-key\","
        "\"accept_routes\":true,\"route_cidrs\":[\"192.168.55.0/24\"],"
        "\"advertise_routes\":[\"192.168.66.0/24\"],\"advertise_exit_node\":true}");
    sb_err err = {0};
    REQUIRE(sb_tailscale_render(&request, settings, "host-123", &err) == 0);
    CHECK_EQ_INT(request.nodes.len, 0);
    CHECK_EQ_INT(sbj_arr_len(request.network_outbounds), 1);
    CHECK(!sbj_has(request.host_context, "tailscale"));
    const sbj *ep = sbj_arr_at(sbj_get(request.profile, "endpoints"), 0);
    CHECK_STR(sbj_get_str(ep, "type", ""), "tailscale");
    CHECK_STR(sbj_get_str(ep, "auth_key", ""), "private-key");
    CHECK_STR(sbj_get_str(ep, "hostname", ""), "sb-easy-host123");
    CHECK_STR(sbj_get_str(ep, "state_directory", ""), "data/tailscale");
    CHECK(!sbj_has(ep, "detour"));
    CHECK(sbj_get_bool(ep, "advertise_exit_node", false));
    CHECK_EQ_INT(sbj_arr_len(request.priority_route_rules), 3);
    const sbj *incoming = sbj_arr_at(request.priority_route_rules, 0);
    CHECK_STR(sbj_get_str(incoming, "inbound", ""), "sb-easy-tailscale");
    CHECK_STR(sbj_get_str(incoming, "outbound", ""), "sb-easy-tailscale-direct");
    const sbj *cidrs = sbj_get(sbj_arr_at(request.priority_route_rules, 1), "ip_cidr");
    CHECK_STR(sbj_as_str(sbj_arr_at(cidrs, 0), ""), "100.64.0.0/10");
    CHECK_STR(sbj_as_str(sbj_arr_at(cidrs, 1), ""), "fd7a:115c:a1e0::/48");
    CHECK_STR(sbj_as_str(sbj_arr_at(cidrs, 2), ""), "192.168.55.0/24");
    CHECK_STR(sbj_get_str(sbj_arr_at(request.priority_route_rules, 2), "preferred_by", ""), "sb-easy-tailscale");
    sb_render_request_free(&request); sbj_free(settings);
}

TEST(tailscale_render_preserves_disabled_profiles_and_avoids_collisions) {
    sb_render_request request;
    sb_render_request_init(&request);
    sbj_free(request.profile);
    request.profile = sbj_parse_cstr("{\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"sb-easy-tailscale\"}],"
        "\"outbounds\":[{\"type\":\"socks\",\"tag\":\"sb-easy-tailscale-direct\"}]}");
    sbj *settings = sbj_object(), *before = sbj_clone(request.profile);
    sb_err err = {0};
    CHECK_EQ_INT(sb_tailscale_render(&request, settings, "self", &err), 0);
    CHECK(sbj_equal(before, request.profile));
    CHECK_EQ_INT(sbj_arr_len(request.priority_route_rules), 0);
    sbj_set_bool(settings, "enabled", true);
    request.mode = SB_PROFILE_FULL;
    CHECK_EQ_INT(sb_tailscale_render(&request, settings, "self", &err), 0);
    const sbj *ep = sbj_arr_at(sbj_get(request.profile, "endpoints"), 1);
    CHECK_STR(sbj_get_str(ep, "tag", ""), "sb-easy-tailscale-next");
    CHECK_STR(sbj_get_str(sbj_arr_at(request.network_outbounds, 0), "tag", ""), "sb-easy-tailscale-direct-next");
    CHECK_STR(sbj_get_str(ep, "hostname", ""), "sb-easy-self");
    CHECK(!sbj_has(ep, "auth_key"));
    sbj_free(before); sbj_free(settings); sb_render_request_free(&request);
}
