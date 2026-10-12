#include "routing.h"
#include <stdlib.h>

static bool gpt_rule(const sbj *rule) {
    const sbj *domains = sbj_get(rule, "domain_suffix");
    for (size_t i = 0; i < sbj_arr_len(domains); ++i)
        if (sbj_string_is(sbj_arr_at(domains, i), "openai.com") ||
            sbj_string_is(sbj_arr_at(domains, i), "chatgpt.com")) return true;
    return false;
}
static bool simple_rule(const sbj *rule, const char *target) {
    if (!sb_streq(sbj_get_str(rule, "action", "route"), "route")) return false;
    for (size_t i = 0; i < sbj_obj_len(rule); ++i) {
        const char *key = sbj_obj_key(rule, i);
        if (!sb_streq(key, "domain_suffix") && !sb_streq(key, "action") && !sb_streq(key, target)) return false;
    }
    return true;
}
sbj *sbw_routing_snapshot(const sbj *source, bool gpt_default, sbw_error *error) {
    return sbw_routing_snapshot_node(source, gpt_default, NULL, error);
}
sbj *sbw_routing_snapshot_node(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error) {
    if (!source) return NULL;
    if (!gpt_default && (!outbound || !*outbound)) return sbj_clone(source);
    const sbj *content = sbj_get(source, "content");
    sbj *config = sbj_is_string(content) ? sbw_json_parse(content->v.str.ptr, content->v.str.len, 32, NULL) : NULL;
    sbj *route = sbj_get(config, "route"), *dns = sbj_get(config, "dns");
    const char *final = outbound && *outbound ? outbound : sbj_get_str(route, "final", "");
    sbj *outbounds = sbj_get(config, "outbounds"), *rules = sbj_get(route, "rules");
    sbj *servers = sbj_get(dns, "servers"), *dns_rules = sbj_get(dns, "rules");
    sbj *gpt = NULL, *gpt_dns = NULL, *dns_server = NULL;
    bool found_final = false;
    const char *tag = "sb-easy-windows-gpt-dns";
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        sbj *node = sbj_arr_at(outbounds, i);
        if (final[0] && sb_streq(sbj_get_str(node, "tag", ""), final) &&
            !sb_streq(sbj_get_str(node, "type", ""), "direct") &&
            !sb_streq(sbj_get_str(node, "type", ""), "block")) found_final = true;
    }
    if (!found_final) {
        sbj_free(config);
        sbw_fail(error, "GPT_OUTBOUND_UNAVAILABLE", "The local GPT node is unavailable. Select another node or restore server routing.");
        return NULL;
    }
    for (size_t i = 0; i < sbj_arr_len(rules); ++i) {
        sbj *rule = sbj_arr_at(rules, i);
        if (!gpt_rule(rule)) continue;
        if (gpt || !simple_rule(rule, "outbound")) goto unsupported;
        gpt = rule;
    }
    if (!gpt) goto unsupported;
    for (size_t i = 0; i < sbj_arr_len(dns_rules); ++i) {
        sbj *rule = sbj_arr_at(dns_rules, i);
        if (!gpt_rule(rule)) continue;
        if (gpt_dns || !simple_rule(rule, "server") ||
            !sbj_equal(sbj_get(rule, "domain_suffix"), sbj_get(gpt, "domain_suffix"))) goto unsupported;
        gpt_dns = rule;
    }
    if (!gpt_dns) goto unsupported;
    for (size_t i = 0; i < sbj_arr_len(servers); ++i) {
        sbj *server = sbj_arr_at(servers, i);
        if (sb_streq(sbj_get_str(server, "tag", ""), tag)) goto unsupported;
        if (sb_streq(sbj_get_str(server, "tag", ""), sbj_get_str(gpt_dns, "server", ""))) dns_server = server;
    }
    if (!dns_server || !sbj_get(dns_server, "type")) goto unsupported;
    /* A server can be shared by other services: isolate the GPT DNS detour. */
    sbj *local_dns = sbj_clone(dns_server);
    sbj_set_str(local_dns, "tag", tag);
    sbj_set_str(local_dns, "detour", final);
    sbj_arr_push(servers, local_dns);
    sbj_set_str(gpt_dns, "server", tag);
    sbj_set_str(gpt, "outbound", final);
    sbj *snapshot = sbj_clone(source);
    sbj_set(snapshot, "content", sbj_str_take(sbj_dump(config, -1)));
    sbj_free(config);
    return snapshot;
unsupported:
    sbj_free(config);
    sbw_fail(error, "GPT_ROUTING_UNSUPPORTED", "The GPT route and DNS group cannot be safely overridden. Restore server routing or update the server configuration.");
    return NULL;
}

/* Runtime-only selector: UI/source catalogs retain the actual chosen exit. */
char *sbw_routing_target(const sbj *effective) {
    sbj *config = sbj_parse_cstr(sbj_get_str(effective, "content", ""));
    const sbj *rules = sbj_get(sbj_get(config, "route"), "rules");
    char *target = NULL;
    for (size_t i = 0; i < sbj_arr_len(rules); ++i) {
        const sbj *rule = sbj_arr_at(rules, i);
        if (gpt_rule(rule)) { target = sb_strdup(sbj_get_str(rule, "outbound", "")); break; }
    }
    sbj_free(config); return target;
}
sbj *sbw_routing_runtime(const sbj *source, bool gpt_default, const char *outbound, sbw_error *error) {
    sbj *effective = sbw_routing_snapshot_node(source, gpt_default, outbound, error);
    if (!effective) return NULL;
    char *target = sbw_routing_target(effective);
    if (!target || !*target) { free(target); return effective; }
    /* Always reserve a separate GPT DNS server, including in server mode. */
    sbw_error unsupported = {0};
    sbj *runtime = sbw_routing_snapshot_node(source, false, target, &unsupported);
    if (!runtime) { free(target); return effective; }
    sbj *config = sbj_parse_cstr(sbj_get_str(runtime, "content", ""));
    sbj *outbounds = sbj_get(config, "outbounds"), *members = sbj_array();
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        const sbj *node = sbj_arr_at(outbounds, i);
        const char *tag = sbj_get_str(node, "tag", "");
        if (sb_streq(tag, SBW_GPT_SELECTOR)) {
            sbj_free(members); sbj_free(config); sbj_free(runtime); free(target); return effective;
        }
        if (*tag && !sb_streq(sbj_get_str(node, "type", ""), "block")) sbj_arr_push(members, sbj_str(tag));
    }
    sbj *selector = sbj_object();
    sbj_set_str(selector, "type", "selector"); sbj_set_str(selector, "tag", SBW_GPT_SELECTOR);
    sbj_set(selector, "outbounds", members); sbj_set_str(selector, "default", target);
    /* Preserve existing user connections; internal DNS connections are refreshed by sing-box. */
    sbj_set_bool(selector, "interrupt_exist_connections", false);
    sbj_arr_push(outbounds, selector);
    sbj *rules = sbj_get(sbj_get(config, "route"), "rules");
    for (size_t i = 0; i < sbj_arr_len(rules); ++i)
        if (gpt_rule(sbj_arr_at(rules, i))) sbj_set_str(sbj_arr_at(rules, i), "outbound", SBW_GPT_SELECTOR);
    sbj *servers = sbj_get(sbj_get(config, "dns"), "servers");
    for (size_t i = 0; i < sbj_arr_len(servers); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(servers, i), "tag"), "sb-easy-windows-gpt-dns"))
            sbj_set_str(sbj_arr_at(servers, i), "detour", SBW_GPT_SELECTOR);
    sbj_set(runtime, "content", sbj_str_take(sbj_dump(config, -1)));
    sbj_free(config); free(target); sbj_free(effective); return runtime;
}
