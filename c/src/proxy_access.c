#include "sb/proxy_access.h"
#include "sb/config_renderer.h"
#include <stdlib.h>
#include <string.h>

bool sb_proxy_access_rule(const sbj *rule) {
    const sbj *in = sbj_get(rule, "inbound");
    return sbj_string_is(in, SB_PROXY_ACCESS_TAG) ||
        (sbj_arr_len(in) == 1 && sbj_string_is(sbj_arr_at(in, 0), SB_PROXY_ACCESS_TAG));
}

static bool text(const sbj *v) {
    return sbj_is_string(v) && v->v.str.len && strlen(v->v.str.ptr) == v->v.str.len;
}

/* Fixed users address database identities, never mutable display names. Only
 * referenced nodes are materialised; a removed/disabled node has no outbound. */
int sb_proxy_access_prepare(const sb_render_request *request, sbj *config, sb_err *err) {
    const sbj *in, *user;
    SBJ_ARR_FOREACH(sbj_get(request->profile, "inbounds"), i, in) {
        if (!sbj_string_is(sbj_get(in, "tag"), SB_PROXY_ACCESS_TAG)) continue;
        SBJ_ARR_FOREACH(sbj_get(in, "users"), j, user) {
            const char *name = sbj_get_str(user, "username", "");
            if (strncmp(name, "node_", 5) != 0) continue;
            const sb_proxy_node *node = NULL;
            for (size_t k = 0; k < request->nodes.len; ++k)
                if (request->nodes.items[k].enabled && sb_strn_eq(request->nodes.items[k].id, request->nodes.items[k].id_len, name + 5))
                    node = &request->nodes.items[k];
            if (!node) continue;
            sbj *out = sb_config_generate_outbound(node, err);
            if (!out) return -1;
            /* Unknown protocols in the generic renderer fall back to direct.
             * That is never acceptable for a pinned proxy identity. */
            if (sbj_string_is(sbj_get(out, "type"), "direct")) { sbj_free(out); continue; }
            char *tag = sb_asprintf(SB_PROXY_NODE_PREFIX "%s", name + 5);
            sbj *outbounds = sbj_get_or_array(config, "outbounds");
            const sbj *existing;
            SBJ_ARR_FOREACH(outbounds, k, existing) {
                if (sbj_string_is(sbj_get(existing, "tag"), tag)) {
                    free(tag); sbj_free(out);
                    return sb_fail(err, SB_ERR_VALIDATION, "Reserved fixed-node outbound already exists");
                }
            }
            sbj_set_str(out, "tag", tag); free(tag);
            sbj_arr_push(outbounds, out);
        }
    }
    return 0;
}

int sb_proxy_access_apply(const sbj *source, sbj *config, bool check_targets, sb_err *err) {
    const sbj *listener = NULL, *item, *user, *outbound;
    SBJ_ARR_FOREACH(sbj_get(source, "inbounds"), i, item) {
        if (!sbj_string_is(sbj_get(item, "tag"), SB_PROXY_ACCESS_TAG)) continue;
        if (listener) return sb_fail(err, SB_ERR_VALIDATION, "Duplicate proxy access listener");
        listener = item;
    }
    if (!listener) return 0;
    const sbj *users = sbj_get(listener, "users");
    if (!sbj_string_is(sbj_get(listener, "type"), "mixed") || !sbj_arr_len(users))
        return sb_fail(err, SB_ERR_VALIDATION, "Proxy access requires a mixed listener with authenticated users");
    int64_t port = sbj_get_int(listener, "listen_port", 0);
    if (port < 1 || port > 65535)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid proxy access port");
    sbj *generated = sbj_array();
    const sbj *rules = sbj_get(sbj_get(source, "route"), "rules");
    SBJ_ARR_FOREACH(users, i, user) {
        const sbj *name = sbj_get(user, "username"), *password = sbj_get(user, "password");
        if (!text(name) || !text(password)) goto invalid;
        for (size_t j = 0; j < i; ++j)
            if (sbj_equal(name, sbj_get(sbj_arr_at(users, j), "username"))) goto invalid;
        const sbj *target = NULL, *rule;
        SBJ_ARR_FOREACH(rules, j, rule) {
            if (!sb_proxy_access_rule(rule)) continue;
            const sbj *auth = sbj_get(rule, "auth_user");
            if (!sbj_equal(auth, name) && !(sbj_arr_len(auth) == 1 && sbj_equal(sbj_arr_at(auth, 0), name))) continue;
            if (target || sbj_obj_len(rule) != 4 || !sbj_string_is(sbj_get(rule, "action"), "route")) goto invalid;
            target = sbj_get(rule, "outbound");
            if (!text(target)) goto invalid;
        }
        if (!target) goto invalid;
        bool fixed = strncmp(name->v.str.ptr, "node_", 5) == 0;
        if (fixed) {
            const char *id = name->v.str.ptr + 5;
            if (!*id || strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(id)) goto invalid;
            char *expected = sb_asprintf(SB_PROXY_NODE_PREFIX "%s", id);
            bool matches = sbj_string_is(target, expected); free(expected);
            if (!matches) goto invalid;
        }
        bool unavailable = false;
        if (check_targets) {
            bool found = false;
            SBJ_ARR_FOREACH(sbj_get(config, "outbounds"), j, outbound)
                if (sbj_equal(sbj_get(outbound, "tag"), target)) found = true;
            if (!found && !fixed) {
                sbj_free(generated);
                return sb_fail(err, SB_ERR_VALIDATION, "Proxy access references unavailable outbound: %s", target->v.str.ptr);
            }
            unavailable = !found;
        }
        sbj *r = sbj_object();
        sbj_set_str(r, "inbound", SB_PROXY_ACCESS_TAG);
        sbj_set(r, "auth_user", sbj_clone(name));
        sbj_set_str(r, "action", unavailable ? "reject" : "route");
        if (!unavailable) sbj_set(r, "outbound", sbj_clone(target));
        sbj_arr_push(generated, r);
    }
    sbj *deny = sbj_object();
    sbj_set_str(deny, "inbound", SB_PROXY_ACCESS_TAG);
    sbj_set_str(deny, "action", "reject");
    sbj_arr_push(generated, deny);
    sbj *route = sbj_get_or_object(config, "route");
    sbj *dest = sbj_get_or_array(route, "rules");
    if (!sbj_is_array(dest)) goto invalid;
    for (size_t i = sbj_arr_len(dest); i > 0; --i)
        if (sb_proxy_access_rule(sbj_arr_at(dest, i - 1))) sbj_arr_remove(dest, i - 1);
    for (size_t i = 0; i < sbj_arr_len(generated); ++i)
        sbj_arr_insert(dest, i, sbj_clone(sbj_arr_at(generated, i)));
    sbj_free(generated);
    return 0;
invalid:
    sbj_free(generated);
    return sb_fail(err, SB_ERR_VALIDATION, "Proxy access needs unique users, nonempty keys and one unconditional outbound per user");
}
