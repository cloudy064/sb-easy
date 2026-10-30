/* Render request assembly for a host. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* ======================================================================
 * render request
 * ====================================================================== */

int sb_store_render_request_for_host(sb_store *s, const char *host_id, sb_render_request *out,
                                     sb_err *err) {
    int rc = -1;
    sb_config_profile profile;
    sb_config_profile_init(&profile);
    sb_proxy_node_vec nodes = {0};
    char *profile_id = NULL;
    sbj *capabilities = NULL;
    sqlite3_stmt *host = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    host = sbq_prepare(h,
                       "SELECT id, name, capabilities, profile_id, clash_api, "
                       "clash_secret FROM hosts WHERE id = ?1",
                       err);
    if (!host) goto done;
    sbq_bind_text(host, 1, S(host_id));
    int r = sbq_step_row(host, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;

    profile_id = sbq_opt_text(host, 3);
    if (!profile_id) profile_id = sb_strdup("default");
    r = find_profile_locked(h, profile_id, &profile, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "host profile not found: %s", profile_id);
    if (r != 1) goto done;

    if (profile.mode == SB_PROFILE_MANAGED) {
        if (read_nodes(h,
                       "SELECT p.id, p.tag, p.node_type, p.enabled, p.server, "
                       "p.server_port, p.protocol_config FROM proxy_nodes p "
                       "JOIN host_outbounds h ON h.node_id = p.id "
                       "WHERE h.host_id = ?1 AND p.enabled = 1 "
                       "ORDER BY p.node_type, p.tag",
                       S(host_id), &nodes, err) != 0)
            goto done;
        if (nodes.len == 0 &&
            read_nodes(h,
                       "SELECT id, tag, node_type, enabled, server, server_port, "
                       "protocol_config FROM proxy_nodes WHERE enabled = 1 "
                       "ORDER BY node_type, tag",
                       NULL, &nodes, err) != 0)
            goto done;
    }

    capabilities = parse_object_col(host, 2, "host capabilities", err);
    if (!capabilities) goto done;

    sb_render_request_free(out);
    sb_render_request_init(out);
    out->mode = profile.mode;
    sbj_free(out->profile);
    out->profile = profile.profile;
    profile.profile = NULL;
    out->nodes = nodes;
    memset(&nodes, 0, sizeof nodes);
    sbj_set(out->host_context, "id", sbj_str_take(sbq_text(host, 0)));
    sbj_set(out->host_context, "name", sbj_strn((const char *)sqlite3_column_text(host, 1),
                                                   (size_t)sqlite3_column_bytes(host, 1)));
    sbj_set(out->host_context, "capabilities", capabilities);
    capabilities = NULL;
    free(out->clash_controller);
    char *clash_api = sbq_opt_text(host, 4);
    out->clash_controller = controller_address(clash_api, (size_t)sqlite3_column_bytes(host, 4),
                                                &out->clash_controller_len);
    free(clash_api);
    free(out->clash_secret);
    out->clash_secret = sbq_text(host, 5);
    out->clash_secret_len = (size_t)sqlite3_column_bytes(host, 5);
    if (profile.rule_script_enabled && profile.rule_script_len > 0) {
        out->rule_script = sb_strndup(profile.rule_script, profile.rule_script_len);
        out->rule_script_len = profile.rule_script_len;
    }

    const sbj *endpoints = sbj_get(out->profile, "endpoints");
    const sbj *endpoint;
    SBJ_ARR_FOREACH(endpoints, i, endpoint) {
        const sbj *tag = sbj_get(endpoint, "tag");
        if (sbj_is_string(tag)) sbj_arr_push(out->external_route_tags, sbj_clone(tag));
    }
    rc = 0;
done:
    sqlite3_finalize(host);
    UNLOCK(s);
    free(profile_id);
    sbj_free(capabilities);
    sb_proxy_node_vec_free(&nodes);
    sb_config_profile_free(&profile);
    return rc;
}


