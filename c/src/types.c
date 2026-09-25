#include "sb/types.h"

#include <stdlib.h>
#include <string.h>

const char *sb_profile_mode_name(sb_profile_mode mode) {
    return mode == SB_PROFILE_FULL ? "full" : "managed";
}

int sb_profile_mode_parse(const char *name, sb_profile_mode *out) {
    if (sb_streq(name, "managed")) *out = SB_PROFILE_MANAGED;
    else if (sb_streq(name, "full")) *out = SB_PROFILE_FULL;
    else return -1;
    return 0;
}

/* ---- proxy node ------------------------------------------------------ */

void sb_proxy_node_init(sb_proxy_node *n) {
    memset(n, 0, sizeof *n);
    n->id = sb_strdup("");
    n->tag = sb_strdup("");
    n->type = sb_strdup("");
    n->server = sb_strdup("");
    n->enabled = true;
    n->protocol_config = sbj_object();
}

void sb_proxy_node_free(sb_proxy_node *n) {
    free(n->id);
    free(n->tag);
    free(n->type);
    free(n->server);
    sbj_free(n->protocol_config);
    memset(n, 0, sizeof *n);
}

void sb_proxy_node_copy(sb_proxy_node *dst, const sb_proxy_node *src) {
    dst->id = sb_strdup(src->id);
    dst->tag = sb_strdup(src->tag);
    dst->type = sb_strdup(src->type);
    dst->enabled = src->enabled;
    dst->server = sb_strdup(src->server);
    dst->server_port = src->server_port;
    dst->protocol_config = sbj_clone(src->protocol_config);
}

int sb_proxy_node_from_json(const sbj *value, sb_proxy_node *out, sb_err *err) {
    sb_proxy_node_init(out);
    const sbj *tag = sbj_get(value, "tag");
    if (!sbj_is_string(tag)) {
        sb_proxy_node_free(out);
        return sb_fail(err, SB_ERR_VALIDATION, "proxy node requires a string tag");
    }
    sb_str_set(&out->tag, tag->v.str.ptr);
    sb_str_set(&out->id, sbj_get_str(value, "id", out->tag));
    sb_str_set(&out->type, sbj_get_str(value, "type", sbj_get_str(value, "node_type", "")));
    out->enabled = sbj_get_bool(value, "enabled", true);
    sb_str_set(&out->server, sbj_get_str(value, "server", ""));
    int64_t port = sbj_get_int(value, "server_port", 0);
    if (port < 0 || port > 65535) {
        sb_proxy_node_free(out);
        return sb_fail(err, SB_ERR_VALIDATION, "proxy server_port is out of range");
    }
    out->server_port = (uint16_t)port;
    const sbj *pc = sbj_get(value, "protocol_config");
    sbj *config = NULL;
    if (sbj_is_string(pc)) {
        config = sbj_parse(pc->v.str.ptr, pc->v.str.len, NULL, 0);
        if (!config) {
            sb_proxy_node_free(out);
            return sb_fail(err, SB_ERR_VALIDATION, "protocol_config is not valid JSON");
        }
    } else if (pc) {
        config = sbj_clone(pc);
    }
    if (!sbj_is_object(config)) {
        sbj_free(config);
        config = sbj_object();
    }
    sbj_free(out->protocol_config);
    out->protocol_config = config;
    return 0;
}

sbj *sb_proxy_node_to_json(const sb_proxy_node *n) {
    sbj *o = sbj_object();
    sbj_set_str(o, "id", n->id);
    sbj_set_str(o, "tag", n->tag);
    sbj_set_str(o, "type", n->type);
    sbj_set_bool(o, "enabled", n->enabled);
    sbj_set_str(o, "server", n->server);
    sbj_set_int(o, "server_port", n->server_port);
    sbj_set(o, "protocol_config", sbj_clone(n->protocol_config));
    return o;
}

sb_proxy_node *sb_proxy_node_vec_push(sb_proxy_node_vec *v) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof *v->items);
    }
    sb_proxy_node *n = &v->items[v->len++];
    sb_proxy_node_init(n);
    return n;
}

void sb_proxy_node_vec_free(sb_proxy_node_vec *v) {
    for (size_t i = 0; i < v->len; ++i) sb_proxy_node_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof *v);
}

/* ---- render request -------------------------------------------------- */

void sb_render_request_init(sb_render_request *r) {
    memset(r, 0, sizeof *r);
    r->mode = SB_PROFILE_MANAGED;
    r->profile = sbj_object();
    r->host_context = sbj_object();
    r->priority_route_rules = sbj_array();
    r->control_plane_server = sb_strdup("");
    r->clash_controller = sb_strdup("");
    r->clash_secret = sb_strdup("");
}

void sb_render_request_free(sb_render_request *r) {
    sbj_free(r->profile);
    sb_proxy_node_vec_free(&r->nodes);
    sbj_free(r->host_context);
    sb_strvec_free(&r->external_route_tags);
    sbj_free(r->priority_route_rules);
    free(r->control_plane_server);
    free(r->rule_script);
    free(r->clash_controller);
    free(r->clash_secret);
    memset(r, 0, sizeof *r);
}

/* ---- parsed node ----------------------------------------------------- */

void sb_parsed_node_init(sb_parsed_node *n) {
    memset(n, 0, sizeof *n);
    n->node_type = sb_strdup("");
    n->tag = sb_strdup("");
    n->server = sb_strdup("");
    n->protocol_config = sbj_object();
}

void sb_parsed_node_free(sb_parsed_node *n) {
    free(n->node_type);
    free(n->tag);
    free(n->server);
    sbj_free(n->protocol_config);
    memset(n, 0, sizeof *n);
}

char *sb_parsed_node_fingerprint(const sb_parsed_node *n) {
    const sbj *pc = n->protocol_config;
    const char *t = n->node_type ? n->node_type : "";
    char *key;
    if (!strcmp(t, "shadowsocks") || !strcmp(t, "trojan") || !strcmp(t, "hysteria2"))
        key = sb_strdup(sbj_get_str(pc, "password", ""));
    else if (!strcmp(t, "vmess") || !strcmp(t, "vless"))
        key = sb_strdup(sbj_get_str(pc, "uuid", ""));
    else if (!strcmp(t, "tuic"))
        key = sb_asprintf("%s:%s", sbj_get_str(pc, "uuid", ""), sbj_get_str(pc, "password", ""));
    else if (!strcmp(t, "http"))
        key = sb_asprintf("%s:%s", sbj_get_str(pc, "username", ""), sbj_get_str(pc, "password", ""));
    else
        key = sb_strdup("");
    char *raw = sb_asprintf("%s:%u:%s:%s", n->server ? n->server : "", (unsigned)n->server_port, t, key);
    char *hex = sb_sha256_hex(raw, strlen(raw));
    free(raw);
    free(key);
    return hex;
}

sb_parsed_node *sb_parsed_node_vec_push(sb_parsed_node_vec *v) {
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = sb_xrealloc(v->items, v->cap * sizeof *v->items);
    }
    sb_parsed_node *n = &v->items[v->len++];
    sb_parsed_node_init(n);
    return n;
}

void sb_parsed_node_vec_free(sb_parsed_node_vec *v) {
    for (size_t i = 0; i < v->len; ++i) sb_parsed_node_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof *v);
}
