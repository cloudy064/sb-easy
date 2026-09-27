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
    dst->id = sb_strndup(src->id, src->id_len);
    dst->id_len = src->id_len;
    dst->tag = sb_strndup(src->tag, src->tag_len);
    dst->tag_len = src->tag_len;
    dst->type = sb_strndup(src->type, src->type_len);
    dst->type_len = src->type_len;
    dst->enabled = src->enabled;
    dst->server = sb_strndup(src->server, src->server_len);
    dst->server_len = src->server_len;
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
    sb_str_setn(&out->tag, tag->v.str.ptr, tag->v.str.len);
    out->tag_len = tag->v.str.len;
    const sbj *id = sbj_get(value, "id");
    if (!sbj_is_string(id)) id = tag;
    sb_str_setn(&out->id, id->v.str.ptr, id->v.str.len);
    out->id_len = id->v.str.len;
    const sbj *type = sbj_get(value, "type");
    if (!sbj_is_string(type)) type = sbj_get(value, "node_type");
    if (sbj_is_string(type)) {
        sb_str_setn(&out->type, type->v.str.ptr, type->v.str.len);
        out->type_len = type->v.str.len;
    }
    out->enabled = sbj_get_bool(value, "enabled", true);
    const sbj *server = sbj_get(value, "server");
    if (sbj_is_string(server)) {
        sb_str_setn(&out->server, server->v.str.ptr, server->v.str.len);
        out->server_len = server->v.str.len;
    }
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
    sbj_set(o, "id", sbj_strn(n->id, n->id_len));
    sbj_set(o, "tag", sbj_strn(n->tag, n->tag_len));
    sbj_set(o, "type", sbj_strn(n->type, n->type_len));
    sbj_set_bool(o, "enabled", n->enabled);
    sbj_set(o, "server", sbj_strn(n->server, n->server_len));
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
    r->external_route_tags = sbj_array();
    r->control_plane_server = sb_strdup("");
    r->clash_controller = sb_strdup("");
    r->clash_secret = sb_strdup("");
}

void sb_render_request_free(sb_render_request *r) {
    sbj_free(r->profile);
    sb_proxy_node_vec_free(&r->nodes);
    sbj_free(r->host_context);
    sbj_free(r->external_route_tags);
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
    const char *t = n->node_type;
    const char *first = NULL, *second = NULL;
    if (sb_strn_eq(t, n->node_type_len, "shadowsocks") ||
        sb_strn_eq(t, n->node_type_len, "trojan") || sb_strn_eq(t, n->node_type_len, "hysteria2"))
        first = "password";
    else if (sb_strn_eq(t, n->node_type_len, "vmess") || sb_strn_eq(t, n->node_type_len, "vless"))
        first = "uuid";
    else if (sb_strn_eq(t, n->node_type_len, "tuic")) { first = "uuid"; second = "password"; }
    else if (sb_strn_eq(t, n->node_type_len, "http")) { first = "username"; second = "password"; }
    sb_buf raw = {0};
    sb_buf_append(&raw, n->server ? n->server : "", n->server_len);
    sb_buf_printf(&raw, ":%u:", (unsigned)n->server_port);
    sb_buf_append(&raw, t ? t : "", n->node_type_len);
    sb_buf_putc(&raw, ':');
    const sbj *key = first ? sbj_get(n->protocol_config, first) : NULL;
    if (sbj_is_string(key)) sb_buf_append(&raw, key->v.str.ptr, key->v.str.len);
    if (second) {
        sb_buf_putc(&raw, ':');
        key = sbj_get(n->protocol_config, second);
        if (sbj_is_string(key)) sb_buf_append(&raw, key->v.str.ptr, key->v.str.len);
    }
    char *hex = sb_sha256_hex(raw.p, raw.len);
    sb_buf_free(&raw);
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
