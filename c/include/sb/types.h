/* Plain data types shared across modules (renderer, parser, store, server).
 * All char* members are owned (malloc'd) unless noted; each type has a
 * *_free() that releases members but not the struct itself. */
#ifndef SB_TYPES_H
#define SB_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { SB_PROFILE_MANAGED = 0, SB_PROFILE_FULL = 1 } sb_profile_mode;
const char *sb_profile_mode_name(sb_profile_mode mode); /* "managed" / "full" */
int sb_profile_mode_parse(const char *name, sb_profile_mode *out); /* 0 ok */

/* C++ ProxyNode (config_renderer.hpp). */
typedef struct {
    char *id;
    char *tag;
    size_t tag_len, server_len;
    char *type;
    size_t id_len, type_len;
    bool enabled;
    char *server;
    uint16_t server_port;
    sbj *protocol_config; /* object; never NULL after init */
} sb_proxy_node;

void sb_proxy_node_init(sb_proxy_node *n);
void sb_proxy_node_free(sb_proxy_node *n);
void sb_proxy_node_copy(sb_proxy_node *dst, const sb_proxy_node *src);
/* from_json / to_json equivalents. */
int sb_proxy_node_from_json(const sbj *value, sb_proxy_node *out, sb_err *err);
sbj *sb_proxy_node_to_json(const sb_proxy_node *n);

typedef struct {
    sb_proxy_node *items;
    size_t len, cap;
} sb_proxy_node_vec;
sb_proxy_node *sb_proxy_node_vec_push(sb_proxy_node_vec *v); /* returns initialised slot */
void sb_proxy_node_vec_free(sb_proxy_node_vec *v);

/* C++ RenderRequest. */
typedef struct {
    sb_profile_mode mode;
    sbj *profile;               /* object */
    sb_proxy_node_vec nodes;
    sbj *host_context;          /* object */
    sbj *external_route_tags; /* array of byte strings */
    sbj *priority_route_rules;  /* array */
    char *control_plane_server; /* "" when unset */
    char *rule_script;          /* NULL == std::nullopt */
    size_t rule_script_len;     /* exact byte length when present */
    char *clash_controller;
    char *clash_secret;
} sb_render_request;

void sb_render_request_init(sb_render_request *r);
void sb_render_request_free(sb_render_request *r);

/* C++ ParsedProxyNode (proxy_parser.hpp). */
typedef struct {
    char *node_type;
    size_t node_type_len;
    char *tag;
    size_t tag_len, server_len;
    char *server;
    uint16_t server_port;
    sbj *protocol_config; /* object */
} sb_parsed_node;

void sb_parsed_node_init(sb_parsed_node *n);
void sb_parsed_node_free(sb_parsed_node *n);
/* ParsedProxyNode::fingerprint(); malloc'd. */
char *sb_parsed_node_fingerprint(const sb_parsed_node *n);

typedef struct {
    sb_parsed_node *items;
    size_t len, cap;
} sb_parsed_node_vec;
sb_parsed_node *sb_parsed_node_vec_push(sb_parsed_node_vec *v);
void sb_parsed_node_vec_free(sb_parsed_node_vec *v);

#ifdef __cplusplus
}
#endif

#endif
