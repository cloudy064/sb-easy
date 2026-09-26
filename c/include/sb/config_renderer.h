/* sing-box configuration renderer (port of cpp config_renderer.hpp).
 * sb_proxy_node / sb_render_request live in sb/types.h. */
#ifndef SB_CONFIG_RENDERER_H
#define SB_CONFIG_RENDERER_H

#include <stddef.h>

#include "sb/json.h"
#include "sb/script_engine.h"
#include "sb/types.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    sb_rule_script_engine scripts;
} sb_config_renderer;

/* limits == NULL -> default script limits. */
int sb_config_renderer_init(sb_config_renderer *renderer, const sb_script_limits *limits,
                            sb_err *err);

/* Renders the final sing-box config. Errors: SB_ERR_VALIDATION
 * (std::invalid_argument), SB_ERR_SCRIPT (ScriptError), SB_ERR_GENERIC
 * (nlohmann type errors on malformed input). */
sbj *sb_config_renderer_render(const sb_config_renderer *renderer,
                               const sb_render_request *request, sb_err *err);

/* Single node -> outbound object. NULL only on malformed protocol_config
 * (e.g. non-numeric vmess alter_id). */
sbj *sb_config_generate_outbound(const sb_proxy_node *node, sb_err *err);
/* Enabled nodes -> outbounds (duplicate tags suffixed " #N") plus "auto" URLTest. */
sbj *sb_config_generate_outbounds(const sb_proxy_node *nodes, size_t count, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
