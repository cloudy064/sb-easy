#ifndef SB_PROXY_ACCESS_H
#define SB_PROXY_ACCESS_H
#include "sb/json.h"
#include "sb/types.h"
#define SB_PROXY_ACCESS_TAG "sb-easy-access"
#define SB_PROXY_NODE_PREFIX "sb-easy-node-"
int sb_proxy_access_prepare(const sb_render_request *request, sbj *config, sb_err *err);
/* Reserved authenticated listener rules precede domain/local/script rules. */
bool sb_proxy_access_rule(const sbj *rule);
int sb_proxy_access_apply(const sbj *source, sbj *config, bool check_targets, sb_err *err);
#endif
