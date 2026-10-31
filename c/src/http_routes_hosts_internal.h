/* Private contract between http_routes_hosts.c and http_routes_agent.c:
 * helpers shared by the host/profile routes and the agent routes. */
#ifndef SB_HTTP_ROUTES_HOSTS_INTERNAL_H
#define SB_HTTP_ROUTES_HOSTS_INTERNAL_H

#include <stdbool.h>

#include "http_internal.h"
#include "sb/config_renderer.h"

int fail_json_aware(sb_err *err);
int json_value_string(const sbj *object, const char *key, const char *fallback, const sbj **found_out,
                      const char **out, sb_err *err);
bool json_string_has_nul(const sbj *value);
void respond_ok(sb_http_resp *resp);
const char *route_param(const sb_http_req *req);
sbj *render_config(const sb_render_request *request, sb_err *err);
sbj *commands_to_json(const sb_host_command_vec *commands);
int managed_render_request(sb_http_server *srv, sb_host *host, bool provision_network_identity,
                           const char *control_plane_server, sb_render_request *out, sb_err *err);

/* http_routes_agent.c: the agent routes, device enrollment and host captures. */
void sb_http_register_agent_routes(sb_http_server *srv);

#endif
