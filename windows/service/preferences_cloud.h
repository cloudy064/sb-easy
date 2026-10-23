#ifndef SBW_PREFERENCES_CLOUD_H
#define SBW_PREFERENCES_CLOUD_H
#include "preferences.h"
#include "control_plane.h"
typedef struct sbw_preferences_cloud sbw_preferences_cloud;
typedef int (*sbw_panel_send)(void *context, const char *server, const char *method, const char *path,
    const char *token, const char *cookie, const char *if_match, const sbj *body, HANDLE cancel,
    DWORD *status, sbj **response, char **flow_cookie, sbw_error *error);
/* Session credentials are memory-only and never returned. Caller serializes. */
sbw_preferences_cloud *sbw_preferences_cloud_new(sbw_panel_send send, void *context);
void sbw_preferences_cloud_free(sbw_preferences_cloud *cloud);
sbj *sbw_preferences_cloud_status(const sbw_preferences_cloud *cloud);
/* login {server,username,password}; every following call requires its random
 * session_id capability returned to that window. mfa {session_id,code},
 * logout/get {session_id}, put {session_id,revision,envelope},
 * delete {session_id,revision}; revision must match a reviewed GET. */
sbj *sbw_preferences_cloud_call(sbw_preferences_cloud *cloud, const char *operation,
    const sbj *params, HANDLE cancel, sbw_error *error);
#endif
