#ifndef SBW_CONTROL_PLANE_H
#define SBW_CONTROL_PLANE_H

#include <windows.h>
#include "../common.h"
#include "sb/json.h"

typedef struct sbw_enrollment_target {
    char *server;
    char *code;
} sbw_enrollment_target;

int sbw_parse_enrollment_uri(const char *uri, sbw_enrollment_target *out, sbw_error *error);
void sbw_enrollment_target_free(sbw_enrollment_target *target);

typedef struct sbw_control_plane {
    void *context;
    int (*enroll)(void *context, const sbw_enrollment_target *target, HANDLE cancel,
                  sbj **identity, sbw_error *error);
    int (*fetch_config)(void *context, const sbj *identity, const char *etag, HANDLE cancel,
                        sbj **download, sbw_error *error);
    int (*upload_capture)(void *context, const sbj *identity, const char *digest,
                          const void *data, size_t length, HANDLE cancel, sbw_error *error);
    int (*report_status)(void *context, const sbj *identity, const sbj *status,
                         HANDLE cancel, sbw_error *error);
    int (*pending_commands)(void *context, const sbj *identity, HANDLE cancel,
                            sbj **commands, sbw_error *error);
    int (*acknowledge_command)(void *context, const sbj *identity, const char *id,
                               const sbj *receipt, HANDLE cancel, sbw_error *error);
    int (*report_telemetry)(void *context, const sbj *identity, const sbj *telemetry,
                            HANDLE cancel, sbw_error *error);
    void (*destroy)(void *context);
} sbw_control_plane;

/* Output JSON is owned by the caller. The cancellation event is borrowed only
 * for the call; WinHTTP callbacks never retain it or caller-owned buffers. */
sbw_control_plane *sbw_winhttp_new(DWORD timeout_ms, sbw_error *error);
void sbw_control_plane_free(sbw_control_plane *client);

/* Separate interactive panel-account transport. HTTPS is mandatory, redirects
 * and ambient credentials/cookies remain disabled. Only fixed auth/preferences
 * endpoints are allowed; callers own outputs and keep session tokens private. */
int sbw_panel_request(void *context, const char *server, const char *method, const char *path,
    const char *token, const char *cookie, const char *if_match, const sbj *body, HANDLE cancel,
    DWORD *status, sbj **response, char **flow_cookie, sbw_error *error);

/* Credential-free HTTPS release downloads with a total deadline. The sink runs
 * on the caller's worker thread and must not retain the borrowed chunk. */
typedef int (*sbw_download_sink)(void *context, const void *data, size_t length, sbw_error *error);
int sbw_https_download(const char *url, uint64_t limit, DWORD timeout_ms, HANDLE cancel,
    sbw_download_sink sink, void *context, uint64_t *received, sbw_error *error);
bool sbw_https_release_url(const char *url);

/* Pure Windows 10 compatibility conversion; an empty advisory name requests
 * fallback to enrollment metadata (or the new profile ID if it changed). */
int sbw_decode_legacy_header(const wchar_t *value, size_t length, bool advisory_name,
                             char **out, sbw_error *error);

#endif
