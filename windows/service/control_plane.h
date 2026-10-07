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
    void (*destroy)(void *context);
} sbw_control_plane;

/* Output JSON is owned by the caller. The cancellation event is borrowed only
 * for the call; WinHTTP callbacks never retain it or caller-owned buffers. */
sbw_control_plane *sbw_winhttp_new(DWORD timeout_ms, sbw_error *error);
void sbw_control_plane_free(sbw_control_plane *client);

/* Pure Windows 10 compatibility conversion; an empty advisory name requests
 * fallback to enrollment metadata (or the new profile ID if it changed). */
int sbw_decode_legacy_header(const wchar_t *value, size_t length, bool advisory_name,
                             char **out, sbw_error *error);

#endif
