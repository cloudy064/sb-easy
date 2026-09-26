/* sb-easy agent control-plane client (C++ agent_client.hpp). */
#ifndef SB_AGENT_CLIENT_H
#define SB_AGENT_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *server;  /* borrowed */
    const char *token;   /* borrowed */
    int64_t timeout_ms;  /* C++ default 15000; must be positive */
} sb_agent_client_options;

typedef struct {
    bool modified;
    char *etag;
    char *body;        /* "" when not modified */
    char *rule_source; /* "profile" when the header is absent */
} sb_agent_config_response;
void sb_agent_config_response_free(sb_agent_config_response *r);

typedef struct {
    const char *server; /* borrowed */
    const char *code;   /* borrowed */
    const sbj *device;  /* borrowed; must be an object (NULL -> {}) */
    int64_t timeout_ms; /* C++ default 15000; must be positive */
} sb_device_enrollment_options;

typedef struct {
    char *server;
    char *host_id;
    char *host_name;
    char *token;
    char *profile_id;
    char *profile_name;
} sb_device_credential;
void sb_device_credential_free(sb_device_credential *c);

/* Redeem the same single-use device enrollment code used by the Android app.
 * The returned bearer token is the device's long-lived internal credential and
 * should be persisted locally instead of exposed in installation commands. */
int sb_enroll_device(const sb_device_enrollment_options *options, sb_device_credential *out,
                     sb_err *err);

typedef struct {
    char *id;
    char *command;
} sb_agent_command;

typedef struct {
    sb_agent_command *items;
    size_t len, cap;
} sb_agent_command_vec;
void sb_agent_command_vec_free(sb_agent_command_vec *v);

typedef struct sb_agent_client sb_agent_client;

/* SB_ERR_VALIDATION for a bad server URL, empty token or bad timeout. */
sb_agent_client *sb_agent_client_new(const sb_agent_client_options *options, sb_err *err);
void sb_agent_client_free(sb_agent_client *client);

/* etag may be NULL. */
int sb_agent_client_poll_config(sb_agent_client *client, const char *etag,
                                sb_agent_config_response *out, sb_err *err);
int sb_agent_client_pending_commands(sb_agent_client *client, sb_agent_command_vec *out,
                                     sb_err *err);
/* result may be NULL (JSON null). */
int sb_agent_client_acknowledge_command(sb_agent_client *client, const char *id, bool success,
                                        const char *result, sb_err *err);
/* running: NULL -> null; etag: NULL -> null. */
int sb_agent_client_report_status(sb_agent_client *client, const char *version,
                                  const bool *running, const char *etag, sb_err *err);
int sb_agent_client_report_telemetry(sb_agent_client *client, const sbj *telemetry,
                                     sb_err *err);
/* Stores the server's "updated" count in *updated. */
int sb_agent_client_report_proxy_latencies(sb_agent_client *client, const sbj *results,
                                           size_t *updated, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
