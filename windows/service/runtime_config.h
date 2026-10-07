#ifndef SBW_RUNTIME_CONFIG_H
#define SBW_RUNTIME_CONFIG_H

#include "../common.h"

typedef struct sbw_runtime_config {
    char *json;                 /* private adapted bytes, never expose to UI */
    char *secret;               /* ephemeral local API bearer secret */
    unsigned short port;       /* 127.0.0.1 only; ownership checked by health */
    bool has_tun;
    bool auto_route;            /* copied from candidate; never enabled implicitly */
    wchar_t *interface_name;   /* NULL without TUN; restricted name, default sb-easy */
} sbw_runtime_config;

/* Output must be initially zeroed. Candidate bytes are not modified. */
int sbw_runtime_config_prepare(const char *json, size_t length, const char *server,
                               sbw_runtime_config *out, sbw_error *error);
void sbw_runtime_config_free(sbw_runtime_config *config);
/* Readiness of this exact process' authenticated loopback API, not proof of
 * internet reachability. Retries startup until the overall deadline. */
int sbw_runtime_config_health(const sbw_runtime_config *config, DWORD expected_pid,
                              HANDLE cancel, DWORD timeout_ms, sbw_error *error);
/* Fixed read-only endpoints, authenticated to the owned process; bounded JSON.
 * The caller owns *out. Never return the API secret or private config. */
int sbw_runtime_config_get(const sbw_runtime_config *config, DWORD expected_pid,
                           HANDLE cancel, const char *path, sbj **out, sbw_error *error);

#endif
