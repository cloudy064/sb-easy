#ifndef SBW_RUNTIME_CONFIG_H
#define SBW_RUNTIME_CONFIG_H

#include "../common.h"

typedef struct sbw_runtime_config {
    char *json;                 /* private adapted bytes, never expose to UI */
    char *secret;               /* ephemeral local API bearer secret */
    unsigned short port;       /* 127.0.0.1 only; ownership checked by health */
    unsigned short probe_port; /* authenticated HTTP diagnostic inbound */
    char *probe_secret;        /* separate ephemeral proxy credential; private */
    bool has_tun;
    bool auto_route;            /* copied from candidate; never enabled implicitly */
    bool remote_rule_sets;      /* first start may download rule-set data */
    wchar_t *interface_name;   /* NULL without TUN; restricted name, default sb-easy */
} sbw_runtime_config;

/* Output must be initially zeroed. Candidate bytes are not modified. */
int sbw_runtime_config_prepare(const char *json, size_t length, const char *server,
                               sbw_runtime_config *out, sbw_error *error);
void sbw_runtime_config_free(sbw_runtime_config *config);
/* Local interface/route evidence only, not an Internet or node reachability test. */
sbj *sbw_runtime_ipv6_status(const sbw_runtime_config *config, bool running);
/* Readiness of this exact process' authenticated loopback API, not proof of
 * internet reachability. Retries startup until the overall deadline. */
int sbw_runtime_config_health(const sbw_runtime_config *config, DWORD expected_pid,
                              HANDLE cancel, DWORD timeout_ms, sbw_error *error);
/* Fixed read-only endpoints, authenticated to the owned process; bounded JSON.
 * The caller owns *out. Never return the API secret or private config. */
int sbw_runtime_config_get(const sbw_runtime_config *config, DWORD expected_pid,
                           HANDLE cancel, const char *path, sbj **out, sbw_error *error);

int sbw_runtime_select_gpt(const sbw_runtime_config *config, DWORD pid, HANDLE cancel,
                           const char *target, sbw_error *error);
int sbw_runtime_select_group(const sbw_runtime_config *config, DWORD pid, HANDLE cancel,
                           const char *selector, const char *target, sbw_error *error);
/* Rechecks TCP listener ownership before any diagnostic proxy credential is
 * sent. No request may bypass this check or fall back to a direct request. */
int sbw_runtime_probe_owner(const sbw_runtime_config *config, DWORD pid, sbw_error *error);
int sbw_runtime_delay(const sbw_runtime_config *config, DWORD pid, HANDLE cancel,
                       const char *target, const char *url, DWORD timeout_ms,
                       sbj **out, sbw_error *error);
#define SBW_PROBE_INBOUND "sb-easy-diagnostic"

#endif
