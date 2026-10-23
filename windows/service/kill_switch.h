#ifndef SBW_KILL_SWITCH_H
#define SBW_KILL_SWITCH_H

#include "../common.h"

/* Opt-in, machine-wide persistent WFP policy. Enabling permits only loopback,
 * the fixed service/core executables, the current TUN, and network maintenance
 * (DHCP/NDP). Other applications, including physical-interface DNS, are denied
 * for both address families. No user-provided application exemptions exist.
 *
 * Apply before core startup with tun_alias=NULL, then again after readiness
 * with the owned TUN alias. NULL installs no TUN exemption; an explicitly named
 * but missing interface fails without changing the previous policy.
 * Core/service exit and closing this API's engine handle do NOT remove policy.
 * Explicit disable removes only this product's rules in one transaction.
 * Caller serializes mutations. core_executable must be the pinned absolute path
 * returned by sbw_core_executable; it is ignored when disabling. */
int sbw_kill_switch_apply(bool enabled, const wchar_t *core_executable, const wchar_t *tun_alias,
                          sbw_error *error);

/* Owned, credential-free observation of actual WFP objects, not a saved setting
 * or proof of packet-level leak protection. Keys: available, enabled, error_code,
 * filter_count, tun_allowed, persistent. Never enables/removes policy. */
sbj *sbw_kill_switch_status(void);
typedef enum sbw_kill_startup_action { SBW_KILL_UNCHANGED, SBW_KILL_ENABLE, SBW_KILL_DISABLE, SBW_KILL_PRESERVE_UNKNOWN } sbw_kill_startup_action;
/* Pure startup decision: only a valid persisted boolean authorizes disable. */
sbw_kill_startup_action sbw_kill_switch_startup_action(const sbj *preference, const sbj *observed);

/* Machine recovery override for an elevated local command while the service is
 * stopped. This marker is accessible without decrypting LocalSystem's DPAPI
 * profile. Set it before removing policy; service startup must honor it until
 * its own disabled preference has been durably saved. */
bool sbw_kill_switch_recovery_disabled(void);
int sbw_kill_switch_set_recovery_disabled(bool disabled, sbw_error *error);

#endif
