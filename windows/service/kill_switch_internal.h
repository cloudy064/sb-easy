#ifndef SBW_KILL_SWITCH_INTERNAL_H
#define SBW_KILL_SWITCH_INTERNAL_H

#include "kill_switch.h"
#include <fwpmu.h>

/* A testable policy emitter; callbacks receive borrowed, ephemeral structures.
 * Production sends these exact filters to FwpmFilterAdd0. Tests inspect them
 * without opening BFE or changing the host firewall. */
typedef DWORD (*sbw_kill_filter_sink)(void *context, const FWPM_FILTER0 *filter);
DWORD sbw_kill_switch_build(const FWP_BYTE_BLOB *service_app, const FWP_BYTE_BLOB *core_app,
                            const FWP_BYTE_BLOB *dhcp_app, UINT64 tun_luid, sbw_kill_filter_sink sink,
                            void *context);

extern const GUID sbw_kill_provider_key, sbw_kill_sublayer_key;
extern const GUID sbw_kill_layers[4]; /* connect4, connect6, receive4, receive6 */
extern const GUID sbw_kill_app_id, sbw_kill_flags, sbw_kill_nexthop, sbw_kill_arrival;
extern const GUID sbw_kill_protocol, sbw_kill_local_port, sbw_kill_remote_port, sbw_kill_remote_address;
GUID sbw_kill_filter_key(unsigned index);

#define SBW_KILL_FILTER_SLOTS 128U
#define SBW_KILL_PERSISTENT 0x00000001U
#define SBW_KILL_DISABLED 0x00000020U

#endif
