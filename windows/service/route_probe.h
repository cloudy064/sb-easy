#ifndef SBW_ROUTE_PROBE_H
#define SBW_ROUTE_PROBE_H
#include "runtime_config.h"
#include "core_process.h"
/* Runs a real HTTP(S) GET through the authenticated, process-owned local
 * diagnostic inbound. The caller serializes probes/config changes and owns
 * the returned JSON. Remote response bodies, cookies and credentials never
 * enter the result. A transport failure is a result with success=false;
 * invalid input, cancellation and failed local ownership checks return NULL. */
sbj *sbw_route_probe(const sbw_runtime_config *config, sbw_core *core, DWORD pid,
                     HANDLE cancel, const sbj *params, sbw_error *error);
/* Real core URL test for a node or selector, without changing its selection. */
sbj *sbw_route_delay(const sbw_runtime_config *config, DWORD pid, HANDLE cancel,
                     const sbj *params, sbw_error *error);
#endif
