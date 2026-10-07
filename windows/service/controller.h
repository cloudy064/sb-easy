#ifndef SB_WINDOWS_CONTROLLER_H
#define SB_WINDOWS_CONTROLLER_H
#include "control_plane.h"
#include "secure_store.h"
#include "../runtime/state.h"
#include "core_process.h"

typedef struct sbw_controller sbw_controller;
/* Takes ownership of remote/store, including on failure. cancel is borrowed. */
sbw_controller *sbw_controller_new(sbw_control_plane *remote, sbw_store *store,
                                 HANDLE cancel, sbw_error *error);
void sbw_controller_free(sbw_controller *controller);
/* Startup-only attachment; owns core. An unavailable core does not block enrollment. */
void sbw_controller_set_core(sbw_controller *controller, sbw_core *core, const sbw_error *error);
/* The returned JSON is caller-owned. No response contains credentials/config. */
sbj *sbw_controller_dispatch(sbw_controller *controller, const char *method,
                             const sbj *params, bool authorized, sbw_error *error);
bool sbw_is_mutating_method(const char *method);
/* Nonblocking when a mutation owns the controller; observes exit and clears
 * stale active metadata. The service also monitors health while UI is closed. */
void sbw_controller_poll(sbw_controller *controller);
#endif
