#ifndef SBW_UPDATE_TRANSACTION_H
#define SBW_UPDATE_TRANSACTION_H
#include "../common.h"
int sbw_update_registered_version(char output[32], sbw_error *error);
/* Fixed SCM service and fixed protected staging paths only. */
int sbw_update_launch_recovery(sbw_error *error);
#endif
