#ifndef SBW_EXTENSION_PROCESS_H
#define SBW_EXTENSION_PROCESS_H
#include "../common.h"
typedef struct sbw_extension_process sbw_extension_process;
sbw_extension_process *sbw_extension_process_new(const wchar_t *relative, sbw_error *error);
void sbw_extension_process_free(sbw_extension_process *process);
bool sbw_extension_process_running(sbw_extension_process *process);
const wchar_t *sbw_extension_process_work_directory(sbw_extension_process *process);
/* Privileged capture broker only; never accepts a handle from an RPC request. */
bool sbw_extension_process_duplicate(sbw_extension_process *process,HANDLE source,HANDLE *remote);
sbj *sbw_extension_process_call(sbw_extension_process *process, const char *method, const sbj *params, sbw_error *error);
#endif
