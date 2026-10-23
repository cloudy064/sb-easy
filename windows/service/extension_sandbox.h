#ifndef SBW_EXTENSION_SANDBOX_H
#define SBW_EXTENSION_SANDBOX_H
#include "../common.h"
typedef struct sbw_extension_sandbox sbw_extension_sandbox;
/* Known plugin ID and host-selected installation root only. No permissive
 * fallback: failure to establish the OS boundary prevents process creation. */
sbw_extension_sandbox *sbw_extension_sandbox_new(const char *id,const wchar_t *root,sbw_error *error);
void sbw_extension_sandbox_free(sbw_extension_sandbox *sandbox);
const SECURITY_CAPABILITIES *sbw_extension_sandbox_capabilities(sbw_extension_sandbox *sandbox);
const wchar_t *sbw_extension_sandbox_environment(sbw_extension_sandbox *sandbox);
const wchar_t *sbw_extension_sandbox_directory(sbw_extension_sandbox *sandbox);
bool sbw_extension_sandbox_verify_process(sbw_extension_sandbox *sandbox,HANDLE process);
#endif
