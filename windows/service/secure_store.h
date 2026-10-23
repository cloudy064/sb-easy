#ifndef SBW_SECURE_STORE_H
#define SBW_SECURE_STORE_H

#include "../common.h"
#include "sb/json.h"
#include <stdbool.h>
#include <windows.h>

typedef struct sbw_store {
    void *context;
    /* Success is 0; -1 fills a public-safe error. A missing envelope yields NULL. */
    int (*load)(void *context, sbj **out, sbw_error *error);
    int (*save)(void *context, const sbj *state, sbw_error *error);
    int (*clear)(void *context, sbw_error *error);
    void (*destroy)(void *context);
} sbw_store;

/* DPAPI user-scope device-state.dat stays compatible with the first preview.
 * The store owns state.lock and pinned, no-delete-sharing directory handles. */
sbw_store *sbw_secure_store_new(const wchar_t *directory, sbw_error *error);
void sbw_store_free(sbw_store *store);
/* Caller frees the returned path with free(). */
wchar_t *sbw_default_data_directory(bool console, sbw_error *error);
bool sbw_trusted_storage_owner(PSID owner, PSID service_user);

/* Private local directories for installer staging. The guard pins every
 * ancestor against rename/reparse replacement and applies the same restricted
 * SYSTEM/administrator/current-service DACL as device storage. No state.lock
 * is acquired, so the signed helper can overlap the service during handoff. */
typedef struct sbw_directory_guard sbw_directory_guard;
sbw_directory_guard *sbw_secure_directory_open(const wchar_t *directory, sbw_error *error);
/* Existing installation trees retain their inherited read/execute ACLs. */
sbw_directory_guard *sbw_secure_directory_open_readonly(const wchar_t *directory, sbw_error *error);
void sbw_secure_directory_close(sbw_directory_guard *directory);
/* Basenames only. The returned file is pinned without write/delete sharing;
 * caller closes it before replacing or removing the file. */
HANDLE sbw_secure_directory_file(sbw_directory_guard *directory, const wchar_t *name,
    DWORD access, DWORD disposition, sbw_error *error);
wchar_t *sbw_secure_directory_path(const sbw_directory_guard *directory, const wchar_t *name);

#endif
