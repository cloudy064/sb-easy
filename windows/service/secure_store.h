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

#endif
