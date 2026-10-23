#ifndef SBW_EXTENSION_STORE_H
#define SBW_EXTENSION_STORE_H
#include "../common.h"
typedef struct sbw_extension_release {
    const char *id,*name,*description,*permissions,*sha256;
    const wchar_t *url;
    size_t bytes;
    const wchar_t *files[10];
    size_t file_count;
} sbw_extension_release;
const sbw_extension_release *sbw_extension_releases(size_t *count);
const sbw_extension_release *sbw_extension_release_find(const char *id);
sbj *sbw_store_catalog(void);
sbj *sbw_store_progress(void);
sbj *sbw_store_status(const char *id);
bool sbw_store_verified(const char *id,sbw_error *error);
bool sbw_store_allowed(const char *id,sbw_error *error);
int sbw_store_catalog_update(const char *envelope,size_t length,sbw_error *error);
int sbw_store_rollback(const char *id,sbw_error *error);
int sbw_store_confirm(const char *id,sbw_error *error);
int sbw_store_install(const char *id,sbw_error *error);
/* Call commit under the host mutation lock after stopping the selected worker
 * and restoring any routing it temporarily owns. Downloading leaves it alive. */
bool sbw_store_ready(void);
const char *sbw_store_pending_id(void);
int sbw_store_commit(sbw_error *error);
void sbw_store_abort(const sbw_error *error);
bool sbw_store_busy(void);
void sbw_store_join(void);
/* Internal installer seam: same pinned hash applies in tests and production. */
int sbw_store_publish(const char *id,const wchar_t *root, const void *bytes, size_t length, sbw_error *error);
#endif
