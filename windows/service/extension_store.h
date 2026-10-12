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
int sbw_store_install(const char *id,sbw_error *error);
bool sbw_store_busy(void);
void sbw_store_join(void);
/* Internal installer seam: same pinned hash applies in tests and production. */
int sbw_store_publish(const char *id,const wchar_t *root, const void *bytes, size_t length, sbw_error *error);
#endif
