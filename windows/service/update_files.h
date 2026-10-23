#ifndef SBW_UPDATE_FILES_H
#define SBW_UPDATE_FILES_H
#include "secure_store.h"

/* All names below are application constants, never paths supplied by IPC. */
int sbw_update_read(sbw_directory_guard *directory, const wchar_t *name, size_t limit,
    bool optional, sb_buf *output, sbw_error *error);
sbj *sbw_update_read_json(sbw_directory_guard *directory, const wchar_t *name, bool optional, sbw_error *error);
int sbw_update_write(sbw_directory_guard *directory, const wchar_t *name,
    const void *data, size_t length, sbw_error *error);
int sbw_update_write_json(sbw_directory_guard *directory, const wchar_t *name, const sbj *json, sbw_error *error);
int sbw_update_copy(sbw_directory_guard *source, const wchar_t *source_name, sbw_directory_guard *destination,
    const wchar_t *destination_name, uint64_t limit, bool optional, bool *existed, sbw_error *error);
int sbw_update_remove(sbw_directory_guard *directory, const wchar_t *name, sbw_error *error);
bool sbw_update_is_system(void);
#endif
