/* Crash-safe file replacement (C++ atomic_file.hpp). */
#ifndef SB_ATOMIC_FILE_H
#define SB_ATOMIC_FILE_H

#include <stddef.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Inspects the complete temporary file before it replaces the destination.
 * Return 0 to accept; return -1 (after filling err) to reject. */
typedef int (*sb_file_validator)(const char *temporary_path, void *user, sb_err *err);

/* Writes and fsyncs a same-directory temporary file, optionally validates it,
 * then atomically renames it over the destination and fsyncs the directory.
 * The temporary file is removed on any failure. validator may be NULL.
 * Errors: SB_ERR_VALIDATION when the destination names no file, SB_ERR_IO for
 * system failures ("<operation>: <strerror>"), or whatever the validator set. */
int sb_atomic_replace_file(const char *destination, const void *contents, size_t len,
                           sb_file_validator validator, void *user, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
