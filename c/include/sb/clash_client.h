/* Blocking client for a Clash-compatible control API (C++ clash_client.hpp). */
#ifndef SB_CLASH_CLIENT_H
#define SB_CLASH_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t timeout_ms;        /* default 10000 */
    size_t maximum_body_bytes; /* default 8 MiB */
} sb_clash_client_options;

void sb_clash_client_options_init(sb_clash_client_options *o);

typedef struct {
    const char *base_url; /* borrowed */
    const char *secret;   /* borrowed; NULL or "" -> no Authorization header */
} sb_clash_target;

typedef struct {
    int status;
    sbj *body; /* owned; {} for empty or non-JSON bodies */
} sb_clash_response;

void sb_clash_response_free(sb_clash_response *r);

typedef struct sb_clash_client sb_clash_client;

/* options may be NULL for defaults. SB_ERR_VALIDATION on non-positive limits. */
sb_clash_client *sb_clash_client_new(const sb_clash_client_options *options, sb_err *err);
void sb_clash_client_free(sb_clash_client *client);

/* Each call returns 0 with *out filled (any HTTP status), or -1 with
 * SB_ERR_UPSTREAM (C++ ClashRequestError) on URL, transport or size errors.
 * path is appended verbatim (no encoding) to the base URL path. */
int sb_clash_get(sb_clash_client *client, const sb_clash_target *target, const char *path,
                 sb_clash_response *out, sb_err *err);
int sb_clash_remove(sb_clash_client *client, const sb_clash_target *target, const char *path,
                    sb_clash_response *out, sb_err *err);
int sb_clash_put(sb_clash_client *client, const sb_clash_target *target, const char *path,
                 const sbj *body, sb_clash_response *out, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
