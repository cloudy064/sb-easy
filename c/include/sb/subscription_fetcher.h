/* Blocking subscription downloader (C++ subscription_fetcher.hpp), built on
 * sb/http_client.h. TLS certificate verification is always on. */
#ifndef SB_SUBSCRIPTION_FETCHER_H
#define SB_SUBSCRIPTION_FETCHER_H

#include <stddef.h>
#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t timeout_ms;        /* default 30000 */
    size_t maximum_body_bytes; /* default 8 MiB */
    size_t maximum_redirects;  /* default 5 */
} sb_subscription_fetcher_options;

void sb_subscription_fetcher_options_init(sb_subscription_fetcher_options *options);

typedef struct sb_subscription_fetcher sb_subscription_fetcher;

/* options may be NULL (defaults). Fails with SB_ERR_VALIDATION
 * "subscription timeout and body limit must be positive". */
sb_subscription_fetcher *sb_subscription_fetcher_new(const sb_subscription_fetcher_options *options,
                                                     sb_err *err);
void sb_subscription_fetcher_free(sb_subscription_fetcher *fetcher);

/* GETs url following up to maximum_redirects redirects. Returns the malloc'd
 * body (NUL-terminated; *len, if non-NULL, is exact) or NULL with err set:
 * SB_ERR_VALIDATION for URL errors (std::invalid_argument), SB_ERR_UPSTREAM
 * for transport/status/size errors (std::runtime_error), same messages as C++. */
char *sb_subscription_fetcher_fetch(sb_subscription_fetcher *fetcher, const char *url, size_t *len,
                                    sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
