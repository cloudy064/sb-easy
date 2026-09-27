/* Blocking HTTP(S) client over libcurl. Replaces the private Drogon event
 * loops the C++ code used for Clash, subscriptions and the agent control
 * plane. Thread-safe: each call uses its own easy handle. TLS verification
 * is always on. */
#ifndef SB_HTTP_CLIENT_H
#define SB_HTTP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maps an sb_http_perform transport error message to Drogon's ReqResult
 * wording ("Timeout", "Network failure", ...). Shared with agent_client. */
const char *sb_http_failure_reason(const char *message);

typedef struct {
    const char *method;          /* "GET" (default), "POST", "PUT", "DELETE", ... */
    const char *url;
    const char *const *headers;  /* NULL-terminated "Name: value" list, may be NULL */
    const char *body;            /* may be NULL */
    size_t body_len;
    int64_t timeout_ms;          /* total; 0 -> 15000 */
    size_t max_body_bytes;       /* 0 -> 8 MiB; larger responses fail */
    long max_redirects;          /* 0 -> redirects disabled */
    const char *proxy;           /* optional "http://host:port" (CONNECT) */
    const char *user_agent;      /* optional */
} sb_http_request;

typedef struct {
    long status;
    char *body;            /* NUL-terminated, may contain NULs; body_len is exact */
    size_t body_len;
    char *etag;            /* ETag response header or NULL */
    char *content_type;    /* or NULL */
    char *headers;         /* raw header block of the final response */
} sb_http_response;

/* Returns 0 when a response was received (any status), -1 on transport
 * failure (err->code = SB_ERR_UPSTREAM). */
int sb_http_perform(const sb_http_request *req, sb_http_response *resp, sb_err *err);
/* Looks up a response header (case-insensitive); malloc'd or NULL. */
char *sb_http_response_header(const sb_http_response *resp, const char *name);
void sb_http_response_free(sb_http_response *resp);
/* Must be called once at process start (curl_global_init). Idempotent. */
void sb_http_global_init(void);

#ifdef __cplusplus
}
#endif

#endif
