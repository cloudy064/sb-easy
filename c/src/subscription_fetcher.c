/* Port of cpp/src/subscription_fetcher.cpp on top of sb_http_perform. */
#include "sb/subscription_fetcher.h"

#include <stdlib.h>
#include <string.h>


#include "sb/http_client.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

struct sb_subscription_fetcher {
    sb_subscription_fetcher_options options;
};

void sb_subscription_fetcher_options_init(sb_subscription_fetcher_options *o) {
    o->timeout_ms = 30000;
    o->maximum_body_bytes = 8u * 1024u * 1024u;
    o->maximum_redirects = 5;
}

sb_subscription_fetcher *sb_subscription_fetcher_new(const sb_subscription_fetcher_options *options,
                                                     sb_err *err) {
    sb_subscription_fetcher_options o;
    if (options) o = *options;
    else sb_subscription_fetcher_options_init(&o);
    if (o.timeout_ms <= 0 || o.maximum_body_bytes == 0) {
        sb_fail(err, SB_ERR_VALIDATION, "subscription timeout and body limit must be positive");
        return NULL;
    }
    sb_subscription_fetcher *f = sb_xcalloc(1, sizeof *f);
    f->options = o;
    return f;
}

void sb_subscription_fetcher_free(sb_subscription_fetcher *f) { free(f); }

typedef struct {
    char *scheme, *origin, *target;
} http_address;

static void address_free(http_address *a) {
    free(a->scheme);
    free(a->origin);
    free(a->target);
}

static int parse_url(const char *url, http_address *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    const char *sep = strstr(url, "://");
    if (!sep)
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must include http:// or https://");
    size_t scheme_len = (size_t)(sep - url);
    if (!((scheme_len == 4 && !strncmp(url, "http", 4)) ||
          (scheme_len == 5 && !strncmp(url, "https", 5))))
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must use HTTP or HTTPS");
    const char *authority = sep + 3;
    if (strchr(authority, '#'))
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must not contain a fragment");
    size_t alen = strcspn(authority, "/?");
    if (alen == 0 || memchr(authority, '@', alen))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "subscription URL authority is empty or contains credentials");
    out->scheme = sb_strndup(url, scheme_len);
    out->origin = sb_strndup(url, scheme_len + 3 + alen);
    const char *path = authority + alen;
    if (!*path) out->target = sb_strdup("/");
    else if (*path == '?') out->target = sb_asprintf("/%s", path);
    else out->target = sb_strdup(path);
    return 0;
}

static char *resolve_redirect(const http_address *cur, const char *location) {
    if (sb_starts_with(location, "http://") || sb_starts_with(location, "https://"))
        return sb_strdup(location);
    if (sb_starts_with(location, "//")) return sb_asprintf("%s:%s", cur->scheme, location);
    if (location[0] == '/') return sb_asprintf("%s%s", cur->origin, location);
    char *base = sb_strdup(cur->target);
    char *q = strchr(base, '?');
    if (q) *q = '\0';
    char *slash = strrchr(base, '/');
    if (slash) slash[1] = '\0';
    char *r = sb_asprintf("%s%s%s", cur->origin, slash ? base : "/", location);
    free(base);
    return r;
}

/* Drogon's HttpRequest encodes the path it sends (setPath + the default
 * pathEncode_): alphanumerics and -_.!~*'()&=/\? pass through, a space
 * becomes '+', and every other byte (including '%') becomes %XX. The C++
 * fetcher passed the whole target (path and query) through setPath, so the
 * request line upstream servers see is encoded the same way here. */
static char *drogon_url_encode(const char *src) {
    static const char hex[] = "0123456789ABCDEF";
    sb_buf b = {0};
    for (const unsigned char *p = (const unsigned char *)src; *p; ++p) {
        unsigned char c = *p;
        if (c == ' ') {
            sb_buf_putc(&b, '+');
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   strchr("-_.!~*'()&=/\\?", c)) {
            sb_buf_putc(&b, (char)c);
        } else {
            char esc[3] = {'%', hex[c >> 4], hex[c & 0x0F]};
            sb_buf_append(&b, esc, 3);
        }
    }
    return sb_buf_detach(&b);
}

static bool redirect_status(long s) {
    return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

char *sb_subscription_fetcher_fetch(sb_subscription_fetcher *f, const char *url_in, size_t *len,
                                    sb_err *err) {
    static const char *const headers[] = {"Accept: text/plain, application/yaml, application/json",
                                          NULL};
    char *url = sb_strdup(url_in ? url_in : "");
    char *result = NULL;
    for (size_t redirects = 0;; ++redirects) {
        http_address addr;
        if (parse_url(url, &addr, err)) break;
        char *target = drogon_url_encode(addr.target);
        char *full = sb_asprintf("%s%s", addr.origin, target);
        free(target);
        sb_http_request req = {0};
        req.url = full;
        req.headers = headers;
        req.timeout_ms = f->options.timeout_ms;
        req.max_body_bytes = f->options.maximum_body_bytes;
        req.max_redirects = 0;
        req.user_agent = "sb-easy-cpp/" SB_EASY_VERSION;
        sb_http_response resp;
        sb_err herr = {0};
        int rc = sb_http_perform(&req, &resp, &herr);
        free(full);
        if (rc != 0) {
            if (sb_starts_with(herr.msg, "response body exceeds"))
                sb_fail(err, SB_ERR_UPSTREAM,
                        "subscription response exceeds the configured size limit");
            else
                sb_fail(err, SB_ERR_UPSTREAM, "subscription HTTP request failed: %s",
                        sb_http_failure_reason(herr.msg));
            address_free(&addr);
            break;
        }
        if (redirect_status(resp.status)) {
            char *location = NULL;
            if (redirects >= f->options.maximum_redirects) {
                sb_fail(err, SB_ERR_UPSTREAM, "subscription exceeded the redirect limit");
            } else if (!(location = sb_http_response_header(&resp, "location")) || !*location) {
                sb_fail(err, SB_ERR_UPSTREAM, "subscription redirect is missing Location");
            } else {
                free(url);
                url = resolve_redirect(&addr, location);
                free(location);
                sb_http_response_free(&resp);
                address_free(&addr);
                continue;
            }
            free(location);
            sb_http_response_free(&resp);
            address_free(&addr);
            break;
        }
        address_free(&addr);
        if (resp.status < 200 || resp.status >= 300) {
            sb_fail(err, SB_ERR_UPSTREAM, "subscription returned HTTP %ld", resp.status);
            sb_http_response_free(&resp);
            break;
        }
        if (resp.body_len > f->options.maximum_body_bytes) {
            sb_fail(err, SB_ERR_UPSTREAM, "subscription response exceeds the configured size limit");
            sb_http_response_free(&resp);
            break;
        }
        if (len) *len = resp.body_len;
        result = resp.body;
        resp.body = NULL;
        sb_http_response_free(&resp);
        break;
    }
    free(url);
    return result;
}
