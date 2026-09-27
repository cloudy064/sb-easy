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
    size_t origin_len, target_len;
} http_address;

static void address_free(http_address *a) {
    free(a->scheme);
    free(a->origin);
    free(a->target);
}

static int parse_url(const char *url, size_t len, http_address *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    size_t scheme_len = 0;
    while (scheme_len + 2 < len && memcmp(url + scheme_len, "://", 3) != 0) ++scheme_len;
    if (scheme_len + 2 >= len)
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must include http:// or https://");
    if (!((scheme_len == 4 && !memcmp(url, "http", 4)) ||
          (scheme_len == 5 && !memcmp(url, "https", 5))))
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must use HTTP or HTTPS");
    size_t start = scheme_len + 3;
    if (memchr(url + start, '#', len - start))
        return sb_fail(err, SB_ERR_VALIDATION, "subscription URL must not contain a fragment");
    size_t path = start;
    while (path < len && url[path] != '/' && url[path] != '?') ++path;
    if (path == start || memchr(url + start, '@', path - start))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "subscription URL authority is empty or contains credentials");
    /* libcurl requires a terminated origin. Never silently reinterpret an
     * embedded-NUL authority as a different host/path. */
    if (memchr(url + start, '\0', path - start))
        return sb_fail(err, SB_ERR_UPSTREAM, "subscription HTTP request failed: Bad server address");
    out->scheme = sb_strndup(url, scheme_len);
    out->origin_len = path;
    out->origin = sb_strndup(url, path);
    sb_buf target = {0};
    if (path == len || url[path] == '?') sb_buf_putc(&target, '/');
    sb_buf_append(&target, url + path, len - path);
    out->target_len = target.len;
    out->target = sb_buf_detach(&target);
    return 0;
}

static char *resolve_redirect(const http_address *cur, const char *location, size_t *len) {
    sb_buf next = {0};
    if (sb_starts_with(location, "http://") || sb_starts_with(location, "https://")) {
        sb_buf_puts(&next, location);
    } else if (sb_starts_with(location, "//")) {
        sb_buf_printf(&next, "%s:%s", cur->scheme, location);
    } else {
        sb_buf_append(&next, cur->origin, cur->origin_len);
        if (location[0] != '/') {
            size_t end = 0, slash = 0;
            while (end < cur->target_len && cur->target[end] != '?') ++end;
            for (size_t i = 0; i < end; ++i) if (cur->target[i] == '/') slash = i + 1;
            if (slash) sb_buf_append(&next, cur->target, slash);
            else sb_buf_putc(&next, '/');
        }
        sb_buf_puts(&next, location);
    }
    *len = next.len;
    return sb_buf_detach(&next);
}

/* Drogon's HttpRequest encodes the path it sends (setPath + the default
 * pathEncode_): alphanumerics and -_.!~*'()&=/\? pass through, a space
 * becomes '+', and every other byte (including '%') becomes %XX. The C++
 * fetcher passed the whole target (path and query) through setPath, so the
 * request line upstream servers see is encoded the same way here. */
static char *drogon_url_encode(const char *src, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    sb_buf b = {0};
    for (const unsigned char *p = (const unsigned char *)src; len; ++p, --len) {
        unsigned char c = *p;
        if (c == ' ') {
            sb_buf_putc(&b, '+');
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   (c != 0 && strchr("-_.!~*'()&=/\\?", c))) {
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
    return sb_subscription_fetcher_fetch_n(f, url_in, url_in ? strlen(url_in) : 0, len, err);
}

char *sb_subscription_fetcher_fetch_n(sb_subscription_fetcher *f, const char *url_in,
                                      size_t url_len, size_t *len, sb_err *err) {
    static const char *const headers[] = {"Accept: text/plain, application/yaml, application/json",
                                          NULL};
    char *url = sb_strndup(url_in ? url_in : "", url_len);
    char *result = NULL;
    for (size_t redirects = 0;; ++redirects) {
        http_address addr;
        if (parse_url(url, url_len, &addr, err)) break;
        char *target = drogon_url_encode(addr.target, addr.target_len);
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
                url = resolve_redirect(&addr, location, &url_len);
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
