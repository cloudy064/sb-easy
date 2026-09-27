#include "sb/http_client.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void do_init(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }
void sb_http_global_init(void) { pthread_once(&g_once, do_init); }

typedef struct {
    sb_buf body;
    size_t limit;
    int overflow;
} body_ctx;

static size_t on_body(char *data, size_t size, size_t n, void *user) {
    body_ctx *c = user;
    size_t len = size * n;
    if (c->body.len + len > c->limit) {
        c->overflow = 1;
        return 0;
    }
    sb_buf_append(&c->body, data, len);
    return len;
}

static size_t on_header(char *data, size_t size, size_t n, void *user) {
    sb_buf *h = user;
    size_t len = size * n;
    /* A new status line starts the header block of a later response
     * (redirect or 100-continue); keep only the final one. */
    if (len >= 5 && strncmp(data, "HTTP/", 5) == 0) sb_buf_reset(h);
    sb_buf_append(h, data, len);
    return len;
}

char *sb_http_response_header(const sb_http_response *resp, const char *name) {
    if (!resp->headers) return NULL;
    size_t nlen = strlen(name);
    const char *p = resp->headers;
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        if (line_len > nlen && p[nlen] == ':' && strncasecmp(p, name, nlen) == 0) {
            const char *v = p + nlen + 1;
            const char *end = p + line_len;
            while (v < end && (*v == ' ' || *v == '\t')) ++v;
            while (end > v && (end[-1] == ' ' || end[-1] == '\t')) --end;
            return sb_strndup(v, (size_t)(end - v));
        }
        if (!eol) break;
        p = eol + 2;
    }
    return NULL;
}

int sb_http_perform(const sb_http_request *req, sb_http_response *resp, sb_err *err) {
    sb_http_global_init();
    memset(resp, 0, sizeof *resp);
    CURL *curl = curl_easy_init();
    if (!curl) return sb_fail(err, SB_ERR_UPSTREAM, "curl initialisation failed");

    body_ctx ctx = {{0}, req->max_body_bytes ? req->max_body_bytes : 8u * 1024u * 1024u, 0};
    sb_buf hdr = {0};
    struct curl_slist *list = NULL;
    for (const char *const *h = req->headers; h && *h; ++h) list = curl_slist_append(list, *h);
    if (req->body) list = curl_slist_append(list, "Expect:");

    const char *method = req->method ? req->method : "GET";
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(req->timeout_ms > 0 ? req->timeout_ms : 15000));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdr);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    if (req->max_redirects > 0) {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, req->max_redirects);
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    }
    if (req->proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, req->proxy);
        curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
    } else {
        /* Never inherit http_proxy from the environment: sb-easy talks to
         * local controllers and its own control plane directly. */
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
    }
    if (req->user_agent) curl_easy_setopt(curl, CURLOPT_USERAGENT, req->user_agent);
    if (list) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if (strcmp(method, "GET") != 0) curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (req->body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req->body_len);
    } else if (!strcmp(method, "POST") || !strcmp(method, "PUT") || !strcmp(method, "PATCH")) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)0);
    }

    CURLcode rc = curl_easy_perform(curl);
    int result = 0;
    if (rc != CURLE_OK) {
        if (ctx.overflow)
            result = sb_fail(err, SB_ERR_UPSTREAM, "response body exceeds %zu bytes", ctx.limit);
        else
            result = sb_fail(err, SB_ERR_UPSTREAM, "%s: %s", req->url, curl_easy_strerror(rc));
        sb_buf_free(&ctx.body);
        sb_buf_free(&hdr);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->status);
        resp->body_len = ctx.body.len;
        resp->body = sb_buf_detach(&ctx.body);
        resp->headers = sb_buf_detach(&hdr);
        resp->etag = sb_http_response_header(resp, "ETag");
        resp->content_type = sb_http_response_header(resp, "Content-Type");
    }
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    return result;
}

void sb_http_response_free(sb_http_response *resp) {
    free(resp->body);
    free(resp->etag);
    free(resp->content_type);
    free(resp->headers);
    memset(resp, 0, sizeof *resp);
}

/* Maps a libcurl failure onto the Drogon ReqResult wording the C++ client
 * reported: failed DNS lookups and refused connections are
 * BadServerAddress, a connection closed before a complete response is
 * NetworkFailure, an unparseable response is BadResponse. */
const char *sb_http_failure_reason(const char *message) {
    if (!message) return "Network failure";
    static const struct {
        CURLcode code;
        const char *reason;
    } map[] = {
        {CURLE_OPERATION_TIMEDOUT, "Timeout"},
        {CURLE_COULDNT_RESOLVE_HOST, "Bad server address"},
        {CURLE_COULDNT_CONNECT, "Bad server address"},
        {CURLE_URL_MALFORMAT, "Bad server address"},
        {CURLE_PEER_FAILED_VERIFICATION, "Invalid certificate"},
        {CURLE_SSL_CACERT_BADFILE, "Invalid certificate"},
        {CURLE_SSL_CONNECT_ERROR, "Handshake error"},
        {CURLE_WEIRD_SERVER_REPLY, "Bad response from server"},
        {CURLE_UNSUPPORTED_PROTOCOL, "Bad response from server"}, /* HTTP/0.9 reply */
        {CURLE_GOT_NOTHING, "Network failure"},
        {CURLE_RECV_ERROR, "Network failure"},
        {CURLE_SEND_ERROR, "Network failure"},
        {CURLE_PARTIAL_FILE, "Network failure"},
    };
    for (size_t i = 0; i < sizeof map / sizeof *map; ++i)
        if (sb_ends_with(message, curl_easy_strerror(map[i].code))) return map[i].reason;
    return "Network failure";
}
