#include "sb/clash_client.h"

#include <stdlib.h>
#include <string.h>

#include "sb/http_client.h"

#ifndef SB_EASY_VERSION
#define SB_EASY_VERSION "1.0.0"
#endif

struct sb_clash_client {
    sb_clash_client_options options;
};

void sb_clash_client_options_init(sb_clash_client_options *o) {
    o->timeout_ms = 10000;
    o->maximum_body_bytes = 8u * 1024u * 1024u;
}

void sb_clash_response_free(sb_clash_response *r) {
    if (!r) return;
    sbj_free(r->body);
    r->body = NULL;
}

const char *sb_http_failure_reason(const char *message) {
    if (!message) return "Network failure";
    if (strstr(message, "Timeout") || strstr(message, "timed out")) return "Timeout";
    if (strstr(message, "resolve") || strstr(message, "URL") || strstr(message, "Malformed"))
        return "Bad server address";
    if (strstr(message, "certificate")) return "Invalid certificate";
    if (strstr(message, "SSL") || strstr(message, "TLS")) return "Handshake error";
    if (strstr(message, "Weird server reply") || strstr(message, "HTTP/0.9"))
        return "Bad response from server";
    return "Network failure";
}

sb_clash_client *sb_clash_client_new(const sb_clash_client_options *options, sb_err *err) {
    sb_clash_client_options o;
    if (options) o = *options;
    else sb_clash_client_options_init(&o);
    if (o.timeout_ms <= 0 || o.maximum_body_bytes == 0) {
        sb_fail(err, SB_ERR_VALIDATION, "Clash timeout and response limit must be positive");
        return NULL;
    }
    sb_http_global_init();
    sb_clash_client *client = sb_xcalloc(1, sizeof *client);
    client->options = o;
    return client;
}

void sb_clash_client_free(sb_clash_client *client) { free(client); }

/* Splits the base URL into origin + path prefix; C++ parse_base_url(). */
static int parse_base_url(const char *base_url, char **origin, char **prefix, sb_err *err) {
    char *url = sb_strdup(base_url ? base_url : "");
    size_t len = strlen(url);
    while (len > 0 && url[len - 1] == '/') url[--len] = '\0';
    const char *separator = strstr(url, "://");
    size_t scheme_len = separator ? (size_t)(separator - url) : 0;
    if (!separator || !((scheme_len == 4 && strncmp(url, "http", 4) == 0) ||
                        (scheme_len == 5 && strncmp(url, "https", 5) == 0))) {
        free(url);
        return sb_fail(err, SB_ERR_UPSTREAM, "Clash API URL must include http:// or https://");
    }
    const char *authority = separator + 3;
    if (strpbrk(authority, "?#")) {
        free(url);
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "Clash API base URL must not contain a query or fragment");
    }
    const char *path = strchr(authority, '/');
    if (path) {
        *origin = sb_strndup(url, (size_t)(path - url));
        *prefix = sb_strdup(path);
    } else {
        *origin = sb_strdup(url);
        *prefix = sb_strdup("");
    }
    free(url);
    if ((*origin)[0] == '\0' || sb_ends_with(*origin, "://")) {
        free(*origin);
        free(*prefix);
        return sb_fail(err, SB_ERR_UPSTREAM, "Clash API URL has an empty authority");
    }
    return 0;
}

static int clash_request(sb_clash_client *client, const char *method,
                         const sb_clash_target *target, const char *path, const sbj *body,
                         sb_clash_response *out, sb_err *err) {
    char *origin = NULL, *prefix = NULL;
    if (parse_base_url(target->base_url, &origin, &prefix, err) != 0) return -1;
    char *url = sb_asprintf("%s%s%s", origin, prefix, path ? path : "");
    char *authorization =
        sb_str_empty(target->secret) ? NULL : sb_asprintf("Authorization: Bearer %s", target->secret);
    const char *headers[5];
    size_t n = 0;
    headers[n++] = "Accept: application/json";
    if (authorization) headers[n++] = authorization;
    char *payload = NULL;
    if (body) {
        headers[n++] = "Content-Type: application/json; charset=utf-8";
        payload = sbj_dump(body, -1);
    } else {
        /* Drogon never sends an Expect/Content-Type for body-less requests. */
    }
    headers[n] = NULL;

    sb_http_request req = {0};
    req.method = method;
    req.url = url;
    req.headers = headers;
    req.body = payload;
    req.body_len = payload ? strlen(payload) : 0;
    req.timeout_ms = client->options.timeout_ms;
    req.max_body_bytes = client->options.maximum_body_bytes;
    req.user_agent = "sb-easy-cpp/" SB_EASY_VERSION;
    sb_http_response resp = {0};
    sb_err transport = {0};
    int rc = sb_http_perform(&req, &resp, &transport);
    free(url);
    free(origin);
    free(prefix);
    free(authorization);
    free(payload);
    if (rc != 0) {
        if (strstr(transport.msg, "response body exceeds"))
            return sb_fail(err, SB_ERR_UPSTREAM,
                           "Clash API response exceeds the configured size limit");
        SB_DEBUG("Clash API transport error: %s", transport.msg);
        return sb_fail(err, SB_ERR_UPSTREAM, "Clash API request failed: %s",
                       sb_http_failure_reason(transport.msg));
    }
    if (resp.body_len > client->options.maximum_body_bytes) {
        sb_http_response_free(&resp);
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "Clash API response exceeds the configured size limit");
    }
    sbj *parsed = NULL;
    if (resp.body_len > 0) parsed = sbj_parse(resp.body, resp.body_len, NULL, 0);
    if (!parsed) parsed = sbj_object();
    out->status = (int)resp.status;
    out->body = parsed;
    sb_http_response_free(&resp);
    return 0;
}

int sb_clash_get(sb_clash_client *client, const sb_clash_target *target, const char *path,
                 sb_clash_response *out, sb_err *err) {
    return clash_request(client, "GET", target, path, NULL, out, err);
}

int sb_clash_remove(sb_clash_client *client, const sb_clash_target *target, const char *path,
                    sb_clash_response *out, sb_err *err) {
    return clash_request(client, "DELETE", target, path, NULL, out, err);
}

int sb_clash_put(sb_clash_client *client, const sb_clash_target *target, const char *path,
                 const sbj *body, sb_clash_response *out, sb_err *err) {
    return clash_request(client, "PUT", target, path, body, out, err);
}
