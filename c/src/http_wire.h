/* Private wire-level types shared by http_server.c, http_wire.c and
 * http_static.c: the per-request exchange, the request method enum and the
 * response as it goes on the wire. */
#ifndef SB_HTTP_WIRE_H
#define SB_HTTP_WIRE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <time.h>

#include "http_internal.h"

struct mg_request_info;

#define SB_HTTP_MAX_HEADERS 64

/* Everything the core keeps for one request; req.core points back here. */
typedef struct {
    sb_http_req req;
    sb_http_server *srv;
    struct mg_connection *conn;
    const struct mg_request_info *ri;
    int method;          /* routing method: HEAD is routed as GET (Drogon) */
    bool head;           /* the request was HEAD: send headers only */
    bool http10;
    bool keep_alive;     /* what civetweb will do with the connection */
    char *path;          /* decoded path; NUL bytes rendered as "%00" */
    bool path_has_nul;
    char *query;         /* raw query string (no '?') or NULL */
    sb_buf body;
    /* Request headers as Drogon stores them: value trimmed, first wins. */
    size_t header_count;
    const char *header_names[SB_HTTP_MAX_HEADERS];
    char *header_values[SB_HTTP_MAX_HEADERS];
    char *params[8];
    sb_auth_claims claims;
    bool has_claims;
} http_exchange;

static inline http_exchange *exchange_of(const sb_http_req *req) { return req ? (http_exchange *)req->core : NULL; }

/* The request methods Drogon's parser accepts (HttpRequestImpl::setMethod);
 * anything else is answered with a bare 405 and the connection is closed. */
enum {
    M_GET,
    M_POST,
    M_HEAD,
    M_PUT,
    M_DELETE,
    M_OPTIONS,
    M_PATCH,
    M_COPY,
    M_MOVE,
    M_MKCOL,
    M_PROPFIND,
    M_COUNT
};

/* What goes on the wire. Header names are stored lowercased with Drogon's
 * addHeader() replace semantics. */
typedef struct {
    int status;
    char *content_type; /* NULL: no content-type header */
    sb_strvec names, values;
    size_t *value_lens;
    char *body;
    size_t body_len;
    char *file;         /* stream this file instead of body */
    uint64_t file_offset, file_length;
    bool raw_close;     /* bare parser error: status line + Connection: close */
} wire_response;

/* http_wire.c */
char *ascii_lower_dup(const char *s, size_t len);
void wire_init(wire_response *w, int status);
void wire_free(wire_response *w);
void wire_set_header_n(wire_response *w, const char *name, const char *value, size_t len);
void wire_set_header(wire_response *w, const char *name, const char *value);
const char *wire_header(const wire_response *w, const char *lowered_name);
void wire_json(wire_response *w, int status, sbj *body);
void wire_error(wire_response *w, int status, const char *message);
void wire_empty_html(wire_response *w, int status);
void wire_not_found_page(wire_response *w);

/* http_static.c */
void http_date(time_t t, char *buf, size_t size);
const char *exchange_header(const http_exchange *ex, const char *name);
void static_file_response(wire_response *w, const char *path, bool immutable);
bool safe_static_relative_path(const char *value, bool has_nul);
void static_router(const http_exchange *ex, wire_response *w);

#endif
