/* Wire response helpers for the panel HTTP server: header storage with
 * Drogon's replace semantics, JSON/error bodies and the Drogon default pages. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "http_wire.h"

char *ascii_lower_dup(const char *s, size_t len) {
    char *out = sb_strndup(s, len);
    for (size_t i = 0; i < len; ++i) out[i] = (char)tolower((unsigned char)out[i]);
    return out;
}

void wire_init(wire_response *w, int status) {
    memset(w, 0, sizeof *w);
    w->status = status;
}

void wire_free(wire_response *w) {
    free(w->content_type);
    sb_strvec_free(&w->names);
    sb_strvec_free(&w->values);
    free(w->value_lens);
    free(w->body);
    free(w->file);
    memset(w, 0, sizeof *w);
}

void wire_set_header_n(wire_response *w, const char *name, const char *value, size_t len) {
    char *lowered = ascii_lower_dup(name, strlen(name));
    for (size_t i = 0; i < w->names.len; ++i) {
        if (strcmp(w->names.items[i], lowered) == 0) {
            free(lowered);
            sb_str_setn(&w->values.items[i], value, len);
            w->value_lens[i] = len;
            return;
        }
    }
    sb_strvec_push_take(&w->names, lowered);
    sb_strvec_push_take(&w->values, sb_strndup(value, len));
    w->value_lens = sb_xrealloc(w->value_lens, w->values.len * sizeof *w->value_lens);
    w->value_lens[w->values.len - 1] = len;
}

void wire_set_header(wire_response *w, const char *name, const char *value) {
    wire_set_header_n(w, name, value, strlen(value));
}

static const char *wire_header(const wire_response *w, const char *lowered_name) {
    for (size_t i = 0; i < w->names.len; ++i)
        if (strcmp(w->names.items[i], lowered_name) == 0) return w->values.items[i];
    return NULL;
}

void wire_json(wire_response *w, int status, sbj *body) {
    w->status = status;
    free(w->body);
    sb_err encoding_error = {0};
    if (sbj_validate_utf8(body, &encoding_error) != 0) {
        sbj_free(body);
        body = sbj_object();
        char *message = sb_asprintf("Invalid JSON request: %s", encoding_error.msg);
        sbj_set_str(body, "error", message);
        free(message);
        w->status = 400;
    }
    w->body = sbj_dump(body, -1);
    w->body_len = strlen(w->body);
    sb_str_set(&w->content_type, "application/json; charset=utf-8");
    sbj_free(body);
}

void wire_error(wire_response *w, int status, const char *message) {
    sbj *body = sbj_object();
    sbj_set_str(body, "error", message);
    wire_json(w, status, body);
}

/* Drogon's custom error handler default: empty text/html body. */
void wire_empty_html(wire_response *w, int status) {
    w->status = status;
    sb_str_set(&w->content_type, "text/html; charset=utf-8");
}

/* HttpResponse::newNotFoundResponse(): the drogon::NotFound view. */
void wire_not_found_page(wire_response *w) {
    static const char page[] =
        "<html>\n<head><title>404 Not Found</title></head>\n"
        "<body bgcolor=\"white\" text=\"black\">\n"
        "<center><h1>404 Not Found</h1></center>\n"
        "<hr><center>drogon/1.9.13</center>\n</body>\n</html>\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n"
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\n";
    w->status = 404;
    sb_str_set(&w->content_type, "text/html; charset=utf-8");
    free(w->body);
    w->body = sb_strndup(page, sizeof page - 1);
    w->body_len = sizeof page - 1;
}
