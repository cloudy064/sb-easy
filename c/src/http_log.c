/* Server log ring (ServerLogBuffer) for the panel HTTP server: the process-wide
 * log sink feeds the ring of one owning server. */
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "http_internal.h"

#define SB_HTTP_LOG_CAPACITY 1000

/* Global state: the log sink is process-wide, so at most one server (the
 * owner) feeds its log ring from it. `g_sink_owner` is guarded by
 * `g_sink_owner_mutex`. */
static pthread_mutex_t g_sink_owner_mutex = PTHREAD_MUTEX_INITIALIZER;
static sb_http_server *g_sink_owner;

static void log_ring_append(sb_http_server *srv, const char *text) {
    pthread_mutex_lock(&srv->log_mutex);
    const char *start = text;
    for (;;) {
        const char *end = strchr(start, '\n');
        size_t len = end ? (size_t)(end - start) : strlen(start);
        if (len > 0) {
            char *line = sb_strndup(start, len);
            if (srv->log_lines.len < SB_HTTP_LOG_CAPACITY) {
                sb_strvec_push_take(&srv->log_lines, line);
            } else {
                free(srv->log_lines.items[srv->log_head]);
                srv->log_lines.items[srv->log_head] = line;
                srv->log_head = (srv->log_head + 1) % SB_HTTP_LOG_CAPACITY;
            }
        }
        if (!end) break;
        start = end + 1;
    }
    pthread_mutex_unlock(&srv->log_mutex);
}

static void log_sink(sb_log_level level, const char *line, void *user) {
    (void)level;
    log_ring_append((sb_http_server *)user, line);
}

/* log_level(): LOG_LEVEL parsing with the C++ std::invalid_argument message. */
int sb_http_parse_log_level(const char *configured, sb_log_level *out, sb_err *err) {
    char *value = sb_http_trim(configured);
    for (char *p = value; *p; ++p) *p = (char)tolower((unsigned char)*p);
    int rc = 0;
    if (strcmp(value, "trace") == 0) *out = SB_LOG_TRACE;
    else if (strcmp(value, "debug") == 0) *out = SB_LOG_DEBUG;
    else if (strcmp(value, "warn") == 0 || strcmp(value, "warning") == 0) *out = SB_LOG_WARN;
    else if (strcmp(value, "error") == 0 || strcmp(value, "fatal") == 0) *out = SB_LOG_ERROR;
    else if (!*value || strcmp(value, "info") == 0) *out = SB_LOG_INFO;
    else rc = sb_fail(err, SB_ERR_VALIDATION, "LOG_LEVEL must be trace, debug, info, warn, error, or fatal");
    free(value);
    return rc;
}

void sb_http_log_attach(sb_http_server *srv) {
    pthread_mutex_lock(&g_sink_owner_mutex);
    g_sink_owner = srv;
    sb_log_set_sink(log_sink, srv);
    pthread_mutex_unlock(&g_sink_owner_mutex);
}

void sb_http_log_detach(sb_http_server *srv) {
    pthread_mutex_lock(&g_sink_owner_mutex);
    if (g_sink_owner == srv) {
        sb_log_set_sink(NULL, NULL);
        g_sink_owner = NULL;
    }
    pthread_mutex_unlock(&g_sink_owner_mutex);
}
