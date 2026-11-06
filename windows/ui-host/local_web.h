#ifndef SB_WINDOWS_LOCAL_WEB_H
#define SB_WINDOWS_LOCAL_WEB_H
#include "../common.h"
#include <stddef.h>

typedef struct sbw_local_web sbw_local_web;
/* Runs on a bounded worker pool. Return a malloc-owned JSON response, or NULL.
 * The owner must cancel outstanding RPCs before stop if they can block. */
typedef char *(*sbw_local_web_rpc)(const char *request, size_t length, void *user);

/* Unelevated, IPv4 loopback-only HTTP adapter. static_root is the packaged UI
 * directory. No service credentials are available to this transport. */
sbw_local_web *sbw_local_web_start(const wchar_t *static_root,
    sbw_local_web_rpc callback, void *user, sbw_error *error);
/* Stops accepting, interrupts network I/O, and joins all callbacks/workers. */
void sbw_local_web_stop(sbw_local_web *server);
unsigned short sbw_local_web_port(const sbw_local_web *server);
/* Borrowed 64-character random token, valid until stop. Never log this value. */
const char *sbw_local_web_token(const sbw_local_web *server);
#endif
