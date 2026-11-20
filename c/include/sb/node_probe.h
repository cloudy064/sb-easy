#ifndef SB_NODE_PROBE_H
#define SB_NODE_PROBE_H

#include "sb/store.h"

/* A nonnegative result is a completed HTTPS probe in milliseconds. */
enum { SB_PROBE_UNREACHABLE = -1, SB_PROBE_UNAVAILABLE = -2,
       SB_PROBE_TIMEOUT_MS = 6500, SB_PROBE_MAX_BYTES = 1024 * 1024 };

int sb_node_probe(const sb_proxy_record *node, const char *binary, sb_err *err,
                  double *latency, bool *measured);
/* Consumes only a renderer node, never a caller-supplied sing-box configuration. */
int sb_probe_run(const sbj *node, const char *binary, uint32_t mark);
void sb_probe_serve_connection(int fd, const char *binary, uint32_t mark);
#endif
