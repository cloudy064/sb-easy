#ifndef SB_PROXY_RUNTIME_H
#define SB_PROXY_RUNTIME_H
#include "sb/database.h"
#include "sb/json.h"

#define SB_PROXY_REQUEST_LIMIT (512U * 1024U)
#define SB_PROXY_POLICY_LIMIT (4U * 1024U * 1024U)
#define SB_PROXY_POLL_MILLIS 10000

/* The bridge callbacks are a narrow test seam. Production uses the compiled
 * embedded bridge; an external sing-box never reports this capability.
 * stats and exchange return malloc-owned strings with their exact byte length.
 * Callbacks must finish within bounded deadlines and must not log credentials. */
typedef struct {
    void *context;
    int (*begin)(void *, const char *, sb_err *);
    int (*apply)(void *, const char *, sb_err *);
    int (*stats)(void *, char **, size_t *, sb_err *);
    int (*acknowledge)(void *, const char *, sb_err *);
    void (*stop)(void *);
} sb_proxy_bridge;
typedef int (*sb_proxy_exchange_fn)(void *, const char *, size_t, char **, size_t *, sb_err *);
typedef struct sb_proxy_runtime sb_proxy_runtime;

bool sb_proxy_runtime_available(void);
sbj *sb_proxy_runtime_capabilities(void);
/* host_id may be empty for legacy agent-token setups. The first fully valid
 * authenticated response then binds the host for this process lifetime.
 * There may be only one production embedded-runtime owner per process. */
sb_proxy_runtime *sb_proxy_runtime_new(const char *host_id, const sb_proxy_bridge *bridge,
    sb_proxy_exchange_fn exchange, void *context, sb_err *err);
/* Self uses the same transactional lease exchange as authenticated agents and
 * refreshes its capability report independently of the normal core polling. */
sb_proxy_runtime *sb_proxy_runtime_new_self(sb_database *database,
    const sb_proxy_bridge *bridge, sb_err *err);
/* One serialized exchange. 1 means an accepted response was already expired:
 * its sequence advanced, and a fresh sequence should be sent immediately.
 * A local apply failure also advances an accepted sequence, returning -1 with
 * a safe error. Network/validation failures retain the exact pending request. */
int sb_proxy_runtime_step(sb_proxy_runtime *runtime, sb_err *err);
int sb_proxy_runtime_start(sb_proxy_runtime *runtime, sb_err *err);
void sb_proxy_runtime_request_stop(sb_proxy_runtime *runtime);
void sb_proxy_runtime_stop(sb_proxy_runtime *runtime);
void sb_proxy_runtime_free(sb_proxy_runtime *runtime);
/* The last public operation outcome, never policy or authentication material. */
sbj *sb_proxy_runtime_status(sb_proxy_runtime *runtime);
#endif
