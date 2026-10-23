#ifndef SB_LINUX_DESKTOP_H
#define SB_LINUX_DESKTOP_H
#include "sb/agent_clash.h"
#include "sb/agent_client.h"
#include "sb/json.h"
#include "sb/singbox_supervisor.h"
#include "sb/util.h"
#include <gio/gio.h>
#include <stdint.h>
#include <sys/types.h>
#define SBL_APP_ID "io.sbeasy.Desktop"
#define SBL_BUS_PATH "/io/sbeasy/Desktop/Tunnel"
#define SBL_BUS_IFACE "io.sbeasy.Desktop.Tunnel1"
#ifndef SBL_VERSION
#error "Build through linux/CMakeLists.txt to use config/client-releases.json"
#endif
#define SBL_MAX_STATE (8u * 1024u * 1024u)
#define SBL_DEFAULT "sb-easy-linux-default"
#define SBL_DIRECT "sb-easy-linux-direct"

typedef struct {
    int dirfd, lockfd;
    unsigned char key[32];
    uint64_t revision;
    char* directory;
} sbl_vault;
/* Explicit key is for the test binary only. Production always obtains a
 * nonempty random master key through the desktop Secret Service. */
int sbl_vault_open(sbl_vault* v, const char* directory, const unsigned char* test_key,
                   sb_err* err);
int sbl_vault_open_cancellable(sbl_vault* v, const char* directory,
                               const unsigned char* test_key, GCancellable* cancel,
                               sb_err* err);
void sbl_vault_close(sbl_vault* v);
sbj* sbl_vault_load(sbl_vault* v, sb_err* err);
int sbl_vault_save(sbl_vault* v, sbj* state, sb_err* err);
int sbl_private_dir(const char* path, uid_t owner, sb_err* err);
char* sbl_uuid(void);
char* sbl_secret(void);
bool sbl_url(const char* url, bool allow_http_loopback, sb_err* err);
char* sbl_url_host(const char* url);
sbj* sbl_parse(const char* text, size_t max, sb_err* err);
sbj* sbl_new_state(void);
sbj* sbl_profile(sbj* state, const char* id);
sbj* sbl_new_profile(const char* name);
int sbl_validate_state(const sbj* state, sb_err* err);
int sbl_import(sbj* profile, const char* name, const char* url, const char* body,
               sb_err* err);
int sbl_refresh_subscription(sbj* profile, const char* id, sb_err* err);
int sbl_enroll(sbj* profile, const char* url, const char* code, sb_err* err);
int sbl_sync_profile(sbj* profile, bool* changed, sb_err* err);
char* sbl_build(const sbj* profile, bool tun, uid_t uid, int proxy_port, int clash_port,
                const char* secret, const char* cache_path, sb_err* err);

typedef struct {
    sb_singbox_supervisor* core;
    sb_agent_clash* clash;
    char *directory, *path, *secret, *profile_id, *configuration;
    int proxy_port, clash_port;
    bool tun;
} sbl_runtime;
int sbl_runtime_init(sbl_runtime* r, const char* directory, sb_err* err);
int sbl_runtime_start(sbl_runtime* r, const sbj* profile, bool tun, uid_t uid,
                      sb_err* err);
int sbl_runtime_validate(sbl_runtime* r, const sbj* profile, sb_err* err);
void sbl_runtime_stop(sbl_runtime* r);
/* Thread-safe: interrupt Box.New/Start without waiting for the runtime worker. */
void sbl_runtime_cancel_start(void);
void sbl_runtime_clear(sbl_runtime* r);
sbj* sbl_runtime_status(sbl_runtime* r, sb_err* err);
sbj* sbl_runtime_select(sbl_runtime* r, const char* group, const char* name,
                        sb_err* err);
sbj* sbl_runtime_delay(sbl_runtime* r, const char* tag, sb_err* err);
sbj* sbl_runtime_probe(sbl_runtime* r, const char* url, sb_err* err);

/* GNOME proxy recovery is conditional: restore only values still equal to
 * this application's saved writes. Other applications' changes survive. */
int sbl_proxy_apply(const char* directory, int port, const char* secret, sb_err* err);
int sbl_proxy_restore(const char* directory, sb_err* err);
bool sbl_proxy_available(void);
#endif
