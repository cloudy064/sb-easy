#include "desktop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                                       \
    do {                                                                               \
        if (!(x)) {                                                                    \
            fprintf(stderr, "System proxy test line %d: %s (%s)\n", __LINE__, #x,      \
                    err.msg);                                                          \
            return 1;                                                                  \
        }                                                                              \
    } while (0)
int main(void) {
    sb_err err = {0};
    CHECK(!g_strcmp0(g_getenv("GSETTINGS_BACKEND"), "memory"));
    CHECK(sbl_proxy_available());
    char path[] = "/tmp/sb-linux-proxy-XXXXXX";
    CHECK(mkdtemp(path));
    char* secret = sbl_secret();
    CHECK(secret);
    GSettings *http = g_settings_new("org.gnome.system.proxy.http"),
              *global = g_settings_new("org.gnome.system.proxy");
    g_settings_set_string(http, "host", "previous-proxy");
    g_settings_set_int(http, "port", 30000);
    g_settings_set_string(global, "mode", "none");
    CHECK(sbl_proxy_apply(path, 32145, secret, &err) == 0);
    char* value = g_settings_get_string(http, "host");
    CHECK(!strcmp(value, "127.0.0.1"));
    g_free(value);
    CHECK(g_settings_get_int(http, "port") == 32145);
    CHECK(g_settings_get_boolean(http, "use-authentication"));
    /* Another application changes one field. Recovery must retain its value. */
    g_settings_set_string(http, "host", "another-app");
    CHECK(sbl_proxy_restore(path, &err) == 0);
    value = g_settings_get_string(http, "host");
    CHECK(!strcmp(value, "another-app"));
    g_free(value);
    CHECK(g_settings_get_int(http, "port") == 30000);
    value = g_settings_get_string(global, "mode");
    CHECK(!strcmp(value, "none"));
    g_free(value);
    CHECK(sbl_proxy_apply(path, 32145, secret, &err) == 0);
    CHECK(sbl_proxy_restore(path, &err) == 0);
    char* file = sb_asprintf("%s/proxy-recovery.json", path);
    CHECK(access(file, F_OK) != 0);
    free(file);
    free(secret);
    g_object_unref(http);
    g_object_unref(global);
    rmdir(path);
    puts("System proxy snapshots, crash recovery and ownership comparison passed");
    return 0;
}
