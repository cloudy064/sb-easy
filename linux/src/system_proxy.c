#include "desktop.h"
#include "sb/atomic_file.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
typedef struct {
    const char *schema, *key;
} proxy_key;
static const proxy_key keys[] = {
    {"org.gnome.system.proxy", "mode"},
    {"org.gnome.system.proxy", "use-same-proxy"},
    {"org.gnome.system.proxy.http", "host"},
    {"org.gnome.system.proxy.http", "port"},
    {"org.gnome.system.proxy.http", "enabled"},
    {"org.gnome.system.proxy.http", "use-authentication"},
    {"org.gnome.system.proxy.http", "authentication-user"},
    {"org.gnome.system.proxy.http", "authentication-password"},
    {"org.gnome.system.proxy.https", "host"},
    {"org.gnome.system.proxy.https", "port"},
    {"org.gnome.system.proxy.socks", "host"},
    {"org.gnome.system.proxy.socks", "port"}};
bool sbl_proxy_available(void) {
    GSettingsSchemaSource* source = g_settings_schema_source_get_default();
    if (!source)
        return false;
    for (size_t i = 0; i < G_N_ELEMENTS(keys); ++i) {
        GSettingsSchema* schema =
            g_settings_schema_source_lookup(source, keys[i].schema, TRUE);
        if (!schema)
            return false;
        bool found = g_settings_schema_has_key(schema, keys[i].key);
        g_settings_schema_unref(schema);
        if (!found)
            return false;
    }
    return true;
}
static GVariant* desired(size_t i, int port, const char* secret) {
    switch (i) {
    case 0:
        return g_variant_new_string("manual");
    case 1:
        return g_variant_new_boolean(FALSE);
    case 2:
    case 8:
        return g_variant_new_string("127.0.0.1");
    case 3:
    case 9:
        return g_variant_new_int32(port);
    case 4:
    case 5:
        return g_variant_new_boolean(TRUE);
    case 6:
        return g_variant_new_string("sbeasy");
    case 7:
        return g_variant_new_string(secret);
    case 10:
        return g_variant_new_string("");
    default:
        return g_variant_new_int32(0);
    }
}
int sbl_proxy_restore(const char* directory, sb_err* err) {
    if (sbl_private_dir(directory, geteuid(), err))
        return -1;
    char* path = sb_asprintf("%s/proxy-recovery.json", directory);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        free(path);
        return 0;
    }
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) || st.st_size < 2 || st.st_size > 65536) {
        if (fd >= 0)
            close(fd);
        free(path);
        return sb_fail(err, SB_ERR_IO, "Cannot read system proxy recovery data safely");
    }
    char* raw = sb_xmalloc((size_t)st.st_size + 1);
    size_t done = 0;
    while (done < (size_t)st.st_size) {
        ssize_t n = read(fd, raw + done, (size_t)st.st_size - done);
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    close(fd);
    raw[done] = 0;
    sbj* snapshot = done == (size_t)st.st_size ? sbl_parse(raw, 65536, NULL) : NULL;
    free(raw);
    if (!sbj_is_array(snapshot) || sbj_arr_len(snapshot) != G_N_ELEMENTS(keys) ||
        !sbl_proxy_available()) {
        sbj_free(snapshot);
        free(path);
        return sb_fail(err, SB_ERR_IO,
                       "System proxy recovery is unavailable; the recovery snapshot "
                       "was preserved");
    }
    bool ok = true;
    for (size_t i = 0; i < G_N_ELEMENTS(keys); ++i) {
        const sbj* entry = sbj_arr_at(snapshot, i);
        GSettings* settings = g_settings_new(keys[i].schema);
        GVariant* now = g_settings_get_value(settings, keys[i].key);
        const GVariantType* type = g_variant_get_type(now);
        GVariant *ours = g_variant_parse(type, sbj_get_str(entry, "ours", ""), NULL,
                                         NULL, NULL),
                 *old = g_variant_parse(type, sbj_get_str(entry, "old", ""), NULL, NULL,
                                        NULL);
        if (!ours || !old)
            ok = false;
        else if (g_variant_equal(now, ours) &&
                 !g_settings_set_value(settings, keys[i].key, old))
            ok = false;
        if (ours)
            g_variant_unref(ours);
        if (old)
            g_variant_unref(old);
        g_variant_unref(now);
        g_object_unref(settings);
    }
    g_settings_sync();
    sbj_free(snapshot);
    if (ok && unlink(path) != 0 && errno != ENOENT)
        ok = false;
    free(path);
    return ok ? 0
              : sb_fail(err, SB_ERR_IO,
                        "Some system proxy settings could not be restored. Retry "
                        "recovery after unlocking desktop settings.");
}
int sbl_proxy_apply(const char* directory, int port, const char* secret, sb_err* err) {
    if (!sbl_proxy_available())
        return sb_fail(err, SB_ERR_NOT_FOUND,
                       "GNOME system proxy settings are unavailable. Use the "
                       "authenticated proxy manually or choose TUN.");
    if (port <= 0 || port > 65535 || !secret || strlen(secret) != 64)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid local proxy endpoint");
    if (sbl_proxy_restore(directory, err))
        return -1;
    sbj* snapshot = sbj_array();
    for (size_t i = 0; i < G_N_ELEMENTS(keys); ++i) {
        GSettings* settings = g_settings_new(keys[i].schema);
        if (!g_settings_is_writable(settings, keys[i].key)) {
            g_object_unref(settings);
            sbj_free(snapshot);
            return sb_fail(err, SB_ERR_IO,
                           "Desktop system proxy settings are locked by policy");
        }
        GVariant *old = g_settings_get_value(settings, keys[i].key),
                 *ours = g_variant_ref_sink(desired(i, port, secret));
        char *old_text = g_variant_print(old, TRUE),
             *ours_text = g_variant_print(ours, TRUE);
        sbj* entry = sbj_object();
        sbj_set_str(entry, "old", old_text);
        sbj_set_str(entry, "ours", ours_text);
        sbj_arr_push(snapshot, entry);
        g_free(old_text);
        g_free(ours_text);
        g_variant_unref(old);
        g_variant_unref(ours);
        g_object_unref(settings);
    }
    char *raw = sbj_dump(snapshot, -1),
         *path = sb_asprintf("%s/proxy-recovery.json", directory);
    int rc = sb_atomic_replace_file(path, raw, strlen(raw), NULL, NULL, err);
    free(path);
    free(raw);
    if (rc) {
        sbj_free(snapshot);
        return rc;
    }
    bool ok = true;
    /* Activate manual mode last, after both authenticated HTTP endpoints. */
    for (size_t n = 1; n <= G_N_ELEMENTS(keys); ++n) {
        size_t i = n % G_N_ELEMENTS(keys);
        GSettings* settings = g_settings_new(keys[i].schema);
        GVariant* value = g_variant_ref_sink(desired(i, port, secret));
        if (!g_settings_set_value(settings, keys[i].key, value))
            ok = false;
        g_variant_unref(value);
        g_object_unref(settings);
    }
    g_settings_sync();
    sbj_free(snapshot);
    if (!ok) {
        sbl_proxy_restore(directory, NULL);
        return sb_fail(err, SB_ERR_IO,
                       "System proxy setup failed and recovery was attempted");
    }
    return 0;
}
