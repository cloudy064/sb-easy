#include "desktop.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int sbl_private_dir(const char* path, uid_t owner, sb_err* err) {
    if (!path || *path != '/')
        return sb_fail(err, SB_ERR_VALIDATION, "Private directory must be absolute");
    if (g_mkdir_with_parents(path, 0700) != 0)
        return sb_fail(err, SB_ERR_IO, "Cannot create private directory");
    int fd = open("/", O_DIRECTORY | O_CLOEXEC);
    bool ok = fd >= 0;
    char** parts = g_strsplit(path, "/", -1);
    for (size_t i = 0; ok && parts[i]; ++i) {
        if (!*parts[i])
            continue;
        if (!strcmp(parts[i], ".") || !strcmp(parts[i], "..")) {
            ok = false;
            break;
        }
        int child = openat(fd, parts[i], O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat st;
        if (child < 0 || fstat(child, &st) || !S_ISDIR(st.st_mode) ||
            (st.st_uid != owner && st.st_uid != 0) ||
            ((st.st_mode & 022) && !(st.st_uid == 0 && (st.st_mode & S_ISVTX)))) {
            if (child >= 0)
                close(child);
            ok = false;
            break;
        }
        close(fd);
        fd = child;
    }
    struct stat st;
    if (ok)
        ok = fstat(fd, &st) == 0 && st.st_uid == owner && !(st.st_mode & 077);
    if (fd >= 0)
        close(fd);
    g_strfreev(parts);
    return ok ? 0
              : sb_fail(err, SB_ERR_IO,
                        "Private directories must have trusted parents, no symbolic "
                        "links, and an owner-only 0700 leaf");
}
char* sbl_uuid(void) {
    char *g = g_uuid_string_random(), *out = sb_strdup(g);
    g_free(g);
    return out;
}
char* sbl_secret(void) {
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof bytes) != 1)
        return NULL;
    char* out = sb_xmalloc(65);
    for (unsigned i = 0; i < 32; ++i)
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
    return out;
}
sbj* sbl_parse(const char* text, size_t max, sb_err* err) {
    if (!text || strlen(text) > max) {
        sb_fail(err, SB_ERR_VALIDATION, "JSON size limit exceeded");
        return NULL;
    }
    /* Bound nesting before recursive JSON parsing. */
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (const char* p = text; *p; ++p) {
        if (quoted) {
            if (escaped)
                escaped = false;
            else if (*p == '\\')
                escaped = true;
            else if (*p == '"')
                quoted = false;
        } else if (*p == '"')
            quoted = true;
        else if (*p == '[' || *p == '{') {
            if (++depth > 48)
                goto bad;
        } else if (*p == ']' || *p == '}') {
            if (!depth)
                goto bad;
            --depth;
        }
    }
    if (depth || quoted)
        goto bad;
    sbj* out = sbj_parse_strict(text, strlen(text), NULL, 0);
    if (!out || sbj_validate_utf8(out, NULL)) {
        sbj_free(out);
        goto bad;
    }
    return out;
bad:
    sb_fail(err, SB_ERR_VALIDATION, "Invalid JSON or excessive nesting");
    return NULL;
}
bool sbl_url(const char* url, bool local, sb_err* err) {
    if (!url || !*url || strlen(url) > 4096 || strpbrk(url, "\r\n\t \\"))
        goto bad;
    GError* error = NULL;
    GUri* uri = g_uri_parse(url, G_URI_FLAGS_NONE, &error);
    g_clear_error(&error);
    if (!uri)
        goto bad;
    const char *host = g_uri_get_host(uri), *scheme = g_uri_get_scheme(uri);
    bool loopback = host && (!strcmp(host, "127.0.0.1") || !strcmp(host, "::1") ||
                             !strcmp(host, "localhost"));
    bool ok =
        host && *host && !g_uri_get_userinfo(uri) && !g_uri_get_fragment(uri) &&
        scheme &&
        (!strcmp(scheme, "https") || (local && loopback && !strcmp(scheme, "http"))) &&
        g_uri_get_port(uri) != 0;
    g_uri_unref(uri);
    if (ok)
        return true;
bad:
    sb_fail(err, SB_ERR_VALIDATION,
            "Use HTTPS without embedded credentials or a fragment (HTTP is limited to "
            "loopback)");
    return false;
}
char* sbl_url_host(const char* url) {
    GUri* uri = g_uri_parse(url, G_URI_FLAGS_NONE, NULL);
    char* host = uri ? sb_strdup(g_uri_get_host(uri)) : NULL;
    if (uri)
        g_uri_unref(uri);
    return host;
}
