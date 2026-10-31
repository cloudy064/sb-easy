/* WireGuard kernel interface (ip/wg/iptables). Moved verbatim from wireguard.c. */
#include "wireguard_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "sb/atomic_file.h"

/* ======================================================================
 * Kernel interface
 * ====================================================================== */

/* std::filesystem::create_directories(path), failing with the libstdc++
 * filesystem_error text. An existing directory is fine. */
static int create_directories(const char *path, sb_err *err) {
    int error = 0;
    struct stat info;
    if (sb_str_empty(path)) {
        error = EINVAL;
    } else if (stat(path, &info) == 0) {
        if (S_ISDIR(info.st_mode)) return 0;
        error = ENOTDIR;
    } else if (errno != ENOENT && errno != ENOTDIR) {
        error = errno;
    } else if (sb_mkdirs(path, 0777) != 0) {
        error = errno;
    } else {
        return 0;
    }
    return sb_fail(err, SB_ERR_IO, "filesystem error: cannot create directories: %s [%s]",
                   strerror(error), S(path));
}

/* The shared head of startup() and sync(): write <config_directory>/
 * <interface>.conf atomically from server_config(). *path_out is malloc'd. */
static int write_server_config(sb_wireguard *wg, const sb_wireguard_options *runtime,
                               char **path_out, sb_err *err) {
    if (create_directories(runtime->config_directory, err) != 0) return -1;
    char *name = sb_asprintf("%s.conf", S(runtime->interface));
    /* std::filesystem::path::operator/ on POSIX. */
    char *path = sb_path_join(runtime->config_directory, name);
    free(name);
    size_t config_len = 0;
    char *config = sb_wireguard_server_config_n(wg, &config_len, err);
    if (!config) {
        free(path);
        return -1;
    }
    int rc = sb_atomic_replace_file(path, config, config_len, NULL, NULL, err);
    free(config);
    if (rc != 0) {
        free(path);
        return -1;
    }
    *path_out = path;
    return 0;
}

int sb_wireguard_sync(sb_wireguard *wg, sb_err *err) {
    if (!wg->options.enabled) return 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return -1;
    char *path = NULL;
    int rc = write_server_config(wg, &runtime, &path, err);
    if (rc == 0) {
        const char *syncconf[] = {"wg", "syncconf", runtime.interface, path, NULL};
        rc = run(syncconf, true, NULL, err);
    }
    free(path);
    sb_wireguard_options_free(&runtime);
    return rc;
}

int sb_wireguard_startup(sb_wireguard *wg, sb_err *err) {
    if (!wg->options.enabled) return 0;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, err) != 0) return -1;
    int rc = -1, code = 0;
    char *path = NULL, *mtu = NULL, *subnet = NULL;
    if (write_server_config(wg, &runtime, &path, err) != 0) goto done;

    const char *show[] = {"ip", "link", "show", runtime.interface, NULL};
    if (run(show, false, &code, err) != 0) goto done;
    if (code == 0) {
        const char *syncconf[] = {"wg", "syncconf", runtime.interface, path, NULL};
        if (run(syncconf, true, NULL, err) != 0) goto done;
    } else {
        const char *add[] = {"ip", "link", "add", runtime.interface, "type", "wireguard", NULL};
        if (run(add, true, NULL, err) != 0) goto done;
        if (runtime.mtu > 0U) {
            mtu = sb_asprintf("%u", (unsigned)runtime.mtu);
            const char *set_mtu[] = {"ip", "link", "set", runtime.interface, "mtu", mtu, NULL};
            if (run(set_mtu, true, NULL, err) != 0) goto done;
        }
        const char *address[] = {"ip", "address", "add", runtime.address, "dev",
                                 runtime.interface, NULL};
        if (run(address, true, NULL, err) != 0) goto done;
        const char *up[] = {"ip", "link", "set", "up", runtime.interface, NULL};
        if (run(up, true, NULL, err) != 0) goto done;
        const char *setconf[] = {"wg", "setconf", runtime.interface, path, NULL};
        if (run(setconf, true, NULL, err) != 0) goto done;
    }

    const char *forward[] = {"sysctl", "-w", "net.ipv4.ip_forward=1", NULL};
    if (run(forward, false, NULL, err) != 0) goto done;
    subnet = subnet_cidr(S(runtime.address));
    const char *masquerade[] = {"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet,
                                "-o", runtime.egress_interface, "-j", "MASQUERADE", NULL};
    if (run(masquerade, false, &code, err) != 0) goto done;
    if (code != 0) {
        masquerade[3] = "-A";
        if (run(masquerade, false, NULL, err) != 0) goto done;
    }
    static const char *const directions[] = {"-i", "-o"};
    for (size_t i = 0; i < 2U; ++i) {
        const char *check[] = {"iptables", "-C", "FORWARD", directions[i], runtime.interface,
                               "-j", "ACCEPT", NULL};
        if (run(check, false, &code, err) != 0) goto done;
        if (code != 0) {
            check[1] = "-A";
            if (run(check, false, NULL, err) != 0) goto done;
        }
    }
    rc = 0;
done:
    free(subnet);
    free(mtu);
    free(path);
    sb_wireguard_options_free(&runtime);
    return rc;
}

void sb_wireguard_shutdown(sb_wireguard *wg) {
    if (!wg || !wg->options.enabled) return;
    /* noexcept in C++: the first failure silently ends the teardown. */
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, NULL) != 0) return;
    char *subnet = subnet_cidr(S(runtime.address));
    const char *delete_masquerade[] = {"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet,
                                       "-o", runtime.egress_interface, "-j", "MASQUERADE", NULL};
    bool ok = run(delete_masquerade, false, NULL, NULL) == 0;
    static const char *const directions[] = {"-i", "-o"};
    for (size_t i = 0; ok && i < 2U; ++i) {
        const char *delete_forward[] = {"iptables", "-D", "FORWARD", directions[i],
                                        runtime.interface, "-j", "ACCEPT", NULL};
        ok = run(delete_forward, false, NULL, NULL) == 0;
    }
    if (ok) {
        const char *delete_link[] = {"ip", "link", "delete", runtime.interface, NULL};
        (void)run(delete_link, false, NULL, NULL);
    }
    free(subnet);
    sb_wireguard_options_free(&runtime);
}

void sb_wireguard_remove_peer(sb_wireguard *wg, const char *public_key) {
    if (!wg || !wg->options.enabled) return;
    sb_wireguard_options runtime;
    if (sb_wireguard_runtime_options(wg, &runtime, NULL) != 0) return;
    const char *remove_argv[] = {"wg", "set", runtime.interface, "peer", S(public_key), "remove",
                                 NULL};
    (void)run(remove_argv, false, NULL, NULL);
    sb_wireguard_options_free(&runtime);
}
