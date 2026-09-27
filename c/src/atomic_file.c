#include "sb/atomic_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* std::system_error(errno, generic_category(), op).what() == "op: strerror". */
static int system_fail(sb_err *err, const char *operation, int error) {
    return sb_fail(err, SB_ERR_IO, "%s: %s", operation, strerror(error));
}

static char *temporary_path_for(const char *destination, sb_err *err) {
    unsigned char random[8];
    if (sb_random_bytes(random, sizeof random) != 0) {
        sb_fail(err, SB_ERR_GENERIC, "secure temporary filename generation failed");
        return NULL;
    }
    char *suffix = sb_hex_encode(random, sizeof random);
    char *path = sb_asprintf("%s.tmp.%s", destination, suffix);
    free(suffix);
    return path;
}

static int destination_mode(const char *destination, mode_t *mode, sb_err *err) {
    struct stat information;
    if (stat(destination, &information) == 0) {
        *mode = information.st_mode & (mode_t)0777;
        return 0;
    }
    if (errno != ENOENT) return system_fail(err, "inspect destination config", errno);
    *mode = (mode_t)0600;
    return 0;
}

static int fsync_directory(const char *directory, sb_err *err) {
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return system_fail(err, "open config directory", errno);
    if (fsync(fd) != 0) {
        int error = errno;
        close(fd);
        return system_fail(err, "fsync config directory", error);
    }
    if (close(fd) != 0) return system_fail(err, "close config directory", errno);
    return 0;
}

static int write_all(int fd, const char *data, size_t len, sb_err *err) {
    size_t written = 0;
    while (written < len) {
        ssize_t result = write(fd, data + written, len - written);
        if (result < 0) {
            if (errno == EINTR) continue;
            return system_fail(err, "write temporary config", errno);
        }
        if (result == 0)
            return sb_fail(err, SB_ERR_IO, "write temporary config made no progress");
        written += (size_t)result;
    }
    if (fsync(fd) != 0) return system_fail(err, "fsync temporary config", errno);
    return 0;
}

int sb_atomic_replace_file(const char *destination, const void *contents, size_t len,
                           sb_file_validator validator, void *user, sb_err *err) {
    /* std::filesystem: an empty path or one ending in '/' has no filename. */
    if (sb_str_empty(destination) || sb_ends_with(destination, "/"))
        return sb_fail(err, SB_ERR_VALIDATION, "config destination must name a file");
    const char *slash = strrchr(destination, '/');
    char *directory = NULL;
    if (!slash) directory = sb_strdup(".");
    else if (slash == destination) directory = sb_strdup("/");
    else directory = sb_strndup(destination, (size_t)(slash - destination));

    int rc = -1;
    char *temporary = NULL;
    int fd = -1;
    if (sb_mkdirs(directory, 0777) != 0) {
        system_fail(err, "create_directories", errno);
        goto out;
    }
    mode_t mode = 0;
    if (destination_mode(destination, &mode, err) != 0) goto out;
    temporary = temporary_path_for(destination, err);
    if (!temporary) goto out;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        system_fail(err, "create temporary config", errno);
        free(temporary);
        temporary = NULL; /* never created: nothing to remove */
        goto out;
    }
    if (write_all(fd, contents, len, err) != 0) goto cleanup;
    int close_result = close(fd);
    fd = -1;
    if (close_result != 0) {
        system_fail(err, "close temporary config", errno);
        goto cleanup;
    }
    if (validator && validator(temporary, user, err) != 0) goto cleanup;
    if (rename(temporary, destination) != 0) {
        system_fail(err, "replace config", errno);
        goto cleanup;
    }
    free(temporary);
    temporary = NULL;
    rc = fsync_directory(directory, err);
    goto out;

cleanup:
    if (fd >= 0) close(fd);
    if (temporary) unlink(temporary);
out:
    free(temporary);
    free(directory);
    return rc;
}
