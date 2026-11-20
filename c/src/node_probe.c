#include "sb/node_probe.h"
#include "sb/config_renderer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static const char probe_url[] = "https://www.gstatic.com/generate_204";

static int run_fetch(const char *binary, const char *config) {
    /* Anonymous file: the child reads credentials on stdin. No shared path,
     * command-line credentials, API listener or change to a running core. */
    FILE *input = tmpfile();
    if (!input) return SB_PROBE_UNAVAILABLE;
    int result = SB_PROBE_UNAVAILABLE;
    if (fcntl(fileno(input), F_SETFD, FD_CLOEXEC) < 0 ||
        fputs(config, input) == EOF || fseek(input, 0, SEEK_SET) != 0) goto done;

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) goto done;
    pid_t child = -1;
    char *argv[] = {(char *)binary, "-c", "stdin", "tools", "--outbound", "probe",
                    "fetch", (char *)probe_url, NULL};
    int64_t start = sb_monotonic_ms();
    int spawned = -1;
    if (posix_spawn_file_actions_adddup2(&actions, fileno(input), STDIN_FILENO) == 0 &&
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0)
        spawned = posix_spawnp(&child, binary, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (spawned != 0) goto done;
    for (;;) {
        int status;
        pid_t waited = waitpid(child, &status, WNOHANG);
        int64_t elapsed = sb_monotonic_ms() - start;
        if (waited == child) {
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 0) result = (int)elapsed;
                else if (code != 126 && code != 127) result = SB_PROBE_UNREACHABLE;
            }
            break;
        }
        if (waited < 0 && errno != EINTR) break;
        if (elapsed >= SB_PROBE_TIMEOUT_MS) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            result = SB_PROBE_UNREACHABLE;
            break;
        }
        nanosleep(&(struct timespec){.tv_nsec = 5000000L}, NULL);
    }
done:
    fclose(input);
    return result;
}

int sb_probe_run(const sbj *value, const char *binary, uint32_t mark) {
    sb_proxy_node node;
    if (sb_proxy_node_from_json(value, &node, NULL) != 0) return SB_PROBE_UNAVAILABLE;
    sbj *outbound = sb_config_generate_outbound(&node, NULL);
    sb_proxy_node_free(&node);
    /* The config renderer falls back to direct for unknown types. A direct
     * connection would attribute the platform's own latency to the node. */
    if (!outbound || sbj_string_is(sbj_get(outbound, "type"), "direct")) {
        sbj_free(outbound);
        return SB_PROBE_UNAVAILABLE;
    }
    sbj_set_str(outbound, "tag", "probe");
    if (mark) sbj_set_int(outbound, "routing_mark", mark);
    sbj *config = sbj_object(), *outbounds = sbj_array();
    sbj_arr_push(outbounds, outbound);
    sbj_set(config, "outbounds", outbounds);
    char *text = sbj_dump(config, -1);
    sbj_free(config);
    int result = text ? run_fetch(binary, text) : SB_PROBE_UNAVAILABLE;
    free(text);
    return result;
}

/* A length-prefixed JSON node and one signed 32-bit result, both lengths and
 * integers in network byte order. Only the platform owns the private socket. */
static bool transfer(int fd, void *data, size_t len, bool writing) {
    char *p = data;
    while (len) {
        ssize_t n = writing ? send(fd, p, len, MSG_NOSIGNAL) : recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return true;
}

static bool set_timeouts(int fd) {
    struct timeval tv = {.tv_sec = 10};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0;
}

void sb_probe_serve_connection(int fd, const char *binary, uint32_t mark) {
    uint32_t wire;
    if (!set_timeouts(fd) || !transfer(fd, &wire, sizeof wire, false)) return;
    size_t n = ntohl(wire);
    if (!n || n > SB_PROBE_MAX_BYTES) return;
    char *data = sb_xmalloc(n);
    sbj *node = transfer(fd, data, n, false) ? sbj_parse_strict(data, n, NULL, 0) : NULL;
    free(data);
    int result = node ? sb_probe_run(node, binary, mark) : SB_PROBE_UNAVAILABLE;
    sbj_free(node);
    wire = htonl((uint32_t)result);
    transfer(fd, &wire, sizeof wire, true);
}

static int remote_probe(const char *path, const sbj *node) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof addr.sun_path) return SB_PROBE_UNAVAILABLE;
    strcpy(addr.sun_path, path);
    char *data = sbj_dump(node, -1);
    size_t n = data ? strlen(data) : 0;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int result = SB_PROBE_UNAVAILABLE;
    if (fd >= 0 && n && n <= SB_PROBE_MAX_BYTES && set_timeouts(fd) &&
        connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
        uint32_t wire = htonl((uint32_t)n);
        if (transfer(fd, &wire, sizeof wire, true) && transfer(fd, data, n, true) &&
            transfer(fd, &wire, sizeof wire, false)) {
            int32_t value = (int32_t)ntohl(wire);
            if (value >= SB_PROBE_UNREACHABLE && value <= SB_PROBE_TIMEOUT_MS + 1000) result = value;
        }
    }
    if (fd >= 0) close(fd);
    free(data);
    return result;
}

int sb_node_probe(const sb_proxy_record *node, const char *binary, sb_err *err,
                  double *latency, bool *measured) {
    sb_proxy_node render = {.id = node->id, .id_len = strlen(node->id),
        .tag = "probe", .tag_len = 5, .enabled = true,
        .type = node->node_type, .type_len = node->node_type_len,
        .server = node->server, .server_len = node->server_len, .server_port = node->server_port,
        .protocol_config = node->protocol_config};
    sbj *value = sb_proxy_node_to_json(&render);
    const char *socket_path = getenv("SB_EASY_PROBE_SOCKET");
    int result = socket_path && *socket_path ? remote_probe(socket_path, value)
                                            : sb_probe_run(value, binary, 0);
    sbj_free(value);
    if (result == SB_PROBE_UNAVAILABLE)
        return sb_fail(err, SB_ERR_UNAVAILABLE, "Platform latency checker unavailable");
    *measured = result >= 0;
    *latency = *measured ? result : 0;
    return 0;
}
