/* Optional same-platform worker for bridge-network panels whose proxy
 * connections need the server's egress namespace. No TCP listener or DB. */
#include "sb/node_probe.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct { int listener; const char *binary; uint32_t mark; } probe_worker;

static void *serve(void *data) {
    const probe_worker *w = data;
    for (;;) {
        int fd = accept4(w->listener, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return NULL;
        }
        sb_probe_serve_connection(fd, w->binary, w->mark);
        close(fd);
    }
}

int main(int argc, char **argv) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    if (argc != 2 || argv[1][0] != '/' || strlen(argv[1]) >= sizeof addr.sun_path) {
        fprintf(stderr, "Usage: sb-easy-c-probe /absolute/path/to/probe.sock\n");
        return 2;
    }
    strcpy(addr.sun_path, argv[1]);
    probe_worker worker = {.binary = getenv("SINGBOX_BIN")};
    if (!worker.binary || !*worker.binary) worker.binary = "sing-box";
    const char *mark = getenv("SB_EASY_PROBE_ROUTING_MARK");
    if (mark && *mark) {
        char *end;
        errno = 0;
        unsigned long value = strtoul(mark, &end, 0);
        if (*mark == '-' || *end || errno || value > UINT32_MAX) return 2;
        worker.mark = (uint32_t)value;
    }
    umask(0077);
    char *lock_path = sb_asprintf("%s.lock", addr.sun_path);
    int lock = open(lock_path, O_NOFOLLOW | O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    free(lock_path);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) < 0) return 1;
    struct stat st;
    if (lstat(addr.sun_path, &st) == 0 && (!S_ISSOCK(st.st_mode) || unlink(addr.sun_path) < 0))
        return 1;
    worker.listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (worker.listener < 0 || bind(worker.listener, (struct sockaddr *)&addr, sizeof addr) < 0 ||
        listen(worker.listener, 32) < 0) return 1;
    pthread_t threads[7];
    for (size_t i = 0; i < 7; ++i)
        if (pthread_create(&threads[i], NULL, serve, &worker) != 0) return 1;
    serve(&worker);
    return 1;
}
