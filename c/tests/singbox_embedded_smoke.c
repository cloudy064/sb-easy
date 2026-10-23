/* Smoke test for SB_EASY_EMBED_SINGBOX builds (port of
 * cpp/tests/singbox_embedded_smoke.cpp): starts the in-process sing-box
 * engine on a minimal config, reloads and stops it. Built as
 * sb-easy-singbox-embedded-smoke only when the Go bridge is linked. */
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sb/singbox_supervisor.h"

static const char *const minimal_config =
    "{\n"
    "  \"log\": {\"level\": \"error\"},\n"
    "  \"inbounds\": [],\n"
    "  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}],\n"
    "  \"route\": {\"final\": \"direct\"}\n"
    "}";

int main(void) {
    char *config = sb_asprintf("/tmp/sb-easy-embedded-singbox-%lld.json", (long long)getpid());
    sb_singbox_supervisor_options options;
    sb_singbox_supervisor_options_init(&options);
    options.binary = "embedded";
    options.config_path = config;
    options.validate_config = true;
    sb_err err = {0};
    int status = 1;
    sb_singbox_supervisor *supervisor = sb_singbox_supervisor_new(&options, &err);
    if (!supervisor) {
        fprintf(stderr, "%s\n", err.msg);
        goto done;
    }
    if (sb_singbox_supervisor_apply_config(supervisor, minimal_config, strlen(minimal_config), &err) != 0) {
        fprintf(stderr, "%s\n", err.msg);
        goto done;
    }
    if (!sb_singbox_supervisor_running(supervisor) || sb_singbox_supervisor_pid(supervisor) != getpid()) {
        fprintf(stderr, "embedded sing-box did not run in the owning process\n");
        goto done;
    }
    if (sb_singbox_supervisor_reload(supervisor, &err) != 0) {
        fprintf(stderr, "%s\n", err.msg);
        goto done;
    }
    /* A valid config can still fail during Start (for example an occupied
     * port). Verify that both the live instance and on-disk config recover. */
    int occupied = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = 0,
                                  .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    socklen_t address_len = sizeof address;
    if (occupied < 0 || bind(occupied, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(occupied, 1) != 0 || getsockname(occupied, (struct sockaddr *)&address, &address_len) != 0) {
        if (occupied >= 0) close(occupied);
        fprintf(stderr, "could not reserve an isolated test port\n");
        goto done;
    }
    char *blocked = sb_asprintf("{\"log\":{\"level\":\"error\"},\"inbounds\":[{\"type\":\"mixed\",\"listen\":\"127.0.0.1\",\"listen_port\":%u}],\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"final\":\"direct\"}}", (unsigned)ntohs(address.sin_port));
    int failed_apply = sb_singbox_supervisor_apply_config(supervisor, blocked, strlen(blocked), &err);
    free(blocked); close(occupied);
    size_t restored_len = 0;
    char *restored = sb_read_file(config, &restored_len);
    bool recovered = restored && restored_len == strlen(minimal_config) &&
        memcmp(restored, minimal_config, restored_len) == 0;
    free(restored);
    if (failed_apply == 0 || !sb_singbox_supervisor_running(supervisor) || !recovered) {
        fprintf(stderr, "failed replacement did not recover the previous runtime and file: %s\n", err.msg);
        goto done;
    }
    sb_singbox_supervisor_stop(supervisor);
    if (sb_singbox_supervisor_running(supervisor)) {
        fprintf(stderr, "embedded sing-box did not stop\n");
        goto done;
    }
    status = 0;
done:
    sb_singbox_supervisor_free(supervisor);
    unlink(config);
    free(config);
    return status;
}
