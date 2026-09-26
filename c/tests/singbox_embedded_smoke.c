/* Smoke test for SB_EASY_EMBED_SINGBOX builds (port of
 * cpp/tests/singbox_embedded_smoke.cpp): starts the in-process sing-box
 * engine on a minimal config, reloads and stops it. Built as
 * sb-easy-singbox-embedded-smoke only when the Go bridge is linked. */
#include <stdio.h>
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
