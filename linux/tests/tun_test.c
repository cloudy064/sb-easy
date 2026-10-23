#include "desktop.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char** argv) {
    if (argc != 3 || geteuid() != 0 ||
        !getenv("SBL_TUN_FIXTURE") ||
        strcmp(getenv("SBL_TUN_FIXTURE"), "disposable-container") ||
        access("/.dockerenv", F_OK))
        return 2;
    sb_err err = {0};
    char work[] = "/tmp/sbl-tun-test-XXXXXX";
    if (!mkdtemp(work))
        return 2;
    sbl_runtime runtime;
    if (sbl_runtime_init(&runtime, work, &err))
        return 2;
    sbj* profile = sbl_new_profile("Isolated TUN acceptance");
    char* body = sb_asprintf("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"Fixture\","
                             "\"server\":\"127.0.0.1\",\"server_port\":%s}]}", argv[1]);
    int result = sbl_import(profile, "Fixture", "", body, &err);
    free(body);
    if (!result)
        result = sbl_runtime_start(&runtime, profile, true, 1000, &err);
    if (!result) {
        puts("TUN_READY");
        fflush(stdout);
        (void)getchar();
    } else {
        fprintf(stderr, "TUN startup: %s\n", err.msg);
    }
    sbl_runtime_clear(&runtime);
    sbj_free(profile);
    if (!strcmp(argv[2], "conflict"))
        return result ? 0 : 3;
    return result ? 1 : 0;
}
