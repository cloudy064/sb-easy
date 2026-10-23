#include "controller.h"
#include "sb/http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct {
    GMainLoop* loop;
    sbl_controller* c;
    sbl_event* event;
} fixture;
#define CHECK(x)                                                                       \
    do {                                                                               \
        if (!(x)) {                                                                    \
            fprintf(stderr, "Controller line %d: %s (%s)\n", __LINE__, #x,             \
                    f.event ? f.event->message : "");                                  \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)
static void receive(sbl_event* event, void* data) {
    fixture* f = data;
    f->event = event;
    g_main_loop_quit(f->loop);
}
static void perform(fixture* f, sbl_action action, const char* a, const char* b,
                    const char* d, int number) {
    sbl_event_free(f->event);
    f->event = NULL;
    if (!sbl_controller_submit(f->c, action, a, b, d, number))
        abort();
    g_main_loop_run(f->loop);
}
int main(int argc, char** argv) {
    if (argc != 5)
        return 2;
    fixture f = {.loop = g_main_loop_new(NULL, FALSE)};
    unsigned char key[32];
    memset(key, 51, sizeof key);
    char *data = sb_asprintf("%s/data", argv[1]),
         *runtime = sb_asprintf("%s/runtime", argv[1]);
    f.c = sbl_controller_new(data, runtime, key, false, receive, &f);
    perform(&f, SBL_OPEN, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    char* body = sb_asprintf("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"Local\","
                             "\"server\":\"127.0.0.1\",\"server_port\":%s}]}",
                             argv[2]);
    perform(&f, SBL_IMPORT, "Fixture", body, NULL, 0);
    free(body);
    CHECK(f.event->success);
    perform(&f, SBL_CONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    char* url = sb_asprintf("http://127.0.0.1:%s/slow", argv[3]);
    perform(&f, SBL_PROBE, url, NULL, NULL, 0);
    CHECK(f.event->success && sbj_get_bool(f.event->result, "success", false));
    perform(&f, SBL_SETTINGS,
            "{\"process_rules\":[{\"process_path\":[\"relative-path\"],\"outbound\":"
            "\"missing\"}]}",
            NULL, NULL, 0);
    CHECK(!f.event->success);
    CHECK(sbj_get_bool(sbj_get(f.event->view, "runtime"), "running", false));
    perform(&f, SBL_DISCONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    char* center = sb_asprintf("http://127.0.0.1:%s", argv[4]);
    perform(&f, SBL_ENROLL, center, "fixture-code-0123456789abcdef0123456789abcdef", NULL, 0);
    CHECK(f.event->success);
    sbj* p = sbl_profile(f.event->view, sbj_get_str(f.event->view, "selected_id", ""));
    CHECK(!sbj_get_bool(p, "source_ready", true));
    perform(&f, SBL_SYNC, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    perform(&f, SBL_CONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    perform(&f, SBL_SYNC, NULL, NULL, NULL, 1);
    CHECK(f.event->success);
    CHECK(sbj_get_bool(sbj_get(f.event->view, "runtime"), "running", false));
    perform(&f, SBL_PROBE, url, NULL, NULL, 0);
    CHECK(f.event->success && sbj_get_bool(f.event->result, "success", false));
    perform(&f, SBL_DISCONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    char* bad = sb_asprintf("%s/fixture/bad", center);
    sb_http_request request = {.url = bad};
    sb_http_response response = {0};
    CHECK(!sb_http_perform(&request, &response, NULL));
    sb_http_response_free(&response);
    free(bad);
    perform(&f, SBL_SYNC, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    perform(&f, SBL_CONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success && sbj_get_bool(f.event->result, "fallback", false));
    perform(&f, SBL_PROBE, url, NULL, NULL, 0);
    CHECK(f.event->success && sbj_get_bool(f.event->result, "success", false));
    perform(&f, SBL_DISCONNECT, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    perform(&f, SBL_ENROLL, center, "fixture-code-0123456789abcdef0123456789abcdef", NULL, 0);
    CHECK(f.event->success);
    p = sbl_profile(f.event->view, sbj_get_str(f.event->view, "selected_id", ""));
    CHECK(!sbj_get_bool(p, "source_ready", true));
    perform(&f, SBL_DETACH, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    p = sbl_profile(f.event->view, sbj_get_str(f.event->view, "selected_id", ""));
    char* subscription_id =
        sb_strdup(sbj_get_str(sbj_arr_at(sbj_get(p, "subscriptions"), 0), "id", ""));
    perform(&f, SBL_REMOVE_SUBSCRIPTION, subscription_id, NULL, NULL, 0);
    free(subscription_id);
    CHECK(f.event->success);
    perform(&f, SBL_SHUTDOWN, NULL, NULL, NULL, 0);
    CHECK(f.event->success);
    sbl_controller_free(f.c);
    sbl_event_free(f.event);
    f.event = NULL;
    sbl_vault vault;
    sb_err err = {0};
    CHECK(!sbl_vault_open(&vault, data, key, &err));
    sbj* saved = sbl_vault_load(&vault, &err);
    CHECK(saved);
    char* plain = sbj_dump(saved, -1);
    CHECK(!strstr(plain, "fixture-token") && !strstr(plain, "last_good"));
    free(plain);
    sbj_free(saved);
    sbl_vault_close(&vault);
    g_main_loop_unref(f.loop);
    free(data);
    free(runtime);
    free(center);
    free(url);
    puts("Native controller independent/managed sync, failed update fallback and "
         "identity removal passed");
    return 0;
}
