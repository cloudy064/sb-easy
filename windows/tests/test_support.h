#ifndef SB_WINDOWS_TEST_SUPPORT_H
#define SB_WINDOWS_TEST_SUPPORT_H
#include "../service/controller.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

typedef struct test_data {
    sbj *saved, *download;
    bool fail_write, fail_fetch;
    unsigned enrollments, downloads;
    char *last_etag;
    HANDLE entered, release, cancel_after_enroll;
} test_data;
static inline int test_load(void *context, sbj **out, sbw_error *error) {
    (void)error; test_data *data = context; *out = sbj_clone(data->saved); return 0;
}
static inline int test_save(void *context, const sbj *state, sbw_error *error) {
    test_data *data = context;
    if (data->fail_write) return sbw_fail(error, "STORAGE_ERROR", "Device state could not be securely saved.");
    sbj_free(data->saved); data->saved = sbj_clone(state); return 0;
}
static inline int test_clear(void *context, sbw_error *error) {
    (void)error; test_data *data = context; sbj_free(data->saved); data->saved = NULL; return 0;
}
static inline int test_enroll(void *context, const sbw_enrollment_target *target, HANDLE cancel, sbj **out, sbw_error *error) {
    (void)cancel; (void)error; test_data *data = context;
    HANDLE token = NULL;
    BOOL impersonating = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    if (token) CloseHandle(token);
    CHECK(!impersonating && GetLastError() == ERROR_NO_TOKEN);
    ++data->enrollments;
    *out = sbj_object();
    sbj_set_str(*out, "server", target->server); sbj_set_str(*out, "host_id", "device-1");
    sbj_set_str(*out, "host_name", "Windows 测试设备"); sbj_set_str(*out, "agent_token", "private-agent-token-never-returned");
    sbj_set_str(*out, "profile_id", "profile-1"); sbj_set_str(*out, "profile_name", "Managed profile");
    if (data->cancel_after_enroll) SetEvent(data->cancel_after_enroll);
    return 0;
}
static inline int test_fetch(void *context, const sbj *identity, const char *etag, HANDLE cancel, sbj **out, sbw_error *error) {
    (void)cancel; test_data *data = context;
    CHECK(sb_streq(sbj_get_str(identity, "agent_token", ""), "private-agent-token-never-returned"));
    ++data->downloads; sb_str_set(&data->last_etag, etag);
    if (data->entered) { SetEvent(data->entered); CHECK(WaitForSingleObject(data->release, 5000) == WAIT_OBJECT_0); }
    if (data->fail_fetch) return sbw_fail(error, "http_error", "The server rejected the request.");
    *out = sbj_clone(data->download); return 0;
}
static inline sbw_controller *test_controller(test_data *data, HANDLE cancel) {
    sbw_control_plane *remote = sb_xcalloc(1, sizeof *remote);
    sbw_store *store = sb_xcalloc(1, sizeof *store);
    remote->context = data; remote->enroll = test_enroll; remote->fetch_config = test_fetch;
    store->context = data; store->load = test_load; store->save = test_save; store->clear = test_clear;
    sbw_controller *controller = sbw_controller_new(remote, store, cancel, NULL);
    CHECK(controller); return controller;
}
static inline void test_data_init(test_data *data) {
    memset(data, 0, sizeof *data);
    data->download = sbj_parse_cstr("{\"not_modified\":false,\"content\":\"{\\\"inbounds\\\":[{\\\"type\\\":\\\"tun\\\"}],\\\"outbounds\\\":[{\\\"type\\\":\\\"direct\\\",\\\"password\\\":\\\"secret-proxy-value\\\"}],\\\"route\\\":{\\\"rules\\\":[{\\\"outbound\\\":\\\"direct\\\"}]}}\",\"etag\":\"revision-1\",\"rule_source\":\"quickjs\",\"profile_id\":\"profile-1\",\"profile_name\":\"Managed profile\"}");
    CHECK(data->download);
}
static inline void test_data_free(test_data *data) {
    sbj_free(data->saved); sbj_free(data->download); free(data->last_etag);
}
static inline sbj *test_enrollment(void) {
    sbj *params = sbj_object();
    sbj_set_str(params, "uri", "sbeasy://enroll?server=https%3A%2F%2Fexample.test%2Fpanel&code=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return params;
}
static inline void test_redacted(const sbj *value) {
    char *text = sbj_dump(value, -1);
    CHECK(!strstr(text, "private-agent-token") && !strstr(text, "secret-proxy-value") && !strstr(text, "agent_token") && !strstr(text, "aaaaaaaaaaaaaaaa"));
    free(text);
}
#endif
