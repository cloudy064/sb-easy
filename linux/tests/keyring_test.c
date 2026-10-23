#include "desktop.h"
#include <libsecret/secret.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                                       \
    do {                                                                               \
        if (!(x)) {                                                                    \
            fprintf(stderr, "Keyring test line %d: %s (%s)\n", __LINE__, #x, err.msg); \
            return 1;                                                                  \
        }                                                                              \
    } while (0)
static gpointer cancel_later(gpointer data) {
    g_usleep(300000);
    g_cancellable_cancel(data);
    return NULL;
}
int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    sb_err err = {0};
    sbl_vault vault;
    CHECK(sbl_vault_open(&vault, argv[1], NULL, &err) == 0);
    sbj* state = sbl_new_state();
    sbj* profile = sbl_new_profile("Keyring fixture");
    sbj_arr_push(sbj_get(state, "profiles"), profile);
    sbj_set_str(state, "selected_id", sbj_get_str(profile, "id", ""));
    CHECK(sbl_vault_save(&vault, state, &err) == 0);
    sbj_free(state);
    sbl_vault_close(&vault);
    CHECK(sbl_vault_open(&vault, argv[1], NULL, &err) == 0);
    state = sbl_vault_load(&vault, &err);
    CHECK(state);
    CHECK(sbj_arr_len(sbj_get(state, "profiles")) == 1);
    sbj_free(state);
    sbl_vault_close(&vault);
    SecretService* service =
        secret_service_get_sync(SECRET_SERVICE_LOAD_COLLECTIONS, NULL, NULL);
    CHECK(service);
    GList *collections = secret_service_get_collections(service), *locked = NULL;
    CHECK(collections);
    int count = secret_service_lock_sync(service, collections, NULL, &locked, NULL);
    CHECK(count > 0);
    g_list_free_full(collections, g_object_unref);
    g_list_free_full(locked, g_object_unref);
    g_object_unref(service);
    GCancellable* cancel = g_cancellable_new();
    GThread* thread = g_thread_new("cancel-keyring-prompt", cancel_later, cancel);
    CHECK(sbl_vault_open_cancellable(&vault, argv[1], NULL, cancel, &err) == -1);
    g_thread_join(thread);
    g_object_unref(cancel);
    CHECK(strstr(err.msg, "keyring") || strstr(err.msg, "Vault key"));
    puts("Secret Service persistence and locked-keyring fail-closed checks passed");
    return 0;
}
