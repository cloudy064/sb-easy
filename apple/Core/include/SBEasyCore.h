/* Portable C11 boundary shared by the native Apple app and packet tunnel.
 * All returned strings (including errors) are owned; release with sba_free.
 * JSON nodes/configuration contain credentials and must remain private. */
#ifndef SB_APPLE_CORE_H
#define SB_APPLE_CORE_H
#include <stdbool.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
char *sba_import_subscription(const char *body, size_t length, char **error);
/* source=NULL means independent mode. subscriptions is an array of
 * {id,nodes}; settings is {selected_tag?,local_groups?}. Control host is a
 * validated hostname/IP, never a URL. Inputs are never changed. */
char *sba_build_runtime(const char *source, const char *subscriptions, const char *settings,
                        const char *control_host, char **error);
/* Validate and normalize local group preferences before writing a profile. */
char *sba_validate_settings(const char *settings, char **error);
/* Subscription-Userinfo parsing; unknown/invalid metadata is unavailable. */
char *sba_subscription_metadata(const char *header, long long now_seconds);
void sba_free(void *memory);
#ifdef __cplusplus
}
#endif
#endif
