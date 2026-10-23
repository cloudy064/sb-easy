#ifndef SBW_CAPTURE_H
#define SBW_CAPTURE_H
#include "../common.h"
typedef struct sbw_capture sbw_capture;
/* Private per-server/device directory, separate from device credentials. */
sbw_capture *sbw_capture_new(const wchar_t *work, const sbj *identity, sbw_error *error);
void sbw_capture_free(sbw_capture *capture);
sbj *sbw_capture_validate(const sbj *config, sbw_error *error);
int sbw_capture_configure(sbw_capture *capture, const sbj *config, sbw_error *error);
sbj *sbw_capture_snapshot(sbw_capture *capture);
void sbw_capture_observe(sbw_capture *capture, DWORD core_pid, const wchar_t *interface_name, const sbj *connections);
void sbw_capture_stop(sbw_capture *capture);
/* Worker-only: receives a host-brokered read-only driver handle over the
 * private inherited channel. There is no public RPC for this operation. */
int sbw_capture_set_broker(sbw_capture *capture,HANDLE driver,DWORD core_pid,DWORD interface_index,sbw_error *error);
int sbw_capture_rotate(sbw_capture *capture, sbw_error *error);
int sbw_capture_read(sbw_capture *capture, const char *digest, unsigned char **bytes, size_t *size, sbw_error *error);
int sbw_capture_delete(sbw_capture *capture, const char *digest, sbw_error *error);
int sbw_capture_mark_uploaded(sbw_capture *capture, const char *digest, sbw_error *error);
bool sbw_capture_wifi(void);
/* Pure parsing/filtering seams used by fixture tests; no network is changed. */
bool sbw_capture_digest_valid(const char *digest);
int sbw_capture_hash(const void *bytes, size_t size, char digest[65]);
int sbw_capture_test_packet(sbw_capture *capture, const void *packet, size_t length,
                            const char *app, const char *host, sbw_error *error);
#endif
