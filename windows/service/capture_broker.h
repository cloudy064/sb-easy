#ifndef SBW_CAPTURE_BROKER_H
#define SBW_CAPTURE_BROKER_H
#include "../common.h"
typedef struct sbw_capture_broker sbw_capture_broker;
/* Host-chosen TUN interface only. A plugin cannot choose a filter, layer,
 * arbitrary interface, driver binary, service name or packet injection mode. */
sbw_capture_broker *sbw_capture_broker_new(const wchar_t *installation,sbw_error *error);
HANDLE sbw_capture_broker_open(sbw_capture_broker *broker,const wchar_t *interface_name,DWORD *interface_index,sbw_error *error);
void sbw_capture_broker_stop(sbw_capture_broker *broker);
void sbw_capture_broker_free(sbw_capture_broker *broker);
/* Pure vendor-byte check shared with the native fixture. */
bool sbw_capture_broker_vendor(const wchar_t *filename,const void *bytes,size_t length);
#endif
