#ifndef SBW_PLUGIN_STORAGE_H
#define SBW_PLUGIN_STORAGE_H
#include "../common.h"
typedef struct sbw_plugin_storage sbw_plugin_storage;
/* The root and trust anchors are chosen by the host, never by an RPC caller.
 * Opening recovers an interrupted publication before any code is usable. */
sbw_plugin_storage *sbw_plugin_storage_open(const wchar_t *root, sbw_error *error);
void sbw_plugin_storage_close(sbw_plugin_storage *storage);
int sbw_plugin_storage_catalog(sbw_plugin_storage *storage, const char *envelope, size_t length, sbw_error *error);
sbj *sbw_plugin_storage_status(sbw_plugin_storage *storage, const char *id);
sbj *sbw_plugin_storage_release(sbw_plugin_storage *storage, const char *id, sbw_error *error);
int sbw_plugin_storage_check_package(sbw_plugin_storage *storage, const char *id, const void *bytes, size_t length, sbw_error *error);
int sbw_plugin_storage_publish(sbw_plugin_storage *storage, const char *id, const void *bytes, size_t length, sbw_error *error);
int sbw_plugin_storage_rollback(sbw_plugin_storage *storage, const char *id, sbw_error *error);
int sbw_plugin_storage_confirm(sbw_plugin_storage *storage, const char *id, sbw_error *error);
/* Checks every installed file against the signed package receipt. */
bool sbw_plugin_storage_verified(sbw_plugin_storage *storage, const char *id, sbw_error *error);
/* Receipt/compatibility/revocation check for an already verified running
 * process. A fresh launch or enable must still call verified(). */
bool sbw_plugin_storage_allowed(sbw_plugin_storage *storage,const char *id,sbw_error *error);
#endif
