#ifndef SB_LINUX_CONTROLLER_H
#define SB_LINUX_CONTROLLER_H
#include "desktop.h"
typedef enum {
    SBL_OPEN,
    SBL_STATUS,
    SBL_NEW_PROFILE,
    SBL_SELECT_PROFILE,
    SBL_RENAME_PROFILE,
    SBL_DELETE_PROFILE,
    SBL_ENROLL,
    SBL_DETACH,
    SBL_IMPORT,
    SBL_ADD_URL,
    SBL_EDIT_SUBSCRIPTION,
    SBL_REMOVE_SUBSCRIPTION,
    SBL_REFRESH,
    SBL_SYNC,
    SBL_SETTINGS,
    SBL_CONNECT,
    SBL_DISCONNECT,
    SBL_SELECT_NODE,
    SBL_DELAY,
    SBL_PROBE,
    SBL_PROXY_SETTING,
    SBL_REFRESH_INTERVAL,
    SBL_COPY_PROXY,
    SBL_SHUTDOWN
} sbl_action;
typedef struct sbl_controller sbl_controller;
typedef struct {
    sbl_action action;
    bool success, pending;
    char* message;
    sbj *view, *result;
} sbl_event;
typedef void (*sbl_event_callback)(sbl_event* event, void* user);
/* Callback runs on the default GLib main context and owns event. */
sbl_controller* sbl_controller_new(const char* data_dir, const char* runtime_dir,
                                   const unsigned char* test_key, bool session_test,
                                   sbl_event_callback callback, void* user);
bool sbl_controller_submit(sbl_controller* c, sbl_action action, const char* a,
                           const char* b, const char* d, int number);
void sbl_controller_cancel(sbl_controller* c);
void sbl_controller_free(sbl_controller* c);
void sbl_event_free(sbl_event* event);
#endif
