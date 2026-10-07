#ifndef SB_WINDOWS_PROTOCOL_H
#define SB_WINDOWS_PROTOCOL_H
#include "controller.h"
#define SBW_MAX_FRAME (1024U * 1024U)
char *sbw_handle_request(const char *request, size_t length, sbw_controller *controller, bool authorized);
#endif
