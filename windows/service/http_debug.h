#ifndef SBW_HTTP_DEBUG_H
#define SBW_HTTP_DEBUG_H
#include "../common.h"
/* Runtime-only overlay. Targets original ingress, never the return/upstream leg. */
char *sbw_http_debug_overlay(const char *json,const sbj *domains,const char *password,sbw_error *error);
#endif
