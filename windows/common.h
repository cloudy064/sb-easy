#ifndef SB_WINDOWS_COMMON_H
#define SB_WINDOWS_COMMON_H
#include <windows.h>
#include "sb/json.h"

typedef struct sbw_error {
    char code[64];
    char message[256];
} sbw_error;

/* Failure text is public: callers must supply fixed messages, never credentials. */
int sbw_fail(sbw_error *error, const char *code, const char *message);
/* Returned strings/JSON are owned by the caller and released with free/sbj_free. */
sbj *sbw_json_parse(const char *text, size_t length, unsigned max_depth, sbw_error *error);
bool sbw_json_string(const sbj *value, size_t limit, bool empty_allowed);
wchar_t *sbw_wide(const char *text, sbw_error *error);
char *sbw_utf8(const wchar_t *text, sbw_error *error);
wchar_t *sbw_path_join(const wchar_t *directory, const wchar_t *name);
wchar_t *sbw_executable_directory(sbw_error *error);
void sbw_secret_free(char *text);
#endif
