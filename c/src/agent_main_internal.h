/* Private entry point of the polling agent (port of cpp/src/agent_main.cpp
 * main()). Shared by sb-easy-c-agent (main_agent.c) and the unified image
 * binary sb-easy (main_unified.c), which the C++ unified image built from the
 * same agent sources (cpp/Dockerfile.unified installs sb-easy-cpp-agent as
 * /usr/local/bin/sb-easy). */
#ifndef SB_AGENT_MAIN_INTERNAL_H
#define SB_AGENT_MAIN_INTERNAL_H

/* Runs the agent: `[--once]`; configured through the environment exactly like
 * the C++ agent. Returns the process exit status (0, 1 on errors, 2 on usage
 * errors). Without --once it only returns on startup failures. */
int sb_agent_main(int argc, char **argv);
#include <stdbool.h>
#include "sb/json.h"
#include "sb/util.h"

typedef struct {
    bool success;
    char *detail; /* owned */
} process_result;

bool c_space(unsigned char c);
int path_exists_or_fail(const char *path, bool *exists, sb_err *err);
int read_stream(const char *path, char **out, size_t *len, sb_err *err);
sbj *parse_json_lenient(const char *text, size_t len);
int split_command_line(const char *command, sb_strvec *out, sb_err *err);
process_result run_program(const sb_strvec *arguments);
int read_existing(const char *path, char **out, size_t *len, sb_err *err);
int proxy_test_tags(const char *command, sbj **tags, bool *all, sb_err *err);

#endif
