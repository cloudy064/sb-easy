/* sb-easy: the unified image binary. cpp/Dockerfile.unified installs the
 * agent executable as /usr/local/bin/sb-easy (the image ENTRYPOINT). */
#include "agent_main_internal.h"

int main(int argc, char **argv) { return sb_agent_main(argc, argv); }
