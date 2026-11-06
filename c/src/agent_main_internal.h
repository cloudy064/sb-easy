/* Private entry point of the C polling agent. Shared by sb-easy-c-agent
 * (main_agent.c) and the unified image binary sb-easy (main_unified.c). */
#ifndef SB_AGENT_MAIN_INTERNAL_H
#define SB_AGENT_MAIN_INTERNAL_H

/* Runs the agent: `[--once]`; configured through the environment.
 * Returns the process exit status (0, 1 on errors, 2 on usage
 * errors). Without --once it only returns on startup failures. */
int sb_agent_main(int argc, char **argv);

#endif
