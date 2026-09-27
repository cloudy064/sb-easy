/* QuickJS rule-script engine (port of cpp script_engine.hpp). */
#ifndef SB_SCRIPT_ENGINE_H
#define SB_SCRIPT_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "sb/json.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t memory_bytes; /* default 16 MiB */
    size_t stack_bytes;  /* default 256 KiB */
    size_t source_bytes; /* default 128 KiB */
    size_t output_bytes; /* default 2 MiB */
    int64_t timeout_ms;  /* default 50 */
} sb_script_limits;

sb_script_limits sb_script_limits_default(void);

/* Executes a deterministic `buildRules(context)` JavaScript function.
 *
 * Each call creates a fresh QuickJS runtime. No filesystem, network, process,
 * module loader, or QuickJS std/os bindings are installed. */
typedef struct {
    sb_script_limits limits;
} sb_rule_script_engine;

/* limits == NULL -> defaults. Fails (SB_ERR_VALIDATION, "QuickJS limits must
 * all be positive") when any limit is zero / non-positive. */
int sb_rule_script_engine_init(sb_rule_script_engine *engine, const sb_script_limits *limits,
                               sb_err *err);

/* Returns the generated rules (a JSON array of objects), or NULL with
 * SB_ERR_SCRIPT on any script failure. */
sbj *sb_rule_script_engine_build_rules(const sb_rule_script_engine *engine, const char *source,
                                       const sbj *context, sb_err *err);

/* Explicit source length, including embedded NUL bytes. */
sbj *sb_rule_script_engine_build_rules_n(const sb_rule_script_engine *engine, const char *source,
                                         size_t source_len, const sbj *context, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
