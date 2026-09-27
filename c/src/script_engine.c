#include "sb/script_engine.h"

#include <stdlib.h>
#include <string.h>

#include <quickjs.h>

sb_script_limits sb_script_limits_default(void) {
    sb_script_limits l;
    l.memory_bytes = 16U * 1024U * 1024U;
    l.stack_bytes = 256U * 1024U;
    l.source_bytes = 128U * 1024U;
    l.output_bytes = 2U * 1024U * 1024U;
    l.timeout_ms = 50;
    return l;
}

int sb_rule_script_engine_init(sb_rule_script_engine *engine, const sb_script_limits *limits,
                               sb_err *err) {
    engine->limits = limits ? *limits : sb_script_limits_default();
    const sb_script_limits *l = &engine->limits;
    if (l->memory_bytes == 0 || l->stack_bytes == 0 || l->source_bytes == 0 ||
        l->output_bytes == 0 || l->timeout_ms <= 0) {
        return sb_fail(err, SB_ERR_VALIDATION, "QuickJS limits must all be positive");
    }
    return 0;
}

typedef struct {
    int64_t at_ms;
} deadline;

static int interrupt_handler(JSRuntime *rt, void *opaque) {
    (void)rt;
    const deadline *d = opaque;
    return sb_monotonic_ms() >= d->at_ms ? 1 : 0;
}

/* Malloc'd copy of ToString(value); "" when conversion fails. */
static char *value_to_string(JSContext *ctx, JSValueConst value, size_t *len_out) {
    size_t length = 0;
    const char *text = JS_ToCStringLen(ctx, &length, value);
    if (!text) {
        if (len_out) *len_out = 0;
        return sb_strdup("");
    }
    char *result = sb_strndup(text, length);
    JS_FreeCString(ctx, text);
    if (len_out) *len_out = length;
    return result;
}

static int fail_with_exception(JSContext *ctx, sb_err *err) {
    JSValue exception = JS_GetException(ctx);
    JSValue stack = JS_GetPropertyStr(ctx, exception, "stack");
    char *result = value_to_string(ctx, stack, NULL);
    if (!*result) {
        free(result);
        result = value_to_string(ctx, exception, NULL);
    }
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, exception);
    sb_fail(err, SB_ERR_SCRIPT, "%s", *result ? result : "QuickJS execution failed");
    free(result);
    return -1;
}

static int evaluate(JSContext *ctx, const char *source, size_t len, const char *filename,
                    sb_err *err) {
    JSValue result =
        JS_Eval(ctx, source, len, filename, JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT);
    if (JS_IsException(result)) {
        JS_FreeValue(ctx, result);
        return fail_with_exception(ctx, err);
    }
    JS_FreeValue(ctx, result);
    return 0;
}

static const char kDeterministicPrelude[] =
    "\n"
    "Object.defineProperty(globalThis, \"Date\", {\n"
    "  value: undefined,\n"
    "  writable: false,\n"
    "  configurable: false\n"
    "});\n"
    "Object.defineProperty(Math, \"random\", {\n"
    "  value() {\n"
    "    throw new Error(\"Math.random is disabled in sb-easy rule scripts\");\n"
    "  },\n"
    "  writable: false,\n"
    "  configurable: false\n"
    "});\n"
    "Object.freeze(Math);\n";

sbj *sb_rule_script_engine_build_rules(const sb_rule_script_engine *engine, const char *source,
                                       const sbj *context, sb_err *err) {
    return sb_rule_script_engine_build_rules_n(engine, source, source ? strlen(source) : 0, context, err);
}

sbj *sb_rule_script_engine_build_rules_n(const sb_rule_script_engine *engine, const char *source,
                                         size_t source_len, const sbj *context, sb_err *err) {
    const sb_script_limits *limits = &engine->limits;
    if (!source) source_len = 0;
    if (source_len == 0) {
        sb_fail(err, SB_ERR_SCRIPT, "rule script is empty");
        return NULL;
    }
    if (source_len > limits->source_bytes) {
        sb_fail(err, SB_ERR_SCRIPT, "rule script exceeds the configured source limit");
        return NULL;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (!rt) {
        sb_fail(err, SB_ERR_SCRIPT, "failed to create QuickJS runtime");
        return NULL;
    }
    JS_SetMemoryLimit(rt, limits->memory_bytes);
    JS_SetMaxStackSize(rt, limits->stack_bytes);

    deadline dl = {sb_monotonic_ms() + limits->timeout_ms};
    JS_SetInterruptHandler(rt, interrupt_handler, &dl);

    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) {
        JS_FreeRuntime(rt);
        sb_fail(err, SB_ERR_SCRIPT, "failed to create QuickJS context");
        return NULL;
    }

    sbj *rules = NULL;
    JSValue global = JS_UNDEFINED, function = JS_UNDEFINED, argument = JS_UNDEFINED,
            output = JS_UNDEFINED, serialized = JS_UNDEFINED;
    char *context_json = NULL;
    char *output_json = NULL;

    if (evaluate(ctx, kDeterministicPrelude, sizeof kDeterministicPrelude - 1,
                 "<sb-easy-bootstrap>", err) != 0)
        goto done;
    /* QuickJS requires a terminator after the specified input bytes. */
    char *source_copy = sb_strndup(source, source_len);
    int evaluated = evaluate(ctx, source_copy, source_len, "<rule-script>", err);
    free(source_copy);
    if (evaluated != 0) goto done;

    global = JS_GetGlobalObject(ctx);
    function = JS_GetPropertyStr(ctx, global, "buildRules");
    if (!JS_IsFunction(ctx, function)) {
        sb_fail(err, SB_ERR_SCRIPT, "rule script must define function buildRules(context)");
        goto done;
    }

    context_json = context ? sbj_dump(context, -1) : sb_strdup("null");
    argument = JS_ParseJSON(ctx, context_json, strlen(context_json), "<rule-context>");
    if (JS_IsException(argument)) {
        fail_with_exception(ctx, err);
        goto done;
    }

    JSValueConst arguments[1] = {argument};
    output = JS_Call(ctx, function, JS_UNDEFINED, 1, arguments);
    if (JS_IsException(output)) {
        fail_with_exception(ctx, err);
        goto done;
    }

    serialized = JS_JSONStringify(ctx, output, JS_UNDEFINED, JS_UNDEFINED);
    if (JS_IsException(serialized)) {
        fail_with_exception(ctx, err);
        goto done;
    }
    if (JS_IsUndefined(serialized)) {
        sb_fail(err, SB_ERR_SCRIPT, "buildRules(context) returned undefined");
        goto done;
    }

    size_t output_len = 0;
    output_json = value_to_string(ctx, serialized, &output_len);
    if (output_len > limits->output_bytes) {
        sb_fail(err, SB_ERR_SCRIPT, "rule script output exceeds the configured limit");
        goto done;
    }

    rules = sbj_parse(output_json, output_len, NULL, 0);
    if (!rules) {
        sb_fail(err, SB_ERR_SCRIPT, "buildRules(context) did not return valid JSON");
        goto done;
    }
    if (!sbj_is_array(rules)) {
        sbj_free(rules);
        rules = NULL;
        sb_fail(err, SB_ERR_SCRIPT, "buildRules(context) must return an array");
        goto done;
    }
    for (size_t i = 0; i < sbj_arr_len(rules); ++i) {
        if (!sbj_is_object(sbj_arr_at(rules, i))) {
            sbj_free(rules);
            rules = NULL;
            sb_fail(err, SB_ERR_SCRIPT, "each generated rule must be a JSON object");
            goto done;
        }
    }

done:
    JS_FreeValue(ctx, serialized);
    JS_FreeValue(ctx, output);
    JS_FreeValue(ctx, argument);
    JS_FreeValue(ctx, function);
    JS_FreeValue(ctx, global);
    free(context_json);
    free(output_json);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return rules;
}
