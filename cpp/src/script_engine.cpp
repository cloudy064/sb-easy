#include "sbeasy/script_engine.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>

extern "C" {
#include <quickjs.h>
}

namespace sbeasy {
namespace {

struct RuntimeDeleter {
    void operator()(JSRuntime* runtime) const noexcept {
        if (runtime != nullptr) {
            JS_FreeRuntime(runtime);
        }
    }
};

struct ContextDeleter {
    void operator()(JSContext* context) const noexcept {
        if (context != nullptr) {
            JS_FreeContext(context);
        }
    }
};

using RuntimePtr = std::unique_ptr<JSRuntime, RuntimeDeleter>;
using ContextPtr = std::unique_ptr<JSContext, ContextDeleter>;

class Value final {
  public:
    Value(JSContext* context, JSValue value) noexcept
        : context_(context), value_(value) {}

    ~Value() {
        JS_FreeValue(context_, value_);
    }

    Value(const Value&) = delete;
    Value& operator=(const Value&) = delete;

    Value(Value&& other) noexcept
        : context_(std::exchange(other.context_, nullptr)),
          value_(std::exchange(other.value_, JS_UNDEFINED)) {}

    Value& operator=(Value&&) = delete;

    [[nodiscard]] JSValueConst get() const noexcept {
        return value_;
    }

  private:
    JSContext* context_;
    JSValue value_;
};

struct Deadline {
    std::chrono::steady_clock::time_point at;
};

int interrupt_handler(JSRuntime*, void* opaque) {
    const auto* deadline = static_cast<const Deadline*>(opaque);
    return std::chrono::steady_clock::now() >= deadline->at ? 1 : 0;
}

[[nodiscard]] std::string value_to_string(JSContext* context, JSValueConst value) {
    std::size_t length = 0;
    const char* text = JS_ToCStringLen(context, &length, value);
    if (text == nullptr) {
        return {};
    }
    std::string result{text, length};
    JS_FreeCString(context, text);
    return result;
}

[[nodiscard]] std::string take_exception(JSContext* context) {
    Value exception{context, JS_GetException(context)};
    Value stack{context, JS_GetPropertyStr(context, exception.get(), "stack")};
    auto result = value_to_string(context, stack.get());
    if (result.empty()) {
        result = value_to_string(context, exception.get());
    }
    return result.empty() ? "QuickJS execution failed" : result;
}

Value evaluate(JSContext* context, const std::string& source, const char* filename) {
    Value result{context, JS_Eval(context, source.c_str(), source.size(), filename,
                                  JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT)};
    if (JS_IsException(result.get())) {
        throw ScriptError(take_exception(context));
    }
    return result;
}

constexpr const char* kDeterministicPrelude = R"JS(
Object.defineProperty(globalThis, "Date", {
  value: undefined,
  writable: false,
  configurable: false
});
Object.defineProperty(Math, "random", {
  value() {
    throw new Error("Math.random is disabled in sb-easy rule scripts");
  },
  writable: false,
  configurable: false
});
Object.freeze(Math);
)JS";

} // namespace

RuleScriptEngine::RuleScriptEngine(ScriptLimits limits) : limits_(limits) {
    if (limits_.memory_bytes == 0 || limits_.stack_bytes == 0 ||
        limits_.source_bytes == 0 || limits_.output_bytes == 0 ||
        limits_.timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("QuickJS limits must all be positive");
    }
}

nlohmann::json RuleScriptEngine::build_rules(const std::string& source,
                                             const nlohmann::json& context) const {
    if (source.empty()) {
        throw ScriptError("rule script is empty");
    }
    if (source.size() > limits_.source_bytes) {
        throw ScriptError("rule script exceeds the configured source limit");
    }

    RuntimePtr runtime{JS_NewRuntime()};
    if (!runtime) {
        throw ScriptError("failed to create QuickJS runtime");
    }
    JS_SetMemoryLimit(runtime.get(), limits_.memory_bytes);
    JS_SetMaxStackSize(runtime.get(), limits_.stack_bytes);

    Deadline deadline{std::chrono::steady_clock::now() + limits_.timeout};
    JS_SetInterruptHandler(runtime.get(), interrupt_handler, &deadline);

    ContextPtr js_context{JS_NewContext(runtime.get())};
    if (!js_context) {
        throw ScriptError("failed to create QuickJS context");
    }
    auto* context_ptr = js_context.get();

    evaluate(context_ptr, kDeterministicPrelude, "<sb-easy-bootstrap>");
    evaluate(context_ptr, source, "<rule-script>");

    Value global{context_ptr, JS_GetGlobalObject(context_ptr)};
    Value function{context_ptr,
                   JS_GetPropertyStr(context_ptr, global.get(), "buildRules")};
    if (!JS_IsFunction(context_ptr, function.get())) {
        throw ScriptError("rule script must define function buildRules(context)");
    }

    const std::string context_json = context.dump();
    Value argument{context_ptr, JS_ParseJSON(context_ptr, context_json.c_str(),
                                             context_json.size(), "<rule-context>")};
    if (JS_IsException(argument.get())) {
        throw ScriptError(take_exception(context_ptr));
    }

    JSValueConst arguments[] = {argument.get()};
    Value output{context_ptr,
                 JS_Call(context_ptr, function.get(), JS_UNDEFINED, 1, arguments)};
    if (JS_IsException(output.get())) {
        throw ScriptError(take_exception(context_ptr));
    }

    Value serialized{context_ptr, JS_JSONStringify(context_ptr, output.get(),
                                                   JS_UNDEFINED, JS_UNDEFINED)};
    if (JS_IsException(serialized.get())) {
        throw ScriptError(take_exception(context_ptr));
    }
    if (JS_IsUndefined(serialized.get())) {
        throw ScriptError("buildRules(context) returned undefined");
    }

    const auto output_json = value_to_string(context_ptr, serialized.get());
    if (output_json.size() > limits_.output_bytes) {
        throw ScriptError("rule script output exceeds the configured limit");
    }

    auto rules = nlohmann::json::parse(output_json, nullptr, false, true);
    if (rules.is_discarded()) {
        throw ScriptError("buildRules(context) did not return valid JSON");
    }
    if (!rules.is_array()) {
        throw ScriptError("buildRules(context) must return an array");
    }
    for (const auto& rule : rules) {
        if (!rule.is_object()) {
            throw ScriptError("each generated rule must be a JSON object");
        }
    }
    return rules;
}

} // namespace sbeasy
