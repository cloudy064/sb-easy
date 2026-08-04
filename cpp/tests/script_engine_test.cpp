#include "test_support.hpp"

#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include "sbeasy/script_engine.hpp"

using namespace std::chrono_literals;

SB_EASY_TEST("QuickJS builds JSON route rules") {
    const sbeasy::RuleScriptEngine engine;
    const auto rules = engine.build_rules(
        R"JS(
function buildRules(context) {
  return [{
    domain_suffix: [".example.com"],
    outbound: context.outboundTags.includes("hk") ? "hk" : "direct"
  }];
}
)JS",
        {
            {"outboundTags", {"hk", "direct"}},
            {"currentRules", nlohmann::json::array()},
        });

    sbeasy::test::require(rules.size() == 1, "expected one rule");
    sbeasy::test::require(rules[0]["outbound"] == "hk", "script did not use context");
}

SB_EASY_TEST("QuickJS interrupts infinite loops") {
    sbeasy::ScriptLimits limits;
    limits.timeout = 20ms;
    const sbeasy::RuleScriptEngine engine{limits};
    const auto started = std::chrono::steady_clock::now();

    sbeasy::test::require_throws<sbeasy::ScriptError>(
        [&engine] {
            static_cast<void>(engine.build_rules(
                "function buildRules() { while (true) {} }", nlohmann::json::object()));
        },
        "infinite script was not interrupted");
    const auto elapsed = std::chrono::steady_clock::now() - started;
    sbeasy::test::require(elapsed < 1s, "interrupt handler took too long");
}

SB_EASY_TEST("QuickJS disables nondeterministic globals") {
    const sbeasy::RuleScriptEngine engine;
    sbeasy::test::require_throws<sbeasy::ScriptError>(
        [&engine] {
            static_cast<void>(engine.build_rules(
                "function buildRules() { Math.random(); return []; }",
                nlohmann::json::object()));
        },
        "Math.random should be disabled");
}

SB_EASY_TEST("QuickJS enforces its memory limit") {
    sbeasy::ScriptLimits limits;
    limits.memory_bytes = 4U * 1024U * 1024U;
    limits.timeout = 500ms;
    const sbeasy::RuleScriptEngine engine{limits};

    sbeasy::test::require_throws<sbeasy::ScriptError>(
        [&engine] {
            static_cast<void>(engine.build_rules(
                R"JS(
function buildRules() {
  const values = [];
  while (true) {
    values.push("x".repeat(65536));
  }
}
)JS",
                nlohmann::json::object()));
        },
        "memory-growing script was not stopped");
}
