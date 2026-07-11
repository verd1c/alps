// Predicate unit tests: parser, evaluator, and lint.

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "alps/core/device_facts.hpp"
#include "alps/core/rule.hpp"
#include "alps/engine/predicate.hpp"

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":" << __LINE__ << "\n";        \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

#define EXPECT_THROWS(expr)                                                                        \
    do {                                                                                           \
        bool threw = false;                                                                        \
        try {                                                                                      \
            (void)(expr);                                                                          \
        } catch (const std::exception&) {                                                          \
            threw = true;                                                                          \
        }                                                                                          \
        if (!threw) {                                                                              \
            std::cerr << "FAIL (expected throw): " << #expr << " @ " << __FILE__ << ":"            \
                      << __LINE__ << "\n";                                                         \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

std::string slurp(const std::string& path)
{
    std::ifstream f(path);
    if (!f) {
        std::cerr << "cannot open " << path << "\n";
        std::abort();
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

using alps::engine::EvalContext;
using alps::engine::evaluate_predicate;
using alps::engine::evaluate_predicate_str;
using alps::engine::lint_predicate;
using alps::engine::parse_predicate;

bool eval_bare(const std::string& src)
{
    EvalContext ctx; // no facts, no rule (pure-literal tests)
    return evaluate_predicate_str(src, ctx);
}

bool eval_with(const std::string& src, const alps::core::DeviceFacts& f)
{
    EvalContext ctx;
    ctx.facts = &f;
    return evaluate_predicate_str(src, ctx);
}

void test_literals_and_ops()
{
    EXPECT(eval_bare("true"));
    EXPECT(!eval_bare("false"));
    EXPECT(eval_bare("!false"));
    EXPECT(eval_bare("true && true"));
    EXPECT(!eval_bare("true && false"));
    EXPECT(eval_bare("false || true"));

    // Integers.
    EXPECT(eval_bare("1 == 1"));
    EXPECT(eval_bare("1 < 2"));
    EXPECT(eval_bare("2 >= 2"));
    EXPECT(eval_bare("3 != 4"));

    // Strings.
    EXPECT(eval_bare("\"a\" == \"a\""));
    EXPECT(!eval_bare("\"a\" == \"b\""));
    EXPECT(eval_bare("'a' == 'a'")); // single-quote also accepted
    EXPECT(eval_bare("\"abc\" != \"abd\""));

    // Nulls.
    EXPECT(eval_bare("null == null"));
    EXPECT(eval_bare("null != 1"));

    // Grouping + precedence.
    EXPECT(eval_bare("true && (false || true)"));
    EXPECT(eval_bare("!(false || false)"));
}

void test_short_circuit()
{
    // rhs of && is not evaluated when lhs is false; a type-error on the rhs
    // would otherwise be a problem.
    EXPECT(!eval_bare("false && (1 < \"x\")"));
    EXPECT(eval_bare("true || (1 < \"x\")"));
}

void test_field_access()
{
    auto facts = alps::core::DeviceFacts::from_json_str(R"({
      "model": "Pixel 6",
      "abis": ["arm64-v8a", "armeabi-v7a"],
      "gpu": {"vendor":"mali","mali_driver":"r32p1","adreno_driver":null,"driver_blob_paths":{}},
      "bootloader_locked": true,
      "raw_props": {"ro.build.version.security_patch":"2022-07-05"}
    })");

    EXPECT(eval_with("model == \"Pixel 6\"", facts));
    EXPECT(eval_with("gpu.vendor == \"mali\"", facts));
    EXPECT(!eval_with("gpu.vendor == \"adreno\"", facts));
    EXPECT(eval_with("bootloader_locked == true", facts));
    EXPECT(eval_with("gpu.adreno_driver == null", facts));

    // Missing field yields null.
    EXPECT(eval_with("does.not.exist == null", facts));
    EXPECT(eval_with("gpu.does_not_exist == null", facts));

    // prop() reaches raw_props map.
    EXPECT(eval_with("prop(\"ro.build.version.security_patch\") == \"2022-07-05\"", facts));
    EXPECT(eval_with("prop(\"missing.prop\") == \"\"", facts));
}

void test_contains_and_exists()
{
    auto facts = alps::core::DeviceFacts::from_json_str(R"({
      "abis": ["arm64-v8a", "armeabi-v7a"]
    })");

    EXPECT(eval_with("abis.contains(\"arm64-v8a\")", facts));
    EXPECT(!eval_with("abis.contains(\"x86_64\")", facts));

    EXPECT(eval_with("abis.exists(a, a == \"arm64-v8a\")", facts));
    EXPECT(!eval_with("abis.exists(a, a == \"x86_64\")", facts));

    // String .contains (substring).
    EXPECT(eval_bare("\"foobar\".contains(\"oba\")"));
    EXPECT(!eval_bare("\"foobar\".contains(\"xyz\")"));
}

void test_parse_errors()
{
    EXPECT_THROWS(parse_predicate("gpu.vendor == "));
    EXPECT_THROWS(parse_predicate("gpu..vendor == \"mali\""));
    EXPECT_THROWS(parse_predicate("(gpu.vendor"));
    EXPECT_THROWS(parse_predicate("a & b")); // single-& not allowed
    EXPECT_THROWS(parse_predicate("a.exists(1, 2)")); // exists arg1 must be ident
    EXPECT_THROWS(parse_predicate("abis.exists("));
}

void test_type_errors()
{
    // Non-bool final result.
    EvalContext ctx;
    EXPECT_THROWS(evaluate_predicate_str("42", ctx));
    EXPECT_THROWS(evaluate_predicate_str("\"hi\" && true", ctx));
    EXPECT_THROWS(evaluate_predicate_str("null < 1", ctx));
}

void test_affected_and_lint_with_real_rule()
{
    auto vuln
        = alps::core::DeviceFacts::from_json_str(slurp("tests/fixtures/pixel6_july2022.json"));
    auto patched
        = alps::core::DeviceFacts::from_json_str(slurp("tests/fixtures/pixel6_patched.json"));

    auto rules = alps::core::load_rules_dir("rules");
    EXPECT(!rules.empty());
    const alps::core::Rule* mali = nullptr;
    for (const auto& r : rules)
        if (r.id == "CVE-2022-38181")
            mali = &r;
    EXPECT(mali != nullptr);
    if (!mali)
        return;

    auto ast = parse_predicate(mali->match);

    // Lint pass: every affected("X") must reference an af.field.
    lint_predicate(*ast, *mali);

    EvalContext vctx;
    vctx.facts = &vuln;
    vctx.rule = mali;
    EXPECT(evaluate_predicate(*ast, vctx));

    EvalContext pctx;
    pctx.facts = &patched;
    pctx.rule = mali;
    EXPECT(!evaluate_predicate(*ast, pctx));

    // A rule with affected("nonsense") must fail lint.
    alps::core::Rule fake = *mali;
    // Point affected() at a non-existent field via a bad predicate.
    auto bad_ast = parse_predicate(R"(affected("gpu.no_such"))");
    EXPECT_THROWS(lint_predicate(*bad_ast, fake));

    // A rule with a bogus mali version literal must also fail lint.
    alps::core::Rule bad_rule = *mali;
    bad_rule.affected[0].events.push_back({});
    bad_rule.affected[0].events.back().fixed = std::string("rNOTVALID");
    EXPECT_THROWS(lint_predicate(*ast, bad_rule));
}

} // namespace

int main()
{
    test_literals_and_ops();
    test_short_circuit();
    test_field_access();
    test_contains_and_exists();
    test_parse_errors();
    test_type_errors();
    test_affected_and_lint_with_real_rule();

    if (g_failures == 0) {
        std::cout << "OK: all predicate tests passed\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
