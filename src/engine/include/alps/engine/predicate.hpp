// Layer-2 predicate engine. A hand-written recursive-descent parser plus
// tree-walking evaluator for a small CEL-syntax-compatible subset, chosen
// over `cel-cpp` because that library drags Bazel + Abseil + protobuf into a
// CMake+NDK project and would erase the "just the NDK, no annoying build"
// property we care about. See docs/RULES.md for the grammar.
//
// The language is non-Turing-complete by construction: no loops, no recursion
// in the language, no unbounded iteration beyond fixed-list `.exists()`.

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "alps/core/device_facts.hpp"
#include "alps/core/rule.hpp"

namespace alps::engine {

// AST is intentionally opaque to callers; Node's shape belongs in the .cpp
// so we can evolve the grammar without ABI churn. The public class is
// non-copyable, movable, and destructible only where Node is complete
// (declared here, defined in predicate.cpp; the standard pimpl trick that
// avoids `incomplete type` errors at every unique_ptr call site).
struct Node;

class PredicateAst {
public:
    PredicateAst();
    ~PredicateAst();
    PredicateAst(PredicateAst&&) noexcept;
    PredicateAst& operator=(PredicateAst&&) noexcept;
    PredicateAst(const PredicateAst&) = delete;
    PredicateAst& operator=(const PredicateAst&) = delete;

    std::unique_ptr<Node> root;
    std::string source;
};

struct EvalContext {
    const alps::core::DeviceFacts* facts = nullptr;
    const alps::core::Rule* rule = nullptr; // for `affected()` lookups

    // Downgrade hypothesis: when true, every `affected(field)` short-circuits
    // to `true`. Used by the downgrade module to answer "would this rule fire
    // if the device were rolled back to a vulnerable firmware?" without
    // needing to synthesize a fake version for every field.
    bool assume_affected = false;
};

// Compile a predicate source string. Throws std::runtime_error with a
// human-readable diagnostic (including a column offset) on any parse failure.
[[nodiscard]] std::unique_ptr<PredicateAst> parse_predicate(std::string_view src);

// Structural checks that don't need a device: every affected("X") references
// a field declared in `rule.affected`, and every literal used with a Layer-1
// comparator parses. Used by `alps rules lint`. Throws on any failure.
void lint_predicate(const PredicateAst& ast, const alps::core::Rule& rule);

// Evaluate to a boolean. Non-bool final results throw. Missing fact fields
// are treated as JSON null (predicates should handle that with `!= null` or
// via `affected()`, which returns false when the fact is absent).
[[nodiscard]] bool evaluate_predicate(const PredicateAst& ast, const EvalContext& ctx);

// Convenience: parse and evaluate in one call. Prefer parsing once and
// evaluating many times when scanning the whole rule KB.
[[nodiscard]] bool evaluate_predicate_str(std::string_view src, const EvalContext& ctx);

} // namespace alps::engine
