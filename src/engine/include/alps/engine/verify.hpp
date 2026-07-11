// Binary verify. When a rule declares a `verify:` step, run it
// AFTER the L1+L2 predicate match and use the result to enrich (never to
// silently drop) the Finding. A failed verify downgrades the match
// to a note; it does NOT remove the finding. A missing target file is
// itself a signal; surface it verbatim.
//
// Build option matrix:
//   ALPS_WITH_YARA=OFF (default): a stub that reports "verify skipped
//     (built without libyara)" plus whether the target file exists on disk.
//   ALPS_WITH_YARA=ON: link libyara via FetchContent and run
//     the referenced rule file against the target binary.

#pragma once

#include <string>
#include <vector>

#include "alps/core/rule.hpp"

namespace alps::engine {

struct VerifyResult {
    std::string step_kind; // "yara"
    std::string target_path;
    bool confirmed = false; // rule matched the binary
    std::string note; // human-readable summary
};

// Run every VerifyStep declared on the rule; return one VerifyResult per step.
// `rules_dir` is the base directory where yara rule files (rule.rule) live
// (typically <rules>/yara/). Returns an empty vector if the rule has no
// verify steps.
[[nodiscard]] std::vector<VerifyResult> run_verify_steps(
    const alps::core::Rule& rule, const std::string& rules_dir);

} // namespace alps::engine
