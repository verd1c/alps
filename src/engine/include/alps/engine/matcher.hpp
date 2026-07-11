// Matcher: L1 + L2 against a device fact sheet, produces candidate
// Findings. Verdicts are left at RESEARCH_LEAD; the downgrade module
// resolves them to the final verdict and reasoning.

#pragma once

#include <string>
#include <vector>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"

namespace alps::engine {

struct RuleError {
    std::string rule_id; // may be empty if the id itself couldn't be read
    std::string message;
};

struct MatchResult {
    std::vector<alps::core::Finding> findings;
    std::vector<RuleError> errors; // rules that failed to parse/lint/eval
};

// Match every rule in `rules` against `facts`. Rules whose predicates parse
// but evaluate to false are silently dropped; parse or evaluation failures
// are surfaced in `errors` so the CLI can report them without killing the
// entire scan.
[[nodiscard]] MatchResult match_rules(
    const std::vector<alps::core::Rule>& rules, const alps::core::DeviceFacts& facts);

} // namespace alps::engine
