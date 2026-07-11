// Downgrade reachability module. Given a rule and device
// facts, decide which of the 5 verdicts applies and emit a human-readable
// reasoning string. The reasoning is deliberately as important as the label:
// "SPL patched 2023-11; downgrade blocked by bootloader_locked + rollback_index=3"
// tells a researcher exactly why a lead is a dead end.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"

namespace alps::engine {

// Blockers that were active on this device; surfaced verbatim in reasoning.
struct BlockerHit {
    std::string name; // e.g. "bootloader_locked"
    std::string detail; // e.g. "rollback_index=3"
};

struct Verdict {
    alps::core::Verdict value = alps::core::Verdict::RESEARCH_LEAD;
    std::string reasoning;
    std::vector<BlockerHit> blockers; // populated for UNREACHABLE

    // Actionable downgrade target for VIA_DOWNGRADE / UNREACHABLE. Format:
    // "SPL < 2022-11-05" or "SPL <= 0". Empty for other verdicts.
    std::string downgrade_target;
};

// Compute the verdict for a rule that has ALREADY matched the current facts
// (matcher's predicate returned true). Reads only exploit metadata and the
// device string; device is in a vuln range by construction.
[[nodiscard]] Verdict verdict_for_current_match(
    const alps::core::Rule& rule, const alps::core::DeviceFacts& facts);

// Attempt a hypothetical downgrade: if the rule declares a
// `downgrade.min_vulnerable_spl`, substitute that SPL into the facts and
// re-check the rule's predicate. Returns nullopt if the rule cannot be
// reached even via downgrade; otherwise returns the (VIA_DOWNGRADE or
// UNREACHABLE) verdict based on which blockers apply.
//
// `predicate_would_match_with_downgraded_spl` is a callback provided by the
// matcher; it does the actual predicate re-evaluation with a substituted
// SPL value, and returns true iff the rule would match then. Injecting the
// check keeps this module independent of the predicate engine.
[[nodiscard]] std::optional<Verdict> verdict_via_downgrade(const alps::core::Rule& rule,
    const alps::core::DeviceFacts& facts, bool predicate_would_match_with_downgraded_spl);

} // namespace alps::engine
