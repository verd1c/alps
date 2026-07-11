// Downgrade reachability and verdict computation. The rules of the road:
//   * Never fabricate a verdict; every branch cites the fact that produced it.
//   * Never emit exploit steps in `reasoning`; it names what's known about the
//     patch level and the blockers, and nothing more.
//   * For unmapped exploit.status values, default to RESEARCH_LEAD (the safest
//     "we don't know how to reach this yet" bucket).

#include "alps/engine/downgrade.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <string>

#include "alps/core/rule.hpp"

namespace alps::engine {

namespace {

    // Blockers we understand. Anything else in `rule.downgrade.blocked_by` gets
    // surfaced verbatim as a "known-name blocker" so rule authors get feedback,
    // but does not by itself flip the verdict; the device fact must be present.
    std::optional<BlockerHit> check_blocker(
        const std::string& name, const alps::core::DeviceFacts& facts)
    {
        if (name == "bootloader_locked") {
            // Historical blocker name. bootloader_locked is user-reversible
            // (unlock, flash old image, relock), so listing it here does
            // not model a real downgrade barrier. We still honour the name
            // for rule-KB backwards compat, but rules should prefer
            // rollback_index (the anti-rollback fuse) instead.
            if (facts.bootloader_locked.value_or(false)) {
                return BlockerHit { name, "bootloader_locked=true" };
            }
            return std::nullopt;
        }
        if (name == "rollback_index") {
            // A non-zero rollback_index means anti-rollback is enforcing a floor
            // on how far back the device can be moved. Missing / zero means no bar.
            if (facts.rollback_index.has_value() && *facts.rollback_index > 0) {
                return BlockerHit { name,
                    "rollback_index=" + std::to_string(*facts.rollback_index) };
            }
            return std::nullopt;
        }
        if (name == "verified_boot_state") {
            // Green = fully locked verified boot; any other state means the user
            // has relaxed verification and downgrade may be possible.
            if (facts.verified_boot_state.value_or("") == "green") {
                return BlockerHit { name, "verified_boot_state=green" };
            }
            return std::nullopt;
        }
        // Unknown blocker name: silently ignore; validation belongs in
        // `rules lint`, not here.
        return std::nullopt;
    }

    std::vector<BlockerHit> active_blockers(
        const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
    {
        std::vector<BlockerHit> hits;
        for (const auto& name : rule.downgrade.blocked_by) {
            if (auto b = check_blocker(name, facts); b)
                hits.push_back(*b);
        }
        return hits;
    }

    std::string join_blocker_names(const std::vector<BlockerHit>& hits)
    {
        std::string out;
        for (std::size_t i = 0; i < hits.size(); ++i) {
            if (i)
                out += ", ";
            out += hits[i].detail;
        }
        return out;
    }

    // Look at the rule's L1 timeline and pick the earliest "fixed" (or "limit")
    // SPL date. Anything strictly below that date is inside the vulnerable range
    // and thus a valid downgrade target. Returns nullopt if the rule has no
    // SPL_DATE field or no fixed/limit events (in which case we fall back to the
    // rule-declared `min_vulnerable_spl` in the caller).
    std::optional<std::string> earliest_spl_fix(const alps::core::Rule& rule)
    {
        std::optional<std::string> best;
        for (const auto& af : rule.affected) {
            if (af.type != alps::core::ComparatorType::SPL_DATE)
                continue;
            if (af.field != "spl" && af.field != "vendor_spl")
                continue;
            for (const auto& e : af.events) {
                std::optional<std::string> candidate;
                if (e.fixed)
                    candidate = *e.fixed;
                else if (e.limit)
                    candidate = *e.limit;
                if (!candidate)
                    continue;
                if (!best || *candidate < *best)
                    best = *candidate;
            }
        }
        return best;
    }

} // namespace

Verdict verdict_for_current_match(
    const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
{
    using S = alps::core::ExploitStatus;
    Verdict v;
    std::ostringstream why;

    const std::string spl = facts.spl.value_or("(unknown SPL)");
    const std::string dev = facts.device.value_or("");

    // For public exploits (poc or weaponized_public), check whether the rule
    // narrows availability to specific device codenames. Empty list means
    // "no device-specific porting required".
    const auto& pocs = rule.exploit.poc_targets;
    const bool is_targeted
        = !pocs.empty() && std::find(pocs.begin(), pocs.end(), dev) == pocs.end();

    why << "device is currently in the vulnerable range (SPL=" << spl << ")";

    switch (rule.exploit.status) {
    case S::WEAPONIZED_PUBLIC:
        if (is_targeted) {
            v.value = alps::core::Verdict::POC_NEEDS_PORTING;
            why << "; weaponized exploit exists but declared for devices [" << pocs[0];
            for (std::size_t i = 1; i < pocs.size(); ++i)
                why << "," << pocs[i];
            why << "]; this device (" << dev << ") likely needs porting";
        } else {
            v.value = alps::core::Verdict::AVAILABLE_NOW;
            why << "; public weaponized exploit exists per rule metadata";
        }
        break;
    case S::POC:
        if (is_targeted) {
            v.value = alps::core::Verdict::POC_NEEDS_PORTING;
            why << "; PoC exists but declared for devices [" << pocs[0];
            for (std::size_t i = 1; i < pocs.size(); ++i)
                why << "," << pocs[i];
            why << "]; this device (" << dev << ") likely needs porting";
        } else {
            v.value = alps::core::Verdict::AVAILABLE_NOW;
            why << "; public proof-of-concept exists per rule metadata";
        }
        break;
    case S::CVE_NO_POC:
        v.value = alps::core::Verdict::RESEARCH_LEAD;
        why << "; no public PoC documented (research lead)";
        break;
    case S::PRIVATE:
        v.value = alps::core::Verdict::RESEARCH_LEAD;
        why << "; only private/undisclosed exploit exists (research lead)";
        break;
    }

    if (rule.exploit.user_interaction) {
        why << "; requires user interaction (may reduce practical impact)";
    }

    v.reasoning = why.str();
    return v;
}

std::optional<Verdict> verdict_via_downgrade(const alps::core::Rule& rule,
    const alps::core::DeviceFacts& facts, bool predicate_would_match_with_downgraded_spl)
{
    if (!predicate_would_match_with_downgraded_spl) {
        // Not reachable even at the min-vulnerable SPL: the device simply
        // doesn't apply. Do not emit a finding.
        return std::nullopt;
    }
    if (!rule.downgrade.min_vulnerable_spl.has_value()) {
        // Downgrade path not declared; refuse to guess.
        return std::nullopt;
    }

    const auto blockers = active_blockers(rule, facts);
    const std::string cur_spl = facts.spl.value_or("(unknown)");
    const auto spl_fix = earliest_spl_fix(rule); // preferred (precise)
    const std::string min_vuln = *rule.downgrade.min_vulnerable_spl;

    // The actionable target: SPL strictly below the fix date is vulnerable.
    std::string target;
    if (spl_fix) {
        target = "SPL < " + *spl_fix;
    } else if (min_vuln != "0") {
        target = "SPL <= " + min_vuln;
    } else {
        target = "any pre-fix SPL";
    }

    Verdict v;
    std::ostringstream why;
    why << "device SPL " << cur_spl << " is past fix; downgrade to " << target;
    if (blockers.empty()) {
        v.value = alps::core::Verdict::VIA_DOWNGRADE;
        why << " to re-expose the CVE (no active blockers)";
    } else {
        v.value = alps::core::Verdict::UNREACHABLE;
        why << " would re-expose it, but blocked by: " << join_blocker_names(blockers);
    }

    v.blockers = blockers;
    v.downgrade_target = target;
    v.reasoning = why.str();
    return v;
}

} // namespace alps::engine
