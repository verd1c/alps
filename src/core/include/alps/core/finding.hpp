// Finding: engine output -> reporter input. Every matched rule becomes one
// Finding with a verdict computed by the downgrade-reachability module and a
// human-readable `reasoning` string explaining how that verdict was reached.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "alps/core/rule.hpp"

namespace alps::core {

enum class Verdict {
    AVAILABLE_NOW, // exploitable on the current patch level, exploit exists
    VIA_DOWNGRADE, // exploit on an older SPL; device downgradable
    POC_NEEDS_PORTING, // PoC exists but for a different device/patch
    RESEARCH_LEAD, // applies here; no public exploit
    UNREACHABLE, // patched, and downgrade blocked
};

std::string verdict_to_string(Verdict v);
Verdict parse_verdict(std::string_view s);
// UTF-8 glyph for the verdict; the reporter picks whether to use it.
std::string verdict_glyph(Verdict v);

struct MatchedFact {
    std::string field; // e.g. "gpu.mali_driver"
    std::string observed_value; // stringified value from DeviceFacts
    std::string reason; // e.g. "r32p1 falls in [0, r40p0)"
};

struct Finding {
    std::string rule_id;
    std::string title;
    std::string component;
    ExploitMeta exploit;
    Verdict verdict = Verdict::RESEARCH_LEAD;
    std::string reasoning;
    std::vector<MatchedFact> matched_facts;
    std::vector<std::string> notes; // e.g. "YARA verify: signature not confirmed"
    std::vector<std::string> refs;
};

void to_json(nlohmann::json& j, const MatchedFact& m);
void from_json(const nlohmann::json& j, MatchedFact& m);
void to_json(nlohmann::json& j, const Finding& f);
void from_json(const nlohmann::json& j, Finding& f);

[[nodiscard]] std::string findings_to_json(const std::vector<Finding>& fs, bool pretty = true);
[[nodiscard]] std::vector<Finding> findings_from_json_str(const std::string& s);

} // namespace alps::core
