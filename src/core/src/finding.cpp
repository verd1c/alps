#include "alps/core/finding.hpp"

#include <stdexcept>

using nlohmann::json;

namespace alps::core {

std::string verdict_to_string(Verdict v)
{
    switch (v) {
    case Verdict::AVAILABLE_NOW:
        return "available_now";
    case Verdict::VIA_DOWNGRADE:
        return "via_downgrade";
    case Verdict::POC_NEEDS_PORTING:
        return "poc_needs_porting";
    case Verdict::RESEARCH_LEAD:
        return "research_lead";
    case Verdict::UNREACHABLE:
        return "unreachable";
    }
    return "unknown";
}

Verdict parse_verdict(std::string_view s)
{
    if (s == "available_now")
        return Verdict::AVAILABLE_NOW;
    if (s == "via_downgrade")
        return Verdict::VIA_DOWNGRADE;
    if (s == "poc_needs_porting")
        return Verdict::POC_NEEDS_PORTING;
    if (s == "research_lead")
        return Verdict::RESEARCH_LEAD;
    if (s == "unreachable")
        return Verdict::UNREACHABLE;
    throw std::invalid_argument("unknown verdict: " + std::string(s));
}

std::string verdict_glyph(Verdict v)
{
    // UTF-8; the reporter decides whether to emit these or ASCII fallbacks.
    switch (v) {
    case Verdict::AVAILABLE_NOW:
        return "\xF0\x9F\x9F\xA2"; // 🟢
    case Verdict::VIA_DOWNGRADE:
        return "\xF0\x9F\x9F\xA1"; // 🟡
    case Verdict::POC_NEEDS_PORTING:
        return "\xF0\x9F\x94\xB5"; // 🔵
    case Verdict::RESEARCH_LEAD:
        return "\xE2\x9A\xAA"; // ⚪
    case Verdict::UNREACHABLE:
        return "\xF0\x9F\x94\xB4"; // 🔴
    }
    return "?";
}

void to_json(json& j, const MatchedFact& m)
{
    j = json {
        { "field", m.field },
        { "observed_value", m.observed_value },
        { "reason", m.reason },
    };
}

void from_json(const json& j, MatchedFact& m)
{
    m.field = j.value("field", "");
    m.observed_value = j.value("observed_value", "");
    m.reason = j.value("reason", "");
}

void to_json(json& j, const Finding& f)
{
    j = json::object();
    j["rule_id"] = f.rule_id;
    j["title"] = f.title;
    j["component"] = f.component;
    j["exploit"] = json {
        { "status", exploit_status_to_string(f.exploit.status) },
        { "gives", exploit_gives_to_string(f.exploit.gives) },
        { "user_interaction", f.exploit.user_interaction },
        { "requires_downgrade", f.exploit.requires_downgrade },
        { "poc_targets", f.exploit.poc_targets },
    };
    j["verdict"] = verdict_to_string(f.verdict);
    j["reasoning"] = f.reasoning;
    j["matched_facts"] = f.matched_facts;
    j["notes"] = f.notes;
    j["refs"] = f.refs;
}

void from_json(const json& j, Finding& f)
{
    f.rule_id = j.value("rule_id", "");
    f.title = j.value("title", "");
    f.component = j.value("component", "");
    if (auto it = j.find("exploit"); it != j.end() && it->is_object()) {
        f.exploit.status = parse_exploit_status(it->value("status", "cve_no_poc"));
        f.exploit.gives = parse_exploit_gives(it->value("gives", "root"));
        f.exploit.user_interaction = it->value("user_interaction", false);
        f.exploit.requires_downgrade = it->value("requires_downgrade", false);
        if (auto pt = it->find("poc_targets"); pt != it->end() && pt->is_array()) {
            f.exploit.poc_targets = pt->get<std::vector<std::string>>();
        }
    }
    f.verdict = parse_verdict(j.value("verdict", "research_lead"));
    f.reasoning = j.value("reasoning", "");
    if (auto it = j.find("matched_facts"); it != j.end() && it->is_array()) {
        f.matched_facts = it->get<std::vector<MatchedFact>>();
    }
    if (auto it = j.find("notes"); it != j.end() && it->is_array()) {
        f.notes = it->get<std::vector<std::string>>();
    }
    if (auto it = j.find("refs"); it != j.end() && it->is_array()) {
        f.refs = it->get<std::vector<std::string>>();
    }
}

std::string findings_to_json(const std::vector<Finding>& fs, bool pretty)
{
    json arr = json::array();
    for (const auto& f : fs) {
        arr.push_back(json(f));
    }
    return pretty ? arr.dump(2) : arr.dump();
}

std::vector<Finding> findings_from_json_str(const std::string& s)
{
    return json::parse(s).get<std::vector<Finding>>();
}

} // namespace alps::core
