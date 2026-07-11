// Matcher pipeline:
//   1. Parse and lint each rule's predicate.
//   2. Evaluate against the device facts.
//        - If true:  the rule applies now; verdict from the current-match table.
//        - If false: substitute the rule's `downgrade.min_vulnerable_spl` and
//                    re-evaluate; if that would match, run the downgrade
//                    reachability decision and emit VIA_DOWNGRADE or
//                    UNREACHABLE with the exact blockers.
//   3. Rules that fail to parse/lint/evaluate get recorded as RuleErrors so
//      one broken rule can't sink the whole scan.

#include "alps/engine/matcher.hpp"

#include <exception>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include "alps/engine/comparator.hpp"
#include "alps/engine/downgrade.hpp"
#include "alps/engine/predicate.hpp"
#include "alps/engine/timeline.hpp"
#include "alps/engine/verify.hpp"

namespace alps::engine {

namespace {

    std::string stringify_observed(const nlohmann::json& v)
    {
        if (v.is_null())
            return "null";
        if (v.is_boolean())
            return v.get<bool>() ? "true" : "false";
        if (v.is_number_integer())
            return std::to_string(v.get<int64_t>());
        if (v.is_number_unsigned())
            return std::to_string(v.get<uint64_t>());
        if (v.is_number_float())
            return std::to_string(v.get<double>());
        if (v.is_string())
            return v.get<std::string>();
        return v.dump();
    }

    std::vector<alps::core::MatchedFact> collect_matched_facts(
        const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
    {
        std::vector<alps::core::MatchedFact> out;
        for (const auto& af : rule.affected) {
            const auto val = facts.get_field(af.field);
            if (val.is_null())
                continue;
            std::string ver;
            if (val.is_string())
                ver = val.get<std::string>();
            else if (val.is_number())
                ver = std::to_string(val.get<int64_t>());
            else
                continue;

            bool affected = false;
            try {
                affected = timeline_affected(af.type, af.events, ver);
            } catch (const std::exception&) {
                continue;
            }
            if (!affected)
                continue;

            out.push_back(
                { af.field, stringify_observed(val), timeline_reason(af.type, af.events, ver) });
        }
        return out;
    }

    alps::core::Finding rule_to_finding(
        const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
    {
        alps::core::Finding f;
        f.rule_id = rule.id;
        f.title = rule.title;
        f.component = rule.component;
        f.exploit = rule.exploit;
        f.matched_facts = collect_matched_facts(rule, facts);
        f.refs = rule.refs;
        return f;
    }

    bool predicate_matches(
        const PredicateAst& ast, const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
    {
        EvalContext ctx;
        ctx.facts = &facts;
        ctx.rule = &rule;
        return evaluate_predicate(ast, ctx);
    }

    // Downgrade hypothesis: would the predicate match if every `affected()` call
    // returned true? All non-`affected()` clauses (GPU vendor, ABI, MTE state,
    // etc.) still evaluate against the real device; the hypothesis is only about
    // version-timeline fields that a firmware rollback would restore.
    bool predicate_matches_if_downgraded(
        const PredicateAst& ast, const alps::core::Rule& rule, const alps::core::DeviceFacts& facts)
    {
        EvalContext ctx;
        ctx.facts = &facts;
        ctx.rule = &rule;
        ctx.assume_affected = true;
        return evaluate_predicate(ast, ctx);
    }

} // namespace

MatchResult match_rules(
    const std::vector<alps::core::Rule>& rules, const alps::core::DeviceFacts& facts)
{
    MatchResult result;

    for (const auto& rule : rules) {
        try {
            auto ast = parse_predicate(rule.match);
            lint_predicate(*ast, rule);

            if (predicate_matches(*ast, rule, facts)) {
                // Currently in the vulnerable range.
                const auto v = verdict_for_current_match(rule, facts);
                auto f = rule_to_finding(rule, facts);
                f.verdict = v.value;
                f.reasoning = v.reasoning;
                // Optional binary verify: a failed/skipped verify enriches
                // the note list but never drops the finding.
                for (const auto& vr : run_verify_steps(rule, /*rules_dir=*/"")) {
                    std::string tag = vr.confirmed ? "verify OK: " : "verify: ";
                    f.notes.push_back(tag + vr.step_kind + ": " + vr.note);
                }
                result.findings.push_back(std::move(f));
                continue;
            }

            // Not currently affected; try the downgrade hypothesis.
            if (!rule.downgrade.min_vulnerable_spl.has_value())
                continue;

            const bool would_match = predicate_matches_if_downgraded(*ast, rule, facts);
            const auto dgv = verdict_via_downgrade(rule, facts, would_match);
            if (!dgv)
                continue;

            // Build the finding. matched_facts stay empty (nothing is
            // actually affected right now); the reasoning and notes carry the
            // downgrade story. A caller that wants the "would match" values
            // can synthesize them from rule.affected and the min-vuln SPL.
            alps::core::Finding f;
            f.rule_id = rule.id;
            f.title = rule.title;
            f.component = rule.component;
            f.exploit = rule.exploit;
            f.refs = rule.refs;
            f.verdict = dgv->value;
            f.reasoning = dgv->reasoning;
            if (!dgv->downgrade_target.empty()) {
                f.notes.push_back("downgrade_target: " + dgv->downgrade_target);
            }
            for (const auto& b : dgv->blockers) {
                f.notes.push_back("blocker: " + b.name + " (" + b.detail + ")");
            }
            result.findings.push_back(std::move(f));
        } catch (const std::exception& e) {
            result.errors.push_back({ rule.id, e.what() });
        }
    }
    return result;
}

} // namespace alps::engine
