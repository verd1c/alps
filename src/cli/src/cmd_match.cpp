#include <iostream>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"
#include "alps/engine/matcher.hpp"
#include "common.hpp"

namespace alps::cli {

int cmd_match(
    const std::string& facts_path, const std::string& rules_dir, const std::string& output_path)
{
    const auto facts = alps::core::DeviceFacts::from_json_str(slurp_file(facts_path));
    const auto rules = load_rules_default_builtin(rules_dir);
    const auto res = alps::engine::match_rules(rules, facts);

    nlohmann::json out = nlohmann::json::object();
    nlohmann::json findings = nlohmann::json::array();
    for (const auto& f : res.findings)
        findings.push_back(nlohmann::json(f));
    out["findings"] = std::move(findings);

    nlohmann::json errors = nlohmann::json::array();
    for (const auto& e : res.errors) {
        errors.push_back(nlohmann::json { { "rule_id", e.rule_id }, { "message", e.message } });
    }
    out["errors"] = std::move(errors);

    write_stdout_or_file(output_path, out.dump(2));
    return 0;
}

} // namespace alps::cli
