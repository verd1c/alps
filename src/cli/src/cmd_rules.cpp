#include <iostream>
#include <sstream>
#include <vector>

#include "alps/core/rule.hpp"
#include "alps/engine/predicate.hpp"
#include "common.hpp"

namespace alps::cli {

int cmd_rules_lint(const std::string& rules_dir)
{
    std::vector<std::string> errors;
    std::vector<alps::core::Rule> rules;
    try {
        rules = load_rules_default_builtin(rules_dir);
    } catch (const std::exception& e) {
        std::cerr << "load failure: " << e.what() << "\n";
        return 1;
    }
    for (const auto& r : rules) {
        try {
            auto ast = alps::engine::parse_predicate(r.match);
            alps::engine::lint_predicate(*ast, r);
        } catch (const std::exception& e) {
            errors.push_back(r.id + ": " + e.what());
        }
    }
    std::cout << "rules loaded: " << rules.size() << ", errors: " << errors.size() << "\n";
    for (const auto& e : errors)
        std::cout << "  " << e << "\n";
    return errors.empty() ? 0 : 1;
}

int cmd_rules_list(const std::string& rules_dir, const std::string& filter_component,
    const std::string& filter_class)
{
    const auto rules = load_rules_default_builtin(rules_dir);
    for (const auto& r : rules) {
        if (!filter_component.empty() && r.component != filter_component)
            continue;
        if (!filter_class.empty() && alps::core::rule_class_to_string(r.rule_class) != filter_class)
            continue;
        std::cout << r.id << "\t" << r.component << "\t"
                  << alps::core::rule_class_to_string(r.rule_class) << "\t"
                  << alps::core::exploit_status_to_string(r.exploit.status) << "\t" << r.title
                  << "\n";
    }
    return 0;
}

} // namespace alps::cli
