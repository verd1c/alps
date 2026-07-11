#include "alps/core/builtin_rules.hpp"

#include <stdexcept>

namespace alps::core {

std::vector<Rule> load_builtin_rules()
{
    std::vector<Rule> out;
    for (const auto& src : builtin_rule_sources()) {
        try {
            out.push_back(Rule::from_yaml_str(src.yaml));
        } catch (const std::exception& e) {
            throw std::runtime_error("built-in rule " + src.filename + ": " + e.what());
        }
    }
    return out;
}

} // namespace alps::core
