// Built-in rule KB: embedded into alps_core at build time by
// cmake/GenerateBuiltinRules.cmake. Deployment is a single binary; no
// external rules directory is required to run. `alps --rules <dir>` still
// overrides the built-ins for KB development.

#pragma once

#include <string>
#include <vector>

#include "alps/core/rule.hpp"

namespace alps::core {

struct BuiltinRuleSource {
    std::string filename; // e.g. "CVE-2022-38181.yaml"
    std::string yaml; // raw YAML source
};

// Returns the static list of every rule embedded at build time.
[[nodiscard]] const std::vector<BuiltinRuleSource>& builtin_rule_sources();

// Parse and return every built-in rule. Throws with context on any parse
// error; the CI/build should have already caught these via `alps rules lint`.
[[nodiscard]] std::vector<Rule> load_builtin_rules();

} // namespace alps::core
