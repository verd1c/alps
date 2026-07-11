#include <iostream>
#include <optional>

#include "alps/collector/collect.hpp"
#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/engine/matcher.hpp"
#include "alps/report/reporter.hpp"
#include "alps/tui/browser.hpp"
#include "common.hpp"

namespace alps::cli {

int cmd_ui(const std::string& facts_path, const std::string& rules_dir, bool no_alt_screen)
{
    // Load / collect facts.
    std::optional<alps::core::DeviceFacts> facts_owner;
    if (facts_path.empty()) {
        facts_owner = alps::collector::collect_on_device();
    } else {
        facts_owner = alps::core::DeviceFacts::from_json_str(slurp_file(facts_path));
    }
    const auto rules = load_rules_default_builtin(rules_dir);
    const auto res = alps::engine::match_rules(rules, *facts_owner);

    alps::report::Report r;
    r.facts = &(*facts_owner);
    r.findings = res.findings;
    r.errors = res.errors;

    alps::tui::BrowserOpts opts;
    opts.use_alt_screen = !no_alt_screen;
    opts.rules = &rules;
    return alps::tui::run_browser(r, opts);
}

} // namespace alps::cli
