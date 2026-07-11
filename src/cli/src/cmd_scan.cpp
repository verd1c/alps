#include <iostream>
#include <unistd.h> // isatty, fileno

#include "alps/collector/collect.hpp"
#include "alps/core/device_facts.hpp"
#include "alps/core/rule.hpp"
#include "alps/engine/matcher.hpp"
#include "alps/report/reporter.hpp"
#include "common.hpp"

namespace alps::cli {

int cmd_scan(const std::string& rules_dir, const std::string& format, bool verbose,
    const std::string& color_mode)
{
    const auto facts = alps::collector::collect_on_device();
    const auto rules = load_rules_default_builtin(rules_dir);
    const auto res = alps::engine::match_rules(rules, facts);

    alps::report::Report r;
    r.facts = &facts;
    r.findings = res.findings;
    r.errors = res.errors;

    if (format == "json") {
        alps::report::write_json(std::cout, r, true);
    } else if (format == "markdown") {
        alps::report::write_markdown(std::cout, r);
    } else {
        alps::report::TermOpts opts;
        opts.ansi = resolve_color(color_mode, ::isatty(fileno(stdout)) != 0);
        opts.verbose = verbose;
        alps::report::write_terminal(std::cout, r, opts);
    }
    return 0;
}

} // namespace alps::cli
