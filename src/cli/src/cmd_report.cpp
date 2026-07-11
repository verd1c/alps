#include <iostream>
#include <sstream>
#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h> // isatty, fileno
#endif

#include <nlohmann/json.hpp>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/engine/matcher.hpp"
#include "alps/report/reporter.hpp"
#include "common.hpp"

namespace alps::cli {

namespace {

    alps::report::Report load_report(const std::string& findings_path,
        const std::string& facts_path, std::optional<alps::core::DeviceFacts>& facts_holder)
    {
        alps::report::Report r;
        auto js = nlohmann::json::parse(slurp_file(findings_path));

        // Accept two shapes: bare findings array, or the wrapped { findings, errors }
        // shape emitted by `alps match`.
        if (js.is_array()) {
            r.findings = js.get<std::vector<alps::core::Finding>>();
        } else if (js.is_object()) {
            if (auto it = js.find("findings"); it != js.end() && it->is_array()) {
                r.findings = it->get<std::vector<alps::core::Finding>>();
            }
            if (auto it = js.find("errors"); it != js.end() && it->is_array()) {
                for (const auto& e : *it) {
                    r.errors.push_back({
                        e.value("rule_id", std::string {}),
                        e.value("message", std::string {}),
                    });
                }
            }
        } else {
            throw std::runtime_error("findings file must be an array or an object");
        }

        if (!facts_path.empty()) {
            facts_holder = alps::core::DeviceFacts::from_json_str(slurp_file(facts_path));
            r.facts = &(*facts_holder);
        }
        return r;
    }

} // namespace

int cmd_report(const std::string& findings_path, const std::string& facts_path,
    const std::string& format, bool verbose, const std::string& color_mode)
{
    std::optional<alps::core::DeviceFacts> facts_holder;
    const auto r = load_report(findings_path, facts_path, facts_holder);

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
