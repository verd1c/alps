#include "alps/report/reporter.hpp"

#include <nlohmann/json.hpp>

namespace alps::report {

using nlohmann::json;

void write_json(std::ostream& os, const Report& r, bool pretty)
{
    json out = json::object();

    if (r.facts) {
        out["facts"] = *r.facts;
    } else {
        out["facts"] = nullptr;
    }

    json findings_arr = json::array();
    for (const auto& f : r.findings)
        findings_arr.push_back(json(f));
    out["findings"] = std::move(findings_arr);

    json errs = json::array();
    for (const auto& e : r.errors) {
        errs.push_back(json { { "rule_id", e.rule_id }, { "message", e.message } });
    }
    out["errors"] = std::move(errs);

    os << (pretty ? out.dump(2) : out.dump()) << "\n";
}

} // namespace alps::report
