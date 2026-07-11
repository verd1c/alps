// Reporters. Three surfaces:
//   * terminal:   grouped by verdict, most-actionable first, ANSI-tinted
//                 when the output stream is a TTY.
//   * markdown:   same grouping, suited to reports and issue trackers.
//   * json:       machine-readable dump (findings + errors + facts summary).
// The reporter never renders anything from the exploit knowledge base beyond
// what's already in the findings: verdicts, reasoning, matched-fact tuples,
// and reference URLs. No exploit content.

#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/engine/matcher.hpp"

namespace alps::report {

struct Report {
    const alps::core::DeviceFacts* facts = nullptr; // optional
    std::vector<alps::core::Finding> findings;
    std::vector<alps::engine::RuleError> errors;
};

struct TermOpts {
    bool ansi = false; // emit ANSI color codes
    bool verbose = false; // include reasoning, matched facts, refs
};

// Terminal reporter. Default (verbose=false) is compact: one line per
// finding, grouped by verdict, so the whole scan fits on one screen. With
// verbose=true, print full reasoning, matched facts, and every reference.
void write_terminal(std::ostream& os, const Report& r, const TermOpts& opts);

// Markdown reporter: verdict headings, matched-fact bullets, references.
void write_markdown(std::ostream& os, const Report& r);

// JSON reporter: { facts, findings, errors } for downstream tooling.
void write_json(std::ostream& os, const Report& r, bool pretty = true);

} // namespace alps::report
