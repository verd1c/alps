// OSV Android ingestion. Reads a directory of OSV JSON files
// (Google publishes the Android Security Bulletin corpus in OSV format:
// https://storage.googleapis.com/osv-vulnerabilities/Android/all.zip) and
// emits ALPS YAML rule files with the L1 SPL_DATE ranges pre-populated.
//
// Everything ingested is metadata: CVE id, summary, affected SPL ranges,
// and advisory references. No exploit content is fetched, generated, or
// stored.

#pragma once

#include <string>
#include <vector>

#include "alps/core/rule.hpp"

namespace alps::osv {

// Parse a single OSV JSON document into an ALPS Rule. Throws with a
// descriptive error on any missing required field.
[[nodiscard]] alps::core::Rule rule_from_osv_json(const std::string& json_text);

// Import every *.json under `osv_dir` (recursive) and return the resulting
// Rule list. Files that fail to parse are recorded in `errors_out` (rule id
// where recoverable, filename otherwise) so a bad entry doesn't sink the
// whole import.
struct ImportError {
    std::string source;
    std::string message;
};
[[nodiscard]] std::vector<alps::core::Rule> load_osv_dir(
    const std::string& osv_dir, std::vector<ImportError>& errors_out);

// Serialize a Rule as YAML text ready to write to rules/osv/<id>.yaml.
[[nodiscard]] std::string rule_to_yaml(const alps::core::Rule& r);

} // namespace alps::osv
