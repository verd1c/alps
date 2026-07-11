#pragma once

#include <map>
#include <string>

namespace alps::collector {

// Parse the multi-line output of `getprop` (one line per property,
// "[key]: [value]") into a key-value map. Malformed lines are skipped.
[[nodiscard]] std::map<std::string, std::string> parse_getprop(const std::string& out);

} // namespace alps::collector
