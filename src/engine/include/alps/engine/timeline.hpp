// OSV-style event-timeline evaluation. Given a comparator, an ordered
// timeline of introduced/fixed/last_affected/limit events, and a candidate
// version, decide whether the candidate is affected.
//
// Multiple ranges (introduced -> fixed, then another introduced -> fixed) are
// naturally supported because events are sorted and applied left-to-right.
//
// GENERIC_STRING skips ordering entirely: the candidate is affected iff its
// value equals any `introduced` event's value (no ordering, no fixed events).

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "alps/core/rule.hpp"

namespace alps::engine {

// Returns true iff `version` falls in an affected range under `events`,
// interpreted through the comparator for `type`. Throws
// std::invalid_argument if any event is unparseable for the comparator.
// For GENERIC_STRING, uses set-membership semantics.
[[nodiscard]] bool timeline_affected(alps::core::ComparatorType type,
    const std::vector<alps::core::AffectedEvent>& events, std::string_view version);

// Explanation string suitable for a Finding's `matched_facts[].reason`.
// Reports the interval or set that captured the version. Never contains
// exploit details; purely a comparator-level trace.
[[nodiscard]] std::string timeline_reason(alps::core::ComparatorType type,
    const std::vector<alps::core::AffectedEvent>& events, std::string_view version);

} // namespace alps::engine
