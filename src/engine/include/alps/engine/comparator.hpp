// Layer-1 version comparators. No string version compares anywhere; the
// comparator's `type` picks a typed parser that then does the numeric ordering.
//
// The special token "0" universally denotes negative infinity: it sorts
// strictly less than every parseable version of that type. This lets a rule
// author write `introduced: "0"` when a bug pre-dates all recorded versions.

#pragma once

#include <memory>
#include <string_view>

#include "alps/core/rule.hpp"

namespace alps::engine {

class Comparator {
public:
    virtual ~Comparator() = default;

    // Return <0 if a < b, 0 if equal, >0 if a > b. Throws std::invalid_argument
    // if either string is unparseable in this comparator's format. For
    // GENERIC_STRING, only equality is meaningful; ordering throws.
    [[nodiscard]] virtual int compare(std::string_view a, std::string_view b) const = 0;

    // Throws std::invalid_argument if the string doesn't parse; useful for
    // `rules lint` to validate rule contents without needing another version
    // to compare against.
    virtual void validate(std::string_view v) const = 0;

    [[nodiscard]] virtual const char* type_name() const noexcept = 0;
};

[[nodiscard]] std::unique_ptr<Comparator> make_comparator(alps::core::ComparatorType t);

} // namespace alps::engine
