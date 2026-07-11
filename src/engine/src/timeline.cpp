// OSV event-timeline evaluation. See timeline.hpp for the model.
//
// Algorithm (typed-numeric types):
//   1. Take every event's version string and its "kind" (introduced / fixed /
//      last_affected / limit).
//   2. Sort events ascending by version, using the comparator for the type.
//   3. Walk events in order. For each event whose version <= V, apply the
//      transition:
//          introduced      -> state = affected
//          fixed | limit   -> state = not affected  (fix applies at that ver)
//          last_affected   -> state = not affected iff V strictly > last_affected
//                            (V == last_affected stays affected)
//   4. Return the final state.
//
// GENERIC_STRING short-circuits: V is affected iff its exact value matches any
// `introduced` event's value. `fixed`/`limit`/`last_affected` are rejected.

#include "alps/engine/timeline.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "alps/engine/comparator.hpp"

namespace alps::engine {

namespace {

    enum class EventKind { Introduced, Fixed, LastAffected, Limit };

    struct FlatEvent {
        EventKind kind;
        std::string version;
    };

    // Extract exactly one (kind, version) from an AffectedEvent. The rule loader
    // already enforces "exactly one member set", but re-check defensively; this
    // function is a natural place for the timeline's own linting.
    FlatEvent flatten(const alps::core::AffectedEvent& e)
    {
        int seen = 0;
        FlatEvent out { EventKind::Introduced, "" };
        if (e.introduced) {
            out = { EventKind::Introduced, *e.introduced };
            ++seen;
        }
        if (e.fixed) {
            out = { EventKind::Fixed, *e.fixed };
            ++seen;
        }
        if (e.last_affected) {
            out = { EventKind::LastAffected, *e.last_affected };
            ++seen;
        }
        if (e.limit) {
            out = { EventKind::Limit, *e.limit };
            ++seen;
        }
        if (seen != 1) {
            throw std::invalid_argument(
                "timeline event must set exactly one of introduced/fixed/last_affected/limit");
        }
        return out;
    }

    const char* kind_str(EventKind k)
    {
        switch (k) {
        case EventKind::Introduced:
            return "introduced";
        case EventKind::Fixed:
            return "fixed";
        case EventKind::LastAffected:
            return "last_affected";
        case EventKind::Limit:
            return "limit";
        }
        return "?";
    }

    bool generic_string_affected(
        const std::vector<alps::core::AffectedEvent>& events, std::string_view version)
    {
        // Two passes: reject any non-`introduced` event so `rules lint` catches
        // schema misuse regardless of whether some earlier event would have
        // short-circuited the match.
        for (const auto& e : events) {
            const auto f = flatten(e);
            if (f.kind != EventKind::Introduced) {
                throw std::invalid_argument(
                    std::string("GENERIC_STRING does not support event kind: ") + kind_str(f.kind));
            }
        }
        for (const auto& e : events) {
            if (e.introduced && *e.introduced == version)
                return true;
        }
        return false;
    }

    // Sort events ascending by version. Sentinel "0" naturally sorts to the front
    // because the comparator treats it as negative infinity.
    void sort_events(const Comparator& cmp, std::vector<FlatEvent>& evs)
    {
        std::sort(evs.begin(), evs.end(), [&](const FlatEvent& a, const FlatEvent& b) {
            return cmp.compare(a.version, b.version) < 0;
        });
    }

} // namespace

bool timeline_affected(alps::core::ComparatorType type,
    const std::vector<alps::core::AffectedEvent>& events, std::string_view version)
{
    if (type == alps::core::ComparatorType::GENERIC_STRING) {
        return generic_string_affected(events, version);
    }

    auto cmp = make_comparator(type);
    // Validate the candidate version parses so an obscure sort-time throw
    // doesn't get blamed on the events.
    cmp->validate(version);

    std::vector<FlatEvent> flat;
    flat.reserve(events.size());
    for (const auto& e : events)
        flat.push_back(flatten(e));
    for (const auto& f : flat)
        cmp->validate(f.version);
    sort_events(*cmp, flat);

    bool state = false;
    for (const auto& e : flat) {
        const int c = cmp->compare(version, e.version); // sign of (version - e.version)
        switch (e.kind) {
        case EventKind::Introduced:
            if (c >= 0)
                state = true;
            break;
        case EventKind::Fixed:
        case EventKind::Limit:
            if (c >= 0)
                state = false;
            break;
        case EventKind::LastAffected:
            // version > last_affected: past the affected range. Equality
            // stays affected (that's the whole point of last_affected).
            if (c > 0)
                state = false;
            break;
        }
    }
    return state;
}

std::string timeline_reason(alps::core::ComparatorType type,
    const std::vector<alps::core::AffectedEvent>& events, std::string_view version)
{
    if (type == alps::core::ComparatorType::GENERIC_STRING) {
        for (const auto& e : events) {
            const auto f = flatten(e);
            if (f.kind == EventKind::Introduced && f.version == version) {
                return std::string("value \"") + std::string(version) + "\" listed in affected set";
            }
        }
        return std::string("value \"") + std::string(version) + "\" not in affected set";
    }

    auto cmp = make_comparator(type);
    std::vector<FlatEvent> flat;
    flat.reserve(events.size());
    for (const auto& e : events)
        flat.push_back(flatten(e));
    sort_events(*cmp, flat);

    // Find the enclosing introduced (last introduced <= V) and the earliest
    // fixed/limit strictly after it, if any.
    std::optional<std::string> intro_v;
    std::optional<std::string> close_v;
    const char* close_kind = "";
    for (const auto& e : flat) {
        const int c = cmp->compare(version, e.version);
        if (e.kind == EventKind::Introduced) {
            if (c >= 0) {
                intro_v = e.version;
                close_v.reset();
                close_kind = "";
            }
        } else if (e.kind == EventKind::Fixed || e.kind == EventKind::Limit
            || e.kind == EventKind::LastAffected) {
            if (intro_v && !close_v && cmp->compare(e.version, *intro_v) >= 0) {
                close_v = e.version;
                close_kind = kind_str(e.kind);
            }
        }
    }

    std::ostringstream ss;
    ss << version << " ";
    if (!intro_v) {
        ss << "before earliest introduced";
        return ss.str();
    }
    if (!close_v) {
        ss << "in [" << *intro_v << ", ∞)";
    } else {
        // For fixed/limit: half-open on the right. For last_affected: closed.
        const bool closed_right = std::string(close_kind) == "last_affected";
        ss << "in [" << *intro_v << ", " << *close_v << (closed_right ? "]" : ")");
    }
    return ss.str();
}

} // namespace alps::engine
