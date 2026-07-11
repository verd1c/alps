// Concrete comparators for each ComparatorType. Each parses its version
// string into a small POD-ish struct, then compares numerically. Every
// comparator treats "0" as negative infinity so rules can express "vulnerable
// from the dawn of time" without picking a real earliest version.

#include "alps/engine/comparator.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace alps::engine {

namespace {

    using alps::core::ComparatorType;

    [[nodiscard]] bool parse_uint(std::string_view s, int& out)
    {
        if (s.empty())
            return false;
        for (char c : s) {
            if (!std::isdigit(static_cast<unsigned char>(c)))
                return false;
        }
        int v = 0;
        auto res = std::from_chars(s.data(), s.data() + s.size(), v);
        if (res.ec != std::errc {} || res.ptr != s.data() + s.size())
            return false;
        out = v;
        return true;
    }

    [[nodiscard]] std::string invalid_msg(const char* t, std::string_view s)
    {
        return std::string("invalid ") + t + " version: '" + std::string(s) + "'";
    }

    // A generic min-sentinel-aware compare on integer tuples. Used by every
    // numeric comparator below.
    template <typename Vec> int compare_tuples(bool a_min, const Vec& a, bool b_min, const Vec& b)
    {
        if (a_min && b_min)
            return 0;
        if (a_min)
            return -1;
        if (b_min)
            return 1;
        const auto n = std::max(a.size(), b.size());
        for (std::size_t i = 0; i < n; ++i) {
            const int av = i < a.size() ? a[i] : 0;
            const int bv = i < b.size() ? b[i] : 0;
            if (av != bv)
                return av < bv ? -1 : 1;
        }
        return 0;
    }

    // SPL_DATE.
    struct SplDate {
        bool is_min = false;
        int y = 0, m = 0, d = 0;

        static SplDate parse(std::string_view s)
        {
            if (s == "0")
                return { true, 0, 0, 0 };
            SplDate out;
            if (s.size() != 10 || s[4] != '-' || s[7] != '-') {
                throw std::invalid_argument(invalid_msg("SPL_DATE", s));
            }
            if (!parse_uint(s.substr(0, 4), out.y) || !parse_uint(s.substr(5, 2), out.m)
                || !parse_uint(s.substr(8, 2), out.d)) {
                throw std::invalid_argument(invalid_msg("SPL_DATE", s));
            }
            if (out.m < 1 || out.m > 12 || out.d < 1 || out.d > 31) {
                throw std::invalid_argument(invalid_msg("SPL_DATE (out-of-range)", s));
            }
            return out;
        }
        int cmp(const SplDate& o) const
        {
            const int a[] = { y, m, d };
            const int b[] = { o.y, o.m, o.d };
            return compare_tuples(
                is_min, std::vector<int> { a, a + 3 }, o.is_min, std::vector<int> { b, b + 3 });
        }
    };

    class SplDateComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            return SplDate::parse(a).cmp(SplDate::parse(b));
        }
        void validate(std::string_view v) const override { (void)SplDate::parse(v); }
        const char* type_name() const noexcept override { return "SPL_DATE"; }
    };

    // SEMVER (MAJOR.MINOR.PATCH; prerelease/build metadata ignored).
    struct SemVer {
        bool is_min = false;
        std::vector<int> parts; // exactly {maj, min, patch}
        static SemVer parse(std::string_view s)
        {
            if (s == "0")
                return { true, {} };
            if (!s.empty() && s[0] == 'v') {
                throw std::invalid_argument(invalid_msg("SEMVER (leading v)", s));
            }
            // Trim prerelease/build suffix; not used for our comparisons.
            auto trim = [](std::string_view v) -> std::string_view {
                auto pos = v.find_first_of("-+");
                return pos == std::string_view::npos ? v : v.substr(0, pos);
            };
            std::string_view core = trim(s);
            SemVer out;
            int parts_seen = 0;
            while (!core.empty() && parts_seen < 3) {
                auto dot = core.find('.');
                std::string_view seg = core.substr(0, dot);
                int n = 0;
                if (!parse_uint(seg, n)) {
                    throw std::invalid_argument(invalid_msg("SEMVER", s));
                }
                out.parts.push_back(n);
                ++parts_seen;
                if (dot == std::string_view::npos) {
                    core = {};
                    break;
                }
                core = core.substr(dot + 1);
            }
            if (out.parts.size() != 3 || !core.empty()) {
                throw std::invalid_argument(invalid_msg("SEMVER (need MAJOR.MINOR.PATCH)", s));
            }
            return out;
        }
        int cmp(const SemVer& o) const { return compare_tuples(is_min, parts, o.is_min, o.parts); }
    };

    class SemverComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            return SemVer::parse(a).cmp(SemVer::parse(b));
        }
        void validate(std::string_view v) const override { (void)SemVer::parse(v); }
        const char* type_name() const noexcept override { return "SEMVER"; }
    };

    // KERNEL_VERSION (maj.min.patch[-androidX-Y][-extra]).
    // Numeric parts ordered per-component. We additionally recognise Google's
    // Android Common Kernel `-androidX-Y` tag as a secondary ordering axis:
    // security backports go into the ACK line before they appear upstream, so a
    // rule saying `fixed: 5.10.107-android12-9` needs to detect a device at
    // `5.10.107-android12-8` as still vulnerable.
    //
    // Semantics chosen to be forgiving:
    //   Both sides carry an ACK tag:  compare (numeric, ack_major, ack_minor).
    //   Either side lacks an ACK tag: compare numeric only. The rule author
    //     signalled "any ACK at this numeric level is equivalent".
    // This keeps existing "fixed: 5.10.102" rules working against devices with
    // `-android12-9-...` suffixes without demanding tag-perfect authoring.
    struct KernelVer {
        bool is_min = false;
        std::vector<int> parts;
        std::optional<int> ack_major;
        std::optional<int> ack_minor;
        std::string extra;

        static KernelVer parse(std::string_view s)
        {
            if (s == "0")
                return { true, {}, {}, {}, {} };
            KernelVer out;

            // Head is [0-9.]*; anything after is `extra` (which may include the
            // ACK tag we parse below).
            std::size_t i = 0;
            for (; i < s.size(); ++i) {
                const char c = s[i];
                if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.')
                    break;
            }
            std::string_view head = s.substr(0, i);
            std::string_view rest = s.substr(i);
            out.extra = std::string(rest);

            // Look for "-android<int>[-<int>]" anywhere in the extra suffix.
            constexpr std::string_view kAndroidMarker = "-android";
            if (auto pos = rest.find(kAndroidMarker); pos != std::string_view::npos) {
                std::string_view after = rest.substr(pos + kAndroidMarker.size());
                std::size_t j = 0;
                while (j < after.size() && std::isdigit(static_cast<unsigned char>(after[j])))
                    ++j;
                if (j > 0) {
                    int m = 0;
                    if (parse_uint(after.substr(0, j), m)) {
                        out.ack_major = m;
                        if (j < after.size() && after[j] == '-') {
                            std::size_t k = j + 1;
                            while (k < after.size()
                                && std::isdigit(static_cast<unsigned char>(after[k])))
                                ++k;
                            int n = 0;
                            if (k > j + 1 && parse_uint(after.substr(j + 1, k - j - 1), n)) {
                                out.ack_minor = n;
                            }
                        }
                    }
                }
            }

            while (!head.empty()) {
                auto dot = head.find('.');
                std::string_view seg = head.substr(0, dot);
                int n = 0;
                if (!parse_uint(seg, n)) {
                    throw std::invalid_argument(invalid_msg("KERNEL_VERSION", s));
                }
                out.parts.push_back(n);
                if (dot == std::string_view::npos)
                    break;
                head = head.substr(dot + 1);
            }
            if (out.parts.empty()) {
                throw std::invalid_argument(invalid_msg("KERNEL_VERSION", s));
            }
            return out;
        }

        int cmp(const KernelVer& o) const
        {
            if (is_min && o.is_min)
                return 0;
            if (is_min)
                return -1;
            if (o.is_min)
                return 1;

            if (const int r = compare_tuples(false, parts, false, o.parts); r != 0) {
                return r;
            }
            // Numeric tie. Compare ACK tags iff BOTH sides carry one.
            if (!ack_major.has_value() || !o.ack_major.has_value())
                return 0;
            if (*ack_major != *o.ack_major)
                return *ack_major < *o.ack_major ? -1 : 1;
            const int a_min = ack_minor.value_or(0);
            const int b_min = o.ack_minor.value_or(0);
            if (a_min != b_min)
                return a_min < b_min ? -1 : 1;
            return 0;
        }
    };

    class KernelVersionComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            return KernelVer::parse(a).cmp(KernelVer::parse(b));
        }
        void validate(std::string_view v) const override { (void)KernelVer::parse(v); }
        const char* type_name() const noexcept override { return "KERNEL_VERSION"; }
    };

    // MALI_DRIVER (r{maj}p{min}).
    struct MaliVer {
        bool is_min = false;
        int major = 0, minor = 0;

        static MaliVer parse(std::string_view s)
        {
            if (s == "0")
                return { true, 0, 0 };
            if (s.size() < 4 || s[0] != 'r') {
                throw std::invalid_argument(invalid_msg("MALI_DRIVER", s));
            }
            const auto p = s.find('p', 1);
            if (p == std::string_view::npos || p == 1 || p == s.size() - 1) {
                throw std::invalid_argument(invalid_msg("MALI_DRIVER", s));
            }
            MaliVer out;
            if (!parse_uint(s.substr(1, p - 1), out.major)
                || !parse_uint(s.substr(p + 1), out.minor)) {
                throw std::invalid_argument(invalid_msg("MALI_DRIVER", s));
            }
            return out;
        }
        int cmp(const MaliVer& o) const
        {
            const std::vector<int> a { major, minor };
            const std::vector<int> b { o.major, o.minor };
            return compare_tuples(is_min, a, o.is_min, b);
        }
    };

    class MaliDriverComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            return MaliVer::parse(a).cmp(MaliVer::parse(b));
        }
        void validate(std::string_view v) const override { (void)MaliVer::parse(v); }
        const char* type_name() const noexcept override { return "MALI_DRIVER"; }
    };

    // ADRENO (dotted-numeric, e.g. "540.0.5").
    // Qualcomm publishes many string schemes; we treat every
    // leading dotted-numeric run as a version tuple and compare per-component.
    // Any non-parseable string throws; rules must normalize to numeric.
    struct AdrenoVer {
        bool is_min = false;
        std::vector<int> parts;

        static AdrenoVer parse(std::string_view s)
        {
            if (s == "0")
                return { true, {} };
            AdrenoVer out;
            std::size_t i = 0;
            for (; i < s.size(); ++i) {
                const char c = s[i];
                if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.')
                    break;
            }
            std::string_view head = s.substr(0, i);
            while (!head.empty()) {
                auto dot = head.find('.');
                std::string_view seg = head.substr(0, dot);
                int n = 0;
                if (!parse_uint(seg, n)) {
                    throw std::invalid_argument(invalid_msg("ADRENO", s));
                }
                out.parts.push_back(n);
                if (dot == std::string_view::npos)
                    break;
                head = head.substr(dot + 1);
            }
            if (out.parts.empty()) {
                throw std::invalid_argument(invalid_msg("ADRENO", s));
            }
            return out;
        }
        int cmp(const AdrenoVer& o) const
        {
            return compare_tuples(is_min, parts, o.is_min, o.parts);
        }
    };

    class AdrenoComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            return AdrenoVer::parse(a).cmp(AdrenoVer::parse(b));
        }
        void validate(std::string_view v) const override { (void)AdrenoVer::parse(v); }
        const char* type_name() const noexcept override { return "ADRENO"; }
    };

    // GENERIC_STRING (set-membership only, no ordering).
    class GenericStringComparator final : public Comparator {
    public:
        int compare(std::string_view a, std::string_view b) const override
        {
            if (a == b)
                return 0;
            throw std::invalid_argument("GENERIC_STRING has no ordering; only equality is defined");
        }
        void validate(std::string_view) const override { }
        const char* type_name() const noexcept override { return "GENERIC_STRING"; }
    };

} // namespace

std::unique_ptr<Comparator> make_comparator(alps::core::ComparatorType t)
{
    switch (t) {
    case ComparatorType::SPL_DATE:
        return std::make_unique<SplDateComparator>();
    case ComparatorType::SEMVER:
        return std::make_unique<SemverComparator>();
    case ComparatorType::KERNEL_VERSION:
        return std::make_unique<KernelVersionComparator>();
    case ComparatorType::MALI_DRIVER:
        return std::make_unique<MaliDriverComparator>();
    case ComparatorType::ADRENO:
        return std::make_unique<AdrenoComparator>();
    case ComparatorType::GENERIC_STRING:
        return std::make_unique<GenericStringComparator>();
    }
    throw std::invalid_argument("unhandled ComparatorType");
}

} // namespace alps::engine
