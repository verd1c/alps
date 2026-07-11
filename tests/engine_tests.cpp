// Engine unit tests: Layer-1 comparators and OSV timeline evaluation.
// Every pathological case has a dedicated assertion.

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "alps/core/rule.hpp"
#include "alps/engine/comparator.hpp"
#include "alps/engine/timeline.hpp"

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":" << __LINE__ << "\n";        \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

#define EXPECT_THROWS(expr)                                                                        \
    do {                                                                                           \
        bool threw = false;                                                                        \
        try {                                                                                      \
            (void)(expr);                                                                          \
        } catch (const std::exception&) {                                                          \
            threw = true;                                                                          \
        }                                                                                          \
        if (!threw) {                                                                              \
            std::cerr << "FAIL (expected throw): " << #expr << " @ " << __FILE__ << ":"            \
                      << __LINE__ << "\n";                                                         \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

using alps::core::AffectedEvent;
using alps::core::ComparatorType;
using alps::engine::make_comparator;
using alps::engine::timeline_affected;
using alps::engine::timeline_reason;

int cmp_of(ComparatorType t, std::string_view a, std::string_view b)
{
    return make_comparator(t)->compare(a, b);
}

AffectedEvent introduced(std::string v)
{
    AffectedEvent e;
    e.introduced = std::move(v);
    return e;
}
AffectedEvent fixed_ev(std::string v)
{
    AffectedEvent e;
    e.fixed = std::move(v);
    return e;
}
AffectedEvent last_aff(std::string v)
{
    AffectedEvent e;
    e.last_affected = std::move(v);
    return e;
}
AffectedEvent limit_ev(std::string v)
{
    AffectedEvent e;
    e.limit = std::move(v);
    return e;
}

void test_spl_date()
{
    // "0" is negative infinity: strictly less than any real date.
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "0", "2022-07-05") < 0);
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "2022-07-05", "0") > 0);
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "0", "0") == 0);

    // Chronological ordering.
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "2022-07-05", "2022-11-05") < 0);
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "2023-01-01", "2022-12-31") > 0);
    EXPECT(cmp_of(ComparatorType::SPL_DATE, "2022-07-05", "2022-07-05") == 0);

    // Malformed inputs throw.
    EXPECT_THROWS(cmp_of(ComparatorType::SPL_DATE, "not-a-date", "2022-07-05"));
    EXPECT_THROWS(cmp_of(ComparatorType::SPL_DATE, "2022/07/05", "2022-07-05"));
    EXPECT_THROWS(cmp_of(ComparatorType::SPL_DATE, "2022-13-05", "2022-07-05"));
}

void test_semver()
{
    EXPECT(cmp_of(ComparatorType::SEMVER, "1.2.3", "1.2.4") < 0);
    EXPECT(cmp_of(ComparatorType::SEMVER, "1.10.0", "1.2.0") > 0);
    EXPECT(cmp_of(ComparatorType::SEMVER, "0.0.0", "0.0.0") == 0);

    // Prerelease/build suffix is trimmed for our purposes.
    EXPECT(cmp_of(ComparatorType::SEMVER, "1.2.3-alpha", "1.2.3") == 0);
    EXPECT(cmp_of(ComparatorType::SEMVER, "1.2.3+build.5", "1.2.3") == 0);

    EXPECT(cmp_of(ComparatorType::SEMVER, "0", "1.0.0") < 0);

    // "v"-prefix rejected.
    EXPECT_THROWS(cmp_of(ComparatorType::SEMVER, "v1.2.3", "1.2.3"));
    EXPECT_THROWS(cmp_of(ComparatorType::SEMVER, "1.2", "1.2.0")); // need 3 parts
    EXPECT_THROWS(cmp_of(ComparatorType::SEMVER, "1.2.3.4", "1.2.3"));
}

void test_kernel_version()
{
    // Canonical pathological case: numeric per-component, not lexical.
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10.99", "5.10.101") < 0);
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10.101", "5.10.99") > 0);

    // Different depths: trailing components default to 0.
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10", "5.10.0") == 0);
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10", "5.10.1") < 0);

    // Real Pixel-6 kernel string: extras must not affect ordering.
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION,
               "5.10.107-android12-9-00027-g43f22c0eff7d-ab8547278", "5.10.140")
        < 0);
    // Rule with no ACK tag is treated as "any ACK at this numeric level".
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android12-9-00027", "5.10.107") == 0);

    // ACK-tag ordering when BOTH sides declare one. This is what a rule
    // author uses when a specific Android Common Kernel drop carries the
    // fix ahead of upstream.
    EXPECT(
        cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android12-8", "5.10.107-android12-9") < 0);
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android12-9", "5.10.107-android12-9")
        == 0);
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android12-10", "5.10.107-android12-9")
        > 0);
    // ACK-major ordering.
    EXPECT(
        cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android11-9", "5.10.107-android12-0") < 0);
    // Missing ACK minor treated as 0.
    EXPECT(
        cmp_of(ComparatorType::KERNEL_VERSION, "5.10.107-android12", "5.10.107-android12-1") < 0);

    // "0" sentinel.
    EXPECT(cmp_of(ComparatorType::KERNEL_VERSION, "0", "3.0.0") < 0);
    EXPECT_THROWS(cmp_of(ComparatorType::KERNEL_VERSION, "nope", "5.10.0"));
}

void test_mali_driver()
{
    // Pathological case: r39 vs r4 vs r40 must order numerically, not lexically.
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "r4p0", "r39p0") < 0);
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "r39p0", "r40p0") < 0);
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "r40p0", "r4p0") > 0);

    // Point release ordering.
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "r32p0", "r32p1") < 0);
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "r32p1", "r32p1") == 0);

    // "0" sentinel.
    EXPECT(cmp_of(ComparatorType::MALI_DRIVER, "0", "r0p0") < 0);

    // Malformed inputs.
    EXPECT_THROWS(cmp_of(ComparatorType::MALI_DRIVER, "r32", "r32p1"));
    EXPECT_THROWS(cmp_of(ComparatorType::MALI_DRIVER, "32p1", "r32p1"));
    EXPECT_THROWS(cmp_of(ComparatorType::MALI_DRIVER, "rXpY", "r32p1"));
}

void test_adreno()
{
    EXPECT(cmp_of(ComparatorType::ADRENO, "540.0.5", "540.0.6") < 0);
    EXPECT(cmp_of(ComparatorType::ADRENO, "540", "541") < 0);
    EXPECT(cmp_of(ComparatorType::ADRENO, "540.10", "540.9") > 0); // numeric, not lex
    EXPECT(cmp_of(ComparatorType::ADRENO, "0", "1.0") < 0);
    EXPECT_THROWS(cmp_of(ComparatorType::ADRENO, "abc", "1.0"));
}

void test_generic_string()
{
    EXPECT(cmp_of(ComparatorType::GENERIC_STRING, "mali", "mali") == 0);
    // Ordering intentionally undefined.
    EXPECT_THROWS(cmp_of(ComparatorType::GENERIC_STRING, "mali", "adreno"));
}

// Timeline evaluation.
void test_timeline_single_range()
{
    std::vector<AffectedEvent> spl = { introduced("0"), fixed_ev("2022-11-05") };

    // Pixel 6 July 2022 fixture: in [0, 2022-11-05) is affected.
    EXPECT(timeline_affected(ComparatorType::SPL_DATE, spl, "2022-07-05"));
    // Patched device: 2023-11-05 >= fixed, so not affected.
    EXPECT(!timeline_affected(ComparatorType::SPL_DATE, spl, "2023-11-05"));
    // Exactly at fixed: not affected.
    EXPECT(!timeline_affected(ComparatorType::SPL_DATE, spl, "2022-11-05"));
}

void test_timeline_mali()
{
    std::vector<AffectedEvent> mali = { introduced("0"), fixed_ev("r40p0") };

    EXPECT(timeline_affected(ComparatorType::MALI_DRIVER, mali, "r32p1")); // vulnerable
    EXPECT(!timeline_affected(ComparatorType::MALI_DRIVER, mali, "r40p0")); // exactly-fixed
    EXPECT(!timeline_affected(ComparatorType::MALI_DRIVER, mali, "r44p1")); // patched
    EXPECT(timeline_affected(ComparatorType::MALI_DRIVER, mali, "r39p9")); // just under
}

void test_timeline_multi_range()
{
    // Backport pattern: fixed once, regressed, fixed again.
    std::vector<AffectedEvent> ev = {
        introduced("5.10.0"),
        fixed_ev("5.10.100"),
        introduced("5.10.150"),
        fixed_ev("5.10.200"),
    };
    EXPECT(timeline_affected(ComparatorType::KERNEL_VERSION, ev, "5.10.50")); // in first  range
    EXPECT(!timeline_affected(ComparatorType::KERNEL_VERSION, ev, "5.10.120")); // between
    EXPECT(timeline_affected(ComparatorType::KERNEL_VERSION, ev, "5.10.180")); // in second range
    EXPECT(!timeline_affected(ComparatorType::KERNEL_VERSION, ev, "5.10.220")); // past all
}

void test_timeline_last_affected()
{
    // Range: [1.0.0, 1.9.9] closed.
    std::vector<AffectedEvent> ev = { introduced("1.0.0"), last_aff("1.9.9") };
    EXPECT(timeline_affected(ComparatorType::SEMVER, ev, "1.5.0"));
    EXPECT(timeline_affected(ComparatorType::SEMVER, ev, "1.9.9")); // closed on the right
    EXPECT(!timeline_affected(ComparatorType::SEMVER, ev, "2.0.0"));
}

void test_timeline_limit()
{
    // `limit` behaves like `fixed`.
    std::vector<AffectedEvent> ev = { introduced("1.0.0"), limit_ev("1.5.0") };
    EXPECT(timeline_affected(ComparatorType::SEMVER, ev, "1.4.9"));
    EXPECT(!timeline_affected(ComparatorType::SEMVER, ev, "1.5.0"));
    EXPECT(!timeline_affected(ComparatorType::SEMVER, ev, "1.5.1"));
}

void test_timeline_generic_string()
{
    std::vector<AffectedEvent> ev = { introduced("mali"), introduced("adreno") };
    EXPECT(timeline_affected(ComparatorType::GENERIC_STRING, ev, "mali"));
    EXPECT(timeline_affected(ComparatorType::GENERIC_STRING, ev, "adreno"));
    EXPECT(!timeline_affected(ComparatorType::GENERIC_STRING, ev, "powervr"));

    // GENERIC_STRING must reject non-`introduced` event kinds.
    std::vector<AffectedEvent> bad = { introduced("mali"), fixed_ev("adreno") };
    EXPECT_THROWS(timeline_affected(ComparatorType::GENERIC_STRING, bad, "mali"));
}

void test_timeline_reason()
{
    std::vector<AffectedEvent> mali = { introduced("0"), fixed_ev("r40p0") };
    auto reason = timeline_reason(ComparatorType::MALI_DRIVER, mali, "r32p1");
    EXPECT(reason.find("r32p1") != std::string::npos);
    EXPECT(reason.find("[0, r40p0)") != std::string::npos);

    // GENERIC_STRING reason.
    std::vector<AffectedEvent> gs = { introduced("mali") };
    auto r2 = timeline_reason(ComparatorType::GENERIC_STRING, gs, "mali");
    EXPECT(r2.find("affected set") != std::string::npos);
}

} // namespace

int main()
{
    test_spl_date();
    test_semver();
    test_kernel_version();
    test_mali_driver();
    test_adreno();
    test_generic_string();

    test_timeline_single_range();
    test_timeline_mali();
    test_timeline_multi_range();
    test_timeline_last_affected();
    test_timeline_limit();
    test_timeline_generic_string();
    test_timeline_reason();

    if (g_failures == 0) {
        std::cout << "OK: all engine tests passed\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
