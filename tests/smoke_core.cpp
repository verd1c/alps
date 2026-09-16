// smoke_core: sanity check that fixtures parse, fields round-trip,
// the sample rule loads cleanly, and Finding JSON survives serialization.
// Not a full unit-test suite: the comparators, matcher, predicate, and
// collector each have their own test binaries alongside this one.

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":" << __LINE__ << "\n";        \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

std::string slurp(const std::string& path)
{
    std::ifstream f(path);
    if (!f) {
        std::cerr << "cannot open " << path << "\n";
        std::abort();
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

int main(int argc, char** argv)
{
    // argv[1] wins over the compiled-in default, so the same binary works on
    // host (ctest) and after being pushed to /data/local/tmp/alps on device.
    std::string root = (argc > 1) ? argv[1] : ALPS_DEFAULT_ROOT;

    using namespace alps::core;

    // DeviceFacts round-trip.
    auto facts_json_in = slurp(root + "/tests/fixtures/pixel6_july2022.json");
    auto facts = DeviceFacts::from_json_str(facts_json_in);

    EXPECT(facts.model.value_or("") == "Pixel 6");
    EXPECT(facts.spl.value_or("") == "2022-07-05");
    EXPECT(facts.vendor_spl.value_or("") == "2022-07-05");
    EXPECT(facts.gpu.vendor.value_or("") == "mali");
    EXPECT(facts.gpu.mali_driver.value_or("") == "r32p1");
    EXPECT(facts.abis.size() == 2);
    EXPECT(facts.bootloader_locked.value_or(false) == true);
    EXPECT(!facts.rollback_index.has_value()); // fixture leaves it null
    EXPECT(facts.raw_props.count("ro.build.version.release") == 1);

    // Dotted-path lookup: this is what the predicate engine will use.
    EXPECT(facts.get_field("model").is_string());
    EXPECT(facts.get_field("model").get<std::string>() == "Pixel 6");
    EXPECT(facts.get_field("gpu.mali_driver").get<std::string>() == "r32p1");
    EXPECT(facts.get_field("gpu.adreno_driver").is_null());
    EXPECT(facts.get_field("does.not.exist").is_null());
    EXPECT(facts.get_field("abis").is_array());
    EXPECT(facts.get_field("abis").size() == 2);

    // Round-trip via JSON.
    auto reserialized = facts.to_json_str(false);
    auto facts2 = DeviceFacts::from_json_str(reserialized);
    EXPECT(facts2.model.value_or("") == "Pixel 6");
    EXPECT(facts2.gpu.mali_driver.value_or("") == "r32p1");
    EXPECT(facts2.raw_props.size() == facts.raw_props.size());

    // Patched fixture: confirms the divergence-friendly schema still works
    // when rollback_index is set and everything is post-fix.
    auto patched = DeviceFacts::from_json_str(slurp(root + "/tests/fixtures/pixel6_patched.json"));
    EXPECT(patched.spl.value_or("") == "2023-11-05");
    EXPECT(patched.gpu.mali_driver.value_or("") == "r44p1");
    EXPECT(patched.rollback_index.value_or(-1) == 3);

    // Rule loading.
    auto rules = load_rules_dir(root + "/rules");
    EXPECT(!rules.empty());

    bool found_mali = false;
    for (const auto& r : rules) {
        if (r.id != "CVE-2022-38181")
            continue;
        found_mali = true;
        EXPECT(r.component == "gpu");
        EXPECT(r.rule_class == RuleClass::LPE);
        EXPECT(r.affected.size() == 2);
        EXPECT(r.affected[0].field == "gpu.mali_driver");
        EXPECT(r.affected[0].type == ComparatorType::MALI_DRIVER);
        EXPECT(r.affected[0].events.size() == 2);
        EXPECT(r.affected[0].events[0].introduced.value_or("") == "0");
        EXPECT(r.affected[0].events[1].fixed.value_or("") == "r40p0");
        EXPECT(r.affected[1].type == ComparatorType::SPL_DATE);
        EXPECT(!r.match.empty());
        EXPECT(r.exploit.status == ExploitStatus::WEAPONIZED_PUBLIC);
        EXPECT(r.exploit.gives == ExploitGives::KERNEL_RW);
        EXPECT(!r.exploit.user_interaction);
        // All 31 shipped rules declare exactly one downgrade blocker. The
        // `e.g. bootloader_locked, rollback_index` comment on DowngradeInfo
        // lists two *examples*, not two required entries.
        EXPECT(r.downgrade.blocked_by.size() == 1);
        EXPECT(r.downgrade.blocked_by[0] == "rollback_index");
        EXPECT(!r.refs.empty());
    }
    EXPECT(found_mali);

    // Finding JSON round-trip.
    Finding f;
    f.rule_id = "CVE-2022-38181";
    f.title = "Arm Mali GPU kbase UAF";
    f.component = "gpu";
    f.exploit.status = ExploitStatus::WEAPONIZED_PUBLIC;
    f.exploit.gives = ExploitGives::KERNEL_RW;
    f.verdict = Verdict::AVAILABLE_NOW;
    f.reasoning = "SPL 2022-07-05 in vuln range (<2022-11-05); "
                  "mali_driver r32p1 in vuln range (<r40p0)";
    f.matched_facts.push_back({ "gpu.mali_driver", "r32p1", "in [0, r40p0)" });
    f.matched_facts.push_back({ "spl", "2022-07-05", "in [0, 2022-11-05)" });
    f.refs.push_back("https://nvd.nist.gov/vuln/detail/CVE-2022-38181");

    auto findings_json = findings_to_json({ f }, false);
    auto findings_back = findings_from_json_str(findings_json);
    EXPECT(findings_back.size() == 1);
    EXPECT(findings_back[0].verdict == Verdict::AVAILABLE_NOW);
    EXPECT(findings_back[0].exploit.status == ExploitStatus::WEAPONIZED_PUBLIC);
    EXPECT(findings_back[0].matched_facts.size() == 2);
    EXPECT(!verdict_glyph(Verdict::AVAILABLE_NOW).empty());

    if (g_failures == 0) {
        std::cout << "OK: all core smoke checks passed (" << rules.size() << " rule(s) loaded)\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
