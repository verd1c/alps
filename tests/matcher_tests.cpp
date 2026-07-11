// Matcher tests. Runs the whole rule KB against the Pixel-6
// fixtures and asserts the shape of the resulting Findings and their verdicts.

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "alps/core/device_facts.hpp"
#include "alps/core/rule.hpp"
#include "alps/engine/matcher.hpp"

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
    const std::string root = (argc > 1) ? argv[1] : ".";
    using namespace alps::core;
    using namespace alps::engine;

    const auto rules = load_rules_dir(root + "/rules");
    EXPECT(!rules.empty());

    // Vulnerable device fires the Mali rule.
    const auto vuln
        = DeviceFacts::from_json_str(slurp(root + "/tests/fixtures/pixel6_july2022.json"));
    const auto mr_v = match_rules(rules, vuln);
    EXPECT(mr_v.errors.empty());
    EXPECT(mr_v.findings.size() >= 1);

    bool saw_mali = false;
    for (const auto& f : mr_v.findings) {
        if (f.rule_id == "CVE-2022-38181") {
            saw_mali = true;
            EXPECT(f.component == "gpu");
            EXPECT(f.exploit.status == ExploitStatus::WEAPONIZED_PUBLIC);
            EXPECT(f.matched_facts.size() == 2);
            // First matched fact should be gpu.mali_driver, second spl (rule order).
            EXPECT(f.matched_facts[0].field == "gpu.mali_driver");
            EXPECT(f.matched_facts[0].observed_value == "r32p1");
            EXPECT(f.matched_facts[0].reason.find("r40p0") != std::string::npos);
            EXPECT(f.matched_facts[1].field == "spl");
            EXPECT(f.matched_facts[1].observed_value == "2022-07-05");
            EXPECT(f.matched_facts[1].reason.find("2022-11-05") != std::string::npos);
            EXPECT(!f.refs.empty());
        }
    }
    EXPECT(saw_mali);

    // Vulnerable Pixel 6 + weaponized_public rule yields AVAILABLE_NOW.
    for (const auto& f : mr_v.findings) {
        if (f.rule_id == "CVE-2022-38181") {
            EXPECT(f.verdict == Verdict::AVAILABLE_NOW);
            EXPECT(f.reasoning.find("public") != std::string::npos);
        }
    }

    // Patched + locked yields UNREACHABLE.
    const auto patched_locked
        = DeviceFacts::from_json_str(slurp(root + "/tests/fixtures/pixel6_patched.json"));
    const auto mr_pl = match_rules(rules, patched_locked);
    EXPECT(mr_pl.errors.empty());

    bool saw_unreachable = false;
    for (const auto& f : mr_pl.findings) {
        if (f.rule_id == "CVE-2022-38181") {
            saw_unreachable = true;
            EXPECT(f.verdict == Verdict::UNREACHABLE);
            EXPECT(f.reasoning.find("bootloader_locked") != std::string::npos
                || f.reasoning.find("rollback_index=3") != std::string::npos);
            // notes[] must name at least one blocker.
            bool any_blocker_note = false;
            for (const auto& n : f.notes) {
                if (n.find("blocker:") != std::string::npos) {
                    any_blocker_note = true;
                    break;
                }
            }
            EXPECT(any_blocker_note);
        }
    }
    EXPECT(saw_unreachable);

    // Patched + UNLOCKED yields VIA_DOWNGRADE.
    const auto patched_unlocked
        = DeviceFacts::from_json_str(slurp(root + "/tests/fixtures/pixel6_unlocked_patched.json"));
    const auto mr_pu = match_rules(rules, patched_unlocked);
    EXPECT(mr_pu.errors.empty());

    bool saw_downgrade = false;
    for (const auto& f : mr_pu.findings) {
        if (f.rule_id == "CVE-2022-38181") {
            saw_downgrade = true;
            EXPECT(f.verdict == Verdict::VIA_DOWNGRADE);
            EXPECT(f.reasoning.find("downgrade") != std::string::npos);
        }
    }
    EXPECT(saw_downgrade);

    if (g_failures == 0) {
        std::cout << "OK: all matcher tests passed\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
