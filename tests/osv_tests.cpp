// OSV importer tests.

#include <iostream>
#include <string>

#include "alps/osv/import.hpp"

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":" << __LINE__ << "\n";        \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

} // namespace

int main()
{
    using namespace alps::core;
    using namespace alps::osv;

    // Minimal but realistic OSV Android entry.
    const std::string sample = R"({
        "id": "ASB-A-123456",
        "aliases": ["CVE-2022-38181"],
        "summary": "Arm Mali GPU kernel driver use-after-free",
        "details": "A memory corruption issue was addressed in the November 2022 SPL.",
        "affected": [{
            "package": { "ecosystem": "Android", "name": "platform/frameworks/base" },
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2022-11-01"}]
            }]
        }],
        "references": [
            {"type": "ADVISORY", "url": "https://source.android.com/docs/security/bulletin/2022-11-01"},
            {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-38181"}
        ]
    })";

    const auto rule = rule_from_osv_json(sample);
    EXPECT(rule.id == "CVE-2022-38181"); // aliased CVE wins over ASB id
    EXPECT(rule.title == "Arm Mali GPU kernel driver use-after-free");
    EXPECT(rule.component == "aosp");
    EXPECT(rule.rule_class == RuleClass::LPE);
    EXPECT(rule.affected.size() == 1);
    EXPECT(rule.affected[0].field == "spl");
    EXPECT(rule.affected[0].type == ComparatorType::SPL_DATE);
    EXPECT(rule.affected[0].events.size() == 2);
    EXPECT(rule.affected[0].events[0].introduced.value_or("") == "0");
    EXPECT(rule.affected[0].events[1].fixed.value_or("") == "2022-11-01");
    EXPECT(rule.exploit.status == ExploitStatus::CVE_NO_POC);
    EXPECT(rule.refs.size() == 2);

    // Round-trip through YAML into the rules parser produces an equivalent rule.
    const auto yaml = rule_to_yaml(rule);
    EXPECT(yaml.find("id: \"CVE-2022-38181\"") != std::string::npos);
    EXPECT(yaml.find("field: spl") != std::string::npos);
    EXPECT(yaml.find("SPL_DATE") != std::string::npos);
    EXPECT(yaml.find("bootloader_locked") != std::string::npos);

    const auto reparsed = Rule::from_yaml_str(yaml);
    EXPECT(reparsed.id == rule.id);
    EXPECT(reparsed.affected.size() == 1);
    EXPECT(reparsed.affected[0].events.size() == 2);
    EXPECT(reparsed.exploit.status == ExploitStatus::CVE_NO_POC);
    EXPECT(reparsed.refs.size() == 2);

    if (g_failures == 0) {
        std::cout << "OK: all OSV tests passed\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
