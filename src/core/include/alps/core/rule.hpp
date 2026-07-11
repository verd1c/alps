// Rule: one CVE per YAML file, git-tracked under rules/. Two-layer model:
//   Layer 1: typed version ranges. No string version compares.
//   Layer 2: a boolean predicate over the whole fact sheet. The
//            `match:` string is stored raw here; the engine parses it.

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace alps::core {

// Layer-1 comparator kinds.
enum class ComparatorType {
    SPL_DATE, // "YYYY-MM-DD"; "0" = -infinity
    SEMVER, // SemVer 2.0.0, no leading v
    KERNEL_VERSION, // maj.min.patch[-extra]; numeric-per-component
    MALI_DRIVER, // r{maj}p{min}
    ADRENO, // Adreno/Qualcomm driver strings
    GENERIC_STRING, // set-membership only, no ordering
};

std::string comparator_type_to_string(ComparatorType t);
ComparatorType parse_comparator_type(std::string_view s);

// A single event in an OSV-style timeline. Exactly one member should have a
// value per event; the loader enforces that during `rules lint`.
struct AffectedEvent {
    std::optional<std::string> introduced;
    std::optional<std::string> fixed;
    std::optional<std::string> last_affected;
    std::optional<std::string> limit;
};

struct AffectedField {
    std::string field; // dotted path into DeviceFacts
    ComparatorType type;
    std::vector<AffectedEvent> events;
};

enum class RuleClass { LPE, TEMPROOT, SANDBOX_ESCAPE };
std::string rule_class_to_string(RuleClass c);
RuleClass parse_rule_class(std::string_view s);

// Exploitability status.
enum class ExploitStatus {
    CVE_NO_POC,
    POC,
    WEAPONIZED_PUBLIC,
    PRIVATE,
};
std::string exploit_status_to_string(ExploitStatus s);
ExploitStatus parse_exploit_status(std::string_view s);

enum class ExploitGives {
    KERNEL_RW,
    ROOT,
    SELINUX_BYPASS,
    SANDBOX_ESCAPE,
};
std::string exploit_gives_to_string(ExploitGives g);
ExploitGives parse_exploit_gives(std::string_view s);

struct ExploitMeta {
    ExploitStatus status = ExploitStatus::CVE_NO_POC;
    ExploitGives gives = ExploitGives::ROOT;
    bool user_interaction = false;
    bool requires_downgrade = false;
    // Device codenames (matches `ro.product.device`) for which the public
    // PoC is known to run out-of-the-box. Empty means the PoC is treated as
    // portable / device-agnostic; when non-empty and the current device is
    // NOT in the list, the verdict downgrades from AVAILABLE_NOW to
    // POC_NEEDS_PORTING.
    std::vector<std::string> poc_targets;
};

// Optional binary confirmation step. A failed verify does not
// silently drop a finding; it downgrades it to a note.
struct VerifyStep {
    std::string type; // "yara"
    std::string rule; // yara rule file, resolved relative to rules/yara/
    std::string path; // path to inspect on the device
};

// Inputs to the downgrade-reachability module.
struct DowngradeInfo {
    std::optional<std::string> min_vulnerable_spl; // "0" = negative infinity
    std::vector<std::string> blocked_by; // e.g. bootloader_locked, rollback_index
};

// Optional exploit-runner block (docs/EXPLOIT.md).
//
// Presence of `exploit_source:` on a rule promotes it from informational-
// only to runnable by `alps exploit`. ALPS itself vendors no exploit
// code: `upstream.commit` pins a public repo, and every artifact ends up
// under the researcher's workspace directory (never in this repo).

struct UpstreamSource {
    std::string kind = "git"; // "git" | "tarball"
    std::string url; // required
    std::string commit; // 40-hex; branches/tags rejected
    std::optional<std::string> subdir;
    std::optional<std::string> tree_sha256; // sha256 of the tar of subdir @ commit
};

// A single declarative prerequisite. `kind` picks a plug-in checker from
// alps_exploit's PrereqRegistry (docs/EXPLOIT.md). `params`
// is opaque per-kind and passed to the checker verbatim.
struct Prerequisite {
    std::string kind; // e.g. "ndk_toolchain"
    std::string description; // optional human label
    nlohmann::json params = nlohmann::json::object();
    bool optional = false; // failing an optional prereq
                           // does not block build/deploy
};

struct BuildRecipe {
    std::string system = "ndk-cmake"; // ndk-cmake | ndk-make | ndk-ninja | custom
    std::string abi = "arm64-v8a";
    std::string platform = "android-31";
    std::string recipe; // script or top-level target
    // Environment variables the researcher may want to plumb through, e.g.
    // MALI_HEADER_PATH pointing at a device-pulled blob. Values may
    // reference prereq artifacts via ${artifact.<key>}; the runner
    // substitutes at build time.
    std::map<std::string, std::string> env;
};

struct DeploySpec {
    std::string workspace = "/data/local/tmp/alps-work/";
    std::vector<std::string> artifacts; // file paths relative to build dir
    std::string entry; // basename to invoke on run
};

struct RunnerGates {
    std::string require_verdict = "available_now"; // available_now | via_downgrade
    std::string require_selinux = "any"; // any | permissive | enforcing
    bool require_root = false;
};

struct ExploitSource {
    UpstreamSource upstream;
    std::vector<Prerequisite> prerequisites;
    BuildRecipe build;
    DeploySpec deploy;
    std::vector<std::string> targets; // device codenames; may override
                                      // exploit.poc_targets
    RunnerGates gates;
};

struct Rule {
    std::string id; // CVE-YYYY-NNNNN or advisory id
    std::string title;
    std::string component; // "gpu", "kernel", "media", ...
    RuleClass rule_class = RuleClass::LPE;
    std::string description;
    std::vector<AffectedField> affected; // Layer 1
    std::string match; // Layer 2 source (parsed by engine)
    std::vector<VerifyStep> verify;
    ExploitMeta exploit;
    DowngradeInfo downgrade;
    std::vector<std::string> refs; // advisories / bulletins / writeups only
    std::optional<ExploitSource> exploit_source; // opt-in runner block

    [[nodiscard]] static Rule from_yaml_file(const std::string& path);
    [[nodiscard]] static Rule from_yaml_str(const std::string& s);
    [[nodiscard]] static Rule from_json(const nlohmann::json& j);
};

// Load every *.yaml / *.yml under `dir` recursively. Throws on the first
// parse error; the CLI's `rules lint` wraps this to report every failure.
[[nodiscard]] std::vector<Rule> load_rules_dir(const std::string& dir);

} // namespace alps::core
