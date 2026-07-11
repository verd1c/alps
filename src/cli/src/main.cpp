// `alps` CLI entry point. Subcommands each live in their own TU under
// src/cli/src/cmd_*.cpp; main.cpp just parses argv with CLI11 and dispatches.

#include <exception>
#include <iostream>
#include <string>

#include <CLI/CLI.hpp>

#include "common.hpp"

int main(int argc, char** argv)
{
    CLI::App app { "ALPS: Android LPE Suite.\n"
                   "Maps CVEs and public exploit availability to a specific device's patch level,\n"
                   "driver versions, and bootloader state; optionally fetches, builds, deploys,\n"
                   "and runs pinned public PoCs on that device. Use only on devices you own or\n"
                   "are authorized to test." };
    app.require_subcommand(1);

    // Defaults that most subcommands share. `rules_dir` is intentionally
    // empty by default; that signals "use the built-in KB embedded in the
    // binary at build time". A non-empty value overrides.
    std::string rules_dir;
    std::string format = "terminal";
    std::string color_mode = "auto";
    bool verbose = false;

#ifdef ALPS_HAVE_COLLECTOR
    // scan.
    auto* scan = app.add_subcommand(
        "scan", "Collect facts on this device, match rules, and print a report.");
    scan->add_option(
        "--rules", rules_dir, "Rule KB directory (default: use built-in KB embedded in binary)");
    scan->add_option("-f,--format", format, "Output format")
        ->check(CLI::IsMember({ "terminal", "markdown", "json" }))
        ->default_val("terminal");
    scan->add_flag("-v,--verbose", verbose,
        "Show reasoning, matched facts, and references (default: compact table)");
    scan->add_option("--color", color_mode, "Colorize output")
        ->check(CLI::IsMember({ "auto", "always", "never" }))
        ->default_val("auto");

    // collect.
    auto* collect = app.add_subcommand(
        "collect", "Collect device facts and emit device_facts.json. Read-only.");
    std::string collect_out;
    collect->add_option("-o,--output", collect_out, "Output file (default: stdout)")
        ->default_val("");
#endif

    // match.
    auto* match = app.add_subcommand(
        "match", "Match rules against a previously-collected device_facts.json.");
    std::string match_facts;
    std::string match_out;
    match->add_option("-f,--facts", match_facts, "Input device_facts.json")->required();
    match->add_option(
        "--rules", rules_dir, "Rule KB directory (default: use built-in KB embedded in binary)");
    match->add_option("-o,--output", match_out, "Output file (default: stdout)")->default_val("");

    // report.
    auto* report
        = app.add_subcommand("report", "Format existing findings JSON as terminal/markdown/json.");
    std::string report_findings;
    std::string report_facts;
    report->add_option("-f,--findings", report_findings, "Input findings.json")->required();
    report->add_option("--facts", report_facts, "Optional device_facts.json for the header");
    report->add_option("--format", format, "Output format")
        ->check(CLI::IsMember({ "terminal", "markdown", "json" }))
        ->default_val("terminal");
    report->add_flag("-v,--verbose", verbose,
        "Show reasoning, matched facts, and references (default: compact table)");
    report->add_option("--color", color_mode, "Colorize output")
        ->check(CLI::IsMember({ "auto", "always", "never" }))
        ->default_val("auto");

    // rules.
    auto* rules = app.add_subcommand("rules", "Rule KB operations")->require_subcommand(1);
    auto* rules_lint = rules->add_subcommand(
        "lint", "Validate every rule (schema, comparators, predicate). Defaults to built-in KB.");
    rules_lint->add_option("--rules", rules_dir, "Rule KB directory (default: built-in KB)");

    auto* rules_list = rules->add_subcommand("list", "Print a compact one-line-per-rule catalog.");
    std::string filter_component;
    std::string filter_class;
    rules_list->add_option("--rules", rules_dir, "Rule KB directory (default: built-in KB)");
    rules_list->add_option(
        "--component", filter_component, "Filter by component (e.g. gpu, kernel)");
    rules_list->add_option(
        "--class", filter_class, "Filter by class (lpe|temproot|sandbox_escape)");

#ifdef ALPS_HAVE_TUI
    // ui.
    auto* ui = app.add_subcommand("ui",
        "Interactive two-pane browser for findings. Requires a TTY; run "
        "via `adb shell -t /data/local/tmp/alps ui`.");
    std::string ui_facts;
    bool no_alt_screen = false;
    ui->add_option(
        "-f,--facts", ui_facts, "Load facts from JSON instead of collecting from this device");
    ui->add_option(
        "--rules", rules_dir, "Rule KB directory (default: built-in KB embedded in binary)");
    ui->add_flag("--no-alt-screen", no_alt_screen,
        "Draw inline instead of using the alt-screen buffer "
        "(useful when the terminal / adb relay drops \\x1b[?1049h)");
#endif

    // update.
    auto* update = app.add_subcommand("update",
        "Import OSV Android ecosystem data into rule YAML. Fetch the dump manually first.");
    std::string osv_from;
    std::string osv_out = "rules/osv";
    update->add_option("--from", osv_from, "OSV JSON directory (already unzipped)");
    update->add_option("--out", osv_out, "Output directory for generated rule YAML")
        ->default_val("rules/osv");

    // exploit.
    // Fetches source from an upstream repo pinned in the rule, builds via NDK,
    // deploys and runs on the target device. Every state-changing verb takes
    // --i-am-authorized-to-test per invocation. docs/EXPLOIT.md.
    auto* exploit
        = app.add_subcommand("exploit",
                 "Fetch / build / deploy / run a rule's public PoC. Every state-changing verb "
                 "requires --i-am-authorized-to-test per invocation. See docs/EXPLOIT.md.")
              ->require_subcommand(1);
    alps::cli::ExploitOpts eo;
    // Every subverb shares the same option bag. We attach --rules to
    // list/show (need rule metadata) and --serial + --i-am-authorized to
    // every state-changing verb.
    auto attach_common = [&](CLI::App* s, bool need_cve, bool state_changing) {
        s->add_option("--rules", eo.rules_dir, "Rule KB directory (default: use built-in KB)");
        if (need_cve) {
            s->add_option("cve", eo.cve_id, "CVE id (e.g. CVE-2022-38181)")->required();
        }
        s->add_option("--facts", eo.facts_path,
            "Use pre-collected device_facts.json instead of live collection "
            "(needed off-device for verdict + codename)");
        s->add_option(
            "--serial", eo.adb_serial, "Target adb serial (default: unique attached device)");
        s->add_flag("--no-color", eo.no_color, "Disable ANSI colors in progress output");
        if (state_changing) {
            s->add_flag("--i-am-authorized-to-test", eo.authorized,
                "REQUIRED: per-invocation authorization statement. "
                "No env var / config file will satisfy this.");
        }
    };

    auto* ex_list = exploit->add_subcommand(
        "list", "List rules with an exploit_source: block, tagged by current-device readiness.");
    attach_common(ex_list, /*need_cve=*/false, /*state_changing=*/false);

    auto* ex_show = exploit->add_subcommand(
        "show", "Show the exploit_source block, prerequisites, and gate status for a CVE.");
    attach_common(ex_show, true, false);

    auto* ex_prereq = exploit->add_subcommand(
        "prereq", "Run every prerequisite check for a CVE. Reports OK / missing / failed.");
    attach_common(ex_prereq, true, true);
    ex_prereq->add_flag("--acknowledge", eo.acknowledge_manual,
        "Mark manual: prerequisites as acknowledged (still records to state)");

    auto* ex_fetch = exploit->add_subcommand(
        "fetch", "Clone the upstream repo at the pinned commit; verify the tree hash.");
    attach_common(ex_fetch, true, true);
    ex_fetch->add_flag("--skip-tree-hash", eo.skip_tree_hash,
        "Continue past a tree_sha256 mismatch (hard-fail otherwise)");

    auto* ex_build = exploit->add_subcommand(
        "build", "Configure and build the fetched source using the rule's build.system.");
    attach_common(ex_build, true, true);
    ex_build->add_flag(
        "--allow-custom-build", eo.allow_custom_build, "Permit build.system=custom recipes");

    auto* ex_deploy = exploit->add_subcommand(
        "deploy", "adb push declared artifacts to the on-device workspace.");
    attach_common(ex_deploy, true, true);
    ex_deploy->add_flag("--force-port", eo.force_port,
        "Attempt anyway when the device codename is not in exploit_source.targets");
    ex_deploy->add_flag("--force-downgrade-path", eo.force_downgrade_path,
        "Attempt anyway when the current verdict is via_downgrade, not available_now");

    auto* ex_run = exploit->add_subcommand(
        "run", "Execute the deployed entry point via `adb shell`; stream output.");
    attach_common(ex_run, true, true);
    ex_run->add_flag("--force-port", eo.force_port);
    ex_run->add_flag("--force-downgrade-path", eo.force_downgrade_path);

    auto* ex_clean = exploit->add_subcommand(
        "cleanup", "Wipe the on-device workspace. Add --local to also delete the host copy.");
    attach_common(ex_clean, true, true);
    ex_clean->add_flag("--local", eo.also_local_cleanup, "Also delete ~/.alps/workspace/<CVE>/");

    // One-shot pipeline: every stage back-to-back, stops at first failure.
    bool go_cleanup_after = false;
    auto* ex_go = exploit->add_subcommand("go",
        "One-shot: prereq -> fetch -> build -> deploy -> run. Stops at the first "
        "failure and reports which stage.");
    attach_common(ex_go, true, true);
    ex_go->add_flag("--force-port", eo.force_port,
        "Attempt anyway when device codename is not in exploit_source.targets");
    ex_go->add_flag("--force-downgrade-path", eo.force_downgrade_path,
        "Attempt anyway when current verdict is via_downgrade, not available_now");
    ex_go->add_flag("--skip-tree-hash", eo.skip_tree_hash, "Continue past a tree_sha256 mismatch");
    ex_go->add_flag(
        "--allow-custom-build", eo.allow_custom_build, "Permit build.system=custom recipes");
    ex_go->add_flag(
        "--cleanup-after", go_cleanup_after, "Wipe the on-device workspace after a successful run");

    int audit_limit = 20;
    auto* ex_audit
        = exploit->add_subcommand("audit", "Tail the JSONL audit log at ~/.alps/audit.log.");
    ex_audit->add_option("--limit", audit_limit, "Number of trailing records")->default_val("20");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    try {
#ifdef ALPS_HAVE_COLLECTOR
        if (*scan)
            return alps::cli::cmd_scan(rules_dir, format, verbose, color_mode);
        if (*collect)
            return alps::cli::cmd_collect(collect_out);
#endif
        if (*match)
            return alps::cli::cmd_match(match_facts, rules_dir, match_out);
        if (*report)
            return alps::cli::cmd_report(
                report_findings, report_facts, format, verbose, color_mode);
        if (*rules_lint)
            return alps::cli::cmd_rules_lint(rules_dir);
        if (*rules_list)
            return alps::cli::cmd_rules_list(rules_dir, filter_component, filter_class);
#ifdef ALPS_HAVE_TUI
        if (*ui)
            return alps::cli::cmd_ui(ui_facts, rules_dir, no_alt_screen);
#endif
        if (*update)
            return alps::cli::cmd_update(osv_from, osv_out);
        if (*ex_list)
            return alps::cli::cmd_exploit_list(eo);
        if (*ex_show)
            return alps::cli::cmd_exploit_show(eo);
        if (*ex_prereq)
            return alps::cli::cmd_exploit_prereq(eo);
        if (*ex_fetch)
            return alps::cli::cmd_exploit_fetch(eo);
        if (*ex_build)
            return alps::cli::cmd_exploit_build(eo);
        if (*ex_deploy)
            return alps::cli::cmd_exploit_deploy(eo);
        if (*ex_run)
            return alps::cli::cmd_exploit_run(eo);
        if (*ex_clean)
            return alps::cli::cmd_exploit_cleanup(eo);
        if (*ex_go)
            return alps::cli::cmd_exploit_go(eo, go_cleanup_after);
        if (*ex_audit)
            return alps::cli::cmd_exploit_audit(audit_limit);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
    // require_subcommand should have caught this.
    std::cerr << "no subcommand selected\n";
    return 2;
}
