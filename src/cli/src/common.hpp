#pragma once

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "alps/core/builtin_rules.hpp"
#include "alps/core/rule.hpp"

namespace alps::cli {

inline std::string slurp_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("cannot open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline void write_to(std::ostream& os, const std::string& contents)
{
    os << contents;
    if (!contents.empty() && contents.back() != '\n')
        os << '\n';
}

inline void write_stdout_or_file(const std::string& path, const std::string& contents)
{
    if (path.empty() || path == "-") {
        std::cout << contents;
        if (!contents.empty() && contents.back() != '\n')
            std::cout << '\n';
        return;
    }
    std::ofstream out(path);
    if (!out)
        throw std::runtime_error("cannot open " + path + " for write");
    out << contents;
    if (!contents.empty() && contents.back() != '\n')
        out << '\n';
}

// Banner shown on the first line of every state-changing CLI invocation.
inline const char* defensive_banner()
{
    return "ALPS. Use only on devices you own or are authorized to test.\n";
}

// Resolve --color=auto|always|never to a boolean. `is_tty_fd` is 1 for
// stdout; passed in so tests can override. When color_mode is "auto"
// (default) we enable colors iff stdout is a real TTY.
inline bool resolve_color(const std::string& color_mode, bool is_tty)
{
    if (color_mode == "always")
        return true;
    if (color_mode == "never")
        return false;
    return is_tty; // "auto"
}

// Rule source resolution: empty --rules argument uses the built-in KB
// (embedded into the binary at build time). Non-empty loads from that
// directory instead (KB dev / custom KB). Emit a one-line "(using: ...)"
// note on stderr so the user always knows which KB is in play.
inline std::vector<alps::core::Rule> load_rules_default_builtin(const std::string& dir)
{
    if (dir.empty()) {
        auto rules = alps::core::load_builtin_rules();
        std::cerr << "(using built-in KB: " << rules.size() << " rule(s))\n";
        return rules;
    }
    auto rules = alps::core::load_rules_dir(dir);
    std::cerr << "(using KB directory " << dir << ": " << rules.size() << " rule(s))\n";
    return rules;
}

// Subcommand entry points implemented in their own translation units.
#ifdef ALPS_HAVE_COLLECTOR
int cmd_scan(const std::string& rules_dir, const std::string& format, bool verbose,
    const std::string& color_mode);
int cmd_collect(const std::string& output_path);
#endif
int cmd_match(
    const std::string& facts_path, const std::string& rules_dir, const std::string& output_path);
int cmd_report(const std::string& findings_path, const std::string& facts_path,
    const std::string& format, bool verbose, const std::string& color_mode);
int cmd_rules_lint(const std::string& rules_dir);
int cmd_rules_list(const std::string& rules_dir, const std::string& filter_component,
    const std::string& filter_class);
int cmd_update(const std::string& from_dir, const std::string& out_dir);
#ifdef ALPS_HAVE_TUI
int cmd_ui(const std::string& facts_path, const std::string& rules_dir, bool no_alt_screen);
#endif

// Exploit runner (docs/EXPLOIT.md).
struct ExploitOpts {
    std::string cve_id;
    std::string rules_dir;
    std::string facts_path; // if empty and !on-device use --serial
    std::string adb_serial; // "" = pick unique attached device
    bool authorized = false;
    bool force_port = false;
    bool force_downgrade_path = false;
    bool allow_custom_build = false;
    bool skip_tree_hash = false;
    bool also_local_cleanup = false;
    bool no_color = false;
    bool acknowledge_manual = false;
};

int cmd_exploit_list(const ExploitOpts& o);
int cmd_exploit_show(const ExploitOpts& o);
int cmd_exploit_prereq(const ExploitOpts& o);
int cmd_exploit_fetch(const ExploitOpts& o);
int cmd_exploit_build(const ExploitOpts& o);
int cmd_exploit_deploy(const ExploitOpts& o);
int cmd_exploit_run(const ExploitOpts& o);
int cmd_exploit_cleanup(const ExploitOpts& o);
int cmd_exploit_go(const ExploitOpts& o, bool cleanup_after);
int cmd_exploit_audit(int limit);

} // namespace alps::cli
