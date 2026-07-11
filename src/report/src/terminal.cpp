// Terminal reporter:
//   * Two-line-per-finding: <id, title> on line 1, actionable takeaway on
//     line 2. The takeaway answers "what do I do about this?", encoded per
//     verdict:
//        AVAILABLE_NOW      "targets <device>"  |  "portable PoC"
//        VIA_DOWNGRADE      "downgrade to <SPL cutoff> (no blockers)"
//        POC_NEEDS_PORTING  "port from <device list>"
//        RESEARCH_LEAD      "matches <field> <observed> in <range>"
//        UNREACHABLE        "downgrade to <cutoff> blocked by <blockers>"
//   * Section headers name the intent, not the tautology ("AVAILABLE NOW",
//     "PoC NEEDS PORTING", ...). A summary line up top gives a bird's-eye
//     count.
//   * Verbose (-v) keeps the full reasoning and refs.

#include "alps/report/reporter.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace alps::report {

namespace {

    using alps::core::Finding;
    using alps::core::Verdict;

    // Most-actionable first.
    constexpr std::array<Verdict, 5> kOrder = {
        Verdict::AVAILABLE_NOW,
        Verdict::VIA_DOWNGRADE,
        Verdict::POC_NEEDS_PORTING,
        Verdict::RESEARCH_LEAD,
        Verdict::UNREACHABLE,
    };

    struct SectionMeta {
        const char* heading;
        const char* subtitle;
    };

    SectionMeta section_of(Verdict v)
    {
        switch (v) {
        case Verdict::AVAILABLE_NOW:
            return { "AVAILABLE NOW", "download, compile, run" };
        case Verdict::VIA_DOWNGRADE:
            return { "REACHABLE VIA DOWNGRADE", "flash older firmware to re-expose" };
        case Verdict::POC_NEEDS_PORTING:
            return { "PoC NEEDS PORTING", "public exploit exists for a different device" };
        case Verdict::RESEARCH_LEAD:
            return { "RESEARCH LEAD", "CVE applies, no public PoC documented" };
        case Verdict::UNREACHABLE:
            return { "UNREACHABLE", "patched here and downgrade is blocked" };
        }
        return { "?", "" };
    }

    // ANSI helpers.
    struct Ansi {
        bool on;
        std::string wrap(std::string_view s, std::string_view code) const
        {
            if (!on)
                return std::string(s);
            std::string out;
            out.reserve(s.size() + code.size() + 6);
            out.append("\x1b[").append(code).append("m").append(s).append("\x1b[0m");
            return out;
        }
        std::string bold(std::string_view s) const { return wrap(s, "1"); }
        std::string dim(std::string_view s) const { return wrap(s, "2"); }
        std::string red(std::string_view s) const { return wrap(s, "31"); }
        std::string green(std::string_view s) const { return wrap(s, "32"); }
        std::string yellow(std::string_view s) const { return wrap(s, "33"); }
        std::string blue(std::string_view s) const { return wrap(s, "34"); }
        std::string cyan(std::string_view s) const { return wrap(s, "36"); }
        std::string grey(std::string_view s) const { return wrap(s, "90"); }
        std::string white_bold(std::string_view s) const { return wrap(s, "1;97"); }
    };

    std::string verdict_color(const Ansi& a, Verdict v, std::string_view s)
    {
        switch (v) {
        case Verdict::AVAILABLE_NOW:
            return a.red(s);
        case Verdict::VIA_DOWNGRADE:
            return a.yellow(s);
        case Verdict::POC_NEEDS_PORTING:
            return a.blue(s);
        case Verdict::RESEARCH_LEAD:
            return a.grey(s);
        case Verdict::UNREACHABLE:
            return a.green(s);
        }
        return std::string(s);
    }

    std::string abbrev(const std::string& s, std::size_t max_len)
    {
        if (s.size() <= max_len)
            return s;
        return s.substr(0, max_len - 1) + "...";
    }

    // Left-pad the given number to a fixed width.
    std::string pad_right(std::string_view s, std::size_t width)
    {
        if (s.size() >= width)
            return std::string(s);
        return std::string(s) + std::string(width - s.size(), ' ');
    }

    // Takeaway derivation.

    std::string chip(const Finding& f)
    {
        return alps::core::exploit_status_to_string(f.exploit.status) + " · "
            + alps::core::exploit_gives_to_string(f.exploit.gives);
    }

    std::string join_csv(const std::vector<std::string>& xs)
    {
        std::string out;
        for (std::size_t i = 0; i < xs.size(); ++i) {
            if (i)
                out += ", ";
            out += xs[i];
        }
        return out;
    }

    // A pretty tag naming which device the PoC targets vs the current device.
    std::string poc_scope(const Finding& f, const std::string& dev)
    {
        const auto& t = f.exploit.poc_targets;
        if (t.empty())
            return "portable PoC";
        const bool in_targets = !dev.empty() && std::find(t.begin(), t.end(), dev) != t.end();
        if (in_targets) {
            return "targets " + dev + " \xE2\x9C\x93"; // check mark
        }
        return "port from " + join_csv(t);
    }

    // Extract "downgrade_target: <target>" from notes[] (matcher wrote it there).
    std::optional<std::string> extract_downgrade_target(const Finding& f)
    {
        constexpr std::string_view kPrefix = "downgrade_target: ";
        for (const auto& n : f.notes) {
            if (n.size() > kPrefix.size() && n.rfind(kPrefix, 0) == 0) {
                return n.substr(kPrefix.size());
            }
        }
        return std::nullopt;
    }

    // Extract "blocker: <name> (<detail>)" entries and re-format compactly.
    std::vector<std::string> extract_blockers(const Finding& f)
    {
        constexpr std::string_view kPrefix = "blocker: ";
        std::vector<std::string> out;
        for (const auto& n : f.notes) {
            if (n.size() > kPrefix.size() && n.rfind(kPrefix, 0) == 0) {
                // Note text is "blocker: <name> (<detail>)". Emit "<detail>".
                const auto paren = n.find('(');
                if (paren != std::string::npos && n.back() == ')') {
                    out.push_back(n.substr(paren + 1, n.size() - paren - 2));
                } else {
                    out.push_back(n.substr(kPrefix.size()));
                }
            }
        }
        return out;
    }

    // A compact "matches <field> <observed> in <range>" summary from the first
    // matched fact; used for RESEARCH_LEAD / AVAILABLE_NOW rows to hint at
    // which condition fired.
    std::string matched_summary(const Finding& f)
    {
        if (f.matched_facts.empty())
            return {};
        const auto& mf = f.matched_facts.front();
        // reason typically looks like "5.10.81 in [0, 5.10.108)"; strip the
        // observed prefix to compact.
        const auto observed = abbrev(mf.observed_value, 28);
        std::string reason = mf.reason;
        // Drop leading "<observed> " prefix if present.
        if (!mf.observed_value.empty() && reason.rfind(mf.observed_value, 0) == 0) {
            reason = reason.substr(mf.observed_value.size());
            while (!reason.empty() && (reason.front() == ' ' || reason.front() == '\t')) {
                reason.erase(reason.begin());
            }
        }
        return mf.field + " " + observed + " " + reason;
    }

    // The per-finding "actionable takeaway": the second line under the CVE row.
    // Kept short: one concept per verdict, plus the status chip. Matched
    // facts, references, and full reasoning live in --verbose.
    std::string takeaway(const Finding& f, const std::string& dev)
    {
        switch (f.verdict) {
        case Verdict::AVAILABLE_NOW:
            return chip(f) + " · " + poc_scope(f, dev);
        case Verdict::VIA_DOWNGRADE: {
            const auto target = extract_downgrade_target(f).value_or("any older SPL");
            return chip(f) + " · downgrade to " + target + " (no blockers)";
        }
        case Verdict::POC_NEEDS_PORTING:
            return chip(f) + " · " + poc_scope(f, dev);
        case Verdict::RESEARCH_LEAD: {
            std::string t = chip(f);
            if (!f.matched_facts.empty()) {
                t += " · matches " + matched_summary(f);
            }
            return t;
        }
        case Verdict::UNREACHABLE: {
            const auto target = extract_downgrade_target(f).value_or("older SPL");
            const auto blockers = extract_blockers(f);
            std::string t = chip(f) + " · downgrade to " + target;
            if (blockers.empty()) {
                t += " (unreachable)";
            } else {
                t += " blocked by " + join_csv(blockers);
            }
            return t;
        }
        }
        return chip(f);
    }

    // Header / summary.

    std::string device_line(const Ansi& a, const alps::core::DeviceFacts& f)
    {
        std::string s;
        s += a.white_bold(f.manufacturer.value_or("?") + " " + f.model.value_or("?"));
        s += " (" + f.device.value_or("?") + ")  ·  ";
        s += "Android " + f.android_release.value_or("?");
        s += "  ·  SPL " + f.spl.value_or("?");
        if (f.vendor_spl && f.vendor_spl != f.spl) {
            s += " (vendor " + *f.vendor_spl + ")";
        }
        return s;
    }

    std::string hardware_line(const Ansi& a, const alps::core::DeviceFacts& f)
    {
        std::string s;
        if (f.gpu.vendor) {
            s += *f.gpu.vendor;
            if (f.gpu.mali_driver)
                s += " " + *f.gpu.mali_driver;
            if (f.gpu.adreno_driver)
                s += " " + *f.gpu.adreno_driver;
            if (f.gpu.mali_arch)
                s += " (" + *f.gpu.mali_arch + ")";
        }
        if (f.kernel_version) {
            if (!s.empty())
                s += "  ·  ";
            const auto& k = *f.kernel_version;
            // Truncate to the numeric prefix plus the `-androidX-Y` ACK tag if
            // present, dropping the build-hash suffix that follows. Never leave
            // a dangling '-' at the end.
            std::size_t cut = k.size();
            if (auto pos = k.find("-android"); pos != std::string::npos) {
                std::size_t end = pos + std::string("-android").size();
                while (end < k.size() && std::isdigit(static_cast<unsigned char>(k[end])))
                    ++end;
                if (end < k.size() && k[end] == '-') {
                    std::size_t after = end + 1;
                    if (after < k.size() && std::isdigit(static_cast<unsigned char>(k[after]))) {
                        end = after;
                        while (end < k.size() && std::isdigit(static_cast<unsigned char>(k[end])))
                            ++end;
                    }
                }
                cut = end;
            }
            while (cut > 0 && k[cut - 1] == '-')
                --cut;
            s += "kernel " + k.substr(0, cut);
        }
        // Bootloader state, verified-boot, rollback index, SELinux.
        std::string boot;
        if (f.bootloader_locked)
            boot += (*f.bootloader_locked ? "locked" : "unlocked");
        if (f.verified_boot_state) {
            if (!boot.empty())
                boot += "/";
            boot += "verified=" + *f.verified_boot_state;
        }
        if (f.rollback_index && *f.rollback_index > 0) {
            if (!boot.empty())
                boot += "/";
            boot += "rollback=" + std::to_string(*f.rollback_index);
        }
        if (!boot.empty()) {
            if (!s.empty())
                s += "  ·  ";
            s += boot;
        }
        if (f.selinux_mode) {
            if (!s.empty())
                s += "  ·  ";
            s += "SELinux " + *f.selinux_mode;
        }
        (void)a;
        return s;
    }

    std::string summary_line(
        const Ansi& a, const std::map<Verdict, std::vector<const Finding*>>& groups)
    {
        // Emit counts for every verdict, in order, with the appropriate colour.
        std::string s = a.dim("Summary: ");
        bool first = true;
        for (const auto v : kOrder) {
            if (!first)
                s += "   ";
            first = false;
            auto it = groups.find(v);
            const std::size_t n = (it == groups.end()) ? 0 : it->second.size();
            s += verdict_color(a, v, alps::core::verdict_glyph(v) + " " + std::to_string(n));
        }
        return s;
    }

    // Compact mode.

    void write_compact(
        std::ostream& os, const Ansi& a, const Report& r, const std::string& device_code)
    {
        std::map<Verdict, std::vector<const Finding*>> groups;
        for (const auto& f : r.findings)
            groups[f.verdict].push_back(&f);

        // Column widths for the two-line layout. We keep the CVE id column
        // narrow (max 14) and let the title wrap by truncation.
        std::size_t id_w = 0;
        for (const auto& f : r.findings)
            id_w = std::max(id_w, f.rule_id.size());
        if (id_w < 12)
            id_w = 12;
        if (id_w > 16)
            id_w = 16; // never longer than "CVE-XXXX-YYYYY"

        os << summary_line(a, groups) << "\n\n";

        if (r.findings.empty()) {
            os << a.dim("No candidate findings.") << "\n";
            return;
        }

        for (const auto v : kOrder) {
            const auto sect = section_of(v);
            auto it = groups.find(v);
            const std::size_t n = (it == groups.end()) ? 0 : it->second.size();

            // Section header: colored glyph + heading + count + subtitle.
            std::string head = verdict_color(a, v, alps::core::verdict_glyph(v)) + "  "
                + verdict_color(a, v, a.bold(sect.heading)) + a.dim("  (" + std::to_string(n) + ")")
                + a.dim("   " + std::string(sect.subtitle));
            os << head << "\n";

            if (n == 0) {
                os << "   " << a.dim("(none)") << "\n\n";
                continue;
            }
            os << "\n";

            const std::string indent(3 + id_w + 2, ' ');
            for (const auto* f : it->second) {
                const auto short_title = abbrev(f->title, 60);
                os << "   " << a.bold(pad_right(f->rule_id, id_w)) << "  " << short_title << "\n";
                os << indent << a.dim(takeaway(*f, device_code)) << "\n";
            }
            os << "\n";
        }
        os << a.dim("Run with -v / --verbose for full reasoning, matched facts, and references.")
           << "\n";
    }

    // Verbose mode.

    void write_verbose(
        std::ostream& os, const Ansi& a, const Report& r, const std::string& device_code)
    {
        std::map<Verdict, std::vector<const Finding*>> groups;
        for (const auto& f : r.findings)
            groups[f.verdict].push_back(&f);

        if (r.findings.empty()) {
            os << a.dim("No candidate findings.") << "\n";
            return;
        }

        for (const auto v : kOrder) {
            const auto sect = section_of(v);
            auto it = groups.find(v);
            const std::size_t n = (it == groups.end()) ? 0 : it->second.size();

            os << verdict_color(a, v, alps::core::verdict_glyph(v)) << "  "
               << verdict_color(a, v, a.bold(sect.heading))
               << a.dim("  (" + std::to_string(n) + ")   " + std::string(sect.subtitle)) << "\n\n";

            if (it == groups.end())
                continue;
            for (const auto* f : it->second) {
                os << "  " << a.bold(f->rule_id) << "  " << f->title << "\n";
                os << "    " << a.dim(takeaway(*f, device_code)) << "\n";
                if (!f->reasoning.empty()) {
                    os << "    " << f->reasoning << "\n";
                }
                for (const auto& mf : f->matched_facts) {
                    const auto observed = abbrev(mf.observed_value, 40);
                    std::string reason = mf.reason;
                    if (!mf.observed_value.empty() && reason.rfind(mf.observed_value, 0) == 0) {
                        reason = reason.substr(mf.observed_value.size());
                        while (
                            !reason.empty() && (reason.front() == ' ' || reason.front() == '\t')) {
                            reason.erase(reason.begin());
                        }
                    }
                    os << "      " << a.cyan(mf.field) << " = " << observed << "   "
                       << a.dim(reason) << "\n";
                }
                for (const auto& note : f->notes) {
                    os << "      " << a.yellow("· " + note) << "\n";
                }
                for (const auto& ref : f->refs) {
                    os << "      " << a.grey("ref: " + ref) << "\n";
                }
                os << "\n";
            }
        }
    }

} // namespace

void write_terminal(std::ostream& os, const Report& r, const TermOpts& opts)
{
    const Ansi a { opts.ansi };

    os << a.dim("ALPS report. Use only on devices you own or are authorized to test.") << "\n\n";

    std::string device_code;
    if (r.facts) {
        device_code = r.facts->device.value_or("");
        // Root warning: bright, hard to miss. If a root-management framework
        // is present, LPE triage is largely moot.
        if (r.facts->root_indicator) {
            os << a.red(a.bold("!! ROOT DETECTED: " + *r.facts->root_indicator
                + "; LPE triage is likely moot on this device"))
               << "\n\n";
        }
        os << device_line(a, *r.facts) << "\n";
        os << hardware_line(a, *r.facts) << "\n\n";
    }

    if (!r.errors.empty()) {
        os << a.red("Rule KB errors (" + std::to_string(r.errors.size()) + "):") << "\n";
        for (const auto& e : r.errors) {
            os << "  " << (e.rule_id.empty() ? "?" : e.rule_id) << ": " << e.message << "\n";
        }
        os << "\n";
    }

    if (opts.verbose) {
        write_verbose(os, a, r, device_code);
    } else {
        write_compact(os, a, r, device_code);
    }
}

} // namespace alps::report
