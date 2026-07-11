#include "alps/report/reporter.hpp"

#include <array>
#include <map>
#include <string>
#include <vector>

namespace alps::report {

namespace {

    using alps::core::Finding;
    using alps::core::Verdict;

    constexpr std::array<Verdict, 5> kOrder = {
        Verdict::AVAILABLE_NOW,
        Verdict::VIA_DOWNGRADE,
        Verdict::POC_NEEDS_PORTING,
        Verdict::RESEARCH_LEAD,
        Verdict::UNREACHABLE,
    };

    const char* verdict_heading(Verdict v)
    {
        switch (v) {
        case Verdict::AVAILABLE_NOW:
            return "Available now";
        case Verdict::VIA_DOWNGRADE:
            return "Reachable via downgrade";
        case Verdict::POC_NEEDS_PORTING:
            return "PoC needs porting";
        case Verdict::RESEARCH_LEAD:
            return "Research leads";
        case Verdict::UNREACHABLE:
            return "Not currently reachable";
        }
        return "?";
    }

} // namespace

void write_markdown(std::ostream& os, const Report& r)
{
    os << "# ALPS report\n\n"
       << "> Use only on devices you own or are authorized to test.\n\n";

    if (r.facts) {
        const auto& f = *r.facts;
        os << "## Device\n\n";
        os << "- Model: **" << f.manufacturer.value_or("?") << " " << f.model.value_or("?")
           << "** (" << f.device.value_or("?") << ")\n";
        os << "- Android release: " << f.android_release.value_or("?") << "\n";
        os << "- SPL: " << f.spl.value_or("?");
        if (f.vendor_spl && f.vendor_spl != f.spl)
            os << " (vendor " << *f.vendor_spl << ")";
        os << "\n";
        if (f.kernel_version)
            os << "- Kernel: `" << *f.kernel_version << "`\n";
        if (f.gpu.vendor) {
            os << "- GPU: " << *f.gpu.vendor;
            if (f.gpu.mali_driver)
                os << " (driver " << *f.gpu.mali_driver << ")";
            if (f.gpu.adreno_driver)
                os << " (driver " << *f.gpu.adreno_driver << ")";
            os << "\n";
        }
        os << "- Verified boot: " << f.verified_boot_state.value_or("?")
           << " · Bootloader locked: " << (f.bootloader_locked.value_or(false) ? "yes" : "no");
        if (f.rollback_index)
            os << " · rollback_index=" << *f.rollback_index;
        os << "\n- SELinux: " << f.selinux_mode.value_or("?") << "\n\n";
    }

    if (!r.errors.empty()) {
        os << "## Rule KB errors\n\n";
        for (const auto& e : r.errors) {
            os << "- **" << (e.rule_id.empty() ? "?" : e.rule_id) << "**: " << e.message << "\n";
        }
        os << "\n";
    }

    std::map<Verdict, std::vector<const Finding*>> groups;
    for (const auto& f : r.findings)
        groups[f.verdict].push_back(&f);

    os << "## Findings\n\n";
    if (r.findings.empty()) {
        os << "_No candidate findings._\n";
        return;
    }

    for (const auto v : kOrder) {
        auto it = groups.find(v);
        if (it == groups.end() || it->second.empty())
            continue;
        os << "### " << alps::core::verdict_glyph(v) << " " << verdict_heading(v) << " ("
           << it->second.size() << ")\n\n";
        for (const auto* f : it->second) {
            os << "#### `" << f->rule_id << "`: " << f->title << "\n\n";
            os << "- Component: **" << f->component << "**\n";
            os << "- Exploit status: `" << alps::core::exploit_status_to_string(f->exploit.status)
               << "` · gives `" << alps::core::exploit_gives_to_string(f->exploit.gives) << "`\n";
            if (!f->reasoning.empty()) {
                os << "- Reasoning: " << f->reasoning << "\n";
            }
            if (!f->matched_facts.empty()) {
                os << "- Matched facts:\n";
                for (const auto& mf : f->matched_facts) {
                    os << "    - `" << mf.field << "` = `" << mf.observed_value << "`: "
                       << mf.reason << "\n";
                }
            }
            if (!f->notes.empty()) {
                os << "- Notes:\n";
                for (const auto& n : f->notes)
                    os << "    - " << n << "\n";
            }
            if (!f->refs.empty()) {
                os << "- References:\n";
                for (const auto& ref : f->refs)
                    os << "    - <" << ref << ">\n";
            }
            os << "\n";
        }
    }
}

} // namespace alps::report
