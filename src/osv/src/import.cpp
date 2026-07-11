#include "alps/osv/import.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using nlohmann::json;

namespace alps::osv {

namespace {

    // If an OSV entry aliases a CVE, prefer that as the rule id. Otherwise use
    // the primary id (ASB-A-..., GHSA-..., etc.) so we still get a stable filename.
    std::string pick_id(const json& j)
    {
        if (auto it = j.find("aliases"); it != j.end() && it->is_array()) {
            for (const auto& a : *it) {
                if (!a.is_string())
                    continue;
                const auto s = a.get<std::string>();
                if (s.rfind("CVE-", 0) == 0)
                    return s;
            }
        }
        if (auto it = j.find("id"); it != j.end() && it->is_string()) {
            return it->get<std::string>();
        }
        throw std::runtime_error("OSV entry missing id");
    }

    std::string infer_component(const json& affected_arr)
    {
        // Look at the first affected package name; classify by well-known prefixes.
        for (const auto& a : affected_arr) {
            auto pkg = a.find("package");
            if (pkg == a.end())
                continue;
            auto name = pkg->find("name");
            if (name == pkg->end() || !name->is_string())
                continue;
            const auto n = name->get<std::string>();
            if (n.find("kernel") != std::string::npos)
                return "kernel";
            if (n.find("qcom") != std::string::npos)
                return "vendor";
            if (n.find("mali") != std::string::npos)
                return "gpu";
            // AOSP: most Android bulletin entries land under "platform/...".
            return "aosp";
        }
        return "aosp";
    }

} // namespace

alps::core::Rule rule_from_osv_json(const std::string& json_text)
{
    auto j = json::parse(json_text);

    alps::core::Rule r;
    r.id = pick_id(j);
    r.title = j.value("summary", r.id);
    r.rule_class = alps::core::RuleClass::LPE; // OSV Android doesn't classify; best default
    r.description = j.value("details", std::string {});

    const auto* affected_arr = j.contains("affected") ? &j["affected"] : nullptr;
    if (!affected_arr || !affected_arr->is_array()) {
        throw std::runtime_error("OSV entry " + r.id + ": missing affected[]");
    }
    r.component = infer_component(*affected_arr);

    // Collect SPL_DATE events from all Android-ecosystem ranges.
    alps::core::AffectedField spl_af;
    spl_af.field = "spl";
    spl_af.type = alps::core::ComparatorType::SPL_DATE;

    for (const auto& a : *affected_arr) {
        auto pkg = a.find("package");
        if (pkg == a.end())
            continue;
        auto eco = pkg->find("ecosystem");
        if (eco == pkg->end() || !eco->is_string())
            continue;
        if (eco->get<std::string>() != "Android")
            continue;

        auto ranges = a.find("ranges");
        if (ranges == a.end() || !ranges->is_array())
            continue;
        for (const auto& range : *ranges) {
            auto events = range.find("events");
            if (events == range.end() || !events->is_array())
                continue;
            for (const auto& ev : *events) {
                alps::core::AffectedEvent e;
                if (auto v = ev.find("introduced"); v != ev.end() && v->is_string())
                    e.introduced = v->get<std::string>();
                if (auto v = ev.find("fixed"); v != ev.end() && v->is_string())
                    e.fixed = v->get<std::string>();
                if (auto v = ev.find("last_affected"); v != ev.end() && v->is_string())
                    e.last_affected = v->get<std::string>();
                if (auto v = ev.find("limit"); v != ev.end() && v->is_string())
                    e.limit = v->get<std::string>();
                // Skip clearly-empty entries.
                if (!e.introduced && !e.fixed && !e.last_affected && !e.limit)
                    continue;
                spl_af.events.push_back(std::move(e));
            }
        }
    }
    if (spl_af.events.empty()) {
        throw std::runtime_error("OSV entry " + r.id + ": no SPL_DATE events");
    }
    r.affected.push_back(std::move(spl_af));

    r.match = "affected(\"spl\")";

    r.exploit.status = alps::core::ExploitStatus::CVE_NO_POC; // OSV import is metadata-only
    r.exploit.gives = alps::core::ExploitGives::ROOT;

    r.downgrade.min_vulnerable_spl = "0";
    r.downgrade.blocked_by = { "bootloader_locked", "rollback_index" };

    if (auto refs = j.find("references"); refs != j.end() && refs->is_array()) {
        for (const auto& ref : *refs) {
            if (auto u = ref.find("url"); u != ref.end() && u->is_string()) {
                r.refs.push_back(u->get<std::string>());
            }
        }
    }
    return r;
}

std::vector<alps::core::Rule> load_osv_dir(
    const std::string& osv_dir, std::vector<ImportError>& errors_out)
{
    std::vector<alps::core::Rule> out;
    if (!fs::exists(osv_dir)) {
        throw std::runtime_error("osv directory does not exist: " + osv_dir);
    }
    for (const auto& entry : fs::recursive_directory_iterator(osv_dir)) {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() != ".json")
            continue;
        std::ifstream f(entry.path());
        if (!f) {
            errors_out.push_back({ entry.path().string(), "cannot open" });
            continue;
        }
        std::ostringstream ss;
        ss << f.rdbuf();
        try {
            out.push_back(rule_from_osv_json(ss.str()));
        } catch (const std::exception& e) {
            errors_out.push_back({ entry.path().string(), e.what() });
        }
    }
    return out;
}

namespace {

    // Escape a string for a YAML double-quoted scalar. We only ever emit values
    // that come from OSV or the (already-validated) rule schema, so we cover
    // backslash, double-quote, and control chars; no need for full YAML escapes.
    std::string yaml_escape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 2);
        for (char c : s) {
            switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // Drop other control chars silently.
                    out += ' ';
                } else {
                    out += c;
                }
            }
        }
        return out;
    }

} // namespace

std::string rule_to_yaml(const alps::core::Rule& r)
{
    std::ostringstream ss;
    ss << "# Auto-imported from OSV Android ecosystem. Metadata only.\n";
    ss << "id: \"" << yaml_escape(r.id) << "\"\n";
    ss << "title: \"" << yaml_escape(r.title) << "\"\n";
    ss << "component: " << r.component << "\n";
    ss << "class: " << alps::core::rule_class_to_string(r.rule_class) << "\n";
    if (!r.description.empty()) {
        ss << "description: \"" << yaml_escape(r.description) << "\"\n";
    }
    ss << "affected:\n";
    for (const auto& af : r.affected) {
        ss << "  - field: " << af.field << "\n"
           << "    type: " << alps::core::comparator_type_to_string(af.type) << "\n"
           << "    events:\n";
        for (const auto& e : af.events) {
            if (e.introduced)
                ss << "      - introduced: \"" << yaml_escape(*e.introduced) << "\"\n";
            if (e.fixed)
                ss << "      - fixed: \"" << yaml_escape(*e.fixed) << "\"\n";
            if (e.last_affected)
                ss << "      - last_affected: \"" << yaml_escape(*e.last_affected) << "\"\n";
            if (e.limit)
                ss << "      - limit: \"" << yaml_escape(*e.limit) << "\"\n";
        }
    }
    ss << "match: |\n  " << r.match << "\n";
    ss << "exploit:\n"
       << "  status: " << alps::core::exploit_status_to_string(r.exploit.status) << "\n"
       << "  gives: " << alps::core::exploit_gives_to_string(r.exploit.gives) << "\n"
       << "  user_interaction: " << (r.exploit.user_interaction ? "true" : "false") << "\n"
       << "  requires_downgrade: " << (r.exploit.requires_downgrade ? "true" : "false") << "\n";
    if (r.downgrade.min_vulnerable_spl || !r.downgrade.blocked_by.empty()) {
        ss << "downgrade:\n";
        if (r.downgrade.min_vulnerable_spl) {
            ss << "  min_vulnerable_spl: \"" << yaml_escape(*r.downgrade.min_vulnerable_spl)
               << "\"\n";
        }
        if (!r.downgrade.blocked_by.empty()) {
            ss << "  blocked_by: [";
            for (std::size_t i = 0; i < r.downgrade.blocked_by.size(); ++i) {
                if (i)
                    ss << ", ";
                ss << r.downgrade.blocked_by[i];
            }
            ss << "]\n";
        }
    }
    if (!r.refs.empty()) {
        ss << "refs:\n";
        for (const auto& ref : r.refs) {
            ss << "  - \"" << yaml_escape(ref) << "\"\n";
        }
    }
    return ss.str();
}

} // namespace alps::osv
