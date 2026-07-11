#include "alps/core/rule.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;
using nlohmann::json;

namespace alps::core {

std::string comparator_type_to_string(ComparatorType t)
{
    switch (t) {
    case ComparatorType::SPL_DATE:
        return "SPL_DATE";
    case ComparatorType::SEMVER:
        return "SEMVER";
    case ComparatorType::KERNEL_VERSION:
        return "KERNEL_VERSION";
    case ComparatorType::MALI_DRIVER:
        return "MALI_DRIVER";
    case ComparatorType::ADRENO:
        return "ADRENO";
    case ComparatorType::GENERIC_STRING:
        return "GENERIC_STRING";
    }
    return "UNKNOWN";
}

ComparatorType parse_comparator_type(std::string_view s)
{
    if (s == "SPL_DATE")
        return ComparatorType::SPL_DATE;
    if (s == "SEMVER")
        return ComparatorType::SEMVER;
    if (s == "KERNEL_VERSION")
        return ComparatorType::KERNEL_VERSION;
    if (s == "MALI_DRIVER")
        return ComparatorType::MALI_DRIVER;
    if (s == "ADRENO")
        return ComparatorType::ADRENO;
    if (s == "GENERIC_STRING")
        return ComparatorType::GENERIC_STRING;
    throw std::invalid_argument("unknown comparator type: " + std::string(s));
}

std::string rule_class_to_string(RuleClass c)
{
    switch (c) {
    case RuleClass::LPE:
        return "lpe";
    case RuleClass::TEMPROOT:
        return "temproot";
    case RuleClass::SANDBOX_ESCAPE:
        return "sandbox_escape";
    }
    return "unknown";
}

RuleClass parse_rule_class(std::string_view s)
{
    if (s == "lpe")
        return RuleClass::LPE;
    if (s == "temproot")
        return RuleClass::TEMPROOT;
    if (s == "sandbox_escape")
        return RuleClass::SANDBOX_ESCAPE;
    throw std::invalid_argument("unknown rule class: " + std::string(s));
}

std::string exploit_status_to_string(ExploitStatus s)
{
    switch (s) {
    case ExploitStatus::CVE_NO_POC:
        return "cve_no_poc";
    case ExploitStatus::POC:
        return "poc";
    case ExploitStatus::WEAPONIZED_PUBLIC:
        return "weaponized_public";
    case ExploitStatus::PRIVATE:
        return "private";
    }
    return "unknown";
}

ExploitStatus parse_exploit_status(std::string_view s)
{
    if (s == "cve_no_poc")
        return ExploitStatus::CVE_NO_POC;
    if (s == "poc")
        return ExploitStatus::POC;
    if (s == "weaponized_public")
        return ExploitStatus::WEAPONIZED_PUBLIC;
    if (s == "private")
        return ExploitStatus::PRIVATE;
    throw std::invalid_argument("unknown exploit status: " + std::string(s));
}

std::string exploit_gives_to_string(ExploitGives g)
{
    switch (g) {
    case ExploitGives::KERNEL_RW:
        return "kernel_rw";
    case ExploitGives::ROOT:
        return "root";
    case ExploitGives::SELINUX_BYPASS:
        return "selinux_bypass";
    case ExploitGives::SANDBOX_ESCAPE:
        return "sandbox_escape";
    }
    return "unknown";
}

ExploitGives parse_exploit_gives(std::string_view s)
{
    if (s == "kernel_rw")
        return ExploitGives::KERNEL_RW;
    if (s == "root")
        return ExploitGives::ROOT;
    if (s == "selinux_bypass")
        return ExploitGives::SELINUX_BYPASS;
    if (s == "sandbox_escape")
        return ExploitGives::SANDBOX_ESCAPE;
    throw std::invalid_argument("unknown exploit gives: " + std::string(s));
}

namespace {

    // Convert a yaml-cpp node into a nlohmann::json value. Scalars stay strings
    // except for the exact tokens "true" and "false"; YAML is otherwise ambiguous
    // about types, and our rule fields expect strings (version identifiers, dates,
    // CVE ids) except for the two boolean fields under `exploit:`.
    json yaml_to_json(const YAML::Node& node)
    {
        switch (node.Type()) {
        case YAML::NodeType::Null:
        case YAML::NodeType::Undefined:
            return json {};
        case YAML::NodeType::Scalar: {
            const auto& s = node.Scalar();
            if (s == "true")
                return true;
            if (s == "false")
                return false;
            return s;
        }
        case YAML::NodeType::Sequence: {
            json arr = json::array();
            for (const auto& item : node) {
                arr.push_back(yaml_to_json(item));
            }
            return arr;
        }
        case YAML::NodeType::Map: {
            json obj = json::object();
            for (const auto& kv : node) {
                obj[kv.first.as<std::string>()] = yaml_to_json(kv.second);
            }
            return obj;
        }
        }
        return json {};
    }

    std::string require_string(const json& j, const char* key, const std::string& ctx)
    {
        auto it = j.find(key);
        if (it == j.end() || !it->is_string()) {
            throw std::runtime_error(ctx + ": missing or non-string field '" + key + "'");
        }
        return it->get<std::string>();
    }

    int count_event_kinds(const AffectedEvent& e)
    {
        int n = 0;
        if (e.introduced)
            ++n;
        if (e.fixed)
            ++n;
        if (e.last_affected)
            ++n;
        if (e.limit)
            ++n;
        return n;
    }

} // namespace

Rule Rule::from_json(const json& j)
{
    Rule r;
    const std::string ctx0 = "rule";
    r.id = require_string(j, "id", ctx0);
    r.title = require_string(j, "title", "rule " + r.id);
    r.component = require_string(j, "component", "rule " + r.id);
    r.rule_class = parse_rule_class(require_string(j, "class", "rule " + r.id));

    if (auto it = j.find("description"); it != j.end() && it->is_string()) {
        r.description = it->get<std::string>();
    }

    // Layer 1: affected version ranges.
    if (auto affected_it = j.find("affected"); affected_it != j.end() && affected_it->is_array()) {
        for (const auto& af_j : *affected_it) {
            AffectedField af;
            af.field = require_string(af_j, "field", "rule " + r.id + ".affected");
            af.type = parse_comparator_type(
                require_string(af_j, "type", "rule " + r.id + ".affected." + af.field));

            auto ev_it = af_j.find("events");
            if (ev_it == af_j.end() || !ev_it->is_array() || ev_it->empty()) {
                throw std::runtime_error(
                    "rule " + r.id + ".affected." + af.field + ": missing/empty events[]");
            }
            for (const auto& ev_j : *ev_it) {
                AffectedEvent ev;
                if (auto v = ev_j.find("introduced"); v != ev_j.end() && v->is_string())
                    ev.introduced = v->get<std::string>();
                if (auto v = ev_j.find("fixed"); v != ev_j.end() && v->is_string())
                    ev.fixed = v->get<std::string>();
                if (auto v = ev_j.find("last_affected"); v != ev_j.end() && v->is_string())
                    ev.last_affected = v->get<std::string>();
                if (auto v = ev_j.find("limit"); v != ev_j.end() && v->is_string())
                    ev.limit = v->get<std::string>();

                if (count_event_kinds(ev) != 1) {
                    throw std::runtime_error("rule " + r.id + ".affected." + af.field
                        + ": each event must have exactly one of "
                          "introduced/fixed/last_affected/limit");
                }
                af.events.push_back(std::move(ev));
            }
            r.affected.push_back(std::move(af));
        }
    }

    // Layer 2: predicate. Parsed lazily by the engine.
    r.match = require_string(j, "match", "rule " + r.id);

    // Optional verify steps.
    if (auto it = j.find("verify"); it != j.end() && it->is_array()) {
        for (const auto& v_j : *it) {
            VerifyStep v;
            v.type = require_string(v_j, "type", "rule " + r.id + ".verify");
            v.rule = require_string(v_j, "rule", "rule " + r.id + ".verify");
            v.path = require_string(v_j, "path", "rule " + r.id + ".verify");
            r.verify.push_back(std::move(v));
        }
    }

    // Exploit metadata (required; label only, no code).
    auto expl_it = j.find("exploit");
    if (expl_it == j.end() || !expl_it->is_object()) {
        throw std::runtime_error("rule " + r.id + ": missing 'exploit' block");
    }
    r.exploit.status
        = parse_exploit_status(require_string(*expl_it, "status", "rule " + r.id + ".exploit"));
    r.exploit.gives
        = parse_exploit_gives(require_string(*expl_it, "gives", "rule " + r.id + ".exploit"));
    if (auto v = expl_it->find("user_interaction"); v != expl_it->end() && v->is_boolean()) {
        r.exploit.user_interaction = v->get<bool>();
    }
    if (auto v = expl_it->find("requires_downgrade"); v != expl_it->end() && v->is_boolean()) {
        r.exploit.requires_downgrade = v->get<bool>();
    }
    if (auto v = expl_it->find("poc_targets"); v != expl_it->end() && v->is_array()) {
        for (const auto& t : *v) {
            if (t.is_string())
                r.exploit.poc_targets.push_back(t.get<std::string>());
        }
    }

    // Downgrade inputs (optional).
    if (auto it = j.find("downgrade"); it != j.end() && it->is_object()) {
        if (auto v = it->find("min_vulnerable_spl"); v != it->end() && v->is_string()) {
            r.downgrade.min_vulnerable_spl = v->get<std::string>();
        }
        if (auto v = it->find("blocked_by"); v != it->end() && v->is_array()) {
            for (const auto& b : *v) {
                if (b.is_string()) {
                    r.downgrade.blocked_by.push_back(b.get<std::string>());
                }
            }
        }
    }

    // Refs (advisories / bulletins / writeups only; no exploit binaries).
    if (auto it = j.find("refs"); it != j.end() && it->is_array()) {
        for (const auto& ref : *it) {
            if (ref.is_string()) {
                r.refs.push_back(ref.get<std::string>());
            }
        }
    }

    // Optional exploit_source: runner block.
    if (auto es_it = j.find("exploit_source"); es_it != j.end() && es_it->is_object()) {
        ExploitSource es;
        const std::string ctx = "rule " + r.id + ".exploit_source";

        auto up_it = es_it->find("upstream");
        if (up_it == es_it->end() || !up_it->is_object()) {
            throw std::runtime_error(ctx + ": missing 'upstream'");
        }
        if (auto v = up_it->find("kind"); v != up_it->end() && v->is_string()) {
            es.upstream.kind = v->get<std::string>();
        }
        es.upstream.url = require_string(*up_it, "url", ctx + ".upstream");
        es.upstream.commit = require_string(*up_it, "commit", ctx + ".upstream");
        if (es.upstream.commit.size() != 40) {
            throw std::runtime_error(ctx + ".upstream.commit: must be a 40-hex SHA (got "
                + std::to_string(es.upstream.commit.size())
                + " chars); "
                  "branches, tags, and short SHAs are rejected");
        }
        for (char c : es.upstream.commit) {
            const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!ok)
                throw std::runtime_error(ctx + ".upstream.commit: must be lowercase hex");
        }
        if (auto v = up_it->find("subdir"); v != up_it->end() && v->is_string()) {
            es.upstream.subdir = v->get<std::string>();
        }
        if (auto v = up_it->find("tree_sha256"); v != up_it->end() && v->is_string()) {
            es.upstream.tree_sha256 = v->get<std::string>();
        }

        // Prerequisites: a list of {kind, params, description, optional}.
        if (auto pr_it = es_it->find("prerequisites"); pr_it != es_it->end() && pr_it->is_array()) {
            for (const auto& pj : *pr_it) {
                Prerequisite p;
                p.kind = require_string(pj, "kind", ctx + ".prerequisites");
                if (auto v = pj.find("description"); v != pj.end() && v->is_string()) {
                    p.description = v->get<std::string>();
                }
                if (auto v = pj.find("optional"); v != pj.end() && v->is_boolean()) {
                    p.optional = v->get<bool>();
                }
                if (auto v = pj.find("params"); v != pj.end() && v->is_object()) {
                    p.params = *v;
                } else {
                    // Any extra fields on the object (other than the four we
                    // consumed) are passed as params; this lets rule authors
                    // write flat prereq blocks instead of nesting `params:`.
                    nlohmann::json params = nlohmann::json::object();
                    for (auto it = pj.begin(); it != pj.end(); ++it) {
                        const std::string& k = it.key();
                        if (k == "kind" || k == "description" || k == "optional" || k == "params")
                            continue;
                        params[k] = it.value();
                    }
                    p.params = std::move(params);
                }
                es.prerequisites.push_back(std::move(p));
            }
        }

        // Build recipe.
        if (auto bi = es_it->find("build"); bi != es_it->end() && bi->is_object()) {
            if (auto v = bi->find("system"); v != bi->end() && v->is_string())
                es.build.system = v->get<std::string>();
            if (auto v = bi->find("abi"); v != bi->end() && v->is_string())
                es.build.abi = v->get<std::string>();
            if (auto v = bi->find("platform"); v != bi->end() && v->is_string())
                es.build.platform = v->get<std::string>();
            if (auto v = bi->find("recipe"); v != bi->end() && v->is_string())
                es.build.recipe = v->get<std::string>();
            if (auto v = bi->find("env"); v != bi->end() && v->is_object()) {
                for (auto it = v->begin(); it != v->end(); ++it) {
                    if (it.value().is_string()) {
                        es.build.env[it.key()] = it.value().get<std::string>();
                    }
                }
            }
        }

        // Deploy spec.
        if (auto di = es_it->find("deploy"); di != es_it->end() && di->is_object()) {
            if (auto v = di->find("workspace"); v != di->end() && v->is_string())
                es.deploy.workspace = v->get<std::string>();
            if (auto v = di->find("entry"); v != di->end() && v->is_string())
                es.deploy.entry = v->get<std::string>();
            if (auto v = di->find("artifacts"); v != di->end() && v->is_array()) {
                for (const auto& a : *v) {
                    if (a.is_string())
                        es.deploy.artifacts.push_back(a.get<std::string>());
                }
            }
            // Guardrail: deploy.workspace must live under /data/local/tmp/alps-work/.
            const std::string prefix = "/data/local/tmp/alps-work/";
            if (es.deploy.workspace.rfind(prefix, 0) != 0) {
                throw std::runtime_error(ctx + ".deploy.workspace: must live under " + prefix
                    + " (got: " + es.deploy.workspace + ")");
            }
        }

        // Targets (device codenames): optional; defaults to rule.exploit.poc_targets.
        if (auto v = es_it->find("targets"); v != es_it->end() && v->is_array()) {
            for (const auto& t : *v) {
                if (t.is_string())
                    es.targets.push_back(t.get<std::string>());
            }
        }
        if (es.targets.empty())
            es.targets = r.exploit.poc_targets;

        // Gates.
        if (auto gi = es_it->find("gates"); gi != es_it->end() && gi->is_object()) {
            if (auto v = gi->find("require_verdict"); v != gi->end() && v->is_string())
                es.gates.require_verdict = v->get<std::string>();
            if (auto v = gi->find("require_selinux"); v != gi->end() && v->is_string())
                es.gates.require_selinux = v->get<std::string>();
            if (auto v = gi->find("require_root"); v != gi->end() && v->is_boolean())
                es.gates.require_root = v->get<bool>();
        }
        // Cross-check gate values.
        if (es.gates.require_verdict != "available_now"
            && es.gates.require_verdict != "via_downgrade") {
            throw std::runtime_error(ctx
                + ".gates.require_verdict: must be 'available_now' or 'via_downgrade' (got: "
                + es.gates.require_verdict + ")");
        }
        if (es.gates.require_selinux != "any" && es.gates.require_selinux != "permissive"
            && es.gates.require_selinux != "enforcing") {
            throw std::runtime_error(ctx
                + ".gates.require_selinux: must be 'any' | 'permissive' | 'enforcing' (got: "
                + es.gates.require_selinux + ")");
        }

        r.exploit_source = std::move(es);
    }

    return r;
}

Rule Rule::from_yaml_str(const std::string& s)
{
    YAML::Node root = YAML::Load(s);
    return Rule::from_json(yaml_to_json(root));
}

Rule Rule::from_yaml_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("cannot open rule file: " + path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    try {
        return Rule::from_yaml_str(ss.str());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("in file ") + path + ": " + e.what());
    }
}

std::vector<Rule> load_rules_dir(const std::string& dir)
{
    std::vector<Rule> rules;
    if (!fs::exists(dir)) {
        throw std::runtime_error("rules directory not found: " + dir);
    }
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file())
            continue;
        const auto ext = entry.path().extension().string();
        if (ext != ".yaml" && ext != ".yml")
            continue;
        rules.push_back(Rule::from_yaml_file(entry.path().string()));
    }
    return rules;
}

} // namespace alps::core
