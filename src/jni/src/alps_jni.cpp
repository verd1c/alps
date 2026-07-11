// liballps.so: the JNI shim. Every JNI entry point is wrapped in a
// try / catch(...) block that converts C++ exceptions into thrown Java
// RuntimeExceptions. A C++ exception unwinding into the JVM would abort
// the whole app; this is MANDATORY.
//
// Ports the CLI's `collect` and `match` subcommands to a Java-facing native
// class at `dev.alps.Native`. Values cross the boundary as UTF-8 JSON
// strings so we never hand-marshal rich C++ objects across JNI.

#include <exception>
#include <string>

#include <jni.h>
#include <nlohmann/json.hpp>

#include "alps/collector/collect.hpp"
#include "alps/core/builtin_rules.hpp"
#include "alps/core/device_facts.hpp"
#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"
#include "alps/engine/matcher.hpp"

namespace {

std::string jstring_to_string(JNIEnv* env, jstring s)
{
    if (!s)
        return {};
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out(c ? c : "");
    if (c)
        env->ReleaseStringUTFChars(s, c);
    return out;
}

jstring to_jstring(JNIEnv* env, const std::string& s) { return env->NewStringUTF(s.c_str()); }

// Throw a Java RuntimeException. We do NOT re-throw C++ exceptions; every
// entry point converts to this before returning null.
void throw_java_runtime(JNIEnv* env, const char* what)
{
    jclass cls = env->FindClass("java/lang/RuntimeException");
    if (!cls)
        return;
    env->ThrowNew(cls, what ? what : "ALPS JNI failed");
}

} // namespace

extern "C" {

// public static native String dev.alps.Native.collectFacts()
JNIEXPORT jstring JNICALL Java_dev_alps_Native_collectFacts(JNIEnv* env, jclass /*cls*/)
{
    try {
        auto facts = alps::collector::collect_on_device();
        return to_jstring(env, facts.to_json_str(true));
    } catch (const std::exception& e) {
        throw_java_runtime(env, e.what());
        return nullptr;
    } catch (...) {
        throw_java_runtime(env, "unknown exception in collectFacts");
        return nullptr;
    }
}

// public static native String dev.alps.Native.matchFacts(
//     String factsJson, String rulesDir);
// Returns a JSON object: { "findings": [...], "errors": [...] }.
JNIEXPORT jstring JNICALL Java_dev_alps_Native_matchFacts(
    JNIEnv* env, jclass /*cls*/, jstring facts_json, jstring rules_dir)
{
    try {
        const auto facts_s = jstring_to_string(env, facts_json);
        const auto dir_s = jstring_to_string(env, rules_dir);

        const auto facts = alps::core::DeviceFacts::from_json_str(facts_s);
        // Empty rules_dir: use the KB embedded in this .so. Non-empty:
        // load from the app's private data dir (for KB dev / custom rules).
        const auto rules
            = dir_s.empty() ? alps::core::load_builtin_rules() : alps::core::load_rules_dir(dir_s);
        const auto res = alps::engine::match_rules(rules, facts);

        using nlohmann::json;
        json out = json::object();
        json findings_arr = json::array();
        for (const auto& f : res.findings)
            findings_arr.push_back(json(f));
        out["findings"] = std::move(findings_arr);

        json errs = json::array();
        for (const auto& e : res.errors) {
            errs.push_back(json { { "rule_id", e.rule_id }, { "message", e.message } });
        }
        out["errors"] = std::move(errs);

        return to_jstring(env, out.dump(2));
    } catch (const std::exception& e) {
        throw_java_runtime(env, e.what());
        return nullptr;
    } catch (...) {
        throw_java_runtime(env, "unknown exception in matchFacts");
        return nullptr;
    }
}

// public static native String dev.alps.Native.version()
JNIEXPORT jstring JNICALL Java_dev_alps_Native_version(JNIEnv* env, jclass /*cls*/)
{
    try {
        return to_jstring(env, std::string("alps 0.1.0 (jni)"));
    } catch (...) {
        return nullptr;
    }
}

} // extern "C"
