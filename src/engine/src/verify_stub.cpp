// Verify path: ALPS_WITH_YARA=OFF stub. Real libyara integration lives in
// verify_yara.cpp and is selected at CMake configure time; this stub always
// records "skipped (built without YARA)" alongside a file-presence check so
// the note is useful even without the optional dependency.

#include "alps/engine/verify.hpp"

#include <filesystem>

namespace fs = std::filesystem;

namespace alps::engine {

std::vector<VerifyResult> run_verify_steps(
    const alps::core::Rule& rule, const std::string& /*rules_dir*/)
{
    std::vector<VerifyResult> out;
    for (const auto& step : rule.verify) {
        VerifyResult v;
        v.step_kind = step.type;
        v.target_path = step.path;
        v.confirmed = false;
        const bool present = fs::exists(step.path);
        v.note = std::string("verify skipped (built without libyara); target ")
            + (present ? "present" : "not present") + " at " + step.path;
        out.push_back(std::move(v));
    }
    return out;
}

} // namespace alps::engine
