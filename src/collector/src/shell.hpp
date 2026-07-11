#pragma once

#include <string>

namespace alps::collector {

// Run `cmd` via popen("r") and return stdout.  Never write; the collector
// is strictly read-only.  Empty return on failure.  Trims trailing newlines.
[[nodiscard]] std::string run_capture(const std::string& cmd);

} // namespace alps::collector
