#pragma once

#include <optional>
#include <string>

namespace alps::collector {

// Best-effort detection of pre-existing root on the device. Returns a short
// tag ("magisk" / "supersu" / "su-binary" / "kernelsu") or nullopt. If any
// indicator is present, LPE triage is largely moot; the reporter surfaces
// this prominently in the device header line.
[[nodiscard]] std::optional<std::string> detect_root_indicator();

} // namespace alps::collector
