#pragma once

#include <optional>
#include <string>

namespace alps::collector {

// Scan a Mali GPU blob (typically /vendor/lib64/libGLES_mali.so) for the
// embedded driver version string ("r{maj}p{min}"). In-process byte scan;
// no external `strings` binary required. Returns the FIRST plausibly-bounded
// match; if the file cannot be read, returns nullopt.
[[nodiscard]] std::optional<std::string> scan_mali_version(const std::string& path);

// Scan a Mali GPU blob for the GPU generation identifier ("Bifrost",
// "Valhall", "Midgard", "Avalon", "5thGen"). Same file / same scan cost as
// `scan_mali_version`; kept as a separate function so the collector can
// call whichever it needs. Returns nullopt if no known family marker
// appears in the file.
[[nodiscard]] std::optional<std::string> scan_mali_arch(const std::string& path);

} // namespace alps::collector
