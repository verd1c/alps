#pragma once

#include <map>
#include <optional>
#include <string>

namespace alps::collector {

// Best-effort Adreno / KGSL driver version detection. Adreno drivers don't
// embed a single canonical version string the way Mali blobs do, so we probe
// in this order:
//   1. Android system properties commonly set by Qualcomm's HAL layer
//      (ro.gpu.driver_version, ro.hardware.gpu.adreno.version, etc.)
//   2. A byte scan of libgsl.so / libGLESv2_adreno.so for well-known version
//      tokens (see the .cpp for the exact patterns and their limitations).
//
// Returns nullopt if no candidate is found; the caller should then still
// record the blob path in driver_blob_paths so `alps rules lint` can catch
// the divergence.
[[nodiscard]] std::optional<std::string> detect_adreno_driver(
    const std::map<std::string, std::string>& props);

} // namespace alps::collector
