// DeviceFacts: the fact sheet produced by the collector and consumed by the
// engine. Every field the collector could not obtain is `nullopt`; do not
// guess. `spl`, `vendor_spl`, and the observed driver blob versions are kept
// separate on purpose (see DESIGN.md).

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace alps::core {

struct Gpu {
    std::optional<std::string> vendor; // "mali" | "adreno" | "powervr" | "xclipse"
    std::optional<std::string> mali_arch; // "Bifrost" | "Valhall" | "Midgard" | "5thGen" | "Avalon"
    std::optional<std::string> mali_driver; // e.g. "r32p1"
    std::optional<std::string> adreno_driver;
    // Path -> observed version. Real blob versions belong here; the SPL claim
    // stays in DeviceFacts::spl / vendor_spl so a rule can catch divergence.
    std::map<std::string, std::string> driver_blob_paths;
};

struct DeviceFacts {
    std::optional<std::string> android_release; // ro.build.version.release
    std::optional<int> sdk_int; // ro.build.version.sdk
    std::optional<std::string> spl; // ro.build.version.security_patch
    std::optional<std::string> vendor_spl; // ro.vendor.build.security_patch
    std::optional<std::string> build_fingerprint; // ro.build.fingerprint
    std::optional<std::string> manufacturer; // ro.product.manufacturer
    std::optional<std::string> model; // ro.product.model
    std::optional<std::string> device; // ro.product.device
    std::optional<std::string> kernel_version; // uname -r
    std::optional<std::string> soc_model; // ro.soc.model
    std::optional<std::string> soc_manufacturer; // ro.soc.manufacturer
    std::vector<std::string> abis; // ro.product.cpu.abilist split
    Gpu gpu;
    std::optional<std::string> selinux_mode; // "enforcing" | "permissive"
    std::optional<bool> bootloader_locked; // derived from verifiedbootstate / flash.locked
    std::optional<int64_t> rollback_index; // ro.boot.rollback_index if present
    std::optional<std::string> verified_boot_state; // green | yellow | orange
    std::optional<bool> mte_enabled;
    std::optional<bool> treble_enabled;
    std::optional<bool> dynamic_partitions;
    std::optional<std::string> collector_mode; // "adb" | "on_device"
    std::optional<std::string> collected_at; // ISO-8601 UTC
    std::optional<std::string> root_indicator; // "magisk" / "kernelsu" / "supersu" / "su-binary"
    std::map<std::string, std::string> raw_props; // full getprop dump; rules may query fields
                                                  // ALPS does not model explicitly

    // Fetch a field by dotted path (e.g. "gpu.mali_driver", "abis"). Returns a
    // nlohmann::json value; the engine wraps this in typed accessors. A
    // missing path returns a null json (not an exception). raw_props keys are
    // reachable via `raw_props.<prop>`.
    [[nodiscard]] nlohmann::json get_field(const std::string& dotted_path) const;

    // JSON round-trip helpers. `to_json_str(true)` pretty-prints for humans.
    [[nodiscard]] static DeviceFacts from_json_str(const std::string& s);
    [[nodiscard]] std::string to_json_str(bool pretty = true) const;
};

// ADL hooks so `nlohmann::json j = facts;` and `j.get<DeviceFacts>()` work.
void to_json(nlohmann::json& j, const Gpu& g);
void from_json(const nlohmann::json& j, Gpu& g);

void to_json(nlohmann::json& j, const DeviceFacts& f);
void from_json(const nlohmann::json& j, DeviceFacts& f);

} // namespace alps::core
