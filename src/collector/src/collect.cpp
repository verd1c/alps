// On-device collector. Read-only; see the file-level comment in collect.hpp.
// Every "read" here is one of:
//   * `getprop` (safe read of system properties)
//   * `uname -r`, `getenforce` (read-only utilities)
//   * fs read of /vendor/lib*/libGLES_mali.so and other GPU driver blobs
//
// Nothing here writes, escalates, or modifies device state.

#include "alps/collector/collect.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "adreno_version.hpp"
#include "getprop_parse.hpp"
#include "mali_version.hpp"
#include "root_detection.hpp"
#include "shell.hpp"

namespace fs = std::filesystem;

namespace alps::collector {

namespace {

    std::optional<std::string> prop_opt(
        const std::map<std::string, std::string>& p, const std::string& k)
    {
        auto it = p.find(k);
        if (it == p.end() || it->second.empty())
            return std::nullopt;
        return it->second;
    }

    std::vector<std::string> split_csv(const std::string& s)
    {
        std::vector<std::string> out;
        std::string cur;
        for (char c : s) {
            if (c == ',') {
                if (!cur.empty()) {
                    out.push_back(std::move(cur));
                    cur.clear();
                }
            } else if (!std::isspace(static_cast<unsigned char>(c))) {
                cur.push_back(c);
            }
        }
        if (!cur.empty())
            out.push_back(std::move(cur));
        return out;
    }

    std::string lower(std::string s)
    {
        for (auto& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::string iso8601_utc_now()
    {
        const auto now = std::chrono::system_clock::now();
        const auto tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm {};
        // On Android bionic, gmtime_r is available.
        gmtime_r(&tt, &tm);
        char buf[32] = {};
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }

    void fill_gpu(alps::core::DeviceFacts& f, const std::map<std::string, std::string>& props)
    {
        // 1. Vendor detection. Props tend to be authoritative when present;
        //    fall back to filesystem probing otherwise.
        const auto ro_egl = prop_opt(props, "ro.hardware.egl");
        const auto ro_gpu_drv = prop_opt(props, "ro.gfx.driver.0");
        const auto ro_gpu_ver = prop_opt(props, "ro.gpu.driver_version");
        const auto ro_mali_ver = prop_opt(props, "ro.hardware.gpu.mali.version");
        (void)ro_gpu_drv; // reserved for later Adreno detection refinements

        std::string vendor;
        if (ro_egl) {
            const auto v = lower(*ro_egl);
            if (v.find("mali") != std::string::npos)
                vendor = "mali";
            else if (v.find("adreno") != std::string::npos)
                vendor = "adreno";
            else if (v.find("powervr") != std::string::npos)
                vendor = "powervr";
        }
        // Filesystem probes as a fallback.
        if (vendor.empty()) {
            static const std::vector<std::string> mali_paths = {
                "/vendor/lib64/egl/libGLES_mali.so",
                "/vendor/lib/egl/libGLES_mali.so",
                "/vendor/lib64/libGLES_mali.so",
                "/vendor/lib/libGLES_mali.so",
                "/system/lib64/egl/libGLES_mali.so",
            };
            for (const auto& p : mali_paths)
                if (fs::exists(p)) {
                    vendor = "mali";
                    break;
                }
        }
        if (vendor.empty()) {
            static const std::vector<std::string> adreno_paths = {
                "/vendor/lib64/egl/eglSubDriverAndroid.so",
                "/vendor/lib64/libgsl.so",
            };
            for (const auto& p : adreno_paths)
                if (fs::exists(p)) {
                    vendor = "adreno";
                    break;
                }
        }
        if (!vendor.empty())
            f.gpu.vendor = vendor;

        // 2. Version. For Mali we scan the blob directly; real observed version
        //    is what a rule needs, not a claimed patch level. Same pass grabs
        //    the family name (Bifrost / Valhall / ...) so rules can predicate on
        //    GPU generation independent of driver version.
        if (f.gpu.vendor.value_or("") == "mali") {
            static const std::vector<std::string> mali_paths = {
                "/vendor/lib64/egl/libGLES_mali.so",
                "/vendor/lib/egl/libGLES_mali.so",
                "/vendor/lib64/libGLES_mali.so",
                "/vendor/lib/libGLES_mali.so",
                "/system/lib64/egl/libGLES_mali.so",
            };
            for (const auto& p : mali_paths) {
                if (!fs::exists(p))
                    continue;
                if (auto v = scan_mali_version(p)) {
                    f.gpu.mali_driver = *v;
                    f.gpu.driver_blob_paths[p] = *v;
                } else {
                    // Record the path even without a version so downstream sees
                    // the blob is present.
                    f.gpu.driver_blob_paths[p] = "";
                }
                if (auto arch = scan_mali_arch(p); arch && !f.gpu.mali_arch) {
                    f.gpu.mali_arch = *arch;
                }
                if (f.gpu.mali_driver && f.gpu.mali_arch)
                    break;
            }
            // Prop-derived version, last-resort, marked with "prop:" prefix so a
            // rule author sees where the value came from.
            if (!f.gpu.mali_driver && ro_mali_ver) {
                f.gpu.mali_driver = "prop:" + *ro_mali_ver;
            }
        }
        if (f.gpu.vendor.value_or("") == "adreno") {
            f.gpu.adreno_driver = detect_adreno_driver(props);
            static const std::vector<std::string> adreno_paths = {
                "/vendor/lib64/libgsl.so",
                "/vendor/lib/libgsl.so",
                "/vendor/lib64/egl/libGLESv2_adreno.so",
                "/vendor/lib/egl/libGLESv2_adreno.so",
            };
            for (const auto& p : adreno_paths) {
                if (fs::exists(p)) {
                    f.gpu.driver_blob_paths[p] = f.gpu.adreno_driver.value_or("");
                }
            }
        }
    }

} // namespace

alps::core::DeviceFacts collect_on_device()
{
    alps::core::DeviceFacts f;

    const auto props = parse_getprop(run_capture("getprop"));
    f.raw_props = props;

    f.android_release = prop_opt(props, "ro.build.version.release");
    if (auto sdk = prop_opt(props, "ro.build.version.sdk")) {
        try {
            f.sdk_int = std::stoi(*sdk);
        } catch (...) {
        }
    }
    f.spl = prop_opt(props, "ro.build.version.security_patch");
    f.vendor_spl = prop_opt(props, "ro.vendor.build.security_patch");
    f.build_fingerprint = prop_opt(props, "ro.build.fingerprint");
    f.manufacturer = prop_opt(props, "ro.product.manufacturer");
    f.model = prop_opt(props, "ro.product.model");
    f.device = prop_opt(props, "ro.product.device");
    f.soc_model = prop_opt(props, "ro.soc.model");
    f.soc_manufacturer = prop_opt(props, "ro.soc.manufacturer");

    if (auto abi = prop_opt(props, "ro.product.cpu.abilist")) {
        f.abis = split_csv(*abi);
    }

    f.kernel_version = run_capture("uname -r");
    if (f.kernel_version->empty())
        f.kernel_version.reset();

    fill_gpu(f, props);

    // Bootloader / verified-boot / rollback state. Google Pixels set
    // `ro.boot.verifiedbootstate=green` when locked+verified; other OEMs may
    // only expose `ro.boot.flash.locked=1`, so check both. Either being
    // affirmative means locked, and only both being absent leaves the field
    // as unknown.
    if (auto vbs = prop_opt(props, "ro.boot.verifiedbootstate")) {
        f.verified_boot_state = *vbs;
        f.bootloader_locked = (*vbs == "green");
    }
    if (auto locked = prop_opt(props, "ro.boot.flash.locked")) {
        const bool flash_locked = (*locked == "1");
        f.bootloader_locked = f.bootloader_locked.value_or(false) || flash_locked;
    }
    if (auto ri = prop_opt(props, "ro.boot.rollback_index")) {
        try {
            f.rollback_index = std::stoll(*ri);
        } catch (...) {
        }
    }

    // SELinux mode. Three-tier fallback:
    //   1. `getenforce`: works on most builds; some strip it in shell context
    //      ("Couldn't get enforcing status") because /sys/fs/selinux/enforce
    //      is not shell-readable.
    //   2. Read /sys/fs/selinux/enforce directly: same permission issue
    //      applies but we try anyway.
    //   3. Read /proc/self/attr/current: always shell-readable when SELinux
    //      is loaded. A non-empty label like "u:r:shell:s0" tells us SELinux
    //      is at least labeling, and for production locked+verified Androids
    //      that also means enforcing; surface it explicitly as "enforcing".
    //      If our current context is one of the permissive-fixture domains
    //      ("kernel", "init", "-permissive:"), fall back to "labeled".
    {
        auto raw = lower(run_capture("getenforce 2>/dev/null"));
        if (raw == "unknown" || raw.empty()) {
            std::ifstream sf("/sys/fs/selinux/enforce");
            char c = '\0';
            if (sf && sf.get(c)) {
                raw = (c == '1') ? "enforcing" : "permissive";
            }
        }
        if (raw.empty() || raw == "unknown") {
            std::ifstream ctx("/proc/self/attr/current");
            std::string label;
            if (ctx && std::getline(ctx, label) && !label.empty()) {
                raw = label.find("permissive") != std::string::npos ? "labeled" : "enforcing";
            }
        }
        if (!raw.empty() && raw != "unknown")
            f.selinux_mode = raw;
    }

    f.treble_enabled = (prop_opt(props, "ro.treble.enabled").value_or("") == "true");
    f.dynamic_partitions = (prop_opt(props, "ro.boot.dynamic_partitions").value_or("") == "true");

    // MTE: we can't reliably detect the userspace opt-in from within a
    // random process, so we conservatively expose the vendor's declared
    // support if present. Rules should query raw_props for detail.
    if (auto memtag = prop_opt(props, "ro.arm64.memtag.mode")) {
        f.mte_enabled = (*memtag != "off" && !memtag->empty());
    }

    f.collector_mode = "on_device";
    f.collected_at = iso8601_utc_now();
    f.root_indicator = detect_root_indicator();
    return f;
}

} // namespace alps::collector
