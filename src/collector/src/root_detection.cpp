// Every check here is a READ. We do not attempt to invoke `su`, load
// modules, or otherwise probe by acting; that would violate the "collector
// is read-only" guardrail.

#include "root_detection.hpp"

#include <array>
#include <filesystem>
#include <string>

#include "shell.hpp"

namespace fs = std::filesystem;

namespace alps::collector {

namespace {

    bool any_exists(std::initializer_list<const char*> paths)
    {
        for (const char* p : paths) {
            std::error_code ec;
            if (fs::exists(p, ec))
                return true;
        }
        return false;
    }

    // True if the given package name shows up in `pm list packages` output.
    // We do not read package internals; only presence-of-name.
    bool package_installed(const std::string& name)
    {
        const auto out = run_capture("pm list packages 2>/dev/null");
        return out.find("package:" + name) != std::string::npos;
    }

} // namespace

std::optional<std::string> detect_root_indicator()
{
    // Magisk: the modern standard.
    if (any_exists({ "/data/adb/magisk", "/sbin/magisk", "/system/etc/init/magisk.rc",
            "/data/adb/modules" })
        || package_installed("com.topjohnwu.magisk")) {
        return "magisk";
    }

    // KernelSU: increasingly common on newer devices.
    if (any_exists({ "/data/adb/ksu", "/data/adb/ksud" })
        || package_installed("me.weishu.kernelsu")) {
        return "kernelsu";
    }

    // SuperSU: legacy but still around.
    if (any_exists({ "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
            "/data/data/eu.chainfire.supersu" })
        || package_installed("eu.chainfire.supersu")) {
        return "supersu";
    }

    // Bare `su` binary without a known framework.
    if (any_exists({ "/system/xbin/su", "/system/bin/su", "/su/bin/su" })) {
        return "su-binary";
    }

    return std::nullopt;
}

} // namespace alps::collector
