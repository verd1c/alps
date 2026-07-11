#include "adreno_version.hpp"

#include <array>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

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

    // Look for a dotted-numeric run inside a chunk that reads like an Adreno
    // driver version. Format observed on Qualcomm HALs is <major>.<minor>[.<patch>]
    // where major is 3-4 digits (500-series through 800-series).
    struct DottedRun {
        std::size_t start;
        std::size_t len;
    };

    std::optional<DottedRun> find_adreno_run(const char* buf, std::size_t bytes, std::size_t from)
    {
        for (std::size_t i = from; i + 5 < bytes; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(buf[i])))
                continue;
            // Left boundary: previous byte must be non-alphanumeric.
            if (i > 0 && std::isalnum(static_cast<unsigned char>(buf[i - 1])))
                continue;

            std::size_t j = i;
            int dot_count = 0;
            int digit_count = 0;
            int leading_digits = 0;
            bool in_leading = true;
            while (j < bytes) {
                const char c = buf[j];
                if (std::isdigit(static_cast<unsigned char>(c))) {
                    ++digit_count;
                    if (in_leading)
                        ++leading_digits;
                    ++j;
                } else if (c == '.') {
                    if (dot_count >= 2)
                        break;
                    ++dot_count;
                    in_leading = false;
                    ++j;
                } else {
                    break;
                }
            }
            // Right boundary: alphanumeric = probably not a version.
            if (j < bytes && std::isalnum(static_cast<unsigned char>(buf[j])))
                continue;

            if (dot_count < 1)
                continue;
            // Adreno versions have 3-digit major and either two or three parts.
            if (leading_digits < 3 || leading_digits > 4)
                continue;
            if (digit_count < 4 || digit_count > 12)
                continue;
            return DottedRun { i, j - i };
        }
        return std::nullopt;
    }

    std::optional<std::string> scan_adreno_version(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f)
            return std::nullopt;

        constexpr std::size_t CHUNK = 128 * 1024;
        constexpr std::size_t OVERLAP = 16;
        std::vector<char> buf(CHUNK + OVERLAP);
        std::size_t carry = 0;

        while (f.read(buf.data() + carry, CHUNK) || f.gcount() > 0) {
            const std::size_t bytes = static_cast<std::size_t>(f.gcount()) + carry;
            if (auto run = find_adreno_run(buf.data(), bytes, 0)) {
                return std::string(buf.data() + run->start, run->len);
            }
            if (bytes >= OVERLAP) {
                std::memmove(buf.data(), buf.data() + bytes - OVERLAP, OVERLAP);
                carry = OVERLAP;
            } else {
                carry = bytes;
            }
        }
        return std::nullopt;
    }

} // namespace

std::optional<std::string> detect_adreno_driver(const std::map<std::string, std::string>& props)
{
    // 1. Prop-based lookups: cheapest and most authoritative when present.
    for (const char* key : {
             "ro.gpu.driver_version",
             "ro.hardware.gpu.adreno.version",
             "ro.boot.qc.adreno_gpu_driver_version",
             "ro.qc.adreno_gpu_driver_version",
             "vendor.opengles.version",
         }) {
        if (auto v = prop_opt(props, key))
            return v;
    }

    // 2. Filesystem scan: best-effort. Many Adreno driver blobs embed a
    //    version tuple somewhere in their strings section. A false positive
    //    here becomes visible as a mismatch in `matched_facts` output, which
    //    is preferable to silent absence.
    static const std::array<const char*, 6> kAdrenoBlobs = {
        "/vendor/lib64/libgsl.so",
        "/vendor/lib/libgsl.so",
        "/vendor/lib64/egl/libGLESv2_adreno.so",
        "/vendor/lib/egl/libGLESv2_adreno.so",
        "/vendor/lib64/hw/vulkan.adreno.so",
        "/vendor/lib/hw/vulkan.adreno.so",
    };
    for (const auto* p : kAdrenoBlobs) {
        if (!fs::exists(p))
            continue;
        if (auto v = scan_adreno_version(p))
            return v;
    }
    return std::nullopt;
}

} // namespace alps::collector
