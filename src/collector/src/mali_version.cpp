#include "mali_version.hpp"

#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace alps::collector {

namespace {

    struct Match {
        std::size_t start;
        std::size_t len;
        bool has_dash_suffix; // ends immediately followed by `-build-tag`
    };

    // Match r<digits>p<digits> at position i in buf[0..bytes). On success,
    // returns the match length; on failure, returns 0. Boundary rules:
    //   * Left byte (if any) must be non-alphanumeric AND NOT '.'; the '.'
    //     exclusion filters out the Mali arch-tag table entries like `tSIx.r1p1`
    //     which are per-generation identifiers, NOT the driver version.
    //   * Right byte (if any) must be non-alphanumeric.
    // `out.has_dash_suffix` is set when the byte after the match is '-', which is
    // the Mali build-tag shape (e.g. `r32p1-00pxl1`). We use this to prefer the
    // real driver version when multiple candidates appear in a single blob.
    bool match_at(const char* buf, std::size_t bytes, std::size_t i, Match& out)
    {
        if (buf[i] != 'r')
            return false;
        if (i + 3 >= bytes)
            return false;
        if (!std::isdigit(static_cast<unsigned char>(buf[i + 1])))
            return false;

        std::size_t j = i + 1;
        while (j < bytes && std::isdigit(static_cast<unsigned char>(buf[j])))
            ++j;
        if (j >= bytes || buf[j] != 'p')
            return false;

        std::size_t p = j + 1;
        if (p >= bytes || !std::isdigit(static_cast<unsigned char>(buf[p])))
            return false;
        while (p < bytes && std::isdigit(static_cast<unsigned char>(buf[p])))
            ++p;

        if (i > 0) {
            const unsigned char prev = static_cast<unsigned char>(buf[i - 1]);
            if (std::isalnum(prev) || prev == '.')
                return false;
        }
        if (p < bytes && std::isalnum(static_cast<unsigned char>(buf[p])))
            return false;

        const std::size_t len = p - i;
        if (len < 4 || len > 12)
            return false;

        out.start = i;
        out.len = len;
        out.has_dash_suffix = (p < bytes && buf[p] == '-');
        return true;
    }

} // namespace

std::optional<std::string> scan_mali_arch(const std::string& path)
{
    // Family markers Arm embeds in the blob banner / feature-string tables.
    // Ordered by rough recency so ties (a blob that includes both "Bifrost"
    // and "Valhall" strings) resolve to the newer arch: Arm's newer blobs
    // sometimes retain compatibility strings from prior families.
    static const std::array<const char*, 5> kMarkers = {
        "5thGen",
        "Avalon",
        "Valhall",
        "Bifrost",
        "Midgard",
    };

    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;

    // Chunked scan. We use a big enough overlap that any marker straddling
    // a chunk boundary is caught in the next chunk's header.
    constexpr std::size_t CHUNK = 128 * 1024;
    constexpr std::size_t OVERLAP = 16;
    std::vector<char> buf(CHUNK + OVERLAP);
    std::size_t carry = 0;

    std::optional<std::string> best;
    // Track priority by index in kMarkers (lower index = newer arch).
    int best_prio = static_cast<int>(kMarkers.size());

    while (f.read(buf.data() + carry, CHUNK) || f.gcount() > 0) {
        const std::size_t bytes = static_cast<std::size_t>(f.gcount()) + carry;
        const std::string_view view(buf.data(), bytes);
        for (std::size_t k = 0; k < kMarkers.size(); ++k) {
            if (static_cast<int>(k) >= best_prio)
                break; // can't improve
            if (view.find(kMarkers[k]) != std::string_view::npos) {
                best = kMarkers[k];
                best_prio = static_cast<int>(k);
                break;
            }
        }
        if (best_prio == 0)
            return best; // top priority; no need to keep scanning

        if (bytes >= OVERLAP) {
            std::memmove(buf.data(), buf.data() + bytes - OVERLAP, OVERLAP);
            carry = OVERLAP;
        } else {
            carry = bytes;
        }
    }
    return best;
}

std::optional<std::string> scan_mali_version(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;

    constexpr std::size_t CHUNK = 64 * 1024;
    constexpr std::size_t OVERLAP = 16;
    std::vector<char> buf(CHUNK + OVERLAP);
    std::size_t carry = 0;

    // Collect matches across the whole file so we can prefer a dash-suffixed
    // candidate (the actual driver banner shape) over any plain r/p tokens.
    std::optional<std::string> dash_hit;
    std::optional<std::string> plain_hit;

    while (f.read(buf.data() + carry, CHUNK) || f.gcount() > 0) {
        const std::size_t bytes = static_cast<std::size_t>(f.gcount()) + carry;
        for (std::size_t i = 0; i + 4 < bytes; ++i) {
            Match m;
            if (!match_at(buf.data(), bytes, i, m))
                continue;
            std::string ver(buf.data() + m.start, m.len);
            if (m.has_dash_suffix) {
                dash_hit = ver;
                return dash_hit; // strongest signal; done
            }
            if (!plain_hit)
                plain_hit = std::move(ver);
        }
        if (bytes >= OVERLAP) {
            std::memmove(buf.data(), buf.data() + bytes - OVERLAP, OVERLAP);
            carry = OVERLAP;
        } else {
            carry = bytes;
        }
    }
    return dash_hit ? dash_hit : plain_hit;
}

} // namespace alps::collector
