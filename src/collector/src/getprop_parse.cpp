#include "getprop_parse.hpp"

#include <sstream>

namespace alps::collector {

std::map<std::string, std::string> parse_getprop(const std::string& out)
{
    // Each getprop line looks like: `[ro.build.version.release]: [12]`.
    // We accept an empty value and skip anything malformed rather than
    // throwing; the raw dump is best-effort input.
    std::map<std::string, std::string> props;
    std::istringstream ss(out);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.size() < 5 || line.front() != '[')
            continue;
        const auto sep = line.find("]: [");
        if (sep == std::string::npos)
            continue;
        if (line.back() != ']')
            continue;
        std::string key = line.substr(1, sep - 1);
        std::string val = line.substr(sep + 4, line.size() - sep - 5);
        props.emplace(std::move(key), std::move(val));
    }
    return props;
}

} // namespace alps::collector
