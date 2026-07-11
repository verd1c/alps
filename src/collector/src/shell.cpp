#include "shell.hpp"

#include <cstdio>
#include <memory>

namespace alps::collector {

std::string run_capture(const std::string& cmd)
{
    std::unique_ptr<FILE, int (*)(FILE*)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe)
        return {};
    std::string out;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), pipe.get()))
        out.append(buf);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
        out.pop_back();
    return out;
}

} // namespace alps::collector
