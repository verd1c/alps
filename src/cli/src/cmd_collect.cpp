#include <iostream>

#include "alps/collector/collect.hpp"
#include "common.hpp"

namespace alps::cli {

int cmd_collect(const std::string& output_path)
{
    const auto facts = alps::collector::collect_on_device();
    write_stdout_or_file(output_path, facts.to_json_str(true));
    return 0;
}

} // namespace alps::cli
