#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "alps/osv/import.hpp"
#include "common.hpp"

namespace fs = std::filesystem;

namespace alps::cli {

int cmd_update(const std::string& from_dir, const std::string& out_dir)
{
    if (from_dir.empty()) {
        std::cout
            << "alps update: imports OSV Android ecosystem data into rule YAML.\n\n"
               "The OSV dump is not fetched by ALPS. Grab it manually first:\n\n"
               "    curl -L https://storage.googleapis.com/osv-vulnerabilities/Android/all.zip \\\n"
               "        -o osv-android.zip\n"
               "    unzip osv-android.zip -d osv-android/\n"
               "    alps update --from osv-android/\n"
               "\nNothing is uploaded, executed, or downloaded on your behalf.\n";
        return 0;
    }
    std::vector<alps::osv::ImportError> errors;
    const auto rules = alps::osv::load_osv_dir(from_dir, errors);

    if (!fs::exists(out_dir))
        fs::create_directories(out_dir);

    std::size_t written = 0;
    for (const auto& r : rules) {
        const auto path = fs::path(out_dir) / (r.id + ".yaml");
        std::ofstream f(path);
        if (!f) {
            errors.push_back({ path.string(), "cannot open for write" });
            continue;
        }
        f << alps::osv::rule_to_yaml(r);
        ++written;
    }

    std::cout << "OSV rules imported: " << written << ", errors: " << errors.size() << "\n";
    for (const auto& e : errors) {
        std::cout << "  " << e.source << ": " << e.message << "\n";
    }
    return errors.empty() ? 0 : 1;
}

} // namespace alps::cli
