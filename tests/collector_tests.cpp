// Assertion tests for collector helpers that don't need a
// live device (getprop line parser, Mali-version byte scanner). The full
// pipeline is smoke-tested on the device via collector_smoke.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "../src/collector/src/getprop_parse.hpp"
#include "../src/collector/src/mali_version.hpp"

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":" << __LINE__ << "\n";        \
            ++g_failures;                                                                          \
        }                                                                                          \
    } while (0)

void test_parse_getprop()
{
    // A representative slice of `getprop` output shape.
    const std::string sample = "[ro.build.version.release]: [12]\n"
                               "[ro.build.version.sdk]: [32]\n"
                               "[ro.hardware.egl]: [mali]\n"
                               "[empty.value]: []\n"
                               "not a getprop line\n"
                               "[malformed line without brackets]: no value\n"
                               "[ro.product.cpu.abilist]: [arm64-v8a,armeabi-v7a]\n";
    const auto props = alps::collector::parse_getprop(sample);
    EXPECT(props.at("ro.build.version.release") == "12");
    EXPECT(props.at("ro.build.version.sdk") == "32");
    EXPECT(props.at("ro.hardware.egl") == "mali");
    EXPECT(props.at("empty.value") == "");
    EXPECT(props.at("ro.product.cpu.abilist") == "arm64-v8a,armeabi-v7a");
    EXPECT(props.find("not a getprop line") == props.end());
}

std::string write_tmp(const std::string& content)
{
    // Use argv[0]-neutral scratch path; on device /data/local/tmp is writable
    // by the shell user, which is where we run.
    auto p = fs::temp_directory_path();
    // Android's temp_directory_path may not exist; fall back.
    if (!fs::exists(p))
        p = "/data/local/tmp";
    const auto file = p / "alps_mali_scan_test.bin";
    std::ofstream f(file, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    return file.string();
}

void test_mali_version_scan()
{
    // Real-world-ish blob content: the version string embedded in text.
    const std::string blob = "some prefix bytes...\n"
                             "Bifrost driver r32p1-01eac0 build\n"
                             "more trailing bytes";
    const auto path = write_tmp(blob);
    auto v = alps::collector::scan_mali_version(path);
    EXPECT(v.has_value());
    if (v)
        EXPECT(*v == "r32p1");

    // Nothing to find: returns nullopt.
    const auto path2 = write_tmp("nothing to see here just some text");
    EXPECT(!alps::collector::scan_mali_version(path2).has_value());

    // Missing file: returns nullopt (does not throw).
    EXPECT(!alps::collector::scan_mali_version("/definitely/not/a/real/path").has_value());
}

} // namespace

int main()
{
    test_parse_getprop();
    test_mali_version_scan();

    if (g_failures == 0) {
        std::cout << "OK: all collector tests passed\n";
        return 0;
    }
    std::cerr << g_failures << " failure(s)\n";
    return 1;
}
