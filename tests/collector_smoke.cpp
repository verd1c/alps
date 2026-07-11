// Smoke test: run the on-device collector and print the resulting DeviceFacts
// as pretty JSON.  Intended to be `adb push`ed and run under `adb shell`.
// Prints and returns 0 unless the collector throws.  Assertion-driven tests
// live in collector_tests.cpp.

#include <cstdio>
#include <iostream>

#include "alps/collector/collect.hpp"

int main()
{
    try {
        auto facts = alps::collector::collect_on_device();
        std::cout << facts.to_json_str(true) << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "collector failed: " << e.what() << "\n";
        return 1;
    }
}
