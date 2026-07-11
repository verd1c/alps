// Reads the device state the engine reasons over. Uses `getprop`,
// `uname -r`, `getenforce`, and blob-file reads only.

#pragma once

#include <string>

#include "alps/core/device_facts.hpp"

namespace alps::collector {

// Collect facts running IN the shell context of the target device (the
// on-device mode). Works when the binary is `adb push`ed and executed under
// `adb shell`, or when the binary is invoked directly on the device.
[[nodiscard]] alps::core::DeviceFacts collect_on_device();

} // namespace alps::collector
