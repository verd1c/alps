// Interactive two-pane TUI for browsing findings. Enters the terminal's
// alternate screen buffer + raw input mode on entry, and always restores
// them on exit (even via signal or exception). Requires a real TTY;
// callers should check `isatty(STDIN_FILENO)` first and print a helpful
// hint about `adb shell -t` when it isn't.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "alps/core/rule.hpp"
#include "alps/report/reporter.hpp"

namespace alps::tui {

struct BrowserOpts {
    // False: skip the alt-screen buffer, drawing inline on the main
    // terminal. Useful when an emulator / relay drops \x1b[?1049h and
    // leaves the drawing on-screen only until the next shell command.
    bool use_alt_screen = true;

    // If set, the browser exposes the `alps exploit` runner on the focused
    // finding via keys p/f/b/d/r/x.  Requires the rule KB so we can find the
    // ExploitSource block for the current selection.
    const std::vector<alps::core::Rule>* rules = nullptr;
    // Passed to the runner for gate 8 (device selection) and audit records.
    std::optional<std::string> adb_serial;
};

// Run the browser against a Report. Returns process exit code
// (0 = normal quit, non-zero = error, e.g. not a TTY).
int run_browser(const alps::report::Report& report, BrowserOpts opts = {});

} // namespace alps::tui
