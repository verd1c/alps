// Runner-related widgets shared with browser.cpp: the runner-status block
// that appears in the right pane when a rule has exploit_source, and the
// modal progress overlay that hosts a running stage.

#pragma once

#include <functional>
#include <string>
#include <vector>

#include "alps/core/rule.hpp"
#include "alps/exploit/events.hpp"

namespace alps::tui {

// Formatted lines describing the runner status of a rule. Rendered as-is
// into the right pane by browser.cpp. Empty vector if the rule has no
// exploit_source block.
struct RunnerSummary {
    std::vector<std::string> lines; // pre-styled ANSI strings
    bool has_source = false;
};
RunnerSummary format_runner_status(const alps::core::Rule& rule, std::size_t width);

// Enter a full-screen modal, run `stage`, stream every emitted event into a
// scrolling log, and return when the stage returns. The user may press `q`
// or ESC to dismiss the log after the stage completes. If the terminal is
// not a TTY, does nothing and returns immediately.
//
// `stage_name` shows in the header ("Prereq check", "Fetch", ...).
// `stage` is any function that accepts an EventSink and runs synchronously.
using StageFn = std::function<bool(alps::exploit::EventSink)>;
void run_stage_modal(const std::string& stage_name, StageFn stage);

// Show an authorization prompt. Returns true iff the user typed 'y' or 'Y'.
// The prompt intentionally requires an explicit y; Enter/space default to N.
bool prompt_authorization(const std::string& question);

} // namespace alps::tui
