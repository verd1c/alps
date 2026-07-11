#include "runner_view.hpp"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alps/exploit/prereq.hpp"
#include "alps/exploit/runner.hpp"
#include "terminal.hpp"

namespace alps::tui {

namespace {

    constexpr const char* kDim = "\x1b[38;5;242m";
    constexpr const char* kLabel = "\x1b[38;5;245m";
    constexpr const char* kValue = "\x1b[38;5;253m";
    constexpr const char* kOk = "\x1b[1;38;5;108m";
    constexpr const char* kWarn = "\x1b[38;5;179m";
    constexpr const char* kErr = "\x1b[1;38;5;203m";
    constexpr const char* kInfo = "\x1b[38;5;75m";
    constexpr const char* kRst = "\x1b[0m";

    std::string sgr(const char* code, const std::string& text)
    {
        return std::string(code) + text + kRst;
    }

    std::size_t vis_width(const std::string& s)
    {
        std::size_t n = 0;
        for (unsigned char c : s) {
            if ((c & 0xC0) != 0x80)
                ++n;
        }
        return n;
    }

} // namespace

RunnerSummary format_runner_status(const alps::core::Rule& rule, std::size_t width)
{
    RunnerSummary s;
    if (!rule.exploit_source)
        return s;
    s.has_source = true;
    const auto& src = *rule.exploit_source;

    // Section header.
    std::string rule_line(4 * 3, 0);
    rule_line.clear();
    for (int i = 0; i < 4; ++i)
        rule_line += "\xE2\x94\x80";
    std::string tail;
    const std::size_t used = 4 + 1 + std::string("Runner").size() + 1;
    for (std::size_t i = 0; i < (width > used ? width - used : 0); ++i) {
        tail += "\xE2\x94\x80";
    }
    s.lines.push_back(
        sgr(kDim, rule_line) + " " + sgr("\x1b[1;38;5;255m", "Runner") + " " + sgr(kDim, tail));

    auto field = [&](std::string label, std::string value) {
        std::ostringstream os;
        os << "  " << sgr(kLabel, label) << "  " << sgr(kValue, value);
        s.lines.push_back(os.str());
    };

    // On-device banner: the runner refuses every state-changing stage
    // when this binary is cross-compiled for Android. Show it up-front so
    // users don't press keys and get a modal full of red errors.
    if (alps::exploit::is_android_target()) {
        s.lines.push_back(
            sgr(kWarn, "  ! host-only: build alps for your workstation to run these actions"));
        s.lines.push_back(sgr(kDim,
            "    (this alps is cross-compiled for Android; git / cmake / adb are host tools)"));
        s.lines.push_back("");
    }

    field("upstream", src.upstream.url);
    field("commit  ", src.upstream.commit.substr(0, 12) + "...");
    if (src.upstream.subdir)
        field("subdir  ", *src.upstream.subdir);
    field("build   ", src.build.system + " (" + src.build.abi + ", " + src.build.platform + ")");
    field("deploy  ", src.deploy.workspace);
    field("entry   ", src.deploy.entry);
    if (!src.targets.empty()) {
        std::string joined;
        for (std::size_t i = 0; i < src.targets.size(); ++i) {
            if (i)
                joined += ", ";
            joined += src.targets[i];
        }
        field("targets ", joined);
    }
    s.lines.push_back("");

    // Prereqs.
    s.lines.push_back(sgr(kLabel, "  Prerequisites"));
    alps::exploit::register_builtin_prereqs();
    const auto& reg = alps::exploit::PrereqRegistry::instance();
    for (const auto& p : src.prerequisites) {
        const auto* c = reg.find(p.kind);
        const std::string desc = p.description.empty()
            ? (c ? c->describe(p.params) : ("unknown: " + p.kind))
            : p.description;
        const std::string tag = p.optional ? " (optional)" : "";
        std::ostringstream os;
        os << "    " << sgr(kDim, "\xC2\xB7") << " " << sgr(kValue, p.kind) << tag << ": "
           << sgr(kDim, desc);
        s.lines.push_back(os.str());
    }
    s.lines.push_back("");

    // Key hints.
    s.lines.push_back(sgr(kLabel, "  Actions"));
    s.lines.push_back("    " + sgr("\x1b[1;38;5;255m", "a") + sgr(kOk, "  do all")
        + sgr(kDim,
            "  (prereq -> fetch -> build -> deploy -> run)"));
    s.lines.push_back("    " + sgr(kDim, "or step by step:  ") + sgr("\x1b[1;38;5;255m", "p")
        + sgr(kDim, " prereq  ") + sgr("\x1b[1;38;5;255m", "f") + sgr(kDim, " fetch  ")
        + sgr("\x1b[1;38;5;255m", "b") + sgr(kDim, " build  ") + sgr("\x1b[1;38;5;255m", "d")
        + sgr(kDim, " deploy  ") + sgr("\x1b[1;38;5;255m", "r") + sgr(kDim, " run  ")
        + sgr("\x1b[1;38;5;255m", "x") + sgr(kDim, " cleanup"));
    return s;
}

// Modal progress overlay.
namespace {

    void draw_modal_header(int rows, int cols, const std::string& title)
    {
        // Row 1: title bar, row 2: hairline.
        move_to(1, 1);
        clear_line();
        write_raw(sgr("\x1b[1;38;5;255m", std::string("ALPS runner: ") + title));
        move_to(2, 1);
        clear_line();
        std::string hairline;
        hairline.reserve(cols * 3);
        for (int i = 0; i < cols; ++i)
            hairline += "\xE2\x94\x80";
        write_raw(sgr(kDim, hairline));
        (void)rows;
    }

    void draw_modal_footer(int rows, int cols)
    {
        move_to(rows - 1, 1);
        clear_line();
        std::string hairline;
        hairline.reserve(cols * 3);
        for (int i = 0; i < cols; ++i)
            hairline += "\xE2\x94\x80";
        write_raw(sgr(kDim, hairline));
        move_to(rows, 1);
        clear_line();
        write_raw(sgr(kDim, "  q / ESC ") + sgr(kLabel, "dismiss"));
    }

    const char* level_glyph(alps::exploit::EventLevel l)
    {
        using L = alps::exploit::EventLevel;
        switch (l) {
        case L::Info:
            return "\xC2\xB7";
        case L::Progress:
            return "\xE2\x86\x92";
        case L::Warn:
            return "!";
        case L::Error:
            return "\xE2\x9C\x97";
        case L::Success:
            return "\xE2\x9C\x93";
        case L::Prompt:
            return "?";
        }
        return "?";
    }

    const char* level_color(alps::exploit::EventLevel l)
    {
        using L = alps::exploit::EventLevel;
        switch (l) {
        case L::Info:
            return kDim;
        case L::Progress:
            return kInfo;
        case L::Warn:
            return kWarn;
        case L::Error:
            return kErr;
        case L::Success:
            return kOk;
        case L::Prompt:
            return kValue;
        }
        return kValue;
    }

} // namespace

void run_stage_modal(const std::string& stage_name, StageFn stage)
{
    // Runs on top of an existing raw / alt-screen: the browser owns the
    // outer RawScreen and we must NOT push a nested one (its destructor
    // would tear down termios and leave the browser stuck). We just draw
    // over the current screen and let the browser redraw on return.
    if (!::isatty(STDOUT_FILENO)) {
        stage([](const alps::exploit::Event&) { });
        return;
    }

    // Best-effort terminal size: the outer RawScreen already sanity-
    // checked this succeeds.
    Size sz { 24, 80 };
    {
        struct winsize ws {};
        if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
            sz.rows = ws.ws_row;
            sz.cols = ws.ws_col;
        }
    }

    std::vector<std::string> log;
    int scroll = 0;
    (void)scroll; // captured

    auto redraw = [&] {
        clear_screen();
        draw_modal_header(sz.rows, sz.cols, stage_name);
        const int content_top = 3;
        const int content_rows = sz.rows - 4; // top hairline + footer
        for (int i = 0; i < content_rows; ++i) {
            move_to(content_top + i, 1);
            clear_line();
            const int idx = i + scroll;
            if (idx >= 0 && idx < static_cast<int>(log.size())) {
                write_raw(log[idx]);
            }
        }
        draw_modal_footer(sz.rows, sz.cols);
        // Park cursor.
        move_to(sz.rows, sz.cols);
        std::fflush(stdout);
    };

    // Sink pushes lines and repaints synchronously; cheap enough for the
    // rate at which stages emit. Auto-scroll to keep the latest visible.
    auto sink = [&](const alps::exploit::Event& e) {
        std::string prefix = std::string("  ") + level_glyph(e.level);
        std::string line;
        line.reserve(80);
        line += sgr(level_color(e.level), prefix);
        line += "  ";
        line += sgr(kLabel, e.stage);
        line += "  ";
        line += sgr(kValue, e.message);
        if (e.progress_pct) {
            line += "  " + sgr(kDim, "(" + std::to_string(*e.progress_pct) + "%)");
        }
        // Log-wrap by width: clip conservatively, don't wrap. Users can
        // widen the terminal if they want the full line.
        const std::size_t max_visible = static_cast<std::size_t>(sz.cols);
        if (vis_width(line) > max_visible + 32) {
            // (No-op: ANSI escapes make vis-width tricky; leave to terminal wrap.)
        }
        log.push_back(std::move(line));

        const int content_rows = sz.rows - 4;
        const int max_scroll = std::max(0, static_cast<int>(log.size()) - content_rows);
        scroll = max_scroll;
        redraw();
    };

    redraw();
    stage(sink);

    // Terminal footer: "stage complete, press q to dismiss".
    move_to(sz.rows, 1);
    clear_line();
    write_raw(sgr(kOk, "  Stage complete.  ")
        + sgr(kDim, "q / ESC to dismiss, arrow keys to scroll"));
    std::fflush(stdout);

    // Simple key loop.
    while (true) {
        const KeyEvent k = read_key();
        if (k.kind == Key::Quit || k.kind == Key::Escape)
            break;
        if (k.kind == Key::Char && (k.ch == 'q' || k.ch == 'Q'))
            break;
        const int content_rows = sz.rows - 4;
        const int max_scroll = std::max(0, static_cast<int>(log.size()) - content_rows);
        if (k.kind == Key::Up)
            scroll = std::max(0, scroll - 1);
        if (k.kind == Key::Down)
            scroll = std::min(max_scroll, scroll + 1);
        if (k.kind == Key::PageUp)
            scroll = std::max(0, scroll - content_rows);
        if (k.kind == Key::PageDown)
            scroll = std::min(max_scroll, scroll + content_rows);
        if (k.kind == Key::Home)
            scroll = 0;
        if (k.kind == Key::End)
            scroll = max_scroll;
        redraw();
    }
}

bool prompt_authorization(const std::string& question)
{
    // Draw a two-row overlay banner at the bottom of the current alt-screen
    // and read one key. The caller owns the outer alt-screen; we just
    // paint two rows and let the caller redraw when we return.
    Size sz { 24, 80 };
    struct winsize ws {};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
        sz.rows = ws.ws_row;
        sz.cols = ws.ws_col;
    }
    move_to(sz.rows - 1, 1);
    clear_line();
    write_raw(sgr(kErr, "  I confirm I am authorized to run this exploit on the target device"));
    move_to(sz.rows, 1);
    clear_line();
    write_raw(sgr(kValue, "  " + question + "  ") + sgr(kLabel, "[y/N] "));
    std::fflush(stdout);
    const KeyEvent k = read_key();
    return k.kind == Key::Char && (k.ch == 'y' || k.ch == 'Y');
}

} // namespace alps::tui
