// Two-pane browser. Left pane: findings grouped by verdict, sections
// marked with a 1-column colored bar (no emoji: the toy circles read
// wrong next to a monospace layout). Right pane: labeled field/value
// blocks with subtle horizontal rules for grouping. Selection uses a
// colored left-margin bar and bold, no reverse-video "shout".
//
// The render is monolithic: we redraw the whole screen every keystroke.
// The KB is small enough that flicker isn't a concern, and this keeps the
// logic straight.

#include "alps/tui/browser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "alps/core/finding.hpp"
#include "alps/core/rule.hpp"
#include "alps/exploit/events.hpp"
#include "alps/exploit/runner.hpp"
#include "runner_view.hpp"
#include "terminal.hpp"

namespace alps::tui {

namespace {

    using alps::core::Finding;
    using alps::core::Verdict;

    constexpr std::array<Verdict, 5> kOrder = {
        Verdict::AVAILABLE_NOW,
        Verdict::VIA_DOWNGRADE,
        Verdict::POC_NEEDS_PORTING,
        Verdict::RESEARCH_LEAD,
        Verdict::UNREACHABLE,
    };

    const char* section_title(Verdict v)
    {
        switch (v) {
        case Verdict::AVAILABLE_NOW:
            return "Available now";
        case Verdict::VIA_DOWNGRADE:
            return "Reachable via downgrade";
        case Verdict::POC_NEEDS_PORTING:
            return "PoC needs porting";
        case Verdict::RESEARCH_LEAD:
            return "Research lead";
        case Verdict::UNREACHABLE:
            return "Unreachable";
        }
        return "?";
    }

    // 256-color palette.
    // Muted, deliberately-chosen fg codes so the sections feel like a
    // cohesive palette rather than a stoplight cartoon.
    const char* verdict_fg(Verdict v)
    {
        switch (v) {
        case Verdict::AVAILABLE_NOW:
            return "38;5;203"; // soft coral red
        case Verdict::VIA_DOWNGRADE:
            return "38;5;179"; // warm amber
        case Verdict::POC_NEEDS_PORTING:
            return "38;5;75"; // steel blue
        case Verdict::RESEARCH_LEAD:
            return "38;5;244"; // neutral gray
        case Verdict::UNREACHABLE:
            return "38;5;108"; // sage green
        }
        return "38;5;15";
    }

    constexpr const char* kAccentDim = "38;5;240"; // borders, hairlines
    constexpr const char* kLabelFg = "38;5;245"; // field labels
    constexpr const char* kValueFg = "38;5;253"; // primary values
    constexpr const char* kSubtleFg = "38;5;242"; // hints, subtitles
    constexpr const char* kEmphasisFg = "38;5;255"; // highlighted values / CVE id
    constexpr const char* kWarnFg = "38;5;208"; // orange, root warning

    std::string sgr(std::string_view code, std::string_view text)
    {
        std::string out;
        out.reserve(text.size() + code.size() + 6);
        out.append("\x1b[").append(code).append("m").append(text).append("\x1b[0m");
        return out;
    }

    // One row in the visible list.
    struct Row {
        bool is_header = false;
        Verdict verdict {};
        std::size_t section_count = 0;
        const Finding* finding = nullptr;
    };

    std::vector<Row> build_rows(const alps::report::Report& r)
    {
        std::vector<Row> out;
        for (const auto v : kOrder) {
            std::vector<const Finding*> group;
            for (const auto& f : r.findings) {
                if (f.verdict == v)
                    group.push_back(&f);
            }
            Row h;
            h.is_header = true;
            h.verdict = v;
            h.section_count = group.size();
            out.push_back(std::move(h));
            for (const auto* f : group) {
                Row row;
                row.is_header = false;
                row.verdict = v;
                row.finding = f;
                out.push_back(std::move(row));
            }
        }
        return out;
    }

    // Utilities.

    std::size_t visible_width(std::string_view s)
    {
        std::size_t n = 0;
        for (unsigned char c : s) {
            if ((c & 0xC0) != 0x80)
                ++n;
        }
        return n;
    }

    std::string abbrev(std::string_view s, std::size_t max_len)
    {
        if (visible_width(s) <= max_len)
            return std::string(s);
        // We cheat slightly and clip on byte length near the target, then append an ellipsis.
        std::string out;
        std::size_t vw = 0;
        for (std::size_t i = 0; i < s.size();) {
            const unsigned char b = static_cast<unsigned char>(s[i]);
            std::size_t bytes = 1;
            if ((b & 0x80) == 0)
                bytes = 1;
            else if ((b & 0xE0) == 0xC0)
                bytes = 2;
            else if ((b & 0xF0) == 0xE0)
                bytes = 3;
            else if ((b & 0xF8) == 0xF0)
                bytes = 4;
            if (vw + 1 > max_len - 1)
                break;
            out.append(s.substr(i, bytes));
            ++vw;
            i += bytes;
        }
        out.append("\xE2\x80\xA6"); // ellipsis
        return out;
    }

    std::string right_pad(std::string_view s, std::size_t width)
    {
        const std::size_t vw = visible_width(s);
        if (vw >= width)
            return std::string(s);
        return std::string(s) + std::string(width - vw, ' ');
    }

    // Simple word wrap for the right pane.
    std::vector<std::string> wrap(std::string_view text, std::size_t width)
    {
        std::vector<std::string> out;
        std::string cur;
        std::size_t cur_w = 0;
        auto flush = [&] {
            out.push_back(cur);
            cur.clear();
            cur_w = 0;
        };

        std::size_t i = 0;
        while (i < text.size()) {
            if (cur.empty() && cur_w == 0 && !out.empty() && text[i] == ' ') {
                ++i;
                continue;
            }
            if (text[i] == '\n') {
                flush();
                ++i;
                continue;
            }

            std::size_t j = i;
            while (j < text.size() && text[j] != ' ' && text[j] != '\n')
                ++j;
            std::string_view word = text.substr(i, j - i);
            std::size_t word_w = visible_width(word);

            if (cur_w > 0 && cur_w + 1 + word_w > width)
                flush();
            if (word_w > width) {
                for (char c : word)
                    cur += c;
                cur_w += word_w;
                flush();
                i = j;
                continue;
            }
            if (cur_w > 0) {
                cur += ' ';
                ++cur_w;
            }
            cur.append(word);
            cur_w += word_w;
            i = j;
            while (i < text.size() && text[i] == ' ')
                ++i;
        }
        if (!cur.empty())
            flush();
        return out;
    }

    // Layout.

    struct DrawContext {
        Size size;
        int header_lines = 3;
        int footer_lines = 2;
        int content_top = 4;
        int content_rows = 0;
        int left_cols = 44;
        int right_col = 0; // 1-indexed column where right pane starts
        int right_cols = 0;
        int sep_col = 0; // 1-indexed column for the vertical separator
    };

    DrawContext compute_layout(const Size& s)
    {
        DrawContext c;
        c.size = s;
        if (s.rows < 14)
            c.header_lines = 2;
        c.content_top = c.header_lines + 1;
        c.content_rows = s.rows - c.header_lines - c.footer_lines;
        c.left_cols = std::clamp(static_cast<int>(s.cols * 0.42), 34, 52);
        if (c.left_cols > s.cols - 32)
            c.left_cols = s.cols - 32;
        c.sep_col = c.left_cols + 2;
        c.right_col = c.left_cols + 4;
        c.right_cols = s.cols - c.right_col;
        if (c.right_cols < 20)
            c.right_cols = 20;
        return c;
    }

    // Header / footer.

    void draw_header(const alps::report::Report& r, const DrawContext& c)
    {
        move_to(1, 1);
        clear_line();
        std::string hdr = sgr("1;" + std::string(kEmphasisFg), "ALPS");
        if (r.facts) {
            const auto& f = *r.facts;
            hdr += "  " + sgr(kAccentDim, "·") + "  "
                + sgr(std::string("1;") + kEmphasisFg,
                    f.manufacturer.value_or("?") + " " + f.model.value_or("?"))
                + sgr(kSubtleFg, "  (" + f.device.value_or("?") + ")") + "  " + sgr(kAccentDim, "·")
                + "  " + sgr(kValueFg, "Android " + f.android_release.value_or("?")) + "  "
                + sgr(kAccentDim, "·") + "  " + sgr(kValueFg, "SPL " + f.spl.value_or("?"));
        }
        write_raw(hdr);

        move_to(2, 1);
        clear_line();
        std::string sub;
        if (r.facts) {
            const auto& f = *r.facts;
            auto sep = [&] {
                if (!sub.empty())
                    sub += "  " + sgr(kAccentDim, "·") + "  ";
            };
            if (f.gpu.vendor) {
                std::string g = *f.gpu.vendor;
                if (f.gpu.mali_driver)
                    g += " " + *f.gpu.mali_driver;
                if (f.gpu.adreno_driver)
                    g += " " + *f.gpu.adreno_driver;
                if (f.gpu.mali_arch)
                    g += " " + sgr(kSubtleFg, "(" + *f.gpu.mali_arch + ")");
                sub += sgr(kValueFg, g);
            }
            if (f.kernel_version) {
                sep();
                // Clip to the "-androidX-Y" suffix, no ugly build hash.
                const auto& k = *f.kernel_version;
                std::size_t cut = k.size();
                if (auto pos = k.find("-android"); pos != std::string_view::npos) {
                    std::size_t end = pos + std::string("-android").size();
                    while (end < k.size() && std::isdigit(static_cast<unsigned char>(k[end])))
                        ++end;
                    if (end < k.size() && k[end] == '-') {
                        std::size_t after = end + 1;
                        if (after < k.size()
                            && std::isdigit(static_cast<unsigned char>(k[after]))) {
                            end = after;
                            while (
                                end < k.size() && std::isdigit(static_cast<unsigned char>(k[end])))
                                ++end;
                        }
                    }
                    cut = end;
                }
                while (cut > 0 && k[cut - 1] == '-')
                    --cut;
                sub += sgr(kValueFg, "kernel " + k.substr(0, cut));
            }
            if (f.bootloader_locked) {
                sep();
                std::string b = *f.bootloader_locked ? "locked" : "unlocked";
                if (f.verified_boot_state)
                    b += "/" + *f.verified_boot_state;
                sub += sgr(kValueFg, b);
            }
            if (f.selinux_mode) {
                sep();
                sub += sgr(kValueFg, "SELinux " + *f.selinux_mode);
            }
            if (f.root_indicator) {
                sep();
                sub += sgr(std::string("1;") + kWarnFg, "\xE2\x9A\xA0 ROOT: " + *f.root_indicator);
            }
        }
        write_raw(sub);

        move_to(3, 1);
        clear_line();
        write_raw(sgr(kAccentDim, std::string(c.size.cols, '\xE2')));
        // Above is 1 byte of '\xE2' repeated: placeholder that we overwrite.
        move_to(3, 1);
        // U+2500 is 3 bytes UTF-8 (E2 94 80). Emit it `cols` times.
        std::string rule;
        rule.reserve(c.size.cols * 3);
        for (int i = 0; i < c.size.cols; ++i)
            rule.append("\xE2\x94\x80");
        write_raw(sgr(kAccentDim, rule));
    }

    void draw_footer(const DrawContext& c)
    {
        move_to(c.size.rows - 1, 1);
        clear_line();
        std::string rule;
        rule.reserve(c.size.cols * 3);
        for (int i = 0; i < c.size.cols; ++i)
            rule.append("\xE2\x94\x80");
        write_raw(sgr(kAccentDim, rule));

        move_to(c.size.rows, 1);
        clear_line();
        auto key = [](std::string_view k, std::string_view label) {
            return sgr(std::string("1;") + kEmphasisFg, k)
                + sgr(kSubtleFg, " " + std::string(label));
        };
        std::string hints;
        hints += "  " + key("\xE2\x86\x91\xE2\x86\x93", "nav");
        hints += "  " + key("PgUp/PgDn", "page");
        hints += "  " + key("\xE2\x86\x90\xE2\x86\x92", "detail");
        hints += "   " + sgr(kSubtleFg, "runner:");
        hints += " " + key("a", "all");
        hints += "  " + sgr(kSubtleFg, "|");
        hints += " " + key("p", "prereq");
        hints += " " + key("f", "fetch");
        hints += " " + key("b", "build");
        hints += " " + key("d", "deploy");
        hints += " " + key("r", "run");
        hints += " " + key("x", "clean");
        hints += "   " + key("q", "quit");
        write_raw(hints);
    }

    // Left pane.

    void draw_left_row(const Row& row, int visible_row, const DrawContext& c, bool selected)
    {
        move_to(visible_row, 1);
        clear_line();

        const std::string vcode = verdict_fg(row.verdict);

        if (row.is_header) {
            // 1-col colored bar in verdict color, then bold title, right-aligned
            // count. No emoji; no all-caps SHOUTING.
            const std::string bar = sgr(vcode, "\xE2\x96\x8E"); // vertical bar
            const std::string title = sgr(std::string("1;") + vcode, section_title(row.verdict));
            const std::string count = sgr(kSubtleFg, std::to_string(row.section_count));

            // Compose: "▎ <title>                 <count>"
            // Left = bar + " " + title (visible width computed on title text).
            std::string left = bar + " " + title;
            const std::size_t left_vw = 2 /* bar+space */
                + visible_width(section_title(row.verdict));
            const std::size_t count_vw = visible_width(std::to_string(row.section_count));
            const std::size_t total_w = static_cast<std::size_t>(c.left_cols);
            if (left_vw + 1 + count_vw <= total_w) {
                const std::size_t pad = total_w - left_vw - count_vw;
                write_raw(left + std::string(pad, ' ') + count);
            } else {
                write_raw(left);
            }
            return;
        }

        // Finding row: 1-col gutter bar for selection (col 1), then indent (col 2),
        // then CVE id (bold when selected), gap, title truncated to fit.
        const std::string gutter = selected ? sgr(vcode, "\xE2\x96\x8E") // vertical bar
                                            : std::string(" ");
        std::string id = row.finding->rule_id;
        std::string id_out
            = selected ? sgr(std::string("1;") + kEmphasisFg, id) : sgr(kValueFg, id);
        const std::size_t id_vw = visible_width(id);

        // Fixed CVE-id column width: 15 chars is comfortable for "CVE-2022-38181"
        // (14) with a single trailing space of breathing room.
        constexpr std::size_t kIdCol = 15;
        std::string id_padded = id_out;
        if (id_vw < kIdCol)
            id_padded += std::string(kIdCol - id_vw, ' ');

        // Title fits in whatever's left of the left pane.
        const int title_room = c.left_cols - 3 /* gutter+space */ - static_cast<int>(kIdCol) - 1;
        const std::string title = abbrev(row.finding->title, std::max(10, title_room));
        const std::string title_out
            = selected ? sgr(std::string("1;") + kValueFg, title) : sgr(kValueFg, title);

        // Compose: "▎ <id>          <title>"
        std::string line = gutter + " " + id_padded + " " + title_out;
        write_raw(line);
    }

    // Right pane.

    // Section rule with a small inline label: "---- About -----..."
    std::string section_rule(std::string_view label, std::size_t width)
    {
        // Fixed prefix of 4 dashes, then " label ", then dashes to fill `width`.
        std::string prefix, suffix;
        for (int i = 0; i < 4; ++i)
            prefix.append("\xE2\x94\x80");
        const std::size_t used = 4 + 1 + visible_width(label) + 1;
        std::size_t tail_count = 0;
        if (width > used)
            tail_count = width - used;
        std::string tail;
        for (std::size_t i = 0; i < tail_count; ++i)
            tail.append("\xE2\x94\x80");
        return sgr(kAccentDim, prefix) + " " + sgr(std::string("1;") + kLabelFg, std::string(label))
            + " " + sgr(kAccentDim, tail);
    }

    const alps::core::Rule* find_rule(
        const std::vector<alps::core::Rule>* rules, const std::string& id)
    {
        if (!rules)
            return nullptr;
        for (const auto& r : *rules)
            if (r.id == id)
                return &r;
        return nullptr;
    }

    std::vector<std::string> compose_details(
        const Finding& f, std::size_t width, const std::vector<alps::core::Rule>* rules = nullptr)
    {
        using alps::core::exploit_gives_to_string;
        using alps::core::exploit_status_to_string;
        using alps::core::verdict_to_string;

        std::vector<std::string> out;

        // Title header.
        out.push_back(sgr(std::string("1;") + kEmphasisFg, f.rule_id));
        for (const auto& l : wrap(f.title, width)) {
            out.push_back(sgr(kValueFg, l));
        }
        out.push_back("");

        // About.
        out.push_back(section_rule("About", width));
        auto field = [&](std::string_view name, std::string_view value) {
            // 13-char label column, then value.
            std::string label = sgr(kLabelFg, right_pad(name, 13));
            for (const auto& l : wrap(value, width - 14)) {
                out.push_back("  " + label + sgr(kValueFg, l));
                // Only the first wrapped line gets the label; subsequent lines
                // indent under it.
                label = sgr(kLabelFg, std::string(13, ' '));
            }
        };
        field("Verdict", verdict_to_string(f.verdict));
        field("Component", f.component);
        field("Status", exploit_status_to_string(f.exploit.status));
        field("Gives", exploit_gives_to_string(f.exploit.gives));
        if (!f.exploit.poc_targets.empty()) {
            std::string joined;
            for (std::size_t i = 0; i < f.exploit.poc_targets.size(); ++i) {
                if (i)
                    joined += ", ";
                joined += f.exploit.poc_targets[i];
            }
            field("PoC targets", joined);
        } else {
            field("PoC targets", "portable (no device offsets required)");
        }
        if (f.exploit.user_interaction)
            field("User interaction", "yes");
        out.push_back("");

        // Reasoning.
        if (!f.reasoning.empty()) {
            out.push_back(section_rule("Reasoning", width));
            for (const auto& l : wrap(f.reasoning, width - 2)) {
                out.push_back("  " + sgr(kValueFg, l));
            }
            out.push_back("");
        }

        // Matched facts.
        if (!f.matched_facts.empty()) {
            out.push_back(section_rule("Matched facts", width));
            for (const auto& mf : f.matched_facts) {
                out.push_back("  " + sgr(std::string("1;") + kLabelFg, mf.field) + " "
                    + sgr(kValueFg, mf.observed_value));
                // Trim leading observed_value from reason (avoids duplication).
                std::string reason = mf.reason;
                if (!mf.observed_value.empty() && reason.rfind(mf.observed_value, 0) == 0) {
                    reason = reason.substr(mf.observed_value.size());
                    while (!reason.empty() && (reason.front() == ' ' || reason.front() == '\t')) {
                        reason.erase(reason.begin());
                    }
                }
                for (const auto& l : wrap(reason, width - 4)) {
                    out.push_back("    " + sgr(kSubtleFg, l));
                }
            }
            out.push_back("");
        }

        // Notes (blockers, downgrade target).
        if (!f.notes.empty()) {
            out.push_back(section_rule("Notes", width));
            for (const auto& n : f.notes) {
                for (const auto& l : wrap(n, width - 4)) {
                    out.push_back("  " + sgr(kValueFg, "\xC2\xB7 ") + sgr(kValueFg, l));
                }
            }
            out.push_back("");
        }

        // References.
        if (!f.refs.empty()) {
            out.push_back(section_rule("References", width));
            for (const auto& r : f.refs) {
                // No wrapping for URLs: they're better left one-per-line even
                // if they run past the pane's right edge (terminals often let
                // the user select the whole line to copy).
                out.push_back("  " + sgr(std::string("4;") + kLabelFg, r)); // underline
            }
            out.push_back("");
        }

        // Runner (only if the rule has an exploit_source: block).
        if (const auto* rule = find_rule(rules, f.rule_id)) {
            const auto summary = format_runner_status(*rule, width);
            for (const auto& l : summary.lines)
                out.push_back(l);
        }
        return out;
    }

    void draw_right_pane(const std::vector<std::string>& lines, const DrawContext& c, int scroll)
    {
        for (int i = 0; i < c.content_rows; ++i) {
            move_to(c.content_top + i, c.right_col);
            clear_line();
            const int line_idx = i + scroll;
            if (line_idx >= 0 && line_idx < static_cast<int>(lines.size())) {
                write_raw(lines[line_idx]);
            }
        }
    }

    void draw_separator(const DrawContext& c)
    {
        for (int i = 0; i < c.content_rows; ++i) {
            move_to(c.content_top + i, c.sep_col);
            write_raw(sgr(kAccentDim, "\xE2\x94\x82")); // vertical bar
        }
    }

    // Selection navigation.

    int first_finding_at_or_after(const std::vector<Row>& rows, int start)
    {
        for (int i = std::max(0, start); i < static_cast<int>(rows.size()); ++i) {
            if (!rows[i].is_header)
                return i;
        }
        return -1;
    }
    int prev_finding(const std::vector<Row>& rows, int cur)
    {
        for (int i = cur - 1; i >= 0; --i)
            if (!rows[i].is_header)
                return i;
        return cur;
    }
    int next_finding(const std::vector<Row>& rows, int cur)
    {
        for (int i = cur + 1; i < static_cast<int>(rows.size()); ++i) {
            if (!rows[i].is_header)
                return i;
        }
        return cur;
    }
    int last_finding(const std::vector<Row>& rows)
    {
        for (int i = static_cast<int>(rows.size()) - 1; i >= 0; --i) {
            if (!rows[i].is_header)
                return i;
        }
        return -1;
    }

} // namespace

int run_browser(const alps::report::Report& report, BrowserOpts opts)
{
    if (!::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) {
        std::cerr << "alps ui: stdin/stdout must be a TTY.\n"
                     "Hint: run through `adb shell -t /data/local/tmp/alps ui` so a "
                     "pty is allocated.\n";
        return 2;
    }

    const auto rows = build_rows(report);
    if (report.findings.empty()) {
        RawScreen scr(opts.use_alt_screen);
        if (!scr.active()) {
            std::cerr << "alps ui: could not enter raw mode.\n";
            return 3;
        }
        Size s = scr.size();
        DrawContext c = compute_layout(s);
        draw_header(report, c);
        move_to(c.content_top, 1);
        write_raw(sgr(kSubtleFg, "No candidate findings."));
        draw_footer(c);
        (void)read_key();
        return 0;
    }

    RawScreen scr(opts.use_alt_screen);
    if (!scr.active()) {
        std::cerr << "alps ui: could not enter raw mode.\n";
        return 3;
    }

    int cursor = first_finding_at_or_after(rows, 0);
    if (cursor < 0)
        cursor = 0;
    int scroll_left = 0;
    int scroll_right = 0;

    bool quit = false;
    while (!quit) {
        Size s = scr.size();
        DrawContext c = compute_layout(s);

        draw_header(report, c);
        draw_footer(c);

        // Left pane first (each row clears from col 1 to EOL).
        if (cursor < scroll_left)
            scroll_left = cursor;
        if (cursor >= scroll_left + c.content_rows) {
            scroll_left = cursor - c.content_rows + 1;
        }
        for (int i = 0; i < c.content_rows; ++i) {
            const int row_idx = i + scroll_left;
            const int visible_row = c.content_top + i;
            if (row_idx >= 0 && row_idx < static_cast<int>(rows.size())) {
                draw_left_row(rows[row_idx], visible_row, c, row_idx == cursor);
            } else {
                move_to(visible_row, 1);
                clear_line();
            }
        }

        // Separator column between the panes: after left, before right.
        draw_separator(c);

        // Right pane details for the selected row.
        std::vector<std::string> detail_lines;
        const Row& cur_row = rows[cursor];
        if (!cur_row.is_header && cur_row.finding) {
            detail_lines = compose_details(
                *cur_row.finding, static_cast<std::size_t>(c.right_cols), opts.rules);
        } else {
            detail_lines.push_back(sgr(kSubtleFg, "(no finding selected)"));
        }
        const int max_right_scroll
            = std::max(0, static_cast<int>(detail_lines.size()) - c.content_rows);
        if (scroll_right > max_right_scroll)
            scroll_right = max_right_scroll;
        if (scroll_right < 0)
            scroll_right = 0;

        draw_right_pane(detail_lines, c, scroll_right);

        // Park cursor off-screen (bottom-right of visible area).
        move_to(c.size.rows, c.size.cols);
        std::fflush(stdout);

        const KeyEvent k = read_key();
        switch (k.kind) {
        case Key::Up:
            cursor = prev_finding(rows, cursor);
            scroll_right = 0;
            break;
        case Key::Down:
            cursor = next_finding(rows, cursor);
            scroll_right = 0;
            break;
        case Key::PageUp:
            for (int i = 0; i < 5; ++i)
                cursor = prev_finding(rows, cursor);
            scroll_right = 0;
            break;
        case Key::PageDown:
            for (int i = 0; i < 5; ++i)
                cursor = next_finding(rows, cursor);
            scroll_right = 0;
            break;
        case Key::Home:
            cursor = first_finding_at_or_after(rows, 0);
            scroll_right = 0;
            break;
        case Key::End: {
            const int last = last_finding(rows);
            if (last >= 0)
                cursor = last;
            scroll_right = 0;
            break;
        }
        case Key::Right:
            scroll_right += 1;
            break;
        case Key::Left:
            scroll_right = std::max(0, scroll_right - 1);
            break;
        case Key::Quit:
        case Key::Escape:
            quit = true;
            break;
        case Key::Char:
            if (k.ch == 'j') {
                cursor = next_finding(rows, cursor);
                scroll_right = 0;
            } else if (k.ch == 'k') {
                cursor = prev_finding(rows, cursor);
                scroll_right = 0;
            } else if (k.ch == 'g') {
                cursor = first_finding_at_or_after(rows, 0);
            } else if (k.ch == 'G') {
                const int last = last_finding(rows);
                if (last >= 0)
                    cursor = last;
            } else if (opts.rules && !rows[cursor].is_header && rows[cursor].finding
                && (k.ch == 'p' || k.ch == 'f' || k.ch == 'b' || k.ch == 'd' || k.ch == 'r'
                    || k.ch == 'x' || k.ch == 'a')) {
                const auto* rule = find_rule(opts.rules, rows[cursor].finding->rule_id);
                if (rule && rule->exploit_source) {
                    const char stage = k.ch;
                    const bool needs_auth = (stage != 'p');
                    if (needs_auth
                        && !prompt_authorization(std::string("Run `alps exploit ")
                            + (stage == 'f'        ? "fetch"
                                    : stage == 'b' ? "build"
                                    : stage == 'd' ? "deploy"
                                    : stage == 'r' ? "run"
                                    : stage == 'a' ? "go (all stages)"
                                                   : "cleanup")
                            + "` for " + rule->id + "?")) {
                        // Declined; fall through to redraw.
                    } else {
                        const auto* fp = rows[cursor].finding;
                        const alps::core::DeviceFacts* facts_ptr = report.facts;
                        const auto* run_rule = rule;
                        const std::optional<std::string> serial = opts.adb_serial;
                        const char launched = stage;
                        run_stage_modal(stage == 'p' ? "Prereq check"
                                : stage == 'f'       ? "Fetch"
                                : stage == 'b'       ? "Build"
                                : stage == 'd'       ? "Deploy"
                                : stage == 'r'       ? "Run"
                                : stage == 'a'       ? "Go (all stages)"
                                                     : "Cleanup",
                            [run_rule, fp, facts_ptr, serial, launched, needs_auth](
                                alps::exploit::EventSink sink) -> bool {
                                alps::exploit::RunOptions ro;
                                ro.authorized = needs_auth;
                                ro.adb_serial = serial;
                                ro.current_verdict = fp->verdict;
                                if (facts_ptr && facts_ptr->device)
                                    ro.device_codename = *facts_ptr->device;
                                if (facts_ptr && facts_ptr->selinux_mode)
                                    ro.selinux_mode = *facts_ptr->selinux_mode;
                                ro.events = std::move(sink);
                                try {
                                    alps::exploit::Runner runner(*run_rule, std::move(ro));
                                    switch (launched) {
                                    case 'p':
                                        return runner.check_prereqs().ok;
                                    case 'f':
                                        return runner.fetch().ok;
                                    case 'b': {
                                        runner.check_prereqs();
                                        return runner.build().ok;
                                    }
                                    case 'd':
                                        return runner.deploy().ok;
                                    case 'r':
                                        return runner.execute().ok;
                                    case 'x':
                                        return runner.cleanup(false).ok;
                                    case 'a':
                                        return runner.run_all(false).ok;
                                    }
                                } catch (const std::exception&) {
                                    return false;
                                }
                                return false;
                            });
                    }
                    // Force a full redraw after the modal.
                    clear_screen();
                }
            }
            break;
        default:
            break;
        }
    }

    const LastRead lr = last_read();
    if (lr != LastRead::UserKey) {
        scr.~RawScreen();
        const char* why = lr == LastRead::Eof ? "stdin closed (EOF)"
            : lr == LastRead::Hup             ? "stdin hangup"
                                              : "stdin read error";
        std::cerr << "\nalps ui: exited early because " << why
                  << ".\n"
                     "  Your terminal or `adb` relay isn't forwarding keystrokes.\n"
                     "  Try Windows Terminal / a real Linux terminal, or add\n"
                     "  --no-alt-screen if the drawing gets clobbered by your shell prompt.\n";
        return 4;
    }
    return 0;
}

} // namespace alps::tui
