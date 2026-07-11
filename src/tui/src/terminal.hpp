// Small self-contained terminal control shim: enter alt-screen + raw mode
// (RAII), read a single key event, query terminal size. Deliberately does
// NOT depend on ncurses/FTXUI; cross-compiling those for the Android NDK
// adds friction we don't need. POSIX termios + ANSI escapes are enough.

#pragma once

#include <string>
#include <string_view>

namespace alps::tui {

struct Size {
    int rows = 24;
    int cols = 80;
};

// RAII: enter raw input mode (always) and the terminal's alternate screen
// buffer (unless `use_alt_screen == false`) on construction, restore both
// on destruction. Destructor is signal-safe enough for SIGINT / SIGTERM
// (registers handlers that call it).
//
// The alt-screen buffer is disabled by some emulators / relay stacks
// (notably `adb shell -t` from certain Windows consoles); in that case
// the drawing gets clobbered by the returning shell prompt. Callers can
// pass `false` to draw inline instead.
class RawScreen {
public:
    explicit RawScreen(bool use_alt_screen = true);
    ~RawScreen();
    RawScreen(const RawScreen&) = delete;
    RawScreen& operator=(const RawScreen&) = delete;

    [[nodiscard]] Size size() const;
    [[nodiscard]] bool active() const { return active_; }

private:
    bool active_ = false;
};

enum class Key {
    None,
    Char,
    Up,
    Down,
    Left,
    Right,
    Enter,
    Escape,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    Quit,
};

struct KeyEvent {
    Key kind = Key::None;
    char ch = 0; // populated for Key::Char
};

// Blocking read from stdin. EOF / HUP / read error map to Key::Quit so
// the caller exits cleanly rather than tight-looping. Ctrl+C / Ctrl+D
// also map to Key::Quit.
[[nodiscard]] KeyEvent read_key();

// After the last call to `read_key`, what happened? Populated for the
// benefit of higher layers that want to differentiate "user quit" from
// "stdin closed on us"; useful when running through adb / ssh relays.
enum class LastRead { UserKey, Eof, Hup, Error };
[[nodiscard]] LastRead last_read();

// Convenience: write a string directly to stdout without buffering.
void write_raw(std::string_view s);

// Cursor / screen ANSI helpers.
void move_to(int row, int col);
void clear_screen();
void clear_line();

} // namespace alps::tui
