#include "terminal.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

namespace alps::tui {

namespace {

    std::atomic<bool> g_installed { false };
    struct termios g_saved_termios {};
    std::atomic<bool> g_has_saved { false };
    std::atomic<bool> g_used_alt_screen { false };
    LastRead g_last_read = LastRead::UserKey;

    void write_direct(std::string_view s)
    {
        ssize_t n = 0;
        const char* p = s.data();
        std::size_t remaining = s.size();
        while (remaining > 0) {
            n = ::write(STDOUT_FILENO, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
    }

    void enter_alt_screen()
    {
        write_direct("\x1b[?1049h"); // alternate screen buffer
        write_direct("\x1b[?25l"); // hide cursor
        write_direct("\x1b[2J\x1b[H"); // clear + home
    }

    void leave_alt_screen()
    {
        write_direct("\x1b[?25h"); // show cursor
        if (g_used_alt_screen.load()) {
            write_direct("\x1b[?1049l");
        } else {
            // Inline mode: leave the drawing where it is, but drop the cursor
            // to a fresh line so the shell prompt lands beneath us.
            write_direct("\n");
        }
    }

    void restore_terminal_signal_safe()
    {
        if (g_has_saved.load()) {
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
        }
        leave_alt_screen();
    }

    extern "C" void signal_restore(int sig)
    {
        restore_terminal_signal_safe();
        // Re-raise with default handler so the process actually exits.
        std::signal(sig, SIG_DFL);
        std::raise(sig);
    }

} // namespace

RawScreen::RawScreen(bool use_alt_screen)
{
    if (!::isatty(STDIN_FILENO))
        return;

    struct termios cur {};
    if (::tcgetattr(STDIN_FILENO, &cur) != 0)
        return;
    g_saved_termios = cur;
    g_has_saved.store(true);

    struct termios raw = cur;
    // Disable canonical mode, echo, and signal chars; we handle Ctrl+C /
    // Ctrl+D ourselves as Quit so the destructor always runs cleanly.
    raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO | ISIG | IEXTEN);
    raw.c_iflag &= ~static_cast<tcflag_t>(IXON | ICRNL | INPCK | ISTRIP | BRKINT);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
        return;

    g_used_alt_screen.store(use_alt_screen);
    if (use_alt_screen) {
        enter_alt_screen();
    } else {
        // Inline mode: still hide the cursor + clear the screen so we
        // start with a clean canvas.
        write_direct("\x1b[?25l");
        write_direct("\x1b[2J\x1b[H");
    }
    active_ = true;

    if (!g_installed.exchange(true)) {
        std::signal(SIGINT, signal_restore);
        std::signal(SIGTERM, signal_restore);
        std::signal(SIGHUP, signal_restore);
        std::atexit(restore_terminal_signal_safe);
    }
}

RawScreen::~RawScreen()
{
    if (!active_)
        return;
    restore_terminal_signal_safe();
    active_ = false;
}

Size RawScreen::size() const
{
    Size s;
    struct winsize ws {};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
        s.rows = ws.ws_row;
        s.cols = ws.ws_col;
    }
    return s;
}

KeyEvent read_key()
{
    // Wait for stdin to become readable so we don't spin on a broken relay
    // that lets read() return 0 immediately. POLLHUP / errors map to Quit,
    // so a closed pipe cleanly ends the browser instead of looping.
    struct pollfd pfd {};
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    while (true) {
        int p = ::poll(&pfd, 1, -1);
        if (p < 0) {
            if (errno == EINTR)
                continue;
            g_last_read = LastRead::Error;
            return { Key::Quit, 0 };
        }
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            g_last_read = LastRead::Hup;
            return { Key::Quit, 0 };
        }
        if (pfd.revents & POLLIN)
            break;
    }

    unsigned char c = 0;
    ssize_t n = ::read(STDIN_FILENO, &c, 1);
    if (n == 0) {
        g_last_read = LastRead::Eof;
        return { Key::Quit, 0 };
    }
    if (n < 0) {
        g_last_read = LastRead::Error;
        return { Key::Quit, 0 };
    }
    g_last_read = LastRead::UserKey;

    // Ctrl+C / Ctrl+D map to Quit.
    if (c == 0x03 || c == 0x04)
        return { Key::Quit, 0 };
    if (c == '\r' || c == '\n')
        return { Key::Enter, 0 };
    if (c == '\t')
        return { Key::Tab, 0 };
    if (c == 0x7f || c == 0x08)
        return { Key::None, 0 }; // backspace (unused)

    if (c == 0x1b) {
        // Peek: no more bytes = bare Escape. We use VMIN/VTIME=1/0 so this
        // is a bit fragile; read with a short timeout.
        struct termios cur {};
        if (::tcgetattr(STDIN_FILENO, &cur) != 0)
            return { Key::Escape, 0 };
        struct termios tmp = cur;
        tmp.c_cc[VMIN] = 0;
        tmp.c_cc[VTIME] = 1; // 100 ms
        ::tcsetattr(STDIN_FILENO, TCSANOW, &tmp);

        unsigned char b1 = 0, b2 = 0, b3 = 0;
        ssize_t r1 = ::read(STDIN_FILENO, &b1, 1);
        ssize_t r2 = 0;
        ssize_t r3 = 0;
        if (r1 > 0)
            r2 = ::read(STDIN_FILENO, &b2, 1);
        if (r2 > 0)
            r3 = ::read(STDIN_FILENO, &b3, 1);
        (void)r3;

        ::tcsetattr(STDIN_FILENO, TCSANOW, &cur);

        if (r1 <= 0)
            return { Key::Escape, 0 };
        if (b1 == '[' || b1 == 'O') {
            switch (b2) {
            case 'A':
                return { Key::Up, 0 };
            case 'B':
                return { Key::Down, 0 };
            case 'C':
                return { Key::Right, 0 };
            case 'D':
                return { Key::Left, 0 };
            case 'H':
                return { Key::Home, 0 };
            case 'F':
                return { Key::End, 0 };
            case '5':
                if (b3 == '~')
                    return { Key::PageUp, 0 };
                break;
            case '6':
                if (b3 == '~')
                    return { Key::PageDown, 0 };
                break;
            default:
                break;
            }
        }
        return { Key::Escape, 0 };
    }

    if (c == 'q' || c == 'Q')
        return { Key::Quit, 0 };

    return { Key::Char, static_cast<char>(c) };
}

LastRead last_read() { return g_last_read; }

void write_raw(std::string_view s) { write_direct(s); }

void move_to(int row, int col)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "\x1b[%d;%dH", row, col);
    write_direct(buf);
}
void clear_screen() { write_direct("\x1b[2J\x1b[H"); }
// Clear from the CURSOR to end of line (\x1b[K, i.e. \x1b[0K). Do NOT use
// \x1b[2K here; that clears the entire line regardless of cursor position
// and would clobber the left pane when the right-pane pass redraws its own
// row (which lands cursor > col 1). The two-pane layout leaks a visible
// left-column flash between the left and right draw passes otherwise.
void clear_line() { write_direct("\x1b[K"); }

} // namespace alps::tui
