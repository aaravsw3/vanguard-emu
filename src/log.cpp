#include "wraith.h"
#include <cstdio>
#include <cstdarg>
#include <ctime>

namespace wraith::log {

static Lvl g_lvl = INF;
static HANDLE g_con = INVALID_HANDLE_VALUE;
static bool g_is_console = false;

void init(bool debug) {
    g_lvl = debug ? DBG : INF;
    g_con = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode = 0;
    g_is_console = (GetConsoleMode(g_con, &mode) != 0);
    if (g_is_console)
        SetConsoleMode(g_con, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

void print(Lvl l, const char* fmt, ...) {
    if (l < g_lvl) return;

    static const char* col[] = {"\x1b[90m", "\x1b[36m", "\x1b[33m", "\x1b[31m"};
    static const char* tag[] = {"DBG", "INF", "WRN", "ERR"};

    SYSTEMTIME st;
    GetLocalTime(&st);

    char buf[4096];
    int off = snprintf(buf, sizeof(buf), "%s[%02d:%02d:%02d][%s]\x1b[0m ",
                       col[l], st.wHour, st.wMinute, st.wSecond, tag[l]);

    va_list ap;
    va_start(ap, fmt);
    off += vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);

    if (off < (int)sizeof(buf) - 1) buf[off++] = '\n';
    buf[off] = 0;

    DWORD w;
    if (g_is_console)
        WriteConsoleA(g_con, buf, off, &w, nullptr);
    else
        WriteFile(g_con, buf, off, &w, nullptr);
}

} // namespace wraith::log
