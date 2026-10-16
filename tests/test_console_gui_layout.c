/* tests/test_console_gui_layout.c - KATs for console->GUI render RPC layout.
 * All console messages share {type,msg_id} header so gui_hw.c's raw-byte
 * decoder (gui_rw offsets) stays in sync. Ref: userspace/gui/gui_hw.c
 * gui_render_dispatch; BusyBox-style display pipeline (console owns text,
 * GUI owns fb); Bochs VGA 800x600x32, 8x16 cells. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../userspace/include/services/ipc_protocol.h"

#define CHECK(c)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(c))                                                                                                      \
        {                                                                                                              \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                                                \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

int main(void)
{
    /* PUTC: x@8 y@12 ch@16 fg@20 bg@24 (control: already had header). */
    CHECK(offsetof(msg_console_putc_t, x) == 8);
    CHECK(offsetof(msg_console_putc_t, y) == 12);
    CHECK(offsetof(msg_console_putc_t, ch) == 16);
    CHECK(offsetof(msg_console_putc_t, fg_color) == 20);
    CHECK(offsetof(msg_console_putc_t, bg_color) == 24);
    CHECK(sizeof(msg_console_putc_t) <= 32);

    /* FILL: x@8 y@12 w@16 h@20 color@24. */
    CHECK(offsetof(msg_console_fill_t, x) == 8);
    CHECK(offsetof(msg_console_fill_t, y) == 12);
    CHECK(offsetof(msg_console_fill_t, width) == 16);
    CHECK(offsetof(msg_console_fill_t, height) == 20);
    CHECK(offsetof(msg_console_fill_t, color) == 24);
    CHECK(sizeof(msg_console_fill_t) <= 32);

    /* SCROLL must share header: lines@8 top@12 bottom@16.
     * Without msg_id, GUI read lines@8 gets top(0): scrolls 0, next output
     * overwrites last row instead of scrolling. */
    CHECK(offsetof(msg_console_scroll_t, lines) == 8);
    CHECK(offsetof(msg_console_scroll_t, top) == 12);
    CHECK(offsetof(msg_console_scroll_t, bottom) == 16);
    CHECK(sizeof(msg_console_scroll_t) <= 32);

    /* CURSOR must share header: x@8 y@12 visible@16.
     * Without msg_id, GUI reads x<-y, y<-visible, visible<-0: never draws. */
    CHECK(offsetof(msg_console_cursor_t, x) == 8);
    CHECK(offsetof(msg_console_cursor_t, y) == 12);
    CHECK(offsetof(msg_console_cursor_t, visible) == 16);
    CHECK(sizeof(msg_console_cursor_t) <= 32);

    /* PUTS must share header: xy@8 lenpal@12 data@16, exactly 32 bytes.
     * Without msg_id, GUI reads xy<-lenpal: paints at wrong coords. */
    CHECK(offsetof(msg_console_puts_t, xy) == 8);
    CHECK(offsetof(msg_console_puts_t, lenpal) == 12);
    CHECK(offsetof(msg_console_puts_t, data) == 16);
    CHECK(sizeof(msg_console_puts_t) == 32);
    CHECK(MSG_CONSOLE_PUTS == 0x2005);

    printf("PASS: test_console_gui_layout\n");
    return 0;
}
